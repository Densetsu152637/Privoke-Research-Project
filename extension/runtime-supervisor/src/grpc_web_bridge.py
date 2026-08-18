from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import re
import threading
from typing import Callable
from urllib.parse import quote

import grpc


CONTROL_PREFIX = "/privoke.v1.PrivokeRuntimeControlService/"
RUNTIME_PREFIX = "/privoke.v1.PrivokeRuntimeService/"
_EXTENSION_ORIGIN = re.compile(
    r"^(?:chrome|moz|opera)-extension://[a-zA-Z0-9_@.{}-]+$"
)


class GrpcWebBridge:
    """Small loopback-only gRPC-Web proxy for the browser extension."""

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 8080,
        control_target: str = "127.0.0.1:50056",
        runtime_target: str = "127.0.0.1:50054",
        rpc_invoker: Callable[[str, bytes, str, float], bytes] | None = None,
    ) -> None:
        self.control_target = control_target
        self.runtime_target = runtime_target
        self.rpc_invoker = rpc_invoker or _invoke_unary_rpc
        bridge = self

        class Handler(BaseHTTPRequestHandler):
            def do_OPTIONS(self) -> None:
                if not self._origin_allowed():
                    self.send_error(403)
                    return
                self.send_response(204)
                self._set_cors_headers()
                self.send_header("Access-Control-Allow-Methods", "POST,OPTIONS")
                self.send_header(
                    "Access-Control-Allow-Headers",
                    "content-type,x-grpc-web,x-user-agent,grpc-timeout",
                )
                self.send_header("Access-Control-Max-Age", "86400")
                self.end_headers()

            def do_POST(self) -> None:
                if not self._origin_allowed():
                    self.send_error(403)
                    return
                target = bridge._target_for_path(self.path)
                if target is None:
                    self.send_error(404)
                    return
                try:
                    content_length = int(self.headers.get("Content-Length", "0"))
                    payload = _decode_grpc_web_frame(self.rfile.read(content_length))
                    timeout = 35.0 if self.path.startswith(CONTROL_PREFIX) else 30.0
                    response = bridge.rpc_invoker(self.path, payload, target, timeout)
                    body = _data_frame(response) + _trailer_frame(0)
                    self.send_response(200)
                    self._set_cors_headers()
                    self.send_header("Content-Type", "application/grpc-web+proto")
                    self.send_header("Access-Control-Expose-Headers", "grpc-status,grpc-message")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except ValueError as exc:
                    self.send_error(400, str(exc))
                except grpc.RpcError as exc:
                    status = exc.code().value[0]
                    message = exc.details() or exc.code().name
                    body = _trailer_frame(status, message)
                    self.send_response(200)
                    self._set_cors_headers()
                    self.send_header("Content-Type", "application/grpc-web+proto")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            def _origin_allowed(self) -> bool:
                origin = self.headers.get("Origin", "")
                return origin in {"http://localhost", "http://127.0.0.1"} or bool(
                    _EXTENSION_ORIGIN.fullmatch(origin)
                )

            def _set_cors_headers(self) -> bool:
                origin = self.headers.get("Origin", "")
                if not self._origin_allowed():
                    return False
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
                return True

            def log_message(self, format: str, *args) -> None:
                return

        self._server = ThreadingHTTPServer((host, port), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="privoke-grpc-web-bridge",
            daemon=True,
        )

    @property
    def port(self) -> int:
        return int(self._server.server_port)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5.0)

    def _target_for_path(self, path: str) -> str | None:
        if path.startswith(CONTROL_PREFIX):
            return self.control_target
        if path.startswith(RUNTIME_PREFIX):
            return self.runtime_target
        return None


def _invoke_unary_rpc(path: str, payload: bytes, target: str, timeout: float) -> bytes:
    with grpc.insecure_channel(target) as channel:
        call = channel.unary_unary(
            path,
            request_serializer=lambda value: value,
            response_deserializer=lambda value: value,
        )
        return call(payload, timeout=timeout)


def _decode_grpc_web_frame(body: bytes) -> bytes:
    if len(body) < 5 or body[0] != 0:
        raise ValueError("Expected one binary gRPC-Web request frame.")
    length = int.from_bytes(body[1:5], "big")
    if length != len(body) - 5:
        raise ValueError("Invalid gRPC-Web request frame length.")
    return body[5:]


def _data_frame(payload: bytes) -> bytes:
    return b"\x00" + len(payload).to_bytes(4, "big") + payload


def _trailer_frame(status: int, message: str = "") -> bytes:
    trailers = f"grpc-status: {status}\r\n"
    if message:
        trailers += f"grpc-message: {quote(message, safe='')}\r\n"
    payload = trailers.encode("ascii")
    return b"\x80" + len(payload).to_bytes(4, "big") + payload
