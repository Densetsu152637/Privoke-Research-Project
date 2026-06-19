from __future__ import annotations

import ipaddress
import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Tuple
from urllib.parse import urlparse

from ..env import env_bool, env_positive_int
from .models import RequestValidationError
from .serialization import (
    DEFAULT_MAX_TEXT_CHARS,
    error_response,
    parse_prompt_request,
)
from .runtime_config import (
    current_llm_config_response,
    update_llm_config_from_payload,
)


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
ANALYZE_PATHS = {"/analyze", "/v1/analyze"}
HEALTH_PATHS = {"/health", "/v1/health"}
LLM_CONFIG_PATHS = {"/config/llm", "/v1/config/llm"}
LOG_PROMPTS_ENV = "PRIVOKE_DEV_LOG_PROMPTS"


class LocalOnlyHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(
        self,
        server_address: Tuple[str, int],
        handler_class,
        *,
        max_text_chars: int = DEFAULT_MAX_TEXT_CHARS,
        cors_origin: str = "*",
    ):
        host, _ = server_address
        if not is_loopback_host(host) and not env_bool(
            "PRIVOKE_ALLOW_NON_LOOPBACK_BIND",
            False,
        ):
            raise ValueError(
                "PriVoke runtime server only binds to localhost/loopback addresses "
                "unless PRIVOKE_ALLOW_NON_LOOPBACK_BIND=true."
            )

        super().__init__(server_address, handler_class)
        self.max_text_chars = max_text_chars
        self.cors_origin = cors_origin


class PrivokeRequestHandler(BaseHTTPRequestHandler):
    server_version = "PriVokeClientRuntime/0.1"

    def do_OPTIONS(self) -> None:
        self._write_json({}, HTTPStatus.NO_CONTENT)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in HEALTH_PATHS:
            self._write_json(
                {
                    "service": "privoke-client-runtime",
                    "status": "SERVING",
                    "host": self.server.server_address[0],
                    "port": self.server.server_address[1],
                    "endpoints": sorted(ANALYZE_PATHS),
                    "config_endpoints": sorted(LLM_CONFIG_PATHS),
                }
            )
            return

        if path in LLM_CONFIG_PATHS:
            self._write_json(current_llm_config_response())
            return

        if path == "/":
            self._write_json(
                {
                    "service": "privoke-client-runtime",
                    "status": "SERVING",
                    "endpoints": {
                        "health": "/health",
                        "analyze": "/analyze",
                        "llm_config": "/config/llm",
                    },
                }
            )
            return

        self._write_error("Not found.", HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path in LLM_CONFIG_PATHS:
            try:
                payload = self._read_json_body()
                response = update_llm_config_from_payload(payload)
            except RequestValidationError as exc:
                self._write_error(str(exc), exc.status_code)
                return
            except json.JSONDecodeError:
                self._write_error(
                    "Request body must be valid JSON.",
                    HTTPStatus.BAD_REQUEST,
                )
                return
            except UnicodeDecodeError:
                self._write_error(
                    "Request body must be UTF-8 JSON.",
                    HTTPStatus.BAD_REQUEST,
                )
                return
            except Exception as exc:
                self._write_error(
                    f"LLM configuration update failed: {exc}",
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                )
                return

            self._write_json(response)
            return

        if path not in ANALYZE_PATHS:
            self._write_error("Not found.", HTTPStatus.NOT_FOUND)
            return

        try:
            payload = self._read_json_body()
            request = parse_prompt_request(
                payload,
                max_text_chars=self.server.max_text_chars,
            )
            _log_dev_prompt_request(request)
            response = _analyse_prompt_request(request)
        except RequestValidationError as exc:
            self._write_error(str(exc), exc.status_code)
            return
        except json.JSONDecodeError:
            self._write_error("Request body must be valid JSON.", HTTPStatus.BAD_REQUEST)
            return
        except UnicodeDecodeError:
            self._write_error("Request body must be UTF-8 JSON.", HTTPStatus.BAD_REQUEST)
            return
        except Exception as exc:
            self._write_error(
                f"Prompt analysis failed: {exc}",
                HTTPStatus.INTERNAL_SERVER_ERROR,
            )
            return

        self._write_json(response)

    def log_message(self, format: str, *args: Any) -> None:
        # Keep logs metadata-only. The request body is intentionally never logged.
        print(
            "%s - - [%s] %s"
            % (self.address_string(), self.log_date_time_string(), format % args)
        )

    def _read_json_body(self) -> Any:
        content_type = self.headers.get("Content-Type", "")
        if content_type and "application/json" not in content_type.lower():
            raise RequestValidationError("Content-Type must be application/json.")

        length_header = self.headers.get("Content-Length")
        if length_header is None:
            raise RequestValidationError("Content-Length header is required.")

        try:
            length = int(length_header)
        except ValueError as exc:
            raise RequestValidationError("Content-Length must be an integer.") from exc

        max_bytes = self.server.max_text_chars * 4 + 4096
        if length > max_bytes:
            raise RequestValidationError(
                f"Request body exceeds {max_bytes} bytes.",
                status_code=HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            )

        raw_body = self.rfile.read(length)
        return json.loads(raw_body.decode("utf-8"))

    def _write_error(self, message: str, status_code: int | HTTPStatus) -> None:
        self._write_json(error_response(message, int(status_code)), status_code)

    def _write_json(
        self,
        payload: Dict[str, Any],
        status_code: int | HTTPStatus = HTTPStatus.OK,
    ) -> None:
        body = b"" if int(status_code) == HTTPStatus.NO_CONTENT else _json_bytes(payload)

        self.send_response(int(status_code))
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", self.server.cors_origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, X-Requested-With",
        )
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)


def create_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    *,
    max_text_chars: int | None = None,
    cors_origin: str | None = None,
) -> LocalOnlyHTTPServer:
    return LocalOnlyHTTPServer(
        (host, port),
        PrivokeRequestHandler,
        max_text_chars=(
            max_text_chars
            if max_text_chars is not None
            else env_positive_int("PRIVOKE_MAX_PROMPT_CHARS", DEFAULT_MAX_TEXT_CHARS)
        ),
        cors_origin=cors_origin or os.getenv("PRIVOKE_CORS_ORIGIN", "*"),
    )


def run_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    *,
    max_text_chars: int | None = None,
    cors_origin: str | None = None,
) -> None:
    server = create_server(
        host,
        port,
        max_text_chars=max_text_chars,
        cors_origin=cors_origin,
    )
    print(f"PriVoke client-runtime listening on http://{host}:{port}")
    try:
        server.serve_forever()
    finally:
        server.server_close()


def is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _json_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def _analyse_prompt_request(request):
    from .analyzer import analyse_prompt_request

    return analyse_prompt_request(request)


def _log_dev_prompt_request(request) -> None:
    if not env_bool(LOG_PROMPTS_ENV, False):
        return

    source = request.source or "unknown"
    if "fuzzer" not in source.lower():
        return

    print(
        "dev prompt received from fuzzer "
        f"source={source} "
        f"request_id={request.request_id or '-'} "
        f"target_app={request.target_app or '-'} "
        f"text={json.dumps(request.text)}",
        flush=True,
    )
