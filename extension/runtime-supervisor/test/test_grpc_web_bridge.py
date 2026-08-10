from __future__ import annotations

import sys
import unittest
from pathlib import Path
from urllib.request import Request, urlopen


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from src.grpc_web_bridge import GrpcWebBridge, _data_frame, _decode_grpc_web_frame


class GrpcWebBridgeTests(unittest.TestCase):
    def test_decodes_one_binary_request_frame(self) -> None:
        self.assertEqual(_decode_grpc_web_frame(_data_frame(b"request")), b"request")

    def test_rejects_a_frame_with_the_wrong_length(self) -> None:
        with self.assertRaises(ValueError):
            _decode_grpc_web_frame(b"\x00\x00\x00\x00\x08short")

    def test_proxies_control_rpc_and_returns_grpc_web_frames(self) -> None:
        calls = []

        def invoke(path, payload, target, timeout):
            calls.append((path, payload, target, timeout))
            return b"response"

        bridge = GrpcWebBridge(port=0, rpc_invoker=invoke)
        bridge.start()
        try:
            request = Request(
                f"http://127.0.0.1:{bridge.port}"
                "/privoke.v1.PrivokeRuntimeControlService/Status",
                data=_data_frame(b"request"),
                headers={
                    "Content-Type": "application/grpc-web+proto",
                    "Origin": "chrome-extension://test_extension",
                },
                method="POST",
            )
            with urlopen(request, timeout=2) as response:
                body = response.read()

            self.assertEqual(body[:5], b"\x00\x00\x00\x00\x08")
            self.assertEqual(body[5:13], b"response")
            self.assertEqual(body[13], 0x80)
            self.assertIn(b"grpc-status: 0", body)
            self.assertEqual(
                calls,
                [
                    (
                        "/privoke.v1.PrivokeRuntimeControlService/Status",
                        b"request",
                        "127.0.0.1:50056",
                        35.0,
                    )
                ],
            )
        finally:
            bridge.stop()

    def test_answers_extension_cors_preflight(self) -> None:
        bridge = GrpcWebBridge(port=0)
        bridge.start()
        try:
            request = Request(
                f"http://127.0.0.1:{bridge.port}"
                "/privoke.v1.PrivokeRuntimeControlService/Status",
                headers={
                    "Origin": "chrome-extension://test_extension",
                    "Access-Control-Request-Method": "POST",
                },
                method="OPTIONS",
            )
            with urlopen(request, timeout=2) as response:
                self.assertEqual(response.status, 204)
                self.assertEqual(
                    response.headers["Access-Control-Allow-Origin"],
                    "chrome-extension://test_extension",
                )
                self.assertIn("POST", response.headers["Access-Control-Allow-Methods"])
        finally:
            bridge.stop()


if __name__ == "__main__":
    unittest.main()
