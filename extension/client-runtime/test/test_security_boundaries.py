from __future__ import annotations

import sys
import unittest
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from src.LLM.local_classifier import _normalise_base_url
from src.hosting.models import RequestValidationError
from src.hosting.serialization import parse_prompt_request
from src.hosting.server import PrivokeRequestHandler, _validated_cors_origin


class RuntimeSecurityBoundaryTests(unittest.TestCase):
    def test_rejects_non_http_llm_url(self) -> None:
        with self.assertRaisesRegex(ValueError, "http"):
            _normalise_base_url("file:///etc/passwd")

    def test_rejects_wildcard_cors(self) -> None:
        with self.assertRaisesRegex(ValueError, "Wildcard"):
            _validated_cors_origin("*")

    def test_accepts_exact_extension_origin(self) -> None:
        self.assertEqual(
            _validated_cors_origin("chrome-extension://abcdefghijklmnop"),
            "chrome-extension://abcdefghijklmnop",
        )

    def test_accepts_cross_browser_extension_origins(self) -> None:
        self.assertEqual(
            _validated_cors_origin(
                "moz-extension://01234567-89ab-cdef-0123-456789abcdef"
            ),
            "moz-extension://01234567-89ab-cdef-0123-456789abcdef",
        )
        self.assertEqual(
            _validated_cors_origin("opera-extension://abcdefghijklmnop"),
            "opera-extension://abcdefghijklmnop",
        )

    def test_rejects_oversized_metadata(self) -> None:
        with self.assertRaisesRegex(RequestValidationError, "metadata value"):
            parse_prompt_request(
                {"text": "hello", "metadata": {"key": "x" * 2_049}}
            )

    def test_rejects_control_characters_in_context(self) -> None:
        with self.assertRaisesRegex(RequestValidationError, "control"):
            parse_prompt_request({"text": "hello", "request_id": "bad\nlog"})

    def test_rejects_negative_content_length(self) -> None:
        handler = object.__new__(PrivokeRequestHandler)
        handler.headers = {
            "Content-Type": "application/json",
            "Content-Length": "-1",
        }
        handler.server = SimpleNamespace(max_text_chars=20_000)
        handler.rfile = BytesIO(b'{}')
        with self.assertRaisesRegex(RequestValidationError, "negative"):
            handler._read_json_body()

    def test_rejects_transfer_encoding(self) -> None:
        handler = object.__new__(PrivokeRequestHandler)
        handler.headers = {
            "Content-Type": "application/json",
            "Content-Length": "2",
            "Transfer-Encoding": "chunked",
        }
        handler.server = SimpleNamespace(max_text_chars=20_000)
        handler.rfile = BytesIO(b'{}')
        with self.assertRaisesRegex(RequestValidationError, "Transfer-Encoding"):
            handler._read_json_body()


if __name__ == "__main__":
    unittest.main()
