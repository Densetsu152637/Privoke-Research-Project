from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from src.LLM.local_classifier import LocalClassifier


class ClassifierOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.classifier = LocalClassifier(
            base_url="http://127.0.0.1:1234/v1",
            model="test-model",
            response_format=None,
        )

    def test_rejects_invalid_json(self) -> None:
        with patch.object(
            self.classifier,
            "_post_chat_completion",
            return_value={"choices": [{"message": {"content": "not json"}}]},
        ):
            with self.assertRaisesRegex(RuntimeError, "invalid JSON"):
                self.classifier.classify("test prompt")

    def test_rejects_empty_result_list(self) -> None:
        with patch.object(
            self.classifier,
            "_post_chat_completion",
            return_value={
                "choices": [{"message": {"content": '{"results": []}'}}]
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "no valid results"):
                self.classifier.classify("test prompt")


if __name__ == "__main__":
    unittest.main()