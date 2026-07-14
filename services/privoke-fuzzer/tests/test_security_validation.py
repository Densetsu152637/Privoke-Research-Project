from __future__ import annotations

import sys
import unittest
from pathlib import Path


SERVICE_ROOT = Path(__file__).resolve().parents[1]
for path in (SERVICE_ROOT / "src", SERVICE_ROOT / "generated"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from fuzzer_service import validate_training_request
from privoke.v1 import parameters_pb2


def valid_request():
    return parameters_pb2.FuzzerTrainingRequest(
        request_id="request-1",
        source_id="param-update-service",
        model_id="privoke-baseline",
        prompt_count=8,
        metadata={"initiator": "test"},
    )


class FuzzerRequestValidationTests(unittest.TestCase):
    def test_accepts_bounded_request(self) -> None:
        validate_training_request(valid_request(), "privoke-baseline")

    def test_rejects_missing_request_id(self) -> None:
        request = valid_request()
        request.request_id = ""
        with self.assertRaisesRegex(ValueError, "request_id"):
            validate_training_request(request, "privoke-baseline")

    def test_rejects_unconfigured_model(self) -> None:
        request = valid_request()
        request.model_id = "other-model"
        with self.assertRaisesRegex(ValueError, "model_id"):
            validate_training_request(request, "privoke-baseline")


if __name__ == "__main__":
    unittest.main()
