from __future__ import annotations

import sys
import unittest
from pathlib import Path


SERVICE_ROOT = Path(__file__).resolve().parents[1]
for path in (SERVICE_ROOT / "src", SERVICE_ROOT / "generated"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from fuzzer_service import validate_training_request, _training_request_fingerprint
from prompt_generation.generator import CONTEXTUAL_SAMPLING_STRATEGY_KEY, CONTEXTUAL_ROLE_QUOTA_STRATEGY
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

    def test_contextual_sampling_policy_is_explicit_validated_and_budgeted(self):
        request = valid_request()
        request.prompt_count = 256
        request.metadata[CONTEXTUAL_SAMPLING_STRATEGY_KEY] = CONTEXTUAL_ROLE_QUOTA_STRATEGY
        validate_training_request(request, "privoke-baseline")
        for value in ("", "unknown", "uniform"):
            request.metadata[CONTEXTUAL_SAMPLING_STRATEGY_KEY] = value
            with self.assertRaisesRegex(ValueError, "sampling strategy"):
                validate_training_request(request, "privoke-baseline")
        request.metadata[CONTEXTUAL_SAMPLING_STRATEGY_KEY] = CONTEXTUAL_ROLE_QUOTA_STRATEGY
        request.prompt_count = 8
        with self.assertRaisesRegex(ValueError, "256"):
            validate_training_request(request, "privoke-baseline")

    def test_sampling_policy_changes_replay_fingerprint_with_same_request_identity(self):
        request = valid_request()
        request.prompt_count = 256
        legacy = _training_request_fingerprint(request)
        request.metadata[CONTEXTUAL_SAMPLING_STRATEGY_KEY] = CONTEXTUAL_ROLE_QUOTA_STRATEGY
        quota = _training_request_fingerprint(request)
        self.assertNotEqual(legacy, quota)
        self.assertEqual(quota, _training_request_fingerprint(request))
        del request.metadata[CONTEXTUAL_SAMPLING_STRATEGY_KEY]
        self.assertEqual(legacy, _training_request_fingerprint(request))

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
