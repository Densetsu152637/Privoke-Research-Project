from __future__ import annotations

import math
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SERVICE_ROOT = Path(__file__).resolve().parents[1]
for path in (SERVICE_ROOT / "app", SERVICE_ROOT / "generated"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from privoke.v1 import parameters_pb2
from server import (
    ParamUpdateService,
    storage_is_writable,
    validate_parameter_update,
)


def valid_request():
    return parameters_pb2.ParameterUpdateRequest(
        source_id="test-fuzzer",
        model_id="privoke-baseline",
        base_version="v1",
        gradients=[
            parameters_pb2.Parameter(name="classifier.bias", values=[0.01])
        ],
        metadata={"request_id": "test-1"},
    )


class ParameterUpdateValidationTests(unittest.TestCase):
    def test_health_is_not_serving_when_storage_is_unwritable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            service = ParamUpdateService(
                Path(directory) / "updates.jsonl",
                expected_model_id="privoke-baseline",
            )
            with patch("server.storage_is_writable", return_value=False):
                response = service.Health(None, None)
        self.assertEqual(response.status, "NOT_SERVING")

    def test_storage_health_checks_the_update_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            storage_path = Path(directory) / "updates.jsonl"
            self.assertTrue(storage_is_writable(storage_path))
            self.assertTrue(storage_path.exists())

    def test_accepts_bounded_update(self) -> None:
        validate_parameter_update(
            valid_request(),
            expected_model_id="privoke-baseline",
            max_abs_gradient=1.0,
        )

    def test_rejects_non_finite_gradient(self) -> None:
        request = valid_request()
        request.gradients[0].values[0] = math.nan
        with self.assertRaisesRegex(ValueError, "non-finite"):
            validate_parameter_update(
                request,
                expected_model_id="privoke-baseline",
                max_abs_gradient=1.0,
            )

    def test_rejects_wrong_model(self) -> None:
        request = valid_request()
        request.model_id = "other-model"
        with self.assertRaisesRegex(ValueError, "model_id"):
            validate_parameter_update(
                request,
                expected_model_id="privoke-baseline",
                max_abs_gradient=1.0,
            )

    def test_rejects_log_control_characters(self) -> None:
        request = valid_request()
        request.source_id = "attacker\nforged-log"
        with self.assertRaisesRegex(ValueError, "control"):
            validate_parameter_update(
                request,
                expected_model_id="privoke-baseline",
                max_abs_gradient=1.0,
            )


if __name__ == "__main__":
    unittest.main()
