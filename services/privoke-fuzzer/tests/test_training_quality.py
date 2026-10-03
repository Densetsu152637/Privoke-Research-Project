from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import grpc


SERVICE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVICE_ROOT.parents[1]
for path in (SERVICE_ROOT / "src", SERVICE_ROOT / "generated", REPO_ROOT / "shared/python"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from fuzzer_service import FuzzerTrainingService, validate_training_update
from privoke.v1 import parameters_pb2
from training.types import BatchTrainingUpdate


def training_update(
    exact_match_rate: float | None,
    *,
    candidate_recall: float = 0.8,
    candidate_specificity: float = 0.6,
) -> BatchTrainingUpdate:
    metrics = {} if exact_match_rate is None else {
        "exact_match_rate": exact_match_rate,
        "heldout_sensitive_recall": 0.8,
        "candidate_heldout_sensitive_recall": candidate_recall,
        "heldout_clean_specificity": 0.6,
        "candidate_heldout_clean_specificity": candidate_specificity,
        "heldout_exact_match_rate": 0.5,
        "candidate_heldout_exact_match_rate": 0.5,
        "heldout_sensitive_examples": 8.0,
        "heldout_clean_examples": 8.0,
        "candidate_heldout_safety_regression_rate": 0.0,
    }
    return BatchTrainingUpdate(
        model_id="privoke-balanced",
        base_version="v1",
        gradients={"head.sensitivity.bias": (0.01,)},
        parameter_shapes={"head.sensitivity.bias": (1,)},
        metrics=metrics,
        metadata={},
    )


class TrainingQualityTests(unittest.TestCase):
    def test_rejected_candidate_never_reaches_parameter_publication(self):
        config = SimpleNamespace(
            model_id="privoke-balanced", max_concurrent_cycles=1,
            max_prompt_count=256, seed=1337, heldout_prompt_count=16,
            prompt_dataset_path=None, minimum_exact_match_rate=0.0,
        )
        service = FuzzerTrainingService(config)
        update = training_update(0.5, candidate_recall=0.7)
        request = parameters_pb2.FuzzerTrainingRequest(prompt_count=8)

        class Rejected(Exception):
            pass

        class Context:
            def abort(self, code, message):
                self.code = code
                raise Rejected(message)

        context = Context()
        with patch.object(service, "_previous_update", return_value=parameters_pb2.ParameterUpdateStatus()), patch.object(service, "_train", return_value=update), patch.object(service, "_submit_update") as publish:
            with self.assertRaisesRegex(Rejected, "worse"):
                service._run_training_cycle(request, context)
        self.assertEqual(context.code, grpc.StatusCode.FAILED_PRECONDITION)
        publish.assert_not_called()

    def test_rejects_individual_severity_regression_with_unchanged_aggregate_metrics(self):
        update = training_update(0.5)
        update.metrics["candidate_heldout_safety_regression_rate"] = 0.125
        with self.assertRaisesRegex(ValueError, "worse"):
            validate_training_update(update, minimum_exact_match_rate=0.0)
    def test_rejects_missing_match_metric(self) -> None:
        with self.assertRaisesRegex(ValueError, "did not report"):
            validate_training_update(
                training_update(None),
                minimum_exact_match_rate=0.0,
            )

    def test_rejects_zero_match_update(self) -> None:
        with self.assertRaisesRegex(ValueError, "greater than the minimum"):
            validate_training_update(
                training_update(0.0),
                minimum_exact_match_rate=0.0,
            )

    def test_accepts_update_above_threshold(self) -> None:
        validate_training_update(
            training_update(0.5),
            minimum_exact_match_rate=0.25,
        )

    def test_rejects_candidate_regression(self) -> None:
        with self.assertRaisesRegex(ValueError, "worse"):
            validate_training_update(
                training_update(0.5, candidate_recall=0.7),
                minimum_exact_match_rate=0.25,
            )

    def test_rejects_non_finite_and_out_of_range_quality_metrics(self):
        for name in training_update(0.5).metrics:
            for value in (float("nan"), float("inf"), -1.0):
                with self.subTest(name=name, value=value):
                    update = training_update(0.5)
                    update.metrics[name] = value
                    with self.assertRaises(ValueError):
                        validate_training_update(update, minimum_exact_match_rate=0.0)

    def test_rejects_missing_heldout_stratum(self):
        for name in ("heldout_sensitive_examples", "heldout_clean_examples"):
            update = training_update(0.5)
            update.metrics[name] = 0.0
            with self.assertRaisesRegex(ValueError, "both clean and sensitive"):
                validate_training_update(update, minimum_exact_match_rate=0.0)

    def test_rejects_exact_classification_regression(self):
        update = training_update(0.5)
        update.metrics["candidate_heldout_exact_match_rate"] = 0.4
        with self.assertRaisesRegex(ValueError, "worse"):
            validate_training_update(update, minimum_exact_match_rate=0.0)


if __name__ == "__main__":
    unittest.main()
