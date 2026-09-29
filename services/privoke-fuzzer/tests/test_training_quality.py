from __future__ import annotations

import sys
import unittest
from pathlib import Path


SERVICE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVICE_ROOT.parents[1]
for path in (SERVICE_ROOT / "src", SERVICE_ROOT / "generated", REPO_ROOT / "shared/python"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from fuzzer_service import validate_training_update
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


if __name__ == "__main__":
    unittest.main()