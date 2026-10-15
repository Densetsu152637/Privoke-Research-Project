"""Synthetic audit checks without training or reading research endpoints."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ObjectiveQualityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (ROOT / "evaluation/run-class-balanced-fuzzer-study.py").is_file():
            raise unittest.SkipTest("Phase-two controller not integrated yet")
        spec = importlib.util.spec_from_file_location("class_quality_tests", ROOT / "evaluation/report-class-balanced-fuzzer-study.py")
        cls.quality = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.quality)

    def setUp(self):
        self.record = {"objective": "class_balanced_contextual_v1"}
        values = {"training_clean_examples": 250, "training_sensitive_examples": 6,
                  "raw_clean_weight": 200, "raw_sensitive_weight": 56, "raw_total_weight": 256,
                  "effective_clean_weight": 128, "effective_sensitive_weight": 128,
                  "clean_objective_mass": .5, "sensitive_objective_mass": .5, "total_weight": 256}
        self.response = {"metadata": {key: str(value) for key, value in values.items()}}
        self.response["metadata"].update(contextual_training_objective=self.record["objective"],
                                         objective_strata="classification_is_sensitive")

    def test_effective_class_mass_and_original_total_are_verified(self):
        audit = self.quality.objective_audit(self.response, self.record)
        self.assertEqual(audit["clean_objective_mass"], .5)
        self.assertEqual(audit["sensitive_objective_mass"], .5)
        self.assertEqual(audit["raw_total_weight"], 256)
        self.assertIn("held-out", audit["heldout_scope"])

    def test_wrong_objective_or_strata_are_rejected(self):
        for key in ("contextual_training_objective", "objective_strata"):
            with self.subTest(key=key):
                response = copy.deepcopy(self.response)
                response["metadata"][key] = "wrong"
                with self.assertRaises(ValueError):
                    self.quality.objective_audit(response, self.record)
        with self.assertRaises(ValueError):
            self.quality.objective_audit(self.response, {"objective": "unknown"})

    def test_false_class_supports_mass_or_total_are_rejected(self):
        changes = {"training_clean_examples": "249", "training_sensitive_examples": "6.5",
                   "raw_clean_weight": "201", "raw_sensitive_weight": "nan", "raw_total_weight": "0",
                   "effective_clean_weight": "129", "effective_sensitive_weight": "127",
                   "clean_objective_mass": ".4", "sensitive_objective_mass": ".6", "total_weight": "257"}
        for key, value in changes.items():
            with self.subTest(key=key):
                response = copy.deepcopy(self.response)
                response["metadata"][key] = value
                with self.assertRaises(ValueError):
                    self.quality.objective_audit(response, self.record)

    def test_original_weight_control_cannot_claim_balancing(self):
        record = {"objective": "uniform"}
        audit = self.quality.objective_audit({"metadata": {"total_weight": "256"}}, record)
        self.assertFalse(audit["class_balance_applied"])
        with self.assertRaises(ValueError):
            self.quality.objective_audit(self.response, record)


if __name__ == "__main__":
    unittest.main()
