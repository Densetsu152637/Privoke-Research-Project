"""Synthetic fixture certification checks; no research endpoints or services."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "contextual_quality", Path(__file__).resolve().parents[1] / "report-contextual-fuzzer-study.py"
)
QUALITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALITY)


class FixtureQualityTests(unittest.TestCase):
    def setUp(self):
        self.cases = [
            {"case_id": f"case-{index:02d}", "ambiguous": index >= 41,
             "required_sensitive": 24 <= index < 41,
             "minimum_action": "WARN" if 24 <= index < 41 else "ALLOW"}
            for index in range(48)
        ]
        self.identities = {
            label: {"model_id": label, "model_version": "synthetic-v1",
                    "artifact_checksum": label + "-checksum",
                    "parameter_fingerprint": label + "-fingerprint"}
            for label in ("live", "winner")
        }
        self.observations = {}
        for label, identity in self.identities.items():
            self.observations[label] = {}
            for index, case in enumerate(self.cases):
                request_id = "ctx-fixture-" + f"{index:040x}"
                action = case["minimum_action"]
                self.observations[label][case["case_id"]] = {
                    "request_id": request_id, "action": action,
                    "raw": {"request_id": request_id, "action": action,
                            "layers": [{"layer": "DETECTION_LAYER_SEMANTIC", "status": "ok",
                                        "results": [{"metadata": copy.deepcopy(identity)}]}]},
                }
        self.assessment = {"contextual_gate": {
            "private_action_losses": [], "added_clean_interventions": [], "passed": True
        }}

    def action(self, label, index, value):
        observation = self.observations[label][f"case-{index:02d}"]
        observation["action"] = observation["raw"]["action"] = value

    def summary(self):
        fixture_bytes = ("\n".join(json.dumps(case) for case in self.cases) + "\n").encode()
        copies = {
            "final-assessment.json": self.assessment,
            "fixture-live.json": self.observations["live"],
            "fixture-winner.json": self.observations["winner"],
        }

        def read_copy(path, *unused):
            return copies[Path(path).name]

        # Patch every read boundary so no fixture, final, artifact or service is accessed.
        with patch.object(QUALITY, "read", side_effect=read_copy), \
             patch.object(QUALITY, "read_bytes", return_value=fixture_bytes), \
             patch.object(Path, "exists", return_value=True):
            return QUALITY.fixture_summary(
                {"finalized": self.assessment, "fixture": "synthetic-fixture.jsonl"},
                Path("synthetic-study"), self.identities["live"], self.identities["winner"]
            )

    def test_missing_semantic_identity_in_either_collection_is_rejected(self):
        for label in ("live", "winner"):
            with self.subTest(label=label):
                saved = copy.deepcopy(self.observations[label])
                for observation in self.observations[label].values():
                    observation["raw"]["layers"] = []
                with self.assertRaisesRegex(ValueError, "no returned model identity"):
                    self.summary()
                self.observations[label] = saved

    def test_successful_semantic_layer_without_detections_has_no_per_case_identity(self):
        self.observations["winner"]["case-00"]["raw"]["layers"][0]["results"] = []
        result = self.summary()
        self.assertEqual(result["semantic_identity_observations"], {"live": 48, "winner": 47})
        self.assertIn("no per-case identity", result["identity_scope"])

    def test_all_empty_successful_semantic_responses_are_not_identity_evidence(self):
        for observation in self.observations["winner"].values():
            observation["raw"]["layers"][0]["results"] = []
        with self.assertRaisesRegex(ValueError, "no returned model identity"):
            self.summary()

    def test_wrong_returned_parameter_fingerprint_is_rejected(self):
        item = self.observations["winner"]["case-00"]["raw"]["layers"][0]["results"][0]
        item["metadata"]["parameter_fingerprint"] = "different-model"
        with self.assertRaisesRegex(ValueError, "identity changed or absent"):
            self.summary()

    def test_regex_block_explanatory_skips_preserve_valid_identity_evidence(self):
        for label in ("live", "winner"):
            self.action(label, 0, "BLOCK")
            self.observations[label]["case-00"]["raw"]["layers"] = [
                {"layer": layer, "status": "skipped", "results": [],
                 "error": "Skipped after regex returned BLOCK."}
                for layer in ("DETECTION_LAYER_NER", "DETECTION_LAYER_SEMANTIC")
            ]
        result = self.summary()
        self.assertTrue(result["assessment"]["contextual_gate"]["passed"])
        self.assertEqual(result["semantic_identity_observations"], {"live": 47, "winner": 47})

    def test_actual_runtime_error_is_rejected(self):
        self.observations["winner"]["case-00"]["raw"]["layers"][0]["status"] = "error"
        with self.assertRaisesRegex(ValueError, "runtime layer failed"):
            self.summary()

    def test_new_private_failure_is_not_cancelled_by_repairing_another_case(self):
        self.action("winner", 24, "ALLOW")
        self.action("live", 25, "ALLOW")  # Winner repairs this existing failure.
        self.assessment["contextual_gate"].update(private_action_losses=["case-24"], passed=False)
        result = self.summary()
        self.assertEqual(result["new_private_action_losses"], ["case-24"])
        self.assertEqual(result["existing_and_remaining_private_failures"],
                         {"live": ["case-25"], "winner": ["case-24"]})
        self.assertFalse(result["assessment"]["contextual_gate"]["passed"])
        self.assessment["contextual_gate"].update(private_action_losses=[], passed=True)
        with self.assertRaisesRegex(ValueError, "disagrees with retention gate"):
            self.summary()

    def test_new_clean_intervention_is_not_cancelled_by_private_improvement(self):
        self.action("winner", 0, "WARN")
        self.action("live", 24, "ALLOW")
        self.assessment["contextual_gate"].update(added_clean_interventions=["case-00"], passed=False)
        result = self.summary()
        self.assertEqual(result["new_clean_interventions"], ["case-00"])
        self.assertFalse(result["assessment"]["contextual_gate"]["passed"])

    def test_ambiguous_cases_are_excluded_from_the_quantitative_gate(self):
        self.action("winner", 41, "BLOCK")
        result = self.summary()
        self.assertTrue(result["assessment"]["contextual_gate"]["passed"])
        self.assertEqual(result["quantitative_cases"], 41)
        self.assertEqual(result["ambiguous_excluded"], 7)
        self.assertFalse(result["per_case_actions"][41]["quantitative_eligible"])


if __name__ == "__main__":
    unittest.main()
