import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("regressions", ROOT / "evaluation/evaluate-contextual-regressions.py")
REGRESSION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REGRESSION)
from test_contextual_cascade import PRESENCE, SEMANTIC, outcome, triplet


def cases():
    return [{"case_id": f"case{i}", "family_id": "fixture", "text": f"fictional prompt {i}",
             "required_sensitive": False if i < 24 else True if i < 41 else None, "expected_sensitivity": "S2" if i < 41 else None,
             "expected_visibility": "PU" if i < 41 else None, "expected_categories": [] if i < 41 else None,
             "expected_action": "ALLOW" if i < 24 else "WARN" if i < 41 else None,
             "minimum_action": "ALLOW" if i < 24 else "WARN" if i < 41 else None,
             "allowed_actions": ["ALLOW"] if i < 24 else ["WARN", "BLOCK"] if i < 41 else None,
             "context_truth_eligible": i < 41, "action_accuracy_eligible": i < 41,
             "ambiguous": i >= 41, "label_status": "provisional_authored", "provisional_annotation_rationale": "Authored regression requirement.",
             "visibility_hint": "P3" if i < 4 else None} for i in range(48)]


class RegressionTests(unittest.TestCase):
    def test_ambiguous_cases_excluded_from_primary_agreements(self):
        rows = [{"case": case, "ordinary": outcome(True), "gated": outcome(False)} for case in cases()]
        report = REGRESSION.paired_metrics(rows)
        self.assertEqual(report["gated"]["primary_cases"], 41)
        self.assertEqual(report["gated"]["ambiguous_excluded"], 7)
        self.assertEqual(len(report["ambiguous_qualitative_case_ids"]), 7)
        self.assertEqual(sum(report["action_transitions"].values()), 41)

    def test_private_warning_loss_even_when_binary_signal_unchanged(self):
        case = cases()[24]
        before, after = outcome(True, "WARN"), outcome(True, "ALLOW")
        report = REGRESSION.paired_metrics([{"case": case, "ordinary": before, "gated": after}])
        self.assertTrue(REGRESSION.CASCADE.detection(before))
        self.assertTrue(REGRESSION.CASCADE.detection(after))
        self.assertEqual(report["private_action_loss_case_ids"], [case["case_id"]])
        self.assertEqual(report["gated"]["provisional_private_action_requirement"]["passed"], 0)

    def test_public_s1_category_is_not_automatically_private_failure(self):
        case = cases()[0]
        case.update(required_sensitive=False, expected_sensitivity="S1", expected_categories=["IDENTITY"],
                    expected_action="ALLOW", minimum_action="ALLOW")
        value = outcome(True, "ALLOW")
        value["classification"].update(sensitivity="S1", categories=["IDENTITY"])
        result = REGRESSION.provisional_metrics([{"case": case, "ordinary": value}], "ordinary")
        self.assertEqual(result["classification_agreement"]["sensitivity"]["agreement"], 1)
        self.assertEqual(result["provisional_clean_interventions"]["intervened"], 0)
        self.assertTrue(REGRESSION.CASCADE.detection(value))

    def test_control_block_fails_allowed_actions_and_is_not_an_allow_floor_pass(self):
        case = cases()[0]
        result = REGRESSION.provisional_metrics([{"case": case, "ordinary": outcome(True, "BLOCK")}], "ordinary")
        self.assertEqual(result["allowed_or_exact_action"], {"passed": 0, "labelled": 1})
        self.assertEqual(result["minimum_action"], {"passed": 0, "labelled": 0})
        self.assertEqual(result["provisional_clean_interventions"]["intervened"], 1)

    def test_warn_or_block_allowed_set_accepts_both_private_actions(self):
        case = cases()[24]
        for action in ("WARN", "BLOCK"):
            result = REGRESSION.provisional_metrics([{"case": case, "ordinary": outcome(True, action)}], "ordinary")
            self.assertEqual(result["allowed_or_exact_action"]["passed"], 1)
            self.assertEqual(result["provisional_private_action_requirement"]["passed"], 1)

    def test_unknown_labels_are_excluded_and_categories_compared_as_sets(self):
        case = cases()[0]
        case.update(expected_sensitivity=None, expected_visibility=None, expected_categories=["HEALTH", "IDENTITY"])
        value = outcome(True)
        value["classification"]["categories"] = ["IDENTITY", "HEALTH"]
        result = REGRESSION.provisional_metrics([{"case": case, "ordinary": value}], "ordinary")
        self.assertEqual(result["classification_agreement"]["sensitivity"]["labelled"], 0)
        self.assertIsNone(result["classification_agreement"]["visibility"]["agreement"])
        self.assertEqual(result["classification_agreement"]["categories"]["agreement"], 1)

    def test_duplicate_case_id_and_invalid_truth_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "cases.jsonl"
            fixture = cases()
            fixture[-1]["case_id"] = fixture[0]["case_id"]
            path.write_text("\n".join(json.dumps(r) for r in fixture), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "identity"):
                REGRESSION.load_cases(path)
            fixture = cases()
            fixture[0]["required_sensitive"] = 1
            path.write_text("\n".join(json.dumps(r) for r in fixture), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "identity"):
                REGRESSION.load_cases(path)

    def fixture_run(self, root, *, ineligible=False):
        case_file, rubric, review = root / "cases.jsonl", root / "rubric.md", root / "review.json"
        case_file.write_text("\n".join(json.dumps(x) for x in cases()), encoding="utf-8")
        rubric.write_text("Provisional rubric", encoding="utf-8")
        REGRESSION.CASCADE.write(review, {"status": "reviewed", "case_file_sha256": REGRESSION.CASCADE.sha(case_file),
                                         "rubric_sha256": REGRESSION.CASCADE.sha(rubric)})
        binding = {"runtime_image_id": "sha256:" + "a" * 64, "target": "fixture",
                   "controls": {"original": {"identity": SEMANTIC}}, "presence": {"efficient": {"identity": PRESENCE}}}
        selection = {"choices": {"original-efficient": {"status": "ineligible" if ineligible else "eligible", "chosen": None if ineligible else {"threshold": .5}}}}
        study = root / "study"
        (root / "validation.jsonl").write_text("fixture", encoding="utf-8")
        REGRESSION.CASCADE.write(study / "calibration/selection.json", selection)
        args = SimpleNamespace(study_root=study, output_dir=root / "output", case_file=case_file,
                               validation_file=root / "validation.jsonl",
                               rubric_file=rubric, fixture_review_file=review, control="original", profile="efficient",
                               source_revision="b" * 40, runtime_image_id=binding["runtime_image_id"],
                               evaluator_image_id="sha256:" + "c" * 64, target=None)
        return args, binding, selection, REGRESSION.CASCADE.sha(study / "calibration/selection.json")

    def test_same_explicit_visibility_hint_passed_to_both_requests_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, binding, selection, digest = self.fixture_run(Path(temporary))
            calls = []
            class Client:
                def analyze(self, row, request_id, semantic_id, **kwargs):
                    calls.append((row["id"], kwargs))
                    ordinary, gated, _ = triplet(threshold=kwargs.get("threshold", 0))
                    value = gated if "presence_id" in kwargs else ordinary
                    return value, copy.deepcopy(value)
                def close(self):
                    pass
            with patch.object(REGRESSION, "frozen_study", return_value=(binding, selection, digest)), patch.object(REGRESSION.CASCADE, "inside_results", side_effect=lambda p: p), patch.object(REGRESSION.CASCADE, "dataset", return_value=[]):
                REGRESSION.run(args, lambda target: Client())
                self.assertEqual(len(calls), 96)
                for index in range(48):
                    a, b = calls[index * 2:index * 2 + 2]
                    self.assertEqual(a[1].get("visibility_hint"), b[1].get("visibility_hint"))
                    self.assertEqual(a[1].get("visibility_hint"), "P3" if index < 4 else None)
                report = REGRESSION.CASCADE.read(args.output_dir / "report.json")
                self.assertEqual(report["rows"], 48)
                with self.assertRaises(FileExistsError):
                    REGRESSION.run(args, lambda target: self.fail("Cannot reuse output"))

    def test_ineligible_choice_skips_all_rpc_calls(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, binding, selection, digest = self.fixture_run(Path(temporary), ineligible=True)
            with patch.object(REGRESSION, "frozen_study", return_value=(binding, selection, digest)), patch.object(REGRESSION.CASCADE, "inside_results", side_effect=lambda p: p):
                REGRESSION.run(args, lambda target: self.fail("Ineligible pair must not run"))
            self.assertEqual(REGRESSION.CASCADE.read(args.output_dir / "skipped.json")["status"], "skipped_ineligible")

    def test_wrong_snapshot_fails_and_preserves_partial_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, binding, selection, digest = self.fixture_run(Path(temporary))
            class Client:
                def analyze(self, row, request_id, semantic_id, **kwargs):
                    ordinary, gated, _ = triplet(threshold=kwargs.get("threshold", 0))
                    if "presence_id" in kwargs:
                        gated["layers"][-1]["semantic_presence_gate"]["model_id"] = "wrong-model"
                    value = gated if "presence_id" in kwargs else ordinary
                    return value, value
                def close(self):
                    pass
            with patch.object(REGRESSION, "frozen_study", return_value=(binding, selection, digest)), patch.object(REGRESSION.CASCADE, "inside_results", side_effect=lambda p: p):
                with self.assertRaisesRegex(ValueError, "identity"):
                    REGRESSION.run(args, lambda target: Client())
            self.assertTrue((args.output_dir / "failure.json").exists())
            self.assertEqual(len(list((args.output_dir / "raw").glob("*.json"))), 2)

    def test_unfrozen_or_incomplete_study_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            REGRESSION.CASCADE.write(root / "study-manifest.json", {"binding": {}})
            REGRESSION.CASCADE.write(root / "calibration/selection.json", {"status": "frozen", "binding": {}, "choices": {}})
            with patch.object(REGRESSION.CASCADE, "inside_results", side_effect=lambda p: p), patch.object(REGRESSION.CASCADE, "dataset", return_value=[]):
                with self.assertRaisesRegex(ValueError, "prescribed"):
                    REGRESSION.frozen_study(root, root / "validation.jsonl")

    def test_frozen_study_requires_pinned_validation_not_its_own_predictions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            REGRESSION.CASCADE.write(root / "study-manifest.json", {"binding": {}})
            validation = root / "validation.jsonl"
            validation.write_text("changed labels or rows", encoding="utf-8")
            with patch.object(REGRESSION.CASCADE, "inside_results", side_effect=lambda p: p):
                with self.assertRaisesRegex(ValueError, "Dataset digest"):
                    REGRESSION.frozen_study(root, validation)


if __name__ == "__main__":
    unittest.main()
