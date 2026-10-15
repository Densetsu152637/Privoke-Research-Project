import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys
from unittest.mock import patch

from privoke_eval.types import EvaluationExample
from privoke_model.training_data import training_text_key

SPEC = importlib.util.spec_from_file_location("public_negatives", Path(__file__).parents[1] / "prepare-public-negatives.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
STUDY_SPEC = importlib.util.spec_from_file_location("negative_study", Path(__file__).parents[1] / "run-public-negative-study.py")
STUDY = importlib.util.module_from_spec(STUDY_SPEC)
STUDY_SPEC.loader.exec_module(STUDY)
CURVE_SPEC = importlib.util.spec_from_file_location("negative_curve", Path(__file__).parents[1] / "run-public-negative-curve.py")
CURVE = importlib.util.module_from_spec(CURVE_SPEC)
CURVE_SPEC.loader.exec_module(CURVE)


def example(identifier, text, positive=False, group=None):
    return EvaluationExample(text, positive, metadata={"example_id": identifier, "group_id": group or identifier})


class PublicNegativeCurriculumTests(unittest.TestCase):
    def test_scoring_failure_records_accepted_attempt_and_restores_previous_selection(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            curriculum = root / "evaluation/results/public-negative-curriculum/prompts.jsonl"
            curriculum.parent.mkdir(parents=True)
            curriculum.write_bytes(b"fixture")
            selected = root / "selected.json"
            selected.write_text('{"version":"v0.3.0+train.1"}', encoding="utf-8")
            study_path = root / "study.json"
            study_path.write_text("{}", encoding="utf-8")
            record = {"artifact": "selected.json", "seed": 42, "rate": .03,
                      "metrics": {"pipeline": {"true_positives": 239, "true_negatives": 70}}}
            manifest = {"curriculum_sha256": hashlib.sha256(curriculum.read_bytes()).hexdigest()}
            settings = {"FUZZ_TRAINING_LEARNING_RATE": "0.03", "FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE": "0",
                        "FUZZ_PROMPT_DATASET_PATH": "/workspace/evaluation/results/public-negative-curriculum/prompts.jsonl"}

            def call(arguments, **kwargs):
                if arguments[0] == "run":
                    raise subprocess.CalledProcessError(1, arguments)
                if arguments[:2] == ["exec", "-T"]:
                    if arguments[2] == "param-update-service":
                        return "0" if "FUZZER_PROMPT_COUNT" in arguments[-1] else '{"version":"v0.3.0+train.2"}'
                    if arguments[4] == "-c":
                        return json.dumps(settings)
                    return json.dumps({"accepted": True, "base_version": "v0.3.0+train.1"})
                return ""

            with patch.object(CURVE, "ROOT", root), patch.object(CURVE, "checked_selection", return_value=(manifest, record)), \
                    patch.object(CURVE.STUDY, "call", side_effect=call), patch.object(CURVE.STUDY, "restore") as restore, \
                    patch.object(CURVE.subprocess, "check_output", return_value="source"), \
                    patch.object(sys, "argv", ["curve", "--study-manifest", str(study_path), "--experiment-id", "fixture"]):
                with self.assertRaises(subprocess.CalledProcessError):
                    CURVE.main()
                self.assertEqual(restore.call_count, 2)
                self.assertEqual(restore.call_args.args[0], selected.read_text(encoding="utf-8"))
            result = json.loads((root / "evaluation/results/fixture/selection.json").read_text(encoding="utf-8"))
            self.assertFalse(result["completed"])
            self.assertTrue(result["selected_restored"])
            self.assertEqual(result["records"][0]["cycle"], 2)
            self.assertTrue(result["records"][0]["accepted"])
            self.assertFalse(result["records"][0]["scored"])
            self.assertEqual(result["error"]["type"], "CalledProcessError")

    def test_extra_cycle_stops_at_recall_floor_or_unchanged_specificity(self):
        selected = {"pipeline": {"true_positives": 239, "true_negatives": 70}}
        self.assertTrue(CURVE.curve_candidate_improves(
            {"pipeline": {"true_positives": 238, "true_negatives": 71}}, selected))
        self.assertFalse(CURVE.curve_candidate_improves(
            {"pipeline": {"true_positives": 237, "true_negatives": 230}}, selected))
        self.assertFalse(CURVE.curve_candidate_improves(
            {"pipeline": {"true_positives": 264, "true_negatives": 70}}, selected))

    def test_extra_cycles_recompute_selection_and_reject_tampered_manifest(self):
        import hashlib
        metrics = {"pipeline": {"true_positives": 239, "true_negatives": 70}}
        records = [{"rate": rate, "seed": seed, "cycle": 1, "scored": False}
                   for rate in (.03, .1, .3) for seed in (42, 1337, 2026)]
        records[0].update(scored=True, eligible=True, metrics=metrics, artifact="selected.json")
        manifest = {"completed": True, "selected_restored": True, "records": records,
                    "selected_artifact": "selected.json", "selected_exact_counts": {
                        "true_positives": 239, "true_negatives": 70}, "additional_cycle_trigger_met": True}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "selected.json"
            artifact.write_text('{"version": "v0.3.0+train.1"}', encoding="utf-8")
            manifest["selected_file_sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
            path = root / "selection.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with patch.object(CURVE, "ROOT", root), patch.object(CURVE.STUDY, "locked_prediction_keys", return_value={}), \
                    patch.object(CURVE.STUDY, "measurements", return_value=metrics):
                self.assertEqual(CURVE.checked_selection(path)[1]["seed"], 42)
                changed = json.loads(json.dumps(manifest))
                changed["selected_exact_counts"]["true_negatives"] = 80
                path.write_text(json.dumps(changed), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "counts or extension trigger"):
                    CURVE.checked_selection(path)
                path.write_text(json.dumps(manifest), encoding="utf-8")
                artifact.write_text("changed", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "digest"):
                    CURVE.checked_selection(path)

    def test_misaligned_candidate_or_incorrect_counts_cannot_enter_selection(self):
        expected = {"positive": (True, "source-a"), "clean": (False, "source-b")}
        rows = [{"example_id": key, "expected_has_pii": label, "group_id": group,
                 "detected_sensitive": label, "status": "ok"}
                for key, (label, group) in expected.items()]
        report = {"errors": [], "metadata": {"predictions": rows}, "metrics": {
            "evaluated_samples": 2, "true_positives": 1, "true_negatives": 1,
            "false_positives": 0, "false_negatives": 0}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for layer in ("semantic", "pipeline"):
                (root / f"local-jsonl_{layer}_fixture_results.json").write_text(json.dumps(report), encoding="utf-8")
            self.assertEqual(STUDY.measurements(root, expected)["pipeline"]["true_negatives"], 1)
            path = root / "local-jsonl_pipeline_fixture_results.json"
            for attribute, changed in (("example_id", "different"), ("expected_has_pii", False),
                                       ("group_id", "source-c")):
                altered = json.loads(json.dumps(report))
                altered["metadata"]["predictions"][0][attribute] = changed
                path.write_text(json.dumps(altered), encoding="utf-8")
                with self.subTest(attribute=attribute), self.assertRaisesRegex(ValueError, "IDs, labels or source groups"):
                    STUDY.measurements(root, expected)
            altered = json.loads(json.dumps(report))
            altered["metrics"]["true_negatives"] = 2
            path.write_text(json.dumps(altered), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "confusion counts"):
                STUDY.measurements(root, expected)

    def test_selection_uses_exact_pipeline_floor_and_declared_ties(self):
        def metrics(tp, tn):
            return {"pipeline": {"true_positives": tp, "true_negatives": tn}}
        self.assertIsNone(STUDY.candidate_key(metrics(237, 230), 1, .03, 42))
        self.assertIsNone(STUDY.candidate_key(metrics(264, 53), 1, .03, 42))
        self.assertIsNotNone(STUDY.candidate_key(metrics(238, 54), 1, .03, 42))
        self.assertGreater(STUDY.candidate_key(metrics(238, 80), 1, .03, 42),
                           STUDY.candidate_key(metrics(264, 79), 1, .03, 42))
        first = STUDY.candidate_key(metrics(247, 80), 1, .03, 42)
        self.assertGreater(first, STUDY.candidate_key(metrics(247, 80), 2, .03, 42))
        self.assertGreater(first, STUDY.candidate_key(metrics(247, 80), 1, .1, 42))
        self.assertGreater(first, STUDY.candidate_key(metrics(247, 80), 1, .03, 1337))

    def test_locked_siblings_ids_and_normalized_variants_are_excluded(self):
        protected = [{"id": "reserved", "group_id": "document", "text": "Locked ＴＥＸＴ 1 2"}]
        rows = [example("sibling", "Other sentence", group="document"),
                example("reserved", "Different identifier content"),
                example("duplicate", "locked text 12"),
                example("valid", "Usable clean sentence")]
        selected, counts = MODULE.select_clean_pool(rows, protected, [], 1, 42)
        self.assertEqual([x.metadata["example_id"] for x in selected], ["valid"])
        self.assertEqual(counts["exclusions"]["locked_group_id_or_text_or_anchor"], 3)

    def test_normalized_label_conflicts_and_anchor_duplicates_are_excluded(self):
        rows = [example("first", "Case Difference"), example("second", "CASE DIFFERENCE", True),
                example("third", "case difference"), example("anchor", "Original sample"),
                example("valid", "Clean alternative")]
        anchors = [("original SAMPLE", "S3", "PU", ("HEALTH",))]
        selected, counts = MODULE.select_clean_pool(rows, [], anchors, 1, 42)
        self.assertEqual([x.metadata["example_id"] for x in selected], ["valid"])
        self.assertEqual(counts["exclusions"]["normalized_conflicting_key"], 1)

    def test_selection_is_reproducible_and_never_fills_an_undersized_pool(self):
        rows = [example(str(i), f"Clean sentence {i}") for i in range(12)]
        first, _ = MODULE.select_clean_pool(rows, [], [], 8, 42)
        second, _ = MODULE.select_clean_pool(list(reversed(rows)), [], [], 8, 42)
        self.assertEqual([x.metadata["example_id"] for x in first], [x.metadata["example_id"] for x in second])
        with self.assertRaisesRegex(ValueError, "eligible clean"):
            MODULE.select_clean_pool(rows, [], [], 13, 42)
        self.assertEqual(len({training_text_key(x.text) for x in first}), 8)

    def test_braces_render_as_literal_data_without_changing_the_sentence(self):
        text = 'A generic example: {"items": []}; placeholder {name}.'
        self.assertEqual(MODULE.escape_template(text).format(name="replacement"), text)


if __name__ == "__main__":
    unittest.main()
