from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "summarize-external-pii-study.py"
SPEC = importlib.util.spec_from_file_location("summarize_external_pii_study", SCRIPT)
SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARY)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path.write_bytes(data)
    return sha(data)


def h(label: str) -> str:
    return sha(label.encode())


class ExternalPiiSummaryTests(unittest.TestCase):
    def _study(self, root: Path) -> Path:
        study = root / "study"
        protocol, prepared = h("protocol"), h("prepared")
        part_hashes = {partition: (SUMMARY.EXPECTED_VALIDATION_SHA256 if partition == "validation"
                                   else h(partition)) for partition in SUMMARY.PARTITIONS}
        images = {"client-runtime": "sha256:" + "1" * 64}
        plan = [{"profile": profile, "control": control, "partition": partition}
                for profile in SUMMARY.PROFILES for control in SUMMARY.CONTROLS
                for partition in SUMMARY.PARTITIONS]
        scores = []
        row_store = {}
        partition_sizes = {"validation": 968, "nemotron_heldout": 2, "meddies_heldout": 2}
        for profile in SUMMARY.PROFILES:
            for control in SUMMARY.CONTROLS:
                for partition in SUMMARY.PARTITIONS:
                    count = partition_sizes[partition]
                    rows = []
                    for index in range(count):
                        truth = (index % 2 == 0) if partition == "validation" else True
                        rows.append({
                            "row_id_sha256": h(f"{partition}-row-{index}"),
                            "group_id_sha256": h(f"{partition}-group-{index % 2}"),
                            "expected_has_pii": truth,
                            "predicted_present": truth if control == "expanded" else index % 4 != 0,
                            "source_family": "synthetic-family",
                            "category": ["IDENTITY"], "domain": "general",
                            "document_format": "email", "word_count": 15,
                        })
                    labels = [row["expected_has_pii"] for row in rows]
                    guesses = [row["predicted_present"] for row in rows]
                    matrix_rows = [{"truth": truth, "prediction": guess}
                                   for truth, guess in zip(labels, guesses)]
                    metrics = SUMMARY.confusion(matrix_rows)
                    overall = {"evaluated_samples": count, "row_count": count,
                               "positive_examples": metrics["positive_examples"],
                               "absent_examples": metrics["negative_examples"],
                               "recall": None if metrics["recall"] is None else round(metrics["recall"], 4),
                               "specificity": None if metrics["specificity"] is None else round(metrics["specificity"], 4),
                               "balanced_accuracy": (None if metrics["balanced_accuracy"] is None
                                                     else round(metrics["balanced_accuracy"], 4))}
                    pred_path = study / profile / control / partition / "predictions.json"
                    pred_sha = write_json(pred_path, {"rows": rows})
                    row_store[(profile, control, partition)] = rows
                    score_path = pred_path.parent / "run-manifest.json"
                    score = {"schema_version": 1, "status": "complete", "profile": profile,
                             "control": control, "partition": partition, "rows": count,
                             "successful_rows": count, "errors": [],
                             "source_revision": "execution", "fit_source_revision": "fitting",
                             "protocol_sha256": protocol, "prepared_manifest_sha256": prepared,
                             "partition_sha256": part_hashes[partition],
                             "runtime_image_id": images["client-runtime"],
                             "evaluator_image_id": "sha256:" + "2" * 64,
                             "predictions_sha256": pred_sha,
                             "metrics": {"overall": overall}}
                    score_sha = write_json(score_path, score)
                    scores.append({"profile": profile, "control": control, "partition": partition,
                                   "status": "complete", "rows": count,
                                   "successful_rows": count, "container_exit_code": 0,
                                   "metrics": score["metrics"],
                                   "run_manifest_sha256": score_sha,
                                   "predictions_sha256": pred_sha,
                                   "evaluator_image_id": score["evaluator_image_id"]})
        controller = {"schema_version": 1, "status": "complete", "phase": "complete",
                      "restoration_verified": True, "errors": [], "execution_source_revision": "execution",
                      "fit_source_revision": "fitting", "protocol_sha256": protocol,
                      "prepared_manifest_sha256": prepared, "partition_sha256": part_hashes,
                      "images_before": images, "images_after": images,
                      "evaluator_image_id": "sha256:" + "2" * 64,
                      "evaluator_image_ids": ["sha256:" + "2" * 64],
                      "plan": plan, "scores": scores}
        write_json(study / "run-manifest.json", controller)
        return study

    def test_summary_recomputes_matched_counts_and_positive_only_specificity_is_null(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = SUMMARY.summarize(self._study(Path(temporary)))
        validation = report["profiles"]["balanced"]["partitions"]["validation"]
        self.assertEqual(validation["baseline"]["overall"]["examples"], 968)
        self.assertEqual(validation["baseline"]["overall"]["tp"], 242)
        self.assertEqual(validation["baseline"]["overall"]["fn"], 242)
        self.assertEqual(validation["expanded"]["overall"]["recall"], 1.0)
        nemotron = report["profiles"]["efficient"]["partitions"]["nemotron_heldout"]
        self.assertIsNone(nemotron["baseline"]["overall"]["specificity"])
        self.assertIsNone(nemotron["baseline"]["overall"]["balanced_accuracy"])
        self.assertEqual(nemotron["paired_delta_expanded_minus_baseline"]["interval_status"],
                         "not_computed")

    def test_paired_group_bootstrap_is_deterministic_and_rejects_misalignment(self):
        baseline, candidate = [], []
        for index in range(40):
            truth = index % 2 == 0
            common = {"row_id_sha256": h(f"r{index}"),
                      "group_id_sha256": h(f"g{index}"), "truth": truth}
            baseline.append({**common, "prediction": not truth})
            candidate.append({**common, "prediction": truth})
        first = SUMMARY.paired_group_bootstrap(baseline, candidate, iterations=100)
        second = SUMMARY.paired_group_bootstrap(baseline, candidate, iterations=100)
        self.assertEqual(first, second)
        self.assertEqual(first["point_delta"]["recall"], 1.0)
        self.assertEqual(first["point_delta"]["specificity"], 1.0)
        candidate[0]["row_id_sha256"] = h("mismatch")
        with self.assertRaisesRegex(ValueError, "do not match"):
            SUMMARY.paired_group_bootstrap(baseline, candidate, iterations=10)

    def test_tampered_score_binding_and_changed_paired_labels_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            study = self._study(Path(temporary))
            bad_path = study / "balanced" / "expanded" / "validation" / "predictions.json"
            payload = json.loads(bad_path.read_text())
            payload["rows"][0]["expected_has_pii"] = not payload["rows"][0]["expected_has_pii"]
            write_json(bad_path, payload)
            with self.assertRaisesRegex(ValueError, "Prediction file does not match"):
                SUMMARY.summarize(study)

    def test_nonboolean_predictions_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            study = self._study(Path(temporary))
            pred = study / "balanced" / "baseline" / "validation" / "predictions.json"
            payload = json.loads(pred.read_text())
            payload["rows"][0]["predicted_present"] = 1
            pred_sha = write_json(pred, payload)
            score = pred.parent / "run-manifest.json"
            score_obj = json.loads(score.read_text())
            score_obj["predictions_sha256"] = pred_sha
            score_sha = write_json(score, score_obj)
            controller_path = study / "run-manifest.json"
            controller = json.loads(controller_path.read_text())
            for item in controller["scores"]:
                if (item["profile"], item["control"], item["partition"]) == (
                        "balanced", "baseline", "validation"):
                    item["predictions_sha256"] = pred_sha
                    item["run_manifest_sha256"] = score_sha
            write_json(controller_path, controller)
            with self.assertRaisesRegex(ValueError, "boolean prediction"):
                SUMMARY.summarize(study)


if __name__ == "__main__":
    unittest.main()
