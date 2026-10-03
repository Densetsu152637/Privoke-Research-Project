"""Fail-closed checks for the offline frozen-representation diagnostic."""
import importlib.util
import hashlib
import json
from pathlib import Path
import sys
import types
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import numpy as np

ROOT = Path(__file__).resolve().parents[1]


def load_script(name):
    if name == "prepare-representation-study":
        stub = types.ModuleType("privoke_eval.datasets")
        stub.load_examples = None
        with patch.dict("sys.modules", {"privoke_eval.datasets": stub}):
            spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / f"{name}.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prep = load_script("prepare-representation-study")
fit = load_script("fit-representation-probe")


class Example:
    def __init__(self, identifier, group, text, label):
        self.text = text
        self.expected_has_pii = label
        self.metadata = {"example_id": identifier, "group_id": group, "source_dataset": "x"}


class RepresentationProbeTests(unittest.TestCase):
    def test_locked_development_schema_serializes_as_rows(self):
        locked = {"id": "locked-1", "group_id": "source-1", "text": "text 1",
                  "expected_has_pii": True, "extra": "ignored"}
        self.assertEqual({"id": "locked-1", "group_id": "source-1", "text": "text 1",
                          "text_key": "text 1", "expected_has_pii": True}, prep.serialize(locked))
        with self.assertRaisesRegex(ValueError, "boolean truth"):
            prep.serialize({**locked, "expected_has_pii": "true"})

    def test_test_loader_restores_dataset_module_mock(self):
        before = sys.modules.get("privoke_eval.datasets")
        load_script("prepare-representation-study")
        self.assertIs(sys.modules.get("privoke_eval.datasets"), before)

    def test_partition_rejects_tampered_text_key_and_malformed_truth(self):
        source = [{"id": "a", "group_id": "g", "text": "text a", "text_key": "text a",
                   "expected_has_pii": True}]
        self.assertEqual({"ids": {"a"}, "groups": {"g"}, "texts": {"text a"}},
                         fit.validate_partition_rows(source, "train"))
        with self.assertRaisesRegex(ValueError, "truth label"):
            fit.validate_partition_rows([{**source[0], "expected_has_pii": 1}], "train")
        with self.assertRaisesRegex(ValueError, "text key"):
            fit.validate_partition_rows([{**source[0], "text_key": "forged"}], "train")

    def test_selection_keeps_groups_disjoint_and_balanced(self):
        rows = [Example(f"i{label}{i}", f"g{i // 5}", f"text {label} {i}", bool(label))
                for label in (0, 1) for i in range(250)]
        selected, train, validation, _ = prep.select_rows(rows, [], [], count=250)
        self.assertEqual(500, len(selected))
        self.assertFalse({r.metadata["group_id"] for r in train} &
                         {r.metadata["group_id"] for r in validation})
        self.assertEqual(250, sum(r.expected_has_pii for r in selected))

    def test_protected_text_and_conflicting_normalized_labels_are_excluded(self):
        rows = [Example("a", "ga", "same [at] text", True), Example("b", "gb", "same @ text", False)]
        with self.assertRaisesRegex(ValueError, "eligible positive"):
            prep.select_rows(rows, [], [], count=1)

    def test_feature_validation_rejects_alignment_dimension_and_nonfinite(self):
        source = [{"id": "a", "group_id": "g", "expected_has_pii": True}]
        good = [{"id": "a", "group_id": "g", "expected_has_pii": True,
                 "pooled": [0.0] * 32, "original_binary": False}]
        self.assertEqual(good, fit.validate_feature_rows(good, source))
        with self.assertRaisesRegex(ValueError, "dimensions"):
            fit.validate_feature_rows([{**good[0], "pooled": [0.0]}], source)
        with self.assertRaisesRegex(ValueError, "non-finite"):
            fit.validate_feature_rows([{**good[0], "pooled": [float("nan")] + [0.0] * 31}], source)
        with self.assertRaisesRegex(ValueError, "row count"):
            fit.validate_feature_rows([], source)
        with self.assertRaisesRegex(ValueError, "truth label"):
            fit.validate_feature_rows([{**good[0], "expected_has_pii": 1}], source)

    def test_original_reference_accepts_empty_error_list_and_joins_locked_rows(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            locked_path = root / "development.jsonl"
            locked = [{"id": f"id-{i}", "group_id": f"g-{i}", "text": f"text {i}",
                       "expected_has_pii": i % 2 == 0} for i in range(502)]
            locked_path.write_text("".join(json.dumps(row) + "\n" for row in locked), encoding="utf-8")
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps({"partitions": {"development": {
                "sha256": hashlib.sha256(locked_path.read_bytes()).hexdigest()}}}), encoding="utf-8")
            reference_path = root / "reference.json"
            reference_path.write_text(json.dumps({"errors": [], "metrics": {"evaluated_samples": 502},
                "metadata": {"predictions": [{"example_id": row["id"], "group_id": row["group_id"],
                    "expected_has_pii": row["expected_has_pii"], "detected_sensitive": False, "status": "ok"}
                    for row in locked]}}), encoding="utf-8")
            features = [{"id": row["id"], "group_id": row["group_id"],
                         "expected_has_pii": row["expected_has_pii"], "original_binary": False}
                        for row in locked]
            fit.verify_locked(features, reference_path, locked, manifest_path)
            features[0]["group_id"] = "tampered"
            with self.assertRaisesRegex(ValueError, "Offline original binary"):
                fit.verify_locked(features, reference_path, locked, manifest_path)

    def test_threshold_obeys_floor_and_tie_order(self):
        threshold, metrics = fit.select_threshold(np.array([1, 1, 1, 0, 0]),
                                                   np.array([0.2, 0.8, 0.9, 0.1, 0.8]))
        self.assertGreaterEqual(metrics["recall"], 0.9)
        self.assertEqual(0.2, threshold)
        self.assertEqual(0.5, metrics["specificity"])


if __name__ == "__main__":
    unittest.main()
