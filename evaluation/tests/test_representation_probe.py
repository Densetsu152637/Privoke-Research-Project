"""Fail-closed checks for the offline frozen-representation diagnostic."""
import importlib.util
import hashlib
import io
import json
from pathlib import Path
import sys
import types
import uuid
from tempfile import TemporaryDirectory
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np
from privoke_model.fingerprint import parameter_fingerprint

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
harness = load_script("run-representation-diagnostic")


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

    def test_text_free_bundle_rows_match_source_and_reject_tampering(self):
        source = [{"id": "a", "group_id": "g", "text": "text a", "text_key": "text a",
                   "expected_has_pii": True}]
        bundle = [{key: row[key] for key in ("id", "group_id", "text_key", "expected_has_pii")}
                  for row in source]
        self.assertEqual(bundle, fit.validate_bundle_metadata(source, bundle, "train"))
        with self.assertRaisesRegex(ValueError, "source partition"):
            fit.validate_bundle_metadata(source, [{**bundle[0], "group_id": "tampered"}], "train")

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
            locked = [{"id": f"id-{i}", "group_id": f"g-{i // 4}", "text": f"text {i}",
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
            fit.verify_locked(features, reference_path, locked, locked_path, manifest_path)
            features[0]["group_id"] = "tampered"
            with self.assertRaisesRegex(ValueError, "Offline original binary"):
                fit.verify_locked(features, reference_path, locked, locked_path, manifest_path)
            features[0]["group_id"] = locked[0]["group_id"]
            moved_text = [dict(row) for row in locked]
            moved_text[0]["text"], moved_text[2]["text"] = moved_text[2]["text"], moved_text[0]["text"]
            with self.assertRaisesRegex(ValueError, "locked text/truth/group"):
                fit.validate_development_source(moved_text, locked)
            reference = json.loads(reference_path.read_text(encoding="utf-8"))
            reference["errors"] = False
            reference_path.write_text(json.dumps(reference), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "incomplete or contains errors"):
                fit.verify_locked(features, reference_path, locked, locked_path, manifest_path)
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                fit.require_sha256(reference_path, "0" * 64, "Archived original semantic report")

    def test_prepare_target_is_fresh_and_downstream_paths_share_it(self):
        output = harness.RESULTS / f"__representation_layout_test_{uuid.uuid4().hex}"
        target, container_target, command = harness.preparation_invocation(output)
        self.assertFalse(target.exists())
        self.assertTrue(container_target.endswith(f"/{output.name}/prepared"))
        self.assertEqual(container_target, command[-1])
        self.assertEqual(f"{container_target}/train.jsonl",
                         harness.prepared_partition_container_path(output, "train.jsonl"))
        self.assertEqual(f"{container_target}/manifest.json",
                         harness.prepared_partition_container_path(output, "manifest.json"))

    def test_runtime_parameter_fingerprint_uses_float32_and_shapes(self):
        artifact = {"parameters": {"weight": {"shape": [2], "values": [0.1000000002, 2.0]}}}
        runtime = {"weight": np.asarray(artifact["parameters"]["weight"]["values"], dtype=np.float32)}
        self.assertEqual(parameter_fingerprint(runtime, {"weight": [2]}), harness.artifact_fingerprint(artifact))

    def test_embedded_export_fingerprints_rank_two_runtime_parameters(self):
        matrix = np.asarray([[0.1, 2.0], [-3.0, 4.5]], dtype=np.float32)

        class FakeModel:
            parameters = {"matrix": matrix}

            @classmethod
            def from_artifact(cls, artifact):
                return cls()

            def predict_many(self, texts):
                return [SimpleNamespace(pooled=[0.0] * 32, sensitivity="S0", categories=[])
                        for _ in texts]

        src = types.ModuleType("src")
        src.__path__ = []
        src_model = types.ModuleType("src.model")
        src_model.TinyTransformerModel = FakeModel
        detection = types.ModuleType("src.detection")
        detection.__path__ = []
        preprocessing = types.ModuleType("src.detection.preprocessing")
        preprocessing.normalize_text = lambda text: text
        modules = {"src": src, "src.model": src_model, "src.detection": detection,
                   "src.detection.preprocessing": preprocessing}
        payload = {"artifact": {"config": {"hidden_size": 32}}, "partitions": {}}
        stdout = io.StringIO()
        with patch.dict("sys.modules", modules), patch("sys.stdin", io.StringIO(json.dumps(payload))), \
                patch("sys.stdout", stdout):
            exec(compile(harness.EXPORT_PROGRAM, "<embedded-export>", "exec"), {})

        emitted = json.loads(stdout.getvalue())
        expected = parameter_fingerprint({"matrix": matrix.ravel()}, {"matrix": [2, 2]})
        self.assertEqual(expected, emitted["parameter_fingerprint"])

    def test_threshold_obeys_floor_and_tie_order(self):
        threshold, metrics = fit.select_threshold(np.array([1, 1, 1, 0, 0]),
                                                   np.array([0.2, 0.8, 0.9, 0.1, 0.8]))
        self.assertGreaterEqual(metrics["recall"], 0.9)
        self.assertEqual(0.2, threshold)
        self.assertEqual(0.5, metrics["specificity"])


if __name__ == "__main__":
    unittest.main()
