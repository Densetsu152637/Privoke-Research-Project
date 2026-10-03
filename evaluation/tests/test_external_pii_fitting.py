"""Focused integrity and serialization tests for external PII profile fitting."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "shared/python"))
sys.path.insert(0, str(ROOT / "evaluation"))

SPEC = importlib.util.spec_from_file_location(
    "fit_external_pii_profiles", ROOT / "evaluation/fit-external-pii-profiles.py")
FIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIT)


def make_rows(prefix: str, count: int, offset: int = 0):
    rows = []
    for i in range(count):
        index = offset + i
        present = i % 2 == 0
        detail = "member private email phone account" if present else "garden weather calendar recipe"
        text = f"{prefix} {detail} sample uniqueindex{index} record"
        rows.append({"id": f"{prefix}:{index}", "group_id": f"{prefix}:{index}",
                     "text": text, "text_key": FIT.training_text_key(text),
                     "expected_has_pii": present, "source": prefix,
                     "expected_categories": ["EMAIL"] if present else [],
                     "domain": "synthetic", "document_format": "plain"})
    return rows


def dump_jsonl(path: Path, rows):
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
                    encoding="utf-8", newline="\n")
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ExternalPiiFittingTests(unittest.TestCase):
    def _prepared(self, root: Path):
        train = make_rows("train", 100)
        validation = make_rows("validation", 968, 1000)
        train = [{key: row[key] for key in ("id", "group_id", "text", "text_key", "expected_has_pii")}
                 for row in train]
        validation = [{key: row[key] for key in ("id", "group_id", "text", "text_key", "expected_has_pii")}
                      for row in validation]
        nemotron = make_rows("nemotron", 500, 3000)
        medd = make_rows("meddies", 500, 4000)
        for row in nemotron + medd:
            row["expected_has_pii"] = True
            row["expected_categories"] = ["EMAIL"]
        original = root / "original-train.jsonl"
        original_sha = dump_jsonl(original, train)
        partition_rows = {"train": train, "validation": validation,
                          "nemotron_heldout": nemotron, "meddies_heldout": medd}
        locators = {"train": "train.jsonl", "validation": "validation.jsonl",
                    "nemotron_heldout": "nemotron-heldout.jsonl",
                    "meddies_heldout": "meddies-heldout.jsonl"}
        hashes = {name: dump_jsonl(root / locators[name], rows)
                  for name, rows in partition_rows.items()}
        protocol_file = root / "protocol.md"
        protocol_file.write_text("synthetic prospective protocol\n", encoding="utf-8")
        protocol_sha = FIT.sha256_file(protocol_file)
        manifest = {"status": "prepared", "schema_version": 1,
                    "source_revision": "1" * 40, "protocol_sha256": protocol_sha,
                    "source_audit_sha256": "b" * 64, "exclusion_index_sha256": "c" * 64,
                    "bootstrap_source_sha256": FIT.FROZEN_BOOTSTRAP_SOURCE_SHA256,
                    "prepared_reference": {"train_sha256": original_sha,
                                           "train_bytes": (root / "original-train.jsonl").stat().st_size,
                                           "validation_sha256": hashes["validation"]},
                    "partition_files": locators, "partition_sha256": hashes,
                    "rows": {name: len(rows) for name, rows in partition_rows.items()}}
        (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        return protocol_sha, original, protocol_file

    def test_validates_fixed_reference_and_rejects_malformed_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            protocol_sha, original, _ = self._prepared(root)
            validation_path = root / "validation.jsonl"
            actual_validation_hash = FIT.sha256_file(validation_path)
            with patch.object(FIT, "FROZEN_VALIDATION_SHA256", actual_validation_hash), \
                    patch.object(FIT, "ORIGINAL_TRAIN_ROW_COUNT", 100), \
                    patch.object(FIT, "FROZEN_ORIGINAL_TRAIN_SHA256", FIT.sha256_file(original)):
                checked = FIT.validate_prepared(root, protocol_sha, original)
                self.assertEqual(checked["partition_rows"]["validation"], 968)
                rows = checked["partitions"]["train"]
                rows[0]["expected_has_pii"] = 1
                with self.assertRaisesRegex(ValueError, "strict boolean"):
                    FIT.validate_rows(rows, "train")

    def test_rejects_cross_partition_source_group_collision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            protocol_sha, original, _ = self._prepared(root)
            validation_path = root / "validation.jsonl"
            rows = FIT.read_jsonl(validation_path)
            rows[0]["group_id"] = FIT.read_jsonl(root / "train.jsonl")[0]["group_id"]
            validation_hash = dump_jsonl(validation_path, rows)
            manifest = FIT.read_json(root / "manifest.json")
            manifest["partition_sha256"]["validation"] = validation_hash
            manifest["prepared_reference"]["validation_sha256"] = validation_hash
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with patch.object(FIT, "FROZEN_VALIDATION_SHA256", validation_hash), \
                    patch.object(FIT, "ORIGINAL_TRAIN_ROW_COUNT", 100), \
                    patch.object(FIT, "FROZEN_ORIGINAL_TRAIN_SHA256", FIT.sha256_file(original)):
                with self.assertRaisesRegex(ValueError, "groups overlap"):
                    FIT.validate_prepared(root, protocol_sha, original)

    def test_profiles_freeze_selection_before_any_diagnostic_callback(self):
        from sklearn.linear_model import LogisticRegression
        from privoke_eval.presence_training import build_artifact, serialized_runtime_model
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "prepared").mkdir()
            protocol_sha, original, protocol_file = self._prepared(root / "prepared")
            train = FIT.read_jsonl(root / "prepared" / "train.jsonl")
            vectorizer = FIT.make_vectorizer("efficient")
            matrix = vectorizer.fit_transform([row["text"] for row in train])
            estimator = LogisticRegression(C=1, class_weight="balanced", solver="lbfgs",
                                           max_iter=1000, tol=1e-4, random_state=7102026)
            estimator.fit(matrix, [int(row["expected_has_pii"]) for row in train])
            base_artifact = build_artifact(vectorizer, estimator, "efficient", 0.5,
                                           {"task": "annotation_presence", "profile": "efficient",
                                            "release_version": "v1.0.0", "training_revision": "0"})
            base_model = serialized_runtime_model(base_artifact)
            baseline_profiles = {name: (base_artifact, base_model) for name in FIT.PROFILES}
            baseline = {"manifest_sha256": "f" * 64, "profiles": baseline_profiles}

            def check_frozen(inputs, output, freeze_path, freeze_sha, profiles):
                self.assertTrue(freeze_path.is_file())
                self.assertEqual(FIT.sha256_file(freeze_path), freeze_sha)
                freeze = FIT.read_json(freeze_path)
                self.assertEqual(freeze["status"], "all_profiles_frozen")
                self.assertTrue(freeze["selections_frozen_before_diagnostic_scoring"])
                for profile in FIT.PROFILES:
                    self.assertEqual(freeze["profiles"][profile]["status"], "selected")
                    self.assertTrue((output / "profiles" / profile / "selection.json").is_file())
                FIT.write_exclusive(output / "diagnostics.json", {
                    "status": "complete", "fit_freeze_sha256": freeze_sha,
                    "source_revision": freeze["source_revision"],
                    "protocol_sha256": freeze["protocol_sha256"],
                    "partition_sha256": inputs["partition_sha256"]})
                return {"status": "complete"}

            output = root / "fresh-output"
            with patch.object(FIT, "FROZEN_VALIDATION_SHA256",
                              FIT.sha256_file(root / "prepared" / "validation.jsonl")), \
                    patch.object(FIT, "ORIGINAL_TRAIN_ROW_COUNT", 100), \
                    patch.object(FIT, "FROZEN_ORIGINAL_TRAIN_SHA256", FIT.sha256_file(original)), \
                    patch.object(FIT, "_load_baseline_models", return_value=baseline), \
                    patch.object(FIT, "score_diagnostics", side_effect=check_frozen):
                result = FIT.fit_profiles(
                    root / "prepared", output, source_revision="e" * 40,
                    protocol_sha256=protocol_sha, protocol_file=protocol_file,
                    original_train_reference=original, baseline_fit_root=root / "unused-baseline")
            self.assertEqual(result["status"], "complete")
            self.assertTrue(result["selections_frozen_before_diagnostic_scoring"])
            with patch.object(FIT, "FROZEN_VALIDATION_SHA256",
                              FIT.sha256_file(root / "prepared" / "validation.jsonl")), \
                    patch.object(FIT, "ORIGINAL_TRAIN_ROW_COUNT", 100), \
                    patch.object(FIT, "FROZEN_ORIGINAL_TRAIN_SHA256", FIT.sha256_file(original)):
                loaded = FIT.load_completed_fit(
                    output, root / "prepared", source_revision="e" * 40,
                    protocol_sha256=protocol_sha, original_train_reference=original)
            self.assertEqual(set(loaded["profiles"]), set(FIT.PROFILES))

    def test_shared_runtime_artifact_and_prediction_export_do_not_leak_text(self):
        from sklearn.linear_model import LogisticRegression
        train, validation = make_rows("train", 100), make_rows("validation", 40, 1000)
        vectorizer = FIT.make_vectorizer("efficient")
        x_train = vectorizer.fit_transform([FIT.training_text_key(row["text"]) for row in train])
        estimator = LogisticRegression(C=1, class_weight="balanced", solver="lbfgs",
                                       max_iter=1000, tol=1e-4, random_state=7102026)
        estimator.fit(x_train, [int(row["expected_has_pii"]) for row in train])
        from privoke_eval.presence_training import build_artifact, serialized_runtime_model, runtime_probabilities
        metadata = {"task": "annotation_presence", "profile": "efficient",
                    "release_version": "v1.0.0", "training_revision": "0"}
        artifact = build_artifact(vectorizer, estimator, "efficient", 0.5, metadata)
        model = serialized_runtime_model(artifact)
        probabilities = runtime_probabilities(model, validation)
        exported = FIT.prediction_rows(validation, probabilities, 0.5)
        self.assertEqual(len(exported), len(validation))
        self.assertTrue(all("text" not in row and "id" not in row and "group_id" not in row
                            for row in exported))
        self.assertTrue(all(0 <= row["probability"] <= 1 for row in exported))
        word_features = set(artifact["config"]["branches"]["word"]["features"])
        self.assertNotIn("validation", word_features)

    def test_metrics_keep_missing_class_rates_null(self):
        rows = make_rows("positive", 4)
        for row in rows:
            row["expected_has_pii"] = True
        metrics = FIT._metric_groups(rows, [0.9, 0.8, 0.7, 0.6], 0.5)
        self.assertIsNone(metrics["pooled"]["specificity"])
        self.assertIsNone(metrics["pooled"]["balanced_accuracy"])


if __name__ == "__main__":
    unittest.main()
