"""Focused integrity and serialization tests for external PII profile fitting."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
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


def make_preparation_helpers(root: Path):
    helper_path = root / "prepare-external-pii-study.py"
    helper_path.write_text("# synthetic reviewed-helper identity for unit test\n", encoding="utf-8")

    def canonical(value):
        return json.dumps(value, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":"), allow_nan=False)

    def digest(value):
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def opaque(kind, value):
        return digest("privoke-external-exclusion-v1\0" + kind + "\0" + value)

    def canonical_group(value, source=None):
        return value.strip()

    def row_keys(identifier, group, text):
        return {"ids": {opaque("id", identifier)},
                "groups": {opaque("group", canonical_group(group))},
                "texts": {opaque("text_key", FIT.training_text_key(text))}}

    source_bindings = {"nemotron-pii": {"repo_id": "nvidia/Nemotron-PII",
                                         "revision": "b70ffaf5ff39e079776134c5bf4381f00a9fd1ed"},
                       "meddies-pii": {"repo_id": "Meddies/meddies-pii",
                                        "revision": "6a5c8f5441e3b421d983c9741770262365acdd77"}}

    def validate_audit(receipt):
        if receipt.get("schema_version") != 1 or receipt.get("status") != "audited" \
                or receipt.get("sources") != source_bindings:
            raise ValueError("invalid source audit fixture")
        return dict(receipt["sources"])

    bootstrap = [f"bootstrap exclusion sentence {i}" for i in range(43)]
    helpers = SimpleNamespace(__file__=str(helper_path), canonical=canonical, digest=digest,
                              opaque=opaque, canonical_group=canonical_group, row_keys=row_keys,
                              validate_audit=validate_audit, bootstrap_texts=lambda path: bootstrap,
                              PIIMB_PIN="4a13e9ffe6fd0d275efbde8afd4d8d8f1ffc2133",
                              LOADER_REVISION="9998e8986c7924223ea4598cb1ba683e32ade0ba",
                              LOADER_SHA256="016a25a56b6fa3a9b8c16fcf9fde8a350c205101b26000cedd1095f097e15733")
    return helpers, source_bindings, bootstrap


class ExternalPiiFittingTests(unittest.TestCase):
    def _prepared(self, root: Path):
        helpers, source_bindings, bootstrap = make_preparation_helpers(root)
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
        audit = {"schema_version": 1, "status": "audited", "sources": source_bindings}
        (root / "source-audit.json").write_text(json.dumps(audit), encoding="utf-8")
        protected_records = []
        protected_keys = {"ids": set(), "groups": set(), "texts": set()}
        for i in range(1000):
            identifier = f"protected-id-{i}"
            group = f"protected-group-{i % 929}"
            text = f"synthetic protected source document {i}"
            keys = helpers.row_keys(identifier, group, text)
            for kind in protected_keys:
                protected_keys[kind].update(keys[kind])
            protected_records.append({"id_sha256": helpers.opaque("id", identifier),
                "canonical_group_sha256": helpers.opaque("group", group),
                "normalized_text_sha256": helpers.opaque("text_key", FIT.training_text_key(text)),
                "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()})
        protected_records.sort(key=helpers.canonical)
        all_keys = {kind: set(values) for kind, values in protected_keys.items()}
        for reference_rows in (train, validation):
            for row in reference_rows:
                for kind, values in helpers.row_keys(row["id"], row["group_id"], row["text"]).items():
                    all_keys[kind].update(values)
        all_keys["texts"].update(helpers.opaque("text_key", FIT.training_text_key(text)) for text in bootstrap)
        key_sets = {kind: sorted(values) for kind, values in protected_keys.items()}
        all_sets = {kind: sorted(values) for kind, values in all_keys.items()}
        aggregate = {"selected": 1000, "rows_seen": 150022, "eligible_rows": 107488,
                     "selected_label_counts": {"pii": 500, "clean": 500},
                     "duplicate_rows": 15354,
                     "population_label_counts": {"pii": 60418, "clean": 47070},
                     "exclusions": {"conflicting_duplicate_label_rows": 598,
                                    "non_english_language_rows": 27180}}
        index = {"schema_version": 1, "records": protected_records, "key_sets": key_sets,
                 "algorithm": "pinned PIIMB balanced full-scan reservoir and sampler order",
                 "loader_revision": helpers.LOADER_REVISION,
                 "loader_canonical_lf_sha256": helpers.LOADER_SHA256,
                 "dataset_revision": helpers.PIIMB_PIN, "seed": 3102026,
                 "aggregate": aggregate, "sorted_records_sha256": helpers.digest(helpers.canonical(protected_records)),
                 "reproduced_twice": True, "all_exclusion_key_sets": all_sets,
                 "all_exclusion_key_sets_sha256": helpers.digest(helpers.canonical(all_sets))}
        (root / "exclusion-index.json").write_text(helpers.canonical(index) + "\n", encoding="utf-8")
        index_sha = FIT.sha256_file(root / "exclusion-index.json")
        manifest = {"status": "prepared", "schema_version": 1,
                    "source_revision": "1" * 40, "protocol_sha256": protocol_sha,
                    "source_audit_sha256": FIT.sha256_file(root / "source-audit.json"),
                    "exclusion_index_file": "exclusion-index.json", "exclusion_index_sha256": index_sha,
                    "bootstrap_source_sha256": FIT.FROZEN_BOOTSTRAP_SOURCE_SHA256,
                    "prepared_reference": {"train_sha256": original_sha,
                                           "train_bytes": (root / "original-train.jsonl").stat().st_size,
                                           "validation_sha256": hashes["validation"]},
                    "protected_selection": aggregate,
                    "protected_selection_sha256": index["sorted_records_sha256"],
                    "preparation_script_sha256": FIT.sha256_file(Path(helpers.__file__)),
                    "training_text_key_source_sha256": FIT.sha256_file(
                        ROOT / "shared/python/privoke_model/training_data.py"),
                    "sources": source_bindings,
                    "partition_files": locators, "partition_sha256": hashes,
                    "rows": {name: len(rows) for name, rows in partition_rows.items()}}
        (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        return protocol_sha, original, protocol_file, helpers

    def test_validates_fixed_reference_and_rejects_malformed_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            protocol_sha, original, _, helpers = self._prepared(root)
            validation_path = root / "validation.jsonl"
            actual_validation_hash = FIT.sha256_file(validation_path)
            with patch.object(FIT, "FROZEN_VALIDATION_SHA256", actual_validation_hash), \
                    patch.object(FIT, "ORIGINAL_TRAIN_ROW_COUNT", 100), \
                    patch.object(FIT, "FROZEN_ORIGINAL_TRAIN_SHA256", FIT.sha256_file(original)), \
                    patch.object(FIT, "load_preparation_helpers", return_value=helpers):
                checked = FIT.validate_prepared(root, protocol_sha, original)
                self.assertEqual(checked["partition_rows"]["validation"], 968)
                rows = checked["partitions"]["train"]
                rows[0]["expected_has_pii"] = 1
                with self.assertRaisesRegex(ValueError, "strict boolean"):
                    FIT.validate_rows(rows, "train")

    def test_rejects_cross_partition_source_group_collision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            protocol_sha, original, _, helpers = self._prepared(root)
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
                    patch.object(FIT, "FROZEN_ORIGINAL_TRAIN_SHA256", FIT.sha256_file(original)), \
                    patch.object(FIT, "load_preparation_helpers", return_value=helpers):
                with self.assertRaisesRegex(ValueError, "groups overlap"):
                    FIT.validate_prepared(root, protocol_sha, original)

    def test_sidecar_missing_or_modified_is_rejected(self):
        for sidecar in ("source-audit.json", "exclusion-index.json"):
            with self.subTest(sidecar=sidecar), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                protocol_sha, original, _, helpers = self._prepared(root)
                (root / sidecar).unlink()
                with patch.object(FIT, "FROZEN_VALIDATION_SHA256",
                                  FIT.sha256_file(root / "validation.jsonl")), \
                        patch.object(FIT, "ORIGINAL_TRAIN_ROW_COUNT", 100), \
                        patch.object(FIT, "FROZEN_ORIGINAL_TRAIN_SHA256", FIT.sha256_file(original)), \
                        patch.object(FIT, "load_preparation_helpers", return_value=helpers):
                    with self.assertRaises(OSError):
                        FIT.validate_prepared(root, protocol_sha, original)

    def test_rehashed_invalid_audit_and_index_contracts_are_rejected(self):
        for sidecar in ("source-audit.json", "exclusion-index.json"):
            with self.subTest(sidecar=sidecar), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                protocol_sha, original, _, helpers = self._prepared(root)
                manifest = FIT.read_json(root / "manifest.json")
                if sidecar == "source-audit.json":
                    audit = FIT.read_json(root / sidecar)
                    audit["sources"]["nemotron-pii"]["revision"] = "0" * 40
                    (root / sidecar).write_text(json.dumps(audit), encoding="utf-8")
                    manifest["source_audit_sha256"] = FIT.sha256_file(root / sidecar)
                else:
                    index = FIT.read_json(root / sidecar)
                    index["loader_revision"] = "0" * 40
                    (root / sidecar).write_text(helpers.canonical(index) + "\n", encoding="utf-8")
                    manifest["exclusion_index_sha256"] = FIT.sha256_file(root / sidecar)
                (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
                with patch.object(FIT, "FROZEN_VALIDATION_SHA256",
                                  FIT.sha256_file(root / "validation.jsonl")), \
                        patch.object(FIT, "ORIGINAL_TRAIN_ROW_COUNT", 100), \
                        patch.object(FIT, "FROZEN_ORIGINAL_TRAIN_SHA256", FIT.sha256_file(original)), \
                        patch.object(FIT, "load_preparation_helpers", return_value=helpers):
                    with self.assertRaises(ValueError):
                        FIT.validate_prepared(root, protocol_sha, original)

    def test_added_train_row_matching_protected_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            protocol_sha, original, _, helpers = self._prepared(root)
            train_path = root / "train.jsonl"
            train_rows = FIT.read_jsonl(train_path)
            text = "synthetic protected source document 0"
            train_rows.append({"id": "protected-id-0", "group_id": "protected-group-0",
                               "text": text, "text_key": FIT.training_text_key(text),
                               "expected_has_pii": True, "source": "nvidia/Nemotron-PII",
                               "expected_categories": ["EMAIL"], "domain": "fixture",
                               "document_format": "plain"})
            train_hash = dump_jsonl(train_path, train_rows)
            manifest = FIT.read_json(root / "manifest.json")
            manifest["partition_sha256"]["train"] = train_hash
            manifest["rows"]["train"] = len(train_rows)
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with patch.object(FIT, "FROZEN_VALIDATION_SHA256",
                              FIT.sha256_file(root / "validation.jsonl")), \
                    patch.object(FIT, "ORIGINAL_TRAIN_ROW_COUNT", 100), \
                    patch.object(FIT, "FROZEN_ORIGINAL_TRAIN_SHA256", FIT.sha256_file(original)), \
                    patch.object(FIT, "load_preparation_helpers", return_value=helpers):
                with self.assertRaisesRegex(ValueError, "collides with a protected"):
                    FIT.validate_prepared(root, protocol_sha, original)

    def test_diagnostic_row_matching_protected_key_and_zero_source_coverage_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            protocol_sha, original, _, helpers = self._prepared(root)
            heldout_path = root / "nemotron-heldout.jsonl"
            heldout_rows = FIT.read_jsonl(heldout_path)
            text = "synthetic protected source document 1"
            heldout_rows[0].update({"id": "protected-id-1", "group_id": "protected-group-1",
                                    "text": text, "text_key": FIT.training_text_key(text)})
            heldout_sha = dump_jsonl(heldout_path, heldout_rows)
            manifest = FIT.read_json(root / "manifest.json")
            manifest["partition_sha256"]["nemotron_heldout"] = heldout_sha
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with patch.object(FIT, "FROZEN_VALIDATION_SHA256",
                              FIT.sha256_file(root / "validation.jsonl")), \
                    patch.object(FIT, "ORIGINAL_TRAIN_ROW_COUNT", 100), \
                    patch.object(FIT, "FROZEN_ORIGINAL_TRAIN_SHA256", FIT.sha256_file(original)), \
                    patch.object(FIT, "load_preparation_helpers", return_value=helpers):
                with self.assertRaisesRegex(ValueError, "collides with a protected"):
                    FIT.validate_prepared(root, protocol_sha, original)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            protocol_sha, original, _, helpers = self._prepared(root)
            heldout_path = root / "nemotron-heldout.jsonl"
            dump_jsonl(heldout_path, [])
            manifest = FIT.read_json(root / "manifest.json")
            manifest["partition_sha256"]["nemotron_heldout"] = FIT.sha256_file(heldout_path)
            manifest["rows"]["nemotron_heldout"] = 0
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with patch.object(FIT, "FROZEN_VALIDATION_SHA256",
                              FIT.sha256_file(root / "validation.jsonl")), \
                    patch.object(FIT, "ORIGINAL_TRAIN_ROW_COUNT", 100), \
                    patch.object(FIT, "FROZEN_ORIGINAL_TRAIN_SHA256", FIT.sha256_file(original)), \
                    patch.object(FIT, "load_preparation_helpers", return_value=helpers):
                with self.assertRaisesRegex(ValueError, "1–1,000 rows"):
                    FIT.validate_prepared(root, protocol_sha, original)

    def test_profiles_freeze_selection_before_any_diagnostic_callback(self):
        from sklearn.linear_model import LogisticRegression
        from privoke_eval.presence_training import build_artifact, serialized_runtime_model
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "prepared").mkdir()
            protocol_sha, original, protocol_file, helpers = self._prepared(root / "prepared")
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
                    patch.object(FIT, "load_preparation_helpers", return_value=helpers), \
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
                    patch.object(FIT, "FROZEN_ORIGINAL_TRAIN_SHA256", FIT.sha256_file(original)), \
                    patch.object(FIT, "load_preparation_helpers", return_value=helpers):
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
        rows[0]["domain"] = None
        metrics = FIT._metric_groups(rows, [0.9, 0.8, 0.7, 0.6], 0.5)
        self.assertIsNone(metrics["pooled"]["specificity"])
        self.assertIsNone(metrics["pooled"]["balanced_accuracy"])
        self.assertIn("__unavailable__", metrics["domain"])


if __name__ == "__main__":
    unittest.main()
