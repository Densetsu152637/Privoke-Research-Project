"""Integrity and ordering tests for the prospective lexical text control."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from tempfile import TemporaryDirectory
from unittest.mock import patch

import numpy as np

SCRIPT = Path(__file__).resolve().parents[1] / "fit-text-control.py"
SPEC = importlib.util.spec_from_file_location("fit_text_control", SCRIPT)
control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control)


def row(partition, index, label):
    return {"id": f"{partition}-id-{index}", "group_id": f"fixture:{partition}-group-{index}",
            "text": f"{partition} {'positive' if label else 'clean'} sharedtoken item{index}",
            "text_key": f"{partition} {'positive' if label else 'clean'} sharedtoken item{index}",
            "expected_has_pii": bool(label)}


def write_jsonl(path, rows):
    path.write_text("".join(json.dumps(item, ensure_ascii=False) + "\n" for item in rows), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TextControlTests(unittest.TestCase):
    def test_prepared_identity_verifies_hashes_labels_groups_text_and_bootstrap(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepared, locked = root / "prepared", root / "locked"
            prepared.mkdir()
            locked.mkdir()
            partitions = {
                "train": [row("train", i, i % 2) for i in range(100)],
                "validation": [row("validation", i, i % 2) for i in range(100)],
                "development": [row("development", i, i % 2) for i in range(12)],
            }
            partition_hashes = {name: write_jsonl(prepared / f"{name}.jsonl", rows)
                                for name, rows in partitions.items()}
            bootstrap = root / "generate_baseline.py"
            bootstrap.write_text("def training_samples():\n    return [(f'control-anchor-{i}', 'S0', 'PU', ()) for i in range(43)]\n",
                                 encoding="utf-8")
            bootstrap_hash = control.sha256_file(bootstrap)
            locked_hashes = {"development": write_jsonl(locked / "development.jsonl", partitions["development"]),
                             "final": hashlib.sha256(b"DO NOT PARSE THIS FINAL PARTITION").hexdigest()}
            (locked / "final.jsonl").write_bytes(b"DO NOT PARSE THIS FINAL PARTITION")
            locked_manifest = {"partitions": {name: {"sha256": digest} for name, digest in locked_hashes.items()}}
            locked_manifest_bytes = json.dumps(locked_manifest).encode()
            (locked / "manifest.json").write_bytes(locked_manifest_bytes)
            manifest = {"dataset": "piimb", "revision": control.EXPECTED_REVISION,
                "seed": 5102026, "validation_seed": 6102026,
                "rows": {name: len(rows) for name, rows in partitions.items()},
                "partition_sha256": partition_hashes, "bootstrap_source_sha256": bootstrap_hash,
                "locked_sha256": locked_hashes}
            manifest_bytes = json.dumps(manifest, indent=2).encode()
            (prepared / "manifest.json").write_bytes(manifest_bytes)
            expected_counts = {name: (len(rows), partition_hashes[name]) for name, rows in partitions.items()}
            with patch.object(control, "EXPECTED_PREPARED_MANIFEST_SHA256", hashlib.sha256(manifest_bytes).hexdigest()), \
                    patch.object(control, "EXPECTED_LOCKED_MANIFEST_SHA256", hashlib.sha256(locked_manifest_bytes).hexdigest()), \
                    patch.object(control, "EXPECTED_LOCKED_SHA256", locked_hashes), \
                    patch.object(control, "EXPECTED_PARTITIONS", expected_counts), \
                    patch.object(control, "EXPECTED_BOOTSTRAP_SHA256", bootstrap_hash):
                validated = control.validate_identity_inputs(prepared, locked, bootstrap)
                self.assertEqual(partition_hashes, validated["partition_sha256"])
                self.assertEqual(locked_hashes, validated["locked_sha256"])
                keys = control.bootstrap_text_keys(bootstrap)
                self.assertEqual(43, len(keys))
                overlapping = copy.deepcopy(partitions)
                overlapping["train"][0]["text_key"] = "control-anchor-0"
                with self.assertRaisesRegex(ValueError, "bootstrap training text"):
                    control.validate_bootstrap_disjoint(overlapping, keys)

                # Strict truth validation rejects integers even when they look binary.
                bad = copy.deepcopy(partitions)
                bad["train"][0]["expected_has_pii"] = 1
                with self.assertRaisesRegex(ValueError, "truth label"):
                    control.validate_disjoint_partitions(bad)

                # A protected-dev text swap is rejected by exact ID-to-text joins.
                bad_locked = copy.deepcopy(partitions["development"])
                bad_locked[0]["text"] += " swapped"
                write_jsonl(locked / "development.jsonl", bad_locked)
                locked_hashes["development"] = control.sha256_file(locked / "development.jsonl")
                locked_manifest["partitions"]["development"]["sha256"] = locked_hashes["development"]
                updated_locked_manifest = json.dumps(locked_manifest).encode()
                (locked / "manifest.json").write_bytes(updated_locked_manifest)
                manifest["locked_sha256"] = locked_hashes
                updated_prepared_manifest = json.dumps(manifest, indent=2).encode()
                (prepared / "manifest.json").write_bytes(updated_prepared_manifest)
                with patch.object(control, "EXPECTED_PREPARED_MANIFEST_SHA256", hashlib.sha256(updated_prepared_manifest).hexdigest()), \
                        patch.object(control, "EXPECTED_LOCKED_MANIFEST_SHA256", hashlib.sha256(updated_locked_manifest).hexdigest()), \
                        patch.object(control, "EXPECTED_LOCKED_SHA256", locked_hashes):
                    with self.assertRaisesRegex(ValueError, "differ from locked text"):
                        control.validate_identity_inputs(prepared, locked, bootstrap)

    def test_cross_partition_group_and_text_overlap_is_rejected(self):
        train = [row("train", i, i % 2) for i in range(100)]
        validation = [row("validation", i, i % 2) for i in range(100)]
        development = [row("development", i, i % 2) for i in range(12)]
        validation[0]["group_id"] = train[0]["group_id"]
        with self.assertRaisesRegex(ValueError, "groups overlap"):
            control.validate_disjoint_partitions({"train": train, "validation": validation,
                                                  "development": development})
        validation[0]["group_id"] = "fixture:other"
        validation[0]["id"] = train[0]["id"]
        with self.assertRaisesRegex(ValueError, "ids overlap"):
            control.validate_disjoint_partitions({"train": train, "validation": validation,
                                                  "development": development})
        validation[0]["id"] = "validation-id-0"
        validation[0]["text"] = train[0]["text"]
        validation[0]["text_key"] = train[0]["text_key"]
        with self.assertRaisesRegex(ValueError, "texts overlap"):
            control.validate_disjoint_partitions({"train": train, "validation": validation,
                                                  "development": development})

    def test_vectorizer_is_train_only_and_selection_precedes_development_transform(self):
        train = [row("train", i, i % 2) for i in range(40)]
        validation = [row("validation", i, i % 2) for i in range(20)]
        for index in (0, 1):
            train[index]["text"] += " " + ("middle " * 110) + " tailmarker"
            train[index]["text_key"] = control.training_text_key(train[index]["text"])
        validation[0]["text"] += " zyxwvutokenonlyvalidation"
        validation[0]["text_key"] = control.training_text_key(validation[0]["text"])
        vectorizer, vec_record, _, candidates, failures, selection = \
            control.fit_validation_candidates(train, validation)
        self.assertFalse(failures)
        self.assertIsNotNone(selection)
        self.assertNotIn("zyxwvutokenonlyvalidation", vec_record["branches"]["word"]["vocabulary"])
        self.assertIn("tailmarker", vec_record["branches"]["word"]["vocabulary"])
        self.assertNotIn("development_candidates", selection)
        self.assertEqual(vec_record["n_features"], selection["candidates"][0]["model"]["coefficient_dimension"])
        for candidate in selection["candidates"]:
            for prediction in candidate["validation_predictions"] + candidate["train_predictions"]:
                self.assertTrue(np.isfinite(prediction["probability"]))

        with TemporaryDirectory() as temporary:
            selection_path = Path(temporary) / "selection.json"
            development = [row("development", i, i % 2) for i in range(12)]
            with patch.object(vectorizer, "transform", wraps=vectorizer.transform) as transform:
                with self.assertRaisesRegex(ValueError, "persisted before development"):
                    control.score_development_after_selection(vectorizer, candidates, development, selection_path)
                transform.assert_not_called()
            control.write_fresh_json(selection_path, selection)
            scores = control.score_development_after_selection(vectorizer, candidates, development, selection_path)
            self.assertEqual({0.1, 1.0, 10.0}, {item["C"] for item in scores})

    def test_development_gate_rejects_forged_selection_before_transform(self):
        train = [row("train", i, i % 2) for i in range(40)]
        validation = [row("validation", i, i % 2) for i in range(20)]
        vectorizer, _, _, candidates, _, selection = control.fit_validation_candidates(train, validation)
        development = [row("development", i, i % 2) for i in range(12)]
        mutations = ("selected_C", "selected_threshold", "coefficient")
        for mutation in mutations:
            with self.subTest(mutation=mutation), TemporaryDirectory() as temporary:
                payload = copy.deepcopy(selection)
                if mutation == "selected_C":
                    payload["selected_C"] = 99
                elif mutation == "selected_threshold":
                    payload["selected_threshold"] += 0.01
                else:
                    payload["candidates"][0]["model"]["coefficients"][0] += 1.0
                path = Path(temporary) / "selection.json"
                control.write_fresh_json(path, payload)
                with patch.object(vectorizer, "transform", wraps=vectorizer.transform) as transform:
                    with self.assertRaisesRegex(ValueError, "Persisted"):
                        control.score_development_after_selection(vectorizer, candidates, development, path)
                    transform.assert_not_called()

    def test_family_metrics_use_null_rates_when_a_class_is_absent(self):
        rows = [{"id": "a", "group_id": "mapa-eur-lex:1", "expected_has_pii": True},
                {"id": "b", "group_id": "mapa-eur-lex:2", "expected_has_pii": True}]
        records = [{"prediction": True}, {"prediction": False}]
        metrics = control.metrics_by_family(rows, records)["mapa-eur-lex"]
        self.assertIsNone(metrics["specificity"])
        self.assertIsNone(metrics["balanced_accuracy"])
        self.assertEqual(0.5, metrics["recall"])

    def test_output_files_are_exclusive(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "artifact.json"
            control.write_fresh_json(path, {"status": "first"})
            with self.assertRaises(FileExistsError):
                control.write_fresh_json(path, {"status": "second"})
            self.assertEqual({"status": "first"}, json.loads(path.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
