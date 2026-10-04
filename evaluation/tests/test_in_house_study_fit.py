"""Synthetic-only input and export checks for the isolated study fitter."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
for source in (ROOT / "evaluation", ROOT / "shared/python",
               ROOT / "extension/client-runtime", ROOT / "models"):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from privoke_eval import in_house_study_fit as fit
from privoke_eval.in_house_study_contract import training_budget


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _jsonl_row(index: int, *, prefix: bool, target=None, group=None, text=None, row_id=None) -> dict:
    value_text = text if text is not None else f"Synthetic prompt row {index:05d} unique marker."
    return {
        "id": row_id if row_id is not None else (f"original:{index}" if prefix else f"added:{index}"),
        "group_id": group if group is not None else (f"original:group:{index}" if prefix else f"added:group:{index}"),
        "text": value_text,
        "text_key": fit.training_text_key(value_text),
        "expected_has_pii": bool(index % 2) if target is None else target,
    }


def _line(row: dict) -> bytes:
    return json.dumps(row, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"


def _bundle(rows=None, *, arm="E-H", view_overrides=None):
    if rows is None:
        rows = [_jsonl_row(index, prefix=index < fit.ORIGINAL_ROWS)
                for index in range(fit.TRAINING_ROWS)]
    lines = [_line(row) for row in rows]
    train_bytes = b"".join(lines)
    prefix_bytes = sum(len(line) for line in lines[:fit.ORIGINAL_ROWS])
    fingerprint_map = {name: _sha(name.encode()) for name in ("efficient", "balanced", "quality")}
    common = {
        "schema_version": 1,
        "kind": fit.VIEW_KIND,
        "source_revision": "a" * 40,
        "programme_sha256": _sha(b"programme canonical"),
        "programme_input_raw_sha256": _sha(b"programme raw"),
        "prepared_manifest_raw_sha256": _sha(b"full prepared manifest raw"),
        "train_raw_sha256": _sha(train_bytes),
        "original_train_raw_sha256": _sha(b"".join(lines[:fit.ORIGINAL_ROWS])),
        "train_prefix_bytes": prefix_bytes,
        "trainer_contract_sha256": fit.trainer_contract_sha256(),
        "allocation_receipt_sha256": _sha(b"allocation receipt"),
        "reviewed_labels_receipt_sha256": _sha(b"reviewed labels receipt"),
        "row_count": fit.TRAINING_ROWS,
        "original_row_count": fit.ORIGINAL_ROWS,
        "addition_row_count": fit.ADDED_ROWS,
        "initialization_fingerprints": fingerprint_map,
    }
    if view_overrides:
        common.update(view_overrides)
    manifest_bytes = json.dumps(common, ensure_ascii=False, sort_keys=True,
                                separators=(",", ":"), allow_nan=False).encode("utf-8")
    expected_value = {
        "schema_version": 1,
        "kind": fit.INPUTS_KIND,
        "arm_key": arm,
        "programme_sha256": common["programme_sha256"],
        "programme_input_raw_sha256": common["programme_input_raw_sha256"],
        "prepared_manifest_raw_sha256": common["prepared_manifest_raw_sha256"],
        "training_view_manifest_raw_sha256": _sha(manifest_bytes),
        "train_raw_sha256": common["train_raw_sha256"],
        "original_train_raw_sha256": common["original_train_raw_sha256"],
        "train_prefix_bytes": prefix_bytes,
        "trainer_contract_sha256": common["trainer_contract_sha256"],
        "allocation_receipt_sha256": common["allocation_receipt_sha256"],
        "reviewed_labels_receipt_sha256": common["reviewed_labels_receipt_sha256"],
        "initialization_fingerprints": fingerprint_map,
        "source_revision": common["source_revision"],
        "actual_training_image_id": "sha256:" + "b" * 64,
        "dependency_lock_sha256": _sha(b"dependency lock"),
    }
    expected_bytes = json.dumps(expected_value, ensure_ascii=False, sort_keys=True,
                                separators=(",", ":"), allow_nan=False).encode("utf-8")
    expected = fit.parse_expected_inputs(
        expected_bytes, pinned_sha256=_sha(expected_bytes),
        expected_arm=arm, expected_revision="a" * 40,
    )
    return train_bytes, manifest_bytes, expected, expected_bytes


class InHouseStudyFitTests(unittest.TestCase):
    def test_fixed_budget_and_last_partial_batch_are_frozen(self):
        budget = training_budget(fit.TRAINING_ROWS)
        self.assertEqual((budget.steps_per_epoch, budget.epochs, budget.total_steps), (490, 5, 2450))
        for profile in ("efficient", "balanced", "quality"):
            first = fit.permutation_sha256(profile, 1, fit.TRAINING_ROWS)
            self.assertEqual(first, fit.permutation_sha256(profile, 1, fit.TRAINING_ROWS))
            batches = fit.epoch_batches(profile, 1, fit.TRAINING_ROWS)
            self.assertEqual(len(batches), 490)
            self.assertEqual([len(batch) for batch in batches[-2:]], [16, 8])
            flattened = [index for batch in batches for index in batch]
            self.assertEqual(sorted(flattened), list(range(fit.TRAINING_ROWS)))

    def test_closed_manifest_binds_exact_original_prefix_and_disjoint_additions(self):
        train_bytes, manifest_bytes, expected, _ = _bundle()
        result = fit.load_verified_training(train_bytes, manifest_bytes, expected)
        self.assertEqual(len(result.rows), 7832)
        self.assertEqual((result.original_count, result.added_count), (3832, 4000))
        self.assertEqual(result.positive_count + result.absent_count, 7832)
        self.assertEqual(result.raw_sha256, _sha(train_bytes))
        self.assertEqual(result.original_prefix_sha256, expected.original_train_raw_sha256)
        self.assertEqual(result.rows[0].row_id, "original:0")
        self.assertEqual(result.rows[-1].row_id, "added:7831")

    def test_train_hash_and_external_expected_inputs_digest_fail_before_json_decode(self):
        train_bytes, manifest_bytes, expected, expected_bytes = _bundle()
        with self.assertRaises(fit.StudyFitError):
            fit.parse_expected_inputs(expected_bytes, pinned_sha256="0" * 64,
                                      expected_arm=expected.arm_key,
                                      expected_revision=expected.source_revision)
        with self.assertRaises(fit.StudyFitError):
            fit.load_verified_training(train_bytes + b"tamper", manifest_bytes, expected)

    def test_malformed_label_duplicate_id_and_unexpected_manifest_fields_fail(self):
        rows = [_jsonl_row(index, prefix=index < fit.ORIGINAL_ROWS)
                for index in range(fit.TRAINING_ROWS)]
        rows[-1]["expected_has_pii"] = 1
        train_bytes, manifest_bytes, expected, _ = _bundle(rows)
        with self.assertRaisesRegex(fit.StudyFitError, "explicit booleans"):
            fit.load_verified_training(train_bytes, manifest_bytes, expected)

        rows = [_jsonl_row(index, prefix=index < fit.ORIGINAL_ROWS)
                for index in range(fit.TRAINING_ROWS)]
        rows[-1]["id"] = rows[0]["id"]
        train_bytes, manifest_bytes, expected, _ = _bundle(rows)
        with self.assertRaisesRegex(fit.StudyFitError, "duplicate row ID"):
            fit.load_verified_training(train_bytes, manifest_bytes, expected)

        train_bytes, manifest_bytes, expected, _ = _bundle(view_overrides={"test_file": "forbidden"})
        with self.assertRaisesRegex(fit.StudyFitError, "closed contract"):
            fit.load_verified_training(train_bytes, manifest_bytes, expected)

        train_bytes, manifest_bytes, expected, _ = _bundle(view_overrides={"schema_version": True})
        with self.assertRaisesRegex(fit.StudyFitError, "closed contract"):
            fit.load_verified_training(train_bytes, manifest_bytes, expected)

    def test_added_rows_cannot_reuse_original_component_or_normalized_text(self):
        rows = [_jsonl_row(index, prefix=index < fit.ORIGINAL_ROWS)
                for index in range(fit.TRAINING_ROWS)]
        rows[-1]["group_id"] = rows[0]["group_id"]
        train_bytes, manifest_bytes, expected, _ = _bundle(rows)
        with self.assertRaisesRegex(fit.StudyFitError, "overlap an original training component"):
            fit.load_verified_training(train_bytes, manifest_bytes, expected)

        rows = [_jsonl_row(index, prefix=index < fit.ORIGINAL_ROWS)
                for index in range(fit.TRAINING_ROWS)]
        rows[-1]["text"] = rows[0]["text"]
        rows[-1]["text_key"] = rows[0]["text_key"]
        train_bytes, manifest_bytes, expected, _ = _bundle(rows)
        with self.assertRaisesRegex(fit.StudyFitError, "duplicate normalized text"):
            fit.load_verified_training(train_bytes, manifest_bytes, expected)

    def test_private_s1_helper_uses_only_train_vocabulary_and_frozen_c1_threshold(self):
        _, _, expected, _ = _bundle(arm="S1")
        rows = tuple(
            fit.TrainingRow(
                row_id=f"synthetic:{index}", group_id=f"synthetic:group:{index}",
                text=(f"synthetic shared phrase token{index % 6} topic{index % 4}"),
                text_key=fit.training_text_key(
                    f"synthetic shared phrase token{index % 6} topic{index % 4}"
                ),
                target=bool(index % 2),
            )
            for index in range(48)
        )
        artifact, diagnostics = fit._fit_s1_model(rows, expected)
        self.assertEqual(artifact["model_id"], "privoke-presence-balanced")
        self.assertEqual(artifact["config"]["threshold"], 0.5)
        self.assertEqual(artifact["metadata"]["selected_C"], "1.0")
        word_vocabulary = artifact["config"]["branches"]["word"]["features"]
        self.assertFalse(any("heldoutonlytoken" in item for item in word_vocabulary))
        self.assertTrue(diagnostics["converged"])
        self.assertEqual(diagnostics["stored_threshold"], 0.5)
        self.assertNotIn("validation", diagnostics)

    def test_failed_run_keeps_sanitized_manifest_and_refuses_existing_output(self):
        train_bytes, manifest_bytes, expected, expected_bytes = _bundle()
        marker = "synthetic-private-marker-must-not-appear"
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            expected_path = base / "expected.json"
            expected_path.write_bytes(expected_bytes)
            output = base / "failed-run"
            with self.assertRaises(fit.StudyFitError):
                fit.run_fit(
                    arm_key=expected.arm_key, train_file=base / "not-read.jsonl",
                    training_manifest=base / "not-read-manifest.json",
                    expected_inputs_file=expected_path,
                    expected_inputs_sha256="0" * 64,
                    output=output, source_revision=expected.source_revision,
                )
            record = json.loads((output / "run-manifest.json").read_text("utf-8"))
            self.assertEqual(record["status"], "failed")
            self.assertEqual(record["research_data_rows_read"], 0)
            self.assertNotIn(marker, json.dumps(record))

            sentinel = base / "existing"
            sentinel.mkdir()
            (sentinel / "keep.txt").write_text("preserve", encoding="utf-8")
            with self.assertRaisesRegex(fit.StudyFitError, "fresh nonexistent"):
                fit.run_fit(
                    arm_key=expected.arm_key, train_file=base / "unused",
                    training_manifest=base / "unused-manifest",
                    expected_inputs_file=expected_path,
                    expected_inputs_sha256=_sha(expected_bytes),
                    output=sentinel, source_revision=expected.source_revision,
                )
            self.assertEqual((sentinel / "keep.txt").read_text("utf-8"), "preserve")

    def test_written_but_rejected_checkpoint_stays_in_failure_manifest(self):
        train_bytes, manifest_bytes, _, expected_bytes = _bundle(arm="S1")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            train = base / "train.jsonl"
            view = base / "training-manifest.json"
            expected_path = base / "expected.json"
            train.write_bytes(train_bytes)
            view.write_bytes(manifest_bytes)
            expected_path.write_bytes(expected_bytes)
            output = base / "failed-checkpoint"
            with mock.patch.object(fit, "_fit_s1", return_value=({"not": "an artifact"}, {})):
                with self.assertRaises(fit.StudyFitError):
                    fit.run_fit(
                        arm_key="S1", train_file=train, training_manifest=view,
                        expected_inputs_file=expected_path,
                        expected_inputs_sha256=_sha(expected_bytes),
                        output=output, source_revision="a" * 40,
                    )
            run = json.loads((output / "run-manifest.json").read_text("utf-8"))
            self.assertEqual(run["status"], "failed")
            self.assertEqual(run["checkpoint_records"], [])
            self.assertEqual(run["artifact_files_written"], [{
                "artifact_file": "checkpoint-epoch-00.json",
                "artifact_sha256": _sha((output / "checkpoint-epoch-00.json").read_bytes()),
                "validation_status": "pending",
            }])


if __name__ == "__main__":
    unittest.main()
