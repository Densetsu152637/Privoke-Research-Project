"""Synthetic-only input and export checks for the isolated study fitter."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

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


class _ScheduleOnlyTrainer:
    """Synthetic no-optimizer backend for exercising the real fixed schedule."""
    def __init__(self, profile, mode, initialization_sha256, *, fail_at=None):
        self.config = {"profile": profile, "training_mode": mode, "max_tokens": 64}
        self.initialization_sha256 = initialization_sha256
        self.model_id = f"privoke-scratch-presence-{profile}-{mode}"
        self._step_count = 0
        self.fail_at = fail_at
        self.batch_sizes = []
        self.batch_target_counts = []
        self.seen_batches = []

    @property
    def successful_steps(self):
        return self._step_count

    def tensor_batch(self, texts):
        ids = fit.torch.zeros((len(texts), 1), dtype=fit.torch.long)
        mask = fit.torch.ones((len(texts), 1), dtype=fit.torch.bool)
        return ids, mask

    def step(self, texts, targets):
        self.batch_sizes.append(len(texts))
        self.batch_target_counts.append(sum(bool(value) for value in targets))
        self.seen_batches.append(tuple(texts))
        if self.fail_at is not None and self._step_count + 1 == self.fail_at:
            raise ValueError("synthetic step failure")
        self._step_count += 1
        return SimpleNamespace(loss=0.5, gradient_norm_before_clip=0.25)

    def build_artifact(self, *, checkpoint_epoch, **_kwargs):
        return {
            "schema_version": 1, "model_id": self.model_id,
            "version": f"v1.0.0+epoch.{checkpoint_epoch}",
            "generated_at_unix": 1, "checksum": "c" * 64,
            "synthetic_only": True,
        }


class InHouseStudyFitTests(unittest.TestCase):
    def test_public_cli_help_imports_without_pythonpath(self):
        script = ROOT / "evaluation/fit-in-house-study-arm.py"
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONHOME", None)
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                [sys.executable, str(script), "--help"], cwd=temporary,
                env=env, capture_output=True, text=True, encoding="utf-8", timeout=20,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--expected-inputs-sha256", result.stdout)
        self.assertEqual(result.stderr, "")

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

    @unittest.skipUnless(fit._private_output_supported(), "requires POSIX dirfd output support")
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

    @unittest.skipUnless(fit._private_output_supported(), "requires POSIX dirfd output support")
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

    def test_private_output_fails_closed_when_descriptor_operations_are_unavailable(self):
        if fit._private_output_supported():
            self.skipTest("host supports the required POSIX held-directory operations")
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(fit.StudyFitError, "POSIX held-directory"):
                fit._FreshOutput(Path(temporary) / "output")

    def _run_schedule_only_arm(self, *, fail_step=None, fail_export=False):
        train_bytes, view_bytes, _, expected_bytes = _bundle(arm="E-H")
        expected = fit.parse_expected_inputs(
            expected_bytes, pinned_sha256=_sha(expected_bytes),
            expected_arm="E-H", expected_revision="a" * 40,
        )
        trainers = {}

        def create(profile):
            init = expected.initialization_fingerprints[profile]
            head = _ScheduleOnlyTrainer(profile, "head_only", init, fail_at=fail_step)
            full = _ScheduleOnlyTrainer(profile, "end_to_end", init)
            trainers["head"] = head
            trainers["full"] = full
            return head, full

        def check_export(_trainer, _artifact):
            if fail_export:
                raise fit.StudyFitError("synthetic export rejection")
            return {"parameter_fingerprint": "d" * 64, "synthetic_check": True}

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            train = base / "train.jsonl"
            view = base / "training-manifest.json"
            expected_path = base / "expected.json"
            train.write_bytes(train_bytes)
            view.write_bytes(view_bytes)
            expected_path.write_bytes(expected_bytes)
            output = base / "run"
            artifact_evidence = ()
            with (mock.patch.object(fit.scratch_mechanics, "create_paired_trainers", create),
                  mock.patch.object(fit, "_check_scratch_export", check_export)):
                try:
                    result = fit.run_fit(
                        arm_key="E-H", train_file=train, training_manifest=view,
                        expected_inputs_file=expected_path,
                        expected_inputs_sha256=_sha(expected_bytes), output=output,
                        source_revision="a" * 40,
                    )
                except fit.StudyFitError:
                    result = json.loads((output / "run-manifest.json").read_text("utf-8"))
            artifact_evidence = tuple(
                (output / item["artifact_file"]).is_file()
                and _sha((output / item["artifact_file"]).read_bytes()) == item["artifact_sha256"]
                for item in result.get("artifact_files_written", [])
            )
            return result, trainers, artifact_evidence

    @unittest.skipUnless(fit._private_output_supported(), "requires POSIX dirfd output support")
    def test_run_fit_executes_all_fixed_scratch_steps_batches_and_checkpoints(self):
        result, trainers, _output = self._run_schedule_only_arm()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["checkpoint_count"], 5)
        self.assertEqual([item["epoch"] for item in result["checkpoint_records"]], [1, 2, 3, 4, 5])
        self.assertTrue(all(item["steps"] == 490 and item["examples"] == 7832
                            for item in result["checkpoint_records"]))
        trainer = trainers["head"]
        self.assertEqual(trainer.successful_steps, 2450)
        self.assertEqual(len(trainer.batch_sizes), 2450)
        self.assertEqual(sum(trainer.batch_sizes), 39160)
        for epoch in range(5):
            self.assertEqual(trainer.batch_sizes[epoch * 490:(epoch + 1) * 490][-1], 8)
            epoch_texts = [text for batch in trainer.seen_batches[epoch * 490:(epoch + 1) * 490]
                           for text in batch]
            self.assertEqual(len(epoch_texts), fit.TRAINING_ROWS)
            self.assertEqual(set(epoch_texts), {
                f"Synthetic prompt row {index:05d} unique marker."
                for index in range(fit.TRAINING_ROWS)
            })
        self.assertEqual([item["permutation_sha256"] for item in result["checkpoint_records"]], [
            fit.permutation_sha256("efficient", epoch, fit.TRAINING_ROWS)
            for epoch in range(1, 6)
        ])

    @unittest.skipUnless(fit._private_output_supported(), "requires POSIX dirfd output support")
    def test_midstep_and_export_failures_never_mark_scratch_arm_complete(self):
        midstep, _trainers, _ = self._run_schedule_only_arm(fail_step=3)
        self.assertEqual(midstep["status"], "failed")
        self.assertEqual(midstep["checkpoint_records"], [])
        self.assertEqual(midstep["artifact_files_written"], [])
        exported, _trainers, artifact_evidence = self._run_schedule_only_arm(fail_export=True)
        self.assertEqual(exported["status"], "failed")
        self.assertEqual(exported["checkpoint_records"], [])
        self.assertEqual(len(exported["artifact_files_written"]), 1)
        self.assertEqual(exported["artifact_files_written"][0]["validation_status"], "pending")
        self.assertEqual(artifact_evidence, (True,))

    @unittest.skipUnless(fit._private_output_supported(), "requires POSIX dirfd output support")
    def test_held_output_writer_detects_directory_replacement_without_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            output = base / "output"
            store = fit._FreshOutput(output)
            moved = base / "moved-output"
            try:
                output.rename(moved)
                output.mkdir(mode=0o700)
                with self.assertRaises(fit.StudyFitError):
                    store.write_exclusive("should-not-escape.bin", b"synthetic")
                self.assertFalse((output / "should-not-escape.bin").exists())
                self.assertFalse((moved / "should-not-escape.bin").exists())
            finally:
                store.close()

    @unittest.skipUnless(fit._private_output_supported(), "requires POSIX dirfd output support")
    def test_held_output_writer_detects_parent_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            parent = base / "parent"
            parent.mkdir()
            output = parent / "output"
            store = fit._FreshOutput(output)
            moved_parent = base / "moved-parent"
            try:
                parent.rename(moved_parent)
                parent.mkdir()
                with self.assertRaises(fit.StudyFitError):
                    store.write_exclusive("escape.bin", b"synthetic")
                self.assertFalse((parent / "output" / "escape.bin").exists())
                self.assertFalse((moved_parent / "output" / "escape.bin").exists())
            finally:
                store.close()

    @unittest.skipUnless(fit._private_output_supported(), "requires POSIX dirfd output support")
    def test_output_writer_checks_file_identity_mode_and_content_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            store = fit._FreshOutput(output)
            try:
                digest = store.write_exclusive("checkpoint.bin", b"synthetic checkpoint")
                info = (output / "checkpoint.bin").stat()
                self.assertEqual(info.st_mode & 0o077, 0)
                self.assertEqual(digest, _sha(b"synthetic checkpoint"))
                store.write_manifest({"schema_version": 1, "status": "synthetic"})
                store.verify_written_files()
                (output / "checkpoint.bin").chmod(0o644)
                with self.assertRaises(fit.StudyFitError):
                    store.verify_written_files()
                (output / "checkpoint.bin").chmod(0o600)
                (output / "checkpoint.bin").unlink()
                (output / "checkpoint.bin").write_bytes(b"substituted")
                with self.assertRaises(fit.StudyFitError):
                    store.verify_written_files()
            finally:
                store.close()

    @unittest.skipUnless(fit._private_output_supported(), "requires POSIX dirfd output support")
    def test_output_writer_rejects_symlinked_artifact_entry(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            output = base / "output"
            store = fit._FreshOutput(output)
            try:
                store.write_exclusive("checkpoint.bin", b"synthetic")
                outside = base / "outside.bin"
                outside.write_bytes(b"outside")
                (output / "checkpoint.bin").unlink()
                (output / "checkpoint.bin").symlink_to(outside)
                with self.assertRaises(fit.StudyFitError):
                    store.verify_written_files()
                self.assertEqual(outside.read_bytes(), b"outside")
            finally:
                store.close()

    @unittest.skipUnless(fit._private_output_supported(), "requires POSIX dirfd output support")
    def test_output_writer_rejects_replaced_manifest_entry(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            output = base / "output"
            store = fit._FreshOutput(output)
            try:
                store.write_manifest({"schema_version": 1, "status": "synthetic"})
                outside = base / "outside.json"
                outside.write_bytes(b"synthetic")
                (output / "run-manifest.json").unlink()
                (output / "run-manifest.json").symlink_to(outside)
                with self.assertRaises(fit.StudyFitError):
                    store.write_manifest({"schema_version": 1, "status": "replacement"})
                self.assertEqual(outside.read_bytes(), b"synthetic")
            finally:
                store.close()

    def test_raw_logit_and_runtime_probability_parity_include_saturation(self):
        from privoke_eval.in_house_presence_training import create_paired_trainers
        from privoke_eval.in_house_study_contract import PIN_ITEMS
        _, _, expected, _ = _bundle(arm="E-H")
        for bias_value in (31.0, -31.0, 0.0):
            trainer = create_paired_trainers("efficient")[0]
            with fit.torch.no_grad():
                trainer._parameters["head.presence.weight"].zero_()
                trainer._parameters["head.presence.bias"].fill_(bias_value)
            trainer._step_count = 490  # synthetic export metadata only; no optimization is run
            artifact = trainer.build_artifact(
                source_revision=expected.source_revision,
                study_plan_sha256=dict(PIN_ITEMS)["plan"],
                prepared_manifest_sha256=expected.prepared_manifest_raw_sha256,
                trainer_contract_sha256=expected.trainer_contract_sha256,
                checkpoint_epoch=1, generated_at_unix=1,
            )
            diagnostics = fit._check_scratch_export(trainer, artifact)
            self.assertEqual(diagnostics["raw_logit_max_abs_error"], 0.0)
            self.assertEqual(diagnostics["runtime_probability_max_abs_error"], 0.0)
            self.assertEqual(diagnostics["parity_probe_rows"], len(fit._PARITY_TEXTS))

    def test_finite_head_parameters_with_overflowing_raw_logits_are_rejected(self):
        from privoke_eval.in_house_presence_training import create_paired_trainers
        from privoke_eval.in_house_study_contract import PIN_ITEMS
        _, _, expected, _ = _bundle(arm="E-H")
        trainer = create_paired_trainers("efficient")[0]
        empty_pool = trainer.numpy_encoder().encode(fit.normalize_text(""))
        weight = fit.np.sign(empty_pool).astype(fit.np.float32) * fit.np.float32(1e38)
        with fit.torch.no_grad():
            trainer._parameters["head.presence.weight"].copy_(
                fit.torch.from_numpy(weight.reshape(-1, 1))
            )
            trainer._parameters["head.presence.bias"].zero_()
        self.assertTrue(all(fit.torch.isfinite(value).all()
                            for value in trainer._parameters.values()))
        trainer._step_count = 490  # synthetic export metadata only; no optimization is run
        artifact = trainer.build_artifact(
            source_revision=expected.source_revision,
            study_plan_sha256=dict(PIN_ITEMS)["plan"],
            prepared_manifest_sha256=expected.prepared_manifest_raw_sha256,
            trainer_contract_sha256=expected.trainer_contract_sha256,
            checkpoint_epoch=1, generated_at_unix=1,
        )
        with self.assertRaises(fit.StudyFitError):
            fit._check_scratch_export(trainer, artifact)

    @unittest.skipUnless(fit._private_output_supported(), "requires POSIX dirfd output support")
    def test_deadline_crossed_by_final_complete_manifest_is_recorded_failed(self):
        train_bytes, view_bytes, _, expected_bytes = _bundle(arm="S1")
        expected = fit.parse_expected_inputs(
            expected_bytes, pinned_sha256=_sha(expected_bytes),
            expected_arm="S1", expected_revision="a" * 40,
        )
        sample_rows = tuple(
            fit.TrainingRow(
                row_id=f"synthetic:{index}", group_id=f"synthetic:{index}",
                text=f"synthetic shared tokens class{index % 2} topic{index % 3}",
                text_key=fit.training_text_key(
                    f"synthetic shared tokens class{index % 2} topic{index % 3}"
                ), target=bool(index % 2),
            ) for index in range(48)
        )
        artifact, diagnostics = fit._fit_s1_model(sample_rows, expected)
        clock = [0.0]
        write_manifest = fit._FreshOutput.write_manifest

        def cross_deadline_on_complete(store, manifest):
            digest = write_manifest(store, manifest)
            if manifest.get("status") == "complete":
                clock[0] = fit.MAX_WALL_SECONDS + 1
            return digest

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            train = base / "train.jsonl"
            view = base / "training-manifest.json"
            expected_path = base / "expected.json"
            train.write_bytes(train_bytes)
            view.write_bytes(view_bytes)
            expected_path.write_bytes(expected_bytes)
            output = base / "deadline-run"
            with (mock.patch.object(fit, "_fit_s1", return_value=(artifact, diagnostics)),
                  mock.patch.object(fit.time, "monotonic", side_effect=lambda: clock[0]),
                  mock.patch.object(fit._FreshOutput, "write_manifest", cross_deadline_on_complete)):
                with self.assertRaisesRegex(
                    fit.StudyFitError,
                    r"Study fit failed in phase s1_train_only_fit \(StudyFitError\)\.",
                ):
                    fit.run_fit(
                        arm_key="S1", train_file=train, training_manifest=view,
                        expected_inputs_file=expected_path,
                        expected_inputs_sha256=_sha(expected_bytes),
                        output=output, source_revision="a" * 40,
                    )
            record = json.loads((output / "run-manifest.json").read_text("utf-8"))
            self.assertEqual(record["status"], "failed")
            self.assertEqual(record["phase"], "s1_train_only_fit")
            self.assertEqual(record["artifact_files_written"][0]["validation_status"], "validated")


if __name__ == "__main__":
    unittest.main()
