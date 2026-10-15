"""Mutable model migration, crash recovery and learned-weight retention."""
import copy
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "shared/python"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from bootstrap import bootstrap_model, PREPARATION_CODE_REVISION
from receipts import UpdateReceipts
from privoke_model.artifact import artifact_checksum, load_artifact, write_artifact_atomic
from privoke_model.contextual_training import prepare_full_encoder_artifact


class ModelBootstrapTests(unittest.TestCase):
    def test_wrong_selected_id_does_not_import_foreign_receipt_or_change_model(self):
        before = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "selected model ID"):
            bootstrap_model(self.path, self.audit, "privoke-quality")
        self.assertEqual(self.path.read_bytes(), before)
        with UpdateReceipts(self.audit) as receipts:
            self.assertIsNone(receipts.get("receipt-key"))

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "model.json"
        self.audit = Path(self.temporary.name) / "updates.jsonl"
        self.original = json.loads((ROOT / "models/privoke-balanced.json").read_text())
        # Represent an existing online update, not merely the shipped weights.
        self.original["parameters"]["head.sensitivity.bias"]["values"][0] += .002
        self.original["parameters"]["position_embedding"]["values"][0] += .003
        self.original["version"] = "v0.3.0+train.9"
        self.receipt = {"key": "receipt-key", "model_id": self.original["model_id"],
                        "base_version": "v0.3.0+train.8", "applied_version": self.original["version"],
                        "payload_digest": "a"*64, "request_fingerprint": "b"*64, "prompts_generated": 32}
        self.original["metadata"]["last_update_receipt"] = json.dumps(self.receipt)
        self.persist(self.original)
        self.original = load_artifact(self.path)

    def persist(self, artifact):
        artifact["checksum"] = artifact_checksum({k:v for k,v in artifact.items() if k != "checksum"})
        write_artifact_atomic(self.path, artifact)

    def migrate(self, **kwargs):
        return bootstrap_model(self.path, self.audit, "privoke-balanced", **kwargs)

    def test_current_learned_prefix_and_other_weights_preserved_restart_reuses_exact_bytes(self):
        prepared = self.migrate()
        self.assertEqual(prepared["config"]["max_tokens"], 256)
        for name, tensor in self.original["parameters"].items():
            self.assertEqual(prepared["parameters"][name]["values"][:len(tensor["values"])], tensor["values"])
        self.assertEqual(prepared["metadata"]["preparation_base_checksum"], self.original["checksum"])
        self.assertEqual(prepared["metadata"]["preparation_source_revision"], PREPARATION_CODE_REVISION)
        with UpdateReceipts(self.audit) as receipts:
            self.assertEqual(receipts.get("receipt-key"), self.receipt)
        before = self.path.read_bytes()
        self.assertEqual(self.migrate(), prepared)
        self.assertEqual(before, self.path.read_bytes())

    def test_crashes_at_each_boundary_recover_without_reset_or_lost_receipt(self):
        for boundary in ("after_checkpoint", "before_prepare", "before_publish", "after_publish"):
            with self.subTest(boundary=boundary):
                self.persist(copy.deepcopy(self.original))
                # Clear the DB only by using a different owned temporary audit.
                self.audit = Path(self.temporary.name) / (boundary + ".jsonl")
                before = self.path.read_bytes()
                def fail(phase):
                    if phase == boundary:
                        raise RuntimeError("simulated crash")
                with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                    self.migrate(checkpoint_hook=fail)
                if boundary != "after_publish":
                    self.assertEqual(self.path.read_bytes(), before)
                with UpdateReceipts(self.audit) as receipts:
                    self.assertEqual(receipts.get("receipt-key"), self.receipt)
                result = self.migrate()
                self.assertEqual(result["metadata"]["preparation_base_checksum"], self.original["checksum"])

    def test_checkpoint_boundary_reloads_actual_changed_model_and_binds_that_checksum(self):
        changed = copy.deepcopy(self.original)
        changed["parameters"]["head.sensitivity.bias"]["values"][1] += .004
        self.persist(changed)
        changed = load_artifact(self.path)
        self.persist(copy.deepcopy(self.original))
        def between(phase):
            if phase == "after_checkpoint":
                self.persist(changed)
        prepared = self.migrate(checkpoint_hook=between)
        self.assertEqual(prepared["metadata"]["preparation_base_checksum"], changed["checksum"])
        self.assertEqual(prepared["parameters"]["head.sensitivity.bias"]["values"], changed["parameters"]["head.sensitivity.bias"]["values"])

    def test_existing_larger_context_is_never_shrunk(self):
        source = copy.deepcopy(self.original)
        source["metadata"].pop("last_update_receipt")
        source["checksum"] = artifact_checksum({k:v for k,v in source.items() if k != "checksum"})
        full = prepare_full_encoder_artifact(source, version="v0.4.0.ctx512", generated_at_unix=1,
                    source_revision=PREPARATION_CODE_REVISION, max_tokens=512)
        self.persist(full)
        before = self.path.read_bytes()
        self.assertEqual(self.migrate()["config"]["max_tokens"], 512)
        self.assertEqual(self.path.read_bytes(), before)

    def test_fresh_shipped_input_is_supported_without_modifying_repository(self):
        source = json.loads((ROOT / "models/privoke-balanced.json").read_text())
        self.persist(source)
        self.assertEqual(self.migrate()["metadata"]["preparation_base_checksum"], source["checksum"])
