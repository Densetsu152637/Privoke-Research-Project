"""Host-only v3 mechanics; synthetic receipts are not quality evidence."""
from __future__ import annotations
import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "services/pretrained-v3/src"), str(ROOT / "shared/python"), str(ROOT / "extension/client-runtime")]
from common import pb, canonical, digest
from checkpoint_store import CheckpointStore
from checkpoint_server import CheckpointServer
from privoke_model.v3_contract import parse, validate_policy, POLICY, validate_manifest, publication_passes
from fuzzer_training import schedule

INITIAL = ROOT / "models/experiments/pretrained_v3_20261012/initials/efficient"

def pilot_policy(): return dict(POLICY, steps=2, window_batches=1, epochs=2)

class ContractTests(unittest.TestCase):
    def test_duplicate_and_noncanonical_json_rejected(self):
        for raw in (b'{"x":1,"x":2}\n', b'{ "x":1}\n', b'{"x":NaN}\n'):
            with self.assertRaises(ValueError): parse(raw)
    def test_policy_exact_work_budget(self):
        validate_policy(pilot_policy(), pilot=True)
        for mutation in ({"weight_decay": .01}, {"steps": 3}, {"microbatch": 8}, {"dropout": True}):
            with self.assertRaises(ValueError): validate_policy(dict(pilot_policy(), **mutation), pilot=True)
    def test_all_originals_complete_and_zero(self):
        import torch
        from safetensors.torch import load_file
        for tier in ("efficient", "balanced", "quality"):
            path = INITIAL.parent / tier
            manifest = validate_manifest(parse((path / "manifest.json").read_bytes()))
            state = load_file(str(path / "model.safetensors"))
            self.assertEqual(sum(t.numel() for t in state.values()), manifest["parameter_count"])
            self.assertTrue(all(torch.count_nonzero(v) == 0 for k, v in state.items() if k.startswith("heads.")))
    def test_strict_encoder_keys_and_no_random_initialization(self):
        import torch
        import json
        from safetensors.torch import load_file
        from src.v3.model import native_encoder
        state = {k.removeprefix("encoder."): v for k, v in load_file(str(INITIAL / "model.safetensors")).items() if k.startswith("encoder.")}
        state.pop("pooler.dense.bias")
        rng = torch.get_rng_state().clone()
        with self.assertRaises(RuntimeError): native_encoder(json.loads((INITIAL / "config.json").read_text()), state)
        self.assertTrue(torch.equal(rng, torch.get_rng_state()))
    def test_native_context_boundary(self):
        from src.v3.model import PretrainedV3
        manifest = parse((INITIAL / "manifest.json").read_bytes())
        model = PretrainedV3.load(manifest, INITIAL / "model.safetensors", INITIAL / "config.json", INITIAL / "vocab.txt")
        self.assertEqual(model.tokenize(["hello " * 510])["input_ids"].shape[1], 512)
        with self.assertRaises(ValueError): model.tokenize(["hello " * 511])
    def test_fuzzer_common_stream_is_scope_independent_and_group_disjoint(self):
        a, ga, sa = schedule(42, pilot_policy())
        b, gb, sb = schedule(42, pilot_policy())
        self.assertEqual(canonical(sa), canonical(sb)); self.assertEqual(a, b); self.assertEqual(ga, gb)
        self.assertEqual(len(a), 64); self.assertEqual(len(ga), 16)
        self.assertFalse(set(sa["train_groups"]) & set(sa["guard_groups"]))

class StoreTests(unittest.TestCase):
    def setUp(self):
        scratch = INITIAL.parent.parent / "mechanics-tmp"; scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.store = CheckpointStore(self.temp.name, INITIAL)
        self.base = self.store.resolve("privoke-v3-efficient")
    def tearDown(self):
        self.store.db.close(); self.temp.cleanup()
    def candidate(self, request_id="mechanics", gate=True):
        import torch
        from safetensors.torch import load_file, save
        parent = self.store.manifest(self.base)
        state = load_file(str(INITIAL / "model.safetensors")); state["heads.sensitivity_bias"][0] = .001
        payload = save(state)
        from src.v3.model import inventory
        evidence = {"layers": [4], "request_id": request_id, "scope": "heads", "base": self.base, "candidate_blob": digest(payload),
            "phases": {k: {"layer": 4, "status": "ok", "examples": 1} for k in ("training", "base_heldout", "candidate_heldout")},
            "changes": {"heads": 1, "encoder": 0}, "changed_tensors": ["heads.sensitivity_bias"],
            "base_guard": {"joint_correct": 0}, "candidate_guard": {"joint_correct": int(gate)}, "action_harms": 0}
        esha = self.store.put(canonical(evidence))
        manifest = dict(parent, parent=self.base, original=self.base, blob=digest(payload), scope="heads", evidence=esha, tensors=inventory(state))
        sha = self.store.stage(payload, canonical(manifest))
        return pb.Commit(request_id=request_id, model_id=parent["model_id"], expected_base=self.base, candidate=sha, evidence=esha)
    def test_atomic_commit_exact_replay_and_restart(self):
        request = self.candidate(); first = self.store.commit(request)
        self.assertEqual(first["status"], "applied"); self.assertEqual(self.store.commit(request), first)
        self.store.db.close(); self.store = CheckpointStore(self.temp.name)
        self.assertEqual(self.store.status(request.request_id), first)
        self.assertEqual(self.store.resolve(request.model_id), request.candidate)
    def test_id_reuse_with_different_content_rejected(self):
        request = self.candidate(); self.store.commit(request)
        request.evidence = "0" * 64
        with self.assertRaises(ValueError): self.store.commit(request)
    def test_stale_base_and_guard_rejection_keep_terminal_candidate(self):
        rejected = self.candidate("reject", gate=False)
        self.assertEqual(self.store.commit(rejected)["reason"], "guard_rejected")
        self.assertEqual(self.store.resolve(rejected.model_id), self.base)
        self.assertEqual(self.store.manifest(rejected.candidate)["scope"], "heads")
        first = self.candidate("first"); stale = self.candidate("stale")
        self.store.commit(first)
        self.assertEqual(self.store.commit(stale)["reason"], "stale_base")
    def test_incomplete_out_of_order_upload_rejected(self):
        server = CheckpointServer(self.store)
        for parts in ([pb.Chunk(sha256="0" * 64, total_bytes=2, offset=1, data=b"a")],
                      [pb.Chunk(sha256=digest(b"ab"), total_bytes=2, offset=0, data=b"a")]):
            with self.assertRaises(ValueError): server.StageCheckpoint(iter(parts), None)
    def test_unknown_receipt_never_fabricates_applied(self):
        self.assertEqual(self.store.status("never-submitted")["status"], "unknown")

if __name__ == "__main__": unittest.main()
