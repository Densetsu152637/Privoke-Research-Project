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
from privoke_model.v3_contract import parse, validate_policy, POLICY, validate_manifest, publication_passes, validate_execution, tensor_changes
from fuzzer_training import schedule, validate_schedule

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
        from privoke_contracts.classification import Classification
        from src.classification import ClassificationResult
        _, _, source = schedule(42, pilot_policy())
        before_rows = []
        for index, record in enumerate(source["guard_sidecar"]):
            truth = Classification(record["packed_target"])
            predicted = Classification(truth.pack() ^ 1) if index == 0 else truth
            action = ClassificationResult(predicted, "guard", "synthetic", confidence=.999).action()
            desired = ClassificationResult(truth, "guard", "synthetic", confidence=.999).action()
            before_rows.append({"target": truth.pack(), "prediction": predicted.pack(), "confidence": .999,
                "action": action.name, "target_action": desired.name, "action_value": action.value,
                "target_action_value": desired.value, "joint_correct": index != 0})
        after_rows = copy.deepcopy(before_rows)
        if gate:
            after_rows[0].update(prediction=after_rows[0]["target"], joint_correct=True,
                action=after_rows[0]["target_action"], action_value=after_rows[0]["target_action_value"])
        guard = lambda rows: {"rows": rows, "examples": 16, "joint_correct": sum(r["joint_correct"] for r in rows),
            "action_correct": sum(r["action"] == r["target_action"] for r in rows)}
        changed, changes = tensor_changes(parent["tensors"], inventory(state), 4)
        evidence = {"schema": 1, "model_id": parent["model_id"], "tier": "efficient", "policy": pilot_policy(),
            "layers": [4], "request_id": request_id, "scope": "heads", "base": self.base, "candidate_blob": digest(payload),
            "source_commitment": "1" * 64, "train_wire_sha256": "2" * 64, "guard_wire_sha256": "3" * 64,
            "phases": {k: {"layer": 4, "status": "ok", "examples": 128 if k == "training" else 16}
                       for k in ("training", "base_heldout", "candidate_heldout")},
            "counts": {"optimizer_steps": 2, "train_rows": 128, "microbatch_forward": 32, "microbatch_backward": 32,
                "encoder_block_forward": 128, "encoder_block_backward": 0},
            "block_counts": {"forward": [32] * 4, "backward": [0] * 4},
            "changes": changes, "changed_tensors": changed, "serialized_guard_parity": True,
            "losses": [1., 1.], "gradient_trace": [{"step": i + 1, "encoder_nonzero_gradients": 0, "norm_before_clip": 1.} for i in range(2)],
            "parameter_count": parent["parameter_count"], "trainable_count": 2580,
            "base_guard": guard(before_rows), "candidate_guard": guard(after_rows), "action_harms": 0}
        evidence.update(source=source, source_commitment=digest(canonical(source)),
            train_wire_sha256=source["train_wire_sha256"], guard_wire_sha256=source["guard_wire_sha256"])
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
    def altered_commit(self, mutate):
        request = self.candidate()
        manifest = self.store.manifest(request.candidate)
        evidence = parse(self.store.read(manifest["evidence"]))
        mutate(manifest, evidence)
        manifest["evidence"] = self.store.put(canonical(evidence))
        request.evidence = manifest["evidence"]
        request.candidate = self.store.put(canonical(manifest))
        return request
    def test_raw_manifest_and_checkpoint_cannot_bypass_admission(self):
        request = self.candidate()
        for payload in (self.store.read(request.candidate), (INITIAL / "model.safetensors").read_bytes()):
            with self.assertRaises((ValueError, UnicodeDecodeError)): self.store.stage(payload, b"")
    def test_commit_repeats_complete_admission(self):
        mutations = (
            lambda m, e: m.update(blob="0" * 64),
            lambda m, e: m.update(original="0" * 64),
            lambda m, e: e.update(candidate_blob="0" * 64),
            lambda m, e: e["counts"].update(train_rows=64),
            lambda m, e: e["candidate_guard"].update(joint_correct=0),
            lambda m, e: e.update(action_harms=1),
            lambda m, e: e.update(serialized_guard_parity=False),
            lambda m, e: e["block_counts"]["forward"].__setitem__(1, 0),
            lambda m, e: e["changes"].update(heads=2))
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                request = self.altered_commit(mutate)
                with self.assertRaises((ValueError, FileNotFoundError)): self.store.commit(request)
    def test_finalized_evidence_upload_only(self):
        request = self.candidate()
        payload = self.store.read(request.evidence)
        self.assertEqual(self.store.stage(payload, b""), digest(payload))

    def test_unknown_receipt_never_fabricates_applied(self):
        self.assertEqual(self.store.status("never-submitted")["status"], "unknown")

class ScheduleTests(unittest.TestCase):
    def test_all_three_seed_replays_and_actual_window_counts(self):
        for seed in (42, 43, 44):
            a, g, source = schedule(seed, POLICY)
            b, h, replay = schedule(seed, POLICY)
            self.assertEqual(a, b); self.assertEqual(g, h); self.assertEqual(source, replay)
            self.assertEqual(source["train_occurrences"], 512)
            self.assertEqual(source["original_occurrences"], 256)
            self.assertEqual(source["guard_occurrences"], 16)
            self.assertFalse(set(source["train_groups"]) & set(source["guard_groups"]))
    def test_forged_group_target_transform_and_wire_rejected(self):
        train, guard, source = schedule(42, pilot_policy())
        for key, value in (("group_id", "forged"), ("packed_target", 0), ("transform", "redact_email"), ("text", "forged")):
            altered = copy.deepcopy(source); altered["train_sidecar"][1][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_schedule(train, guard, altered, pilot_policy())
        train[0].target.packed ^= 1
        with self.assertRaises(ValueError): validate_schedule(train, guard, source, pilot_policy())


class AutogradTests(unittest.TestCase):
    def test_heads_full_serialized_parity_and_every_block(self):
        import torch
        from src.v3.model import PretrainedV3
        from src.v3.training import fit, assess
        torch.set_num_threads(4)
        manifest = parse((INITIAL / "manifest.json").read_bytes())
        from common import runtime_pb2
        from privoke_contracts.classification import initialise_unpacked, Sensitivity, Visibility, Category
        truth = initialise_unpacked(Sensitivity.S3, Visibility.P0, [Category.IDENTITY])
        def row(text):
            return runtime_pb2.RuntimeTrainingExample(text=text, has_target=True, weight=1,
                target=runtime_pb2.RuntimeClassification(**truth.to_dict(), packed=truth.pack()))
        for scope in (pb.HEADS, pb.FULL_ENCODER):
            model = PretrainedV3.load(manifest, INITIAL / "model.safetensors", INITIAL / "config.json", INITIAL / "vocab.txt")
            request = pb.FitRequest(request_id="synthetic-" + str(scope), model_id=manifest["model_id"],
                base=digest((INITIAL / "manifest.json").read_bytes()), scope=scope, layers=[4],
                source_commitment="1" * 64, train=[row("John Doe has a secret identity.") for _ in range(64)],
                guard=[row("Alex has a private record.") for _ in range(16)])
            evidence = fit(model, request, pilot_policy())
            scratch = INITIAL.parent.parent / "mechanics-tmp"
            with tempfile.TemporaryDirectory(dir=scratch) as temp:
                path = Path(temp) / "candidate.safetensors"; tensors = model.export(path)
                candidate = dict(manifest, parent=request.base, original=request.base, scope=evidence["scope"],
                    evidence="2" * 64, blob=digest(path.read_bytes()), tensors=tensors)
                reloaded = PretrainedV3.load(candidate, path, INITIAL / "config.json", INITIAL / "vocab.txt")
                self.assertEqual(assess(reloaded, list(request.guard)), evidence["candidate_guard"])
                evidence.update(candidate_blob=candidate["blob"], serialized_guard_parity=True)
                validate_execution(evidence)
            self.assertEqual(evidence["changes"]["encoder"] == 0, scope == pb.HEADS)
            self.assertTrue(all(n > 0 for n in evidence["changes"]["blocks"]) if scope == pb.FULL_ENCODER else not any(evidence["changes"]["blocks"]))

if __name__ == "__main__": unittest.main()
