"""AU3 orchestration boundaries and reused full-component mechanics, host only."""
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import torch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "evaluation"), str(Path(__file__).parent)]
from privoke_eval import audience_v3 as au
from test_privacy_encoder_v3 import Toy, rows


class AudienceTraining(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        au.en.ph.configure_repository(ROOT)
        cls.scratch = ROOT / "evaluation/results/audience_v3_20261013/tests/tmp"
        cls.scratch.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        torch.set_num_threads(1)
        torch.use_deterministic_algorithms(True)
        torch.manual_seed(42)

    def test_dynamic_schedule_residual_and_no_legacy_pin_change(self):
        policy = au.recipe(9360)
        self.assertEqual((policy["updates_per_epoch"], policy["warmup_updates"], policy["total_updates"]), (147, 147, 4410))
        self.assertEqual(9360 % policy["effective_batch"], 16)
        self.assertEqual(au.en.lr_scale(147, policy), 1)
        self.assertEqual(au.en.lr_scale(4410, policy), 0)
        self.assertEqual(au.en.POLICY["warmup_updates"], 98)
        self.assertNotEqual(au.PARENTS, au.en.SELECTED_PINS)

    def test_epoch_ancestry_selected_and_completed_are_separate(self):
        result = au.component_epochs("efficient", 3, 8)
        self.assertEqual(result["encoder"], {"inherited_selected": 19, "new_selected": 3, "new_completed": 8, "cumulative_selected": 22})
        self.assertEqual(result["heads"]["cumulative_selected"], 34)
        self.assertEqual(result["source_stages"]["EN3_completed_joint"], 24)
        self.assertIsNone(result["source_stages"]["official_pretraining_epochs"])
        self.assertEqual(au.component_epochs("quality", 2, 7)["heads"]["cumulative_selected"], 10)
        with self.assertRaises(ValueError):
            au.component_epochs("balanced", 0, 5)

    def test_real_parent_and_original_asset_pins_without_loading_models(self):
        au.en.ph.configure_repository(ROOT)
        for tier in au.TIERS:
            directory = ROOT / "models/experiments/privacy_encoder_v3_20261013/runs/cpu-01/exports" / tier / "selected"
            self.assertEqual(au.check_assets(directory, au.PARENTS[tier])["original"], au.ORIGINALS[tier])
            original = ROOT / "models/experiments/pretrained_v3_20261012/initials" / tier
            self.assertEqual(au.check_assets(original, au.ORIGINALS[tier], original=True)["scope"], "original")
        with self.assertRaises(ValueError):
            au.check_assets(directory, "0" * 64)

    def test_prepare_rejects_old_data_before_opening_rows_or_models(self):
        with patch.object(au.en, "configure", return_value=ROOT), patch.object(au, "file_hash", return_value="0" * 64), \
                patch.object(au.data, "validate_training_data") as loader, patch.object(au.en, "load_model") as model:
            with self.assertRaisesRegex(ValueError, "reviewed AU3"):
                au.prepare(ROOT, self.scratch, self.scratch, "old.json", "pending.json")
            loader.assert_not_called()
            model.assert_not_called()

    def test_accepted_data_review_does_not_substitute_for_pending_pilots(self):
        with tempfile.TemporaryDirectory(dir=self.scratch) as directory:
            path = Path(directory) / "acceptance.json"
            au.retain(path, {"status": "accepted", "study_id": au.STUDY_ID, "evidence_files": {}})
            with self.assertRaisesRegex(ValueError, "review/pilot"):
                au.retained_acceptance(path, {"study_id": au.STUDY_ID}, required_evidence=("normal_pilot", "v3_pilot"))
            proof = Path(directory) / "proof.json"
            au.retain(proof, {"actual": "pilot"})
            accepted = Path(directory) / "complete.json"
            au.retain(accepted, {"status": "accepted", "study_id": au.STUDY_ID,
                                 "evidence_files": {"normal_pilot": {"path": str(proof), "sha256": au.file_hash(proof)}}})
            au.retained_acceptance(accepted, {"study_id": au.STUDY_ID}, required_evidence=("normal_pilot",))
            proof.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "evidence bytes"):
                au.retained_acceptance(accepted, {"study_id": au.STUDY_ID}, required_evidence=("normal_pilot",))

    def test_au3_policy_full_groups_and_dropout_resume_equivalence(self):
        model = Toy()
        policy = dict(au.recipe(9360), effective_batch=8, microbatch=3)
        chosen = rows(17)
        weights = au.en.ph.class_weights(au.en.ph.targets(chosen))
        initial = au.en.cpu_state(model)
        optimizer = au.en.make_optimizer(model, policy)
        first = au.en.train_epoch(model, optimizer, chosen, weights, 1, policy=policy)
        self.assertEqual(first["optimizer_steps"], 3)
        self.assertTrue(all(au.en.change_proof(initial, model.state_dict())["groups_changed"].values()))
        state = {"identity": {"study_id": au.STUDY_ID}, "epoch": 1, "model": au.en.cpu_state(model),
                 "optimizer": copy.deepcopy(optimizer.state_dict()), "rng": au.cpu_rng_state(), "scheduler": first["scheduler"]}
        with tempfile.TemporaryDirectory(dir=self.scratch) as directory:
            au.en.ph.save_checkpoint(directory, state)
            au.en.train_epoch(model, optimizer, chosen, weights, 2, first["updates"], policy)
            expected = au.en.cpu_state(model)
            saved = au.en.ph.restore_checkpoint(directory, state["identity"])
            replay = Toy()
            replay.load_state_dict(saved["model"])
            replay_optimizer = au.en.make_optimizer(replay, policy)
            replay_optimizer.load_state_dict(saved["optimizer"])
            au.en.restore_rng(saved["rng"])
            au.en.train_epoch(replay, replay_optimizer, chosen, weights, 2, first["updates"], policy)
            self.assertTrue(all(torch.equal(v, replay.state_dict()[k]) for k, v in expected.items()))

    def test_cpu_rng_capture_never_initializes_cuda(self):
        with patch.object(torch.cuda, "is_available", side_effect=AssertionError("GPU probe forbidden")), \
                patch.object(torch.cuda, "get_rng_state_all", side_effect=AssertionError("GPU state forbidden")):
            state = au.cpu_rng_state()
            au.en.restore_rng(state)
            self.assertEqual(state["cuda"], [])

    def test_rng_validation_round_trip_preserves_auditor_and_rejects_incomplete(self):
        value = au.cpu_rng_state()
        torch.rand(3)
        before = au.cpu_rng_state()
        au.validate_cpu_rng(value)
        self.assertTrue(torch.equal(au.cpu_rng_state()["torch"], before["torch"]))
        for key in ("python", "numpy", "torch", "cuda"):
            bad = dict(value)
            del bad[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                au.validate_cpu_rng(bad)
        bad = dict(value, cuda=[torch.tensor([1])])
        with self.assertRaises(ValueError):
            au.validate_cpu_rng(bad)

    def test_optimizer_checkpoint_moments_and_group_binding_are_required(self):
        model = Toy()
        initial = copy.deepcopy(model)
        policy = dict(au.recipe(9360), effective_batch=8, microbatch=3, train_rows=17,
                      updates_per_epoch=3, warmup_updates=3, total_updates=15)
        chosen = rows(17)
        optimizer = au.en.make_optimizer(model, policy)
        work = au.en.train_epoch(model, optimizer, chosen, au.en.ph.class_weights(au.en.ph.targets(chosen)), 1, policy=policy)
        saved = {"identity": {"synthetic": True}, "epoch": 1, "optimizer_steps": 3, "train_exposures": 17,
                 "best_loss": 1., "best_epoch": 1, "best_model": au.en.cpu_state(model), "stale_epochs": 0,
                 "model": au.en.cpu_state(model), "optimizer": copy.deepcopy(optimizer.state_dict()), "rng": au.cpu_rng_state(),
                 "scheduler": work["scheduler"], "epoch_record": {}, "initial_checkpoint": "zero"}
        au.validate_checkpoint(saved, initial, policy, saved["identity"], 1, "zero")
        for mutation in ("moment", "group", "step", "missing_moment"):
            bad = copy.deepcopy(saved)
            state = next(iter(bad["optimizer"]["state"].values()))
            if mutation == "moment": state["exp_avg_sq"] = torch.tensor([float("nan")])
            if mutation == "group": bad["optimizer"]["param_groups"][0]["base_lr"] = 1.
            if mutation == "step": state["step"] = torch.tensor(2.)
            if mutation == "missing_moment": del state["exp_avg"]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                au.validate_checkpoint(bad, initial, policy, saved["identity"], 1, "zero")

    def test_actual_toy_controller_epoch_zero_and_epoch_one_resume_and_audit(self):
        policy = dict(au.recipe(9360), effective_batch=8, microbatch=3, train_rows=17,
                      updates_per_epoch=3, warmup_updates=3, total_updates=15, min_epochs=5, max_epochs=5)
        chosen = rows(17)
        with tempfile.TemporaryDirectory(dir=self.scratch) as directory:
            location = Path(directory)
            outputs = []
            for mode, stop in (("complete", None), ("epoch0", 1), ("epoch1", 2)):
                results, models = location / mode / "results", location / mode / "models"
                protocol = {"policy": policy, "source_closure": "synthetic", "threads": 4}
                binding = {"repository": str(ROOT), "models": str(models)}
                au.retain(results / "protocol.json", protocol)
                au.retain(results / "bindings.json", binding)
                probes = {}
                for tier in au.TIERS:
                    path = results / "probe" / (tier + ".json")
                    au.retain(path, {"identity": au.identity(results, protocol, tier), "status": "passed", "probe_acceptance_sha256": "accepted"})
                    probes[tier] = au.file_hash(path)
                au.retain(results / "prefit-acceptance.json", {"probe_sha256": probes})
                real_train_epoch = au.en.train_epoch
                def interrupt(*args, **kwargs):
                    if args[4] == stop:
                        raise RuntimeError("interrupted boundary")
                    return real_train_epoch(*args, **kwargs)
                with patch.object(au, "validate", return_value=(protocol, binding, chosen, chosen)), \
                        patch.object(au, "approval", return_value="accepted"), \
                        patch.object(au.en, "load_model", side_effect=lambda *a, **kw: ({}, Toy())):
                    if stop:
                        with patch.object(au.en, "train_epoch", side_effect=interrupt), patch("builtins.print"), self.assertRaisesRegex(RuntimeError, "interrupted"):
                            au.fit(results, "efficient")
                        latest = au.read(models / "cells/efficient/checkpoints/latest.json")
                        self.assertEqual(latest["epoch"], stop - 1)
                    with patch("builtins.print"):
                        summary = au.fit(results, "efficient", resume=bool(stop))
                    state = au.en.ph.restore_checkpoint(models / "cells/efficient/checkpoints", summary["identity"])
                    outputs.append(state["model"])
                    receipt = au.read(results / "fits/efficient/epoch-zero.json")
                    self.assertEqual(receipt["checkpoint"], state["initial_checkpoint"])
                    # Audit actual on-disk Toy checkpoints; only native export
                    # admission is replaced, so no CURRENT model is touched.
                    au.retain(results / "native-verification/efficient.json", {"synthetic": True})
                    au.retain(results / "exports/efficient.json", {"synthetic": True})
                    with patch.object(au, "verify_native", return_value={}), \
                            patch.object(au.en, "load_model", side_effect=lambda *a, **kw: self.initial_toy()):
                        audit = au.audit_training(results, "efficient")
                        self.assertEqual(audit["cpu_rng_boundaries_checked"], 6)
                        epoch_record_path = results / "fits/efficient/epochs/0001.json"
                        record = au.read(epoch_record_path)
                        saved = au.en.ph.load_torch(models / "cells/efficient/checkpoints" / (record["checkpoint"] + ".pt"))
                        del saved["rng"]
                        payload = au.en.ph.torch_bytes(saved)
                        invalid = au.digest(payload)
                        au.retain(models / "cells/efficient/checkpoints" / (invalid + ".pt"), payload)
                        record["checkpoint"] = invalid
                        epoch_record_path.write_bytes(au.canonical(record))
                        with self.assertRaisesRegex(ValueError, "checkpoint schema"):
                            au.audit_training(results, "efficient")
                        (results / "fits/efficient/epoch-zero.json").unlink()
                        with self.assertRaises(FileNotFoundError):
                            au.audit_training(results, "efficient")
            self.assertTrue(all(torch.equal(outputs[0][k], state[k]) for state in outputs[1:] for k in outputs[0]))

    @staticmethod
    def initial_toy():
        # configure() seeds42 immediately before each actual fit's initial load.
        previous = au.cpu_rng_state()
        try:
            torch.manual_seed(42)
            return {}, Toy()
        finally:
            au.en.restore_rng(previous)

    def test_only_finite_trained_new_validation_selection(self):
        model = Toy()
        policy = au.recipe(9360)
        state = {"best_loss": float("inf"), "best_epoch": 0, "stale_epochs": 0}
        for epoch, loss in ((0, 1.), (1, float("nan"))):
            with self.assertRaises(ValueError):
                au.en.select(state, loss, epoch, model, policy)
        self.assertTrue(au.en.select(state, 2., 1, model, policy))
        self.assertFalse(au.en.select(state, 2. - .00005, 2, model, policy))
        self.assertEqual(state["best_epoch"], 1)

    def test_controller_failure_classifies_fresh_access(self):
        spec = importlib.util.spec_from_file_location("au3_controller", ROOT / "evaluation/run-audience-v3.py")
        controller = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(controller)
        from privoke_eval import audience_v3_comparison as comparison
        for action, owner, function, extra, possible in (
                ("prepare", au, "prepare", ["--admission", "pending.json"], False),
                ("audit-test", comparison, "audit", [], True)):
            with patch.object(owner, function, side_effect=ValueError("injected")), patch.object(au, "retain") as retained:
                with self.assertRaises(ValueError):
                    controller.main([action, "--results", str(self.scratch), *extra])
                self.assertEqual(retained.call_args.args[1]["fresh_access"], None if possible else False)


if __name__ == "__main__":
    unittest.main()
