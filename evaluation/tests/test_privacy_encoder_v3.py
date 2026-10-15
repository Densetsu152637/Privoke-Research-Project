"""Synthetic EN3 arithmetic, full-gradient, resume and serialization regressions."""
from __future__ import annotations
import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import torch
from torch import nn
from safetensors.torch import load_file, save_file

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from privoke_eval import privacy_encoder_v3 as en


class Toy(nn.Module):
    """Small text-indexed encoder/pooler with native task-head dimensions."""
    def __init__(self, dropout=.1):
        super().__init__()
        self.encoder = nn.Module()
        self.encoder.embeddings = nn.Embedding(16, 8)
        self.encoder.encoder = nn.Module()
        self.encoder.encoder.layer = nn.ModuleList([nn.Linear(8, 8), nn.Linear(8, 8)])
        self.encoder.pooler = nn.Linear(8, 8)
        self.dropout = nn.Dropout(dropout)
        self.heads = nn.ParameterDict({task+"_"+part: nn.Parameter(torch.randn(shape)*.1)
                                      for task, labels in en.ph.LABELS.items()
                                      for part, shape in (("weight", (len(labels), 8)), ("bias", (len(labels),)))})
        self.device_name = "cpu"

    def forward(self, texts):
        x = self.encoder.embeddings(torch.tensor([int(t) % 16 for t in texts]))
        for layer in self.encoder.encoder.layer:
            x = self.dropout(torch.tanh(layer(x)))
        return en.ph.affine(torch.tanh(self.encoder.pooler(x)), self.heads)

    def predictions(self, texts):
        from src.classification import initialise_unpacked, Sensitivity, Visibility, Category
        with torch.no_grad():
            logits = self(texts)
        result = []
        for s, v, c in zip(logits["sensitivity"].softmax(-1), logits["visibility"].softmax(-1),
                           logits["category"].sigmoid()):
            value = initialise_unpacked(Sensitivity[en.ph.LABELS["sensitivity"][int(s.argmax())]],
                                        Visibility[en.ph.LABELS["visibility"][int(v.argmax())]],
                                        [Category[n] for n, x in zip(en.ph.LABELS["category"], c) if x >= .5])
            result.append((value, round(min(float(torch.cat([s, c]).max()), .999), 3)))
        return result


def rows(count=17):
    return [{"text": str(i), "classification": {"sensitivity": en.ph.LABELS["sensitivity"][i % 4],
            "visibility": en.ph.LABELS["visibility"][i % 6],
            "categories": [en.ph.LABELS["category"][i % 10]]}} for i in range(count)]


def small_policy():
    return dict(en.POLICY, effective_batch=8, microbatch=3, warmup_updates=2, total_updates=12)


class EncoderMechanics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        en.ph.configure_repository(Path(__file__).resolve().parents[2])
        cls.scratch = Path(__file__).resolve().parents[1]/"results/privacy_encoder_v3_20261013/tests/tmp"
        cls.scratch.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        torch.set_num_threads(1)
        torch.use_deterministic_algorithms(True)
        torch.manual_seed(19)
        np.random.seed(19)

    def test_scheduler_exact_update_convention(self):
        self.assertEqual(en.lr_scale(1), 1/98)
        self.assertEqual(en.lr_scale(98), 1)
        self.assertEqual(en.lr_scale(2940), 0)
        self.assertGreater(en.lr_scale(99), en.lr_scale(100))
        for invalid in (0, 2941, 1.5):
            with self.assertRaises(ValueError):
                en.lr_scale(invalid)

    def test_inherited_data_and_selected_pins_are_exact_hex(self):
        import re
        root = Path(__file__).resolve().parents[2]
        for pin in [en.DATA_PIN, *en.SELECTED_PINS.values()]:
            self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", pin))
        manifest = root/"evaluation/results/privacy_heads_v3_20261013/data/release-03/manifest.json"
        self.assertEqual(en.file_hash(manifest), en.DATA_PIN)
        for tier, pin in en.SELECTED_PINS.items():
            self.assertEqual(en.file_hash(root/f"models/experiments/privacy_heads_v3_20261013/exports/{tier}/selected/manifest.json"), pin)
        # A changed commitment must fail before loading any native model or payload.
        with patch.object(en, "configure", return_value=root), patch.object(en, "file_hash", return_value="0"*64):
            with self.assertRaisesRegex(ValueError, "Only admitted"):
                en.prepare(root, self.scratch/"unused", self.scratch/"unused-models", manifest)

    def test_optimizer_covers_all_and_decay_rules(self):
        model = Toy()
        optimizer = en.make_optimizer(model)
        seen = []
        for group in optimizer.param_groups:
            for name, p in zip(group["names"], group["params"]):
                seen.append(id(p))
                self.assertEqual(group["base_lr"], 1e-4 if name.startswith("heads.") else 2e-5)
                self.assertEqual(group["weight_decay"], .01 if p.ndim > 1 else 0.)
        self.assertEqual(len(seen), len(set(seen)))
        self.assertEqual(set(seen), {id(p) for p in model.parameters()})
        model.encoder.pooler.bias.requires_grad_(False)
        with self.assertRaises(ValueError):
            en.make_optimizer(model)

    def test_uneven_accumulation_matches_global_weighted_gradient(self):
        model = Toy(dropout=0)
        other = copy.deepcopy(model)
        data = rows()
        truth = en.ph.targets(data)
        weights = en.ph.class_weights(truth)
        texts = [r["text"] for r in data]
        en.backward_batch(model, texts, truth, weights, microbatch=3)
        sum(en.ph.loss_parts(other(texts), truth, weights).values()).backward()
        for a, b in zip(model.parameters(), other.parameters()):
            torch.testing.assert_close(a.grad, b.grad, atol=2e-8, rtol=2e-5)

    def test_full_gradient_and_each_group_changes(self):
        model = Toy()
        before = en.cpu_state(model)
        data = rows()
        work = en.train_epoch(model, en.make_optimizer(model), data,
                              en.ph.class_weights(en.ph.targets(data)), 1, policy=small_policy())
        proof = en.change_proof(before, model.state_dict())
        self.assertTrue(all(proof["groups_changed"].values()))
        self.assertIn("embeddings", proof["groups_changed"])
        self.assertIn("layer.1", proof["groups_changed"])
        self.assertIn("pooler", proof["groups_changed"])
        self.assertEqual(work["optimizer_steps"], 3)
        self.assertEqual(work["train_exposures"], 17)
        self.assertTrue(model.training)

    def test_missing_gradient_and_unchanged_group_fail_closed(self):
        model = Toy()
        with self.assertRaises(ValueError):
            en.gradient_proof(model)
        with self.assertRaises(ValueError):
            en.change_proof(en.cpu_state(model), model.state_dict())

    def test_validation_uneven_batches_global_objective(self):
        model = Toy()
        data = rows()
        weights = en.ph.class_weights(en.ph.targets(data))
        actual = en.validation_metrics(model, data, weights, batch=3)
        expected = sum(en.ph.loss_parts(model([r["text"] for r in data]), en.ph.targets(data), weights).values())
        self.assertAlmostEqual(actual["weighted_objective"], float(expected.detach()), places=6)
        self.assertFalse(model.training)

    def test_baseline_not_eligible_and_ties_keep_earliest(self):
        model = Toy()
        state = {"best_loss": float("inf"), "best_epoch": 0, "stale_epochs": 0}
        with self.assertRaises(ValueError):
            en.select(state, 1., 0, model)
        self.assertTrue(en.select(state, 8., 1, model))
        self.assertFalse(en.select(state, 8.-.00005, 2, model))
        self.assertEqual(state["best_epoch"], 1)
        self.assertTrue(en.select(state, 7., 3, model))
        self.assertEqual(state["stale_epochs"], 0)

    def test_atomic_checkpoint_resume_full_dropout_optimizer_rng(self):
        model = Toy()
        optimizer = en.make_optimizer(model)
        data = rows()
        weights = en.ph.class_weights(en.ph.targets(data))
        policy = small_policy()
        first = en.train_epoch(model, optimizer, data, weights, 1, policy=policy)
        state = {"identity": {"run": "test"}, "epoch": 1, "model": en.cpu_state(model),
                 "optimizer": copy.deepcopy(optimizer.state_dict()), "rng": en.rng_state(),
                 "scheduler": first["scheduler"]}
        with tempfile.TemporaryDirectory(dir=self.scratch) as temporary:
            directory = Path(temporary)
            digest = en.ph.save_checkpoint(directory, state)
            en.train_epoch(model, optimizer, data, weights, 2, first["updates"], policy)
            expected = en.cpu_state(model)
            expected_optimizer = optimizer.state_dict()
            restored = en.ph.restore_checkpoint(directory, {"run": "test"})
            replay = Toy()
            replay.load_state_dict(restored["model"])
            replay_optimizer = en.make_optimizer(replay)
            replay_optimizer.load_state_dict(restored["optimizer"])
            en.restore_rng(restored["rng"])
            en.train_epoch(replay, replay_optimizer, data, weights, 2, first["updates"], policy)
            for name, value in expected.items():
                self.assertTrue(torch.equal(value, replay.state_dict()[name]), name)
            for key, value in expected_optimizer["state"].items():
                for field, tensor in value.items():
                    self.assertTrue(torch.equal(tensor, replay_optimizer.state_dict()["state"][key][field]))
            with self.assertRaises(ValueError):
                en.ph.restore_checkpoint(directory, {"run": "changed"})
            (directory/(digest+".pt")).write_bytes(b"corrupt")
            with self.assertRaises(ValueError):
                en.ph.restore_checkpoint(directory, {"run": "test"})

    def test_pointer_failure_preserves_old_durable_checkpoint(self):
        with tempfile.TemporaryDirectory(dir=self.scratch) as temporary:
            directory = Path(temporary)
            en.ph.save_checkpoint(directory, {"identity": {}, "epoch": 1})
            old = (directory/"latest.json").read_bytes()
            with patch.object(en.ph, "atomic_write", side_effect=OSError("injected pointer failure")):
                with self.assertRaises(OSError):
                    en.ph.save_checkpoint(directory, {"identity": {}, "epoch": 2})
            self.assertEqual((directory/"latest.json").read_bytes(), old)
            self.assertEqual(en.ph.restore_checkpoint(directory, {})["epoch"], 1)

    def test_safetensors_full_state_and_value_parity(self):
        model = Toy().eval()
        other = Toy().eval()
        with tempfile.TemporaryDirectory(dir=self.scratch) as temporary:
            path = Path(temporary)/"model.safetensors"
            save_file(en.cpu_state(model), str(path))
            other.load_state_dict(load_file(str(path)), strict=True)
            self.assertEqual(en.parity(model, other, ["1", "2"])["max_abs_logit_error"], 0)
            with torch.no_grad():
                other.heads["category_bias"][0] += .3
            with self.assertRaises(ValueError):
                en.parity(model, other, ["1", "2"])

    def test_dropout_train_eval_transition(self):
        model = Toy()
        model.train()
        a = model(["1", "2"])["category"]
        b = model(["1", "2"])["category"]
        self.assertFalse(torch.equal(a, b))
        model.eval()
        self.assertTrue(torch.equal(model(["1"])["category"], model(["1"])["category"]))


if __name__ == "__main__":
    unittest.main()
