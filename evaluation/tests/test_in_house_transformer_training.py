"""Synthetic autograd checks; missing Torch is an error, never a skipped pass."""
from pathlib import Path
import sys
import unittest
from dataclasses import replace

ROOT = Path(__file__).resolve().parents[2]
for path in (ROOT / "evaluation", ROOT / "shared/python", ROOT / "extension/client-runtime", ROOT / "models"):
    sys.path.insert(0, str(path))

import numpy as np
import torch
from generate_baseline import initial_parameters, SENSITIVITIES, VISIBILITIES, CATEGORIES
from src.model import ModelConfig, TinyTransformerModel
from src.detection.preprocessing import normalize_text
from privoke_eval.in_house_transformer_training import (
    ContextualTarget, InHouseTransformerTrainer, TrainingOptions,
)

TEXTS = ("Synthetic alpha contact and payment words.", "Benign synthetic weather discussion.")
TARGETS = (ContextualTarget("S2", "P3", ("FINANCIAL",)), ContextualTarget("S0", "PU", ()))


def fixture(layers=2):
    config = ModelConfig(64, 8, 16, 16, SENSITIVITIES, VISIBILITIES, CATEGORIES,
                         num_layers=layers, num_attention_heads=2)
    return config, initial_parameters(config, np.random.default_rng(73))


def runtime(config, arrays):
    return TinyTransformerModel(config, {n: a.ravel() for n, a in arrays.items()},
                                {n: a.shape for n, a in arrays.items()}, device="cpu")


class InHouseTransformerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        torch.set_num_threads(1)

    def test_numpy_logits_padding_empty_unicode_and_single_layer_parity(self):
        texts = ("", "Ｓｙｎｔｈｅｔｉｃ [at] example.test 🧪", "Short", "word " * 40)
        for layers in (1, 2):
            config, arrays = fixture(layers)
            # Fresh nonzero heads exercise the encoder logits parity directly.
            rng = np.random.default_rng(19)
            for name in arrays:
                if name.startswith("head.") and name.endswith("weight"):
                    arrays[name] = rng.normal(0, .1, arrays[name].shape).astype(np.float32)
            trainer = InHouseTransformerTrainer(config, arrays)
            reference = runtime(config, arrays)
            ids, mask = trainer.tensor_batch(texts)
            actual = trainer.logits(ids, mask)
            for index, text in enumerate(texts):
                pooled = reference.encode(normalize_text(text))
                for head in ("sensitivity", "visibility", "category"):
                    expected = pooled @ arrays[f"head.{head}.weight"] + arrays[f"head.{head}.bias"]
                    np.testing.assert_allclose(actual[head][index].detach().numpy(), expected, atol=2e-6, rtol=2e-5)
                    single = trainer.logits(*trainer.tensor_batch((text,)))[head][0]
                    torch.testing.assert_close(actual[head][index], single, atol=2e-6, rtol=2e-5)
            self.assertTrue(mask[:, 0].all())
            self.assertEqual(ids[0].tolist(), [0] * ids.shape[1])
            self.assertEqual(int(mask[0].sum()), 1)

    def test_nonhead_gradients_and_changes_after_zero_head_warmup(self):
        config, arrays = fixture()
        before = {n: a.copy() for n, a in arrays.items()}
        trainer = InHouseTransformerTrainer(config, arrays)
        # Scratch generator has zero head weights, so first-step backbone
        # gradients legitimately vanish. A second step must reach the encoder.
        trainer.step(TEXTS, TARGETS)
        loss, grads = trainer.gradients(TEXTS, TARGETS)
        self.assertTrue(np.isfinite(loss))
        for name, grad in grads.items():
            self.assertTrue(torch.isfinite(grad).all())
            self.assertGreater(float(grad.abs().max()), 0, name)
        self.assertGreater(float(grads["token_embedding"][0].abs().max()), 0)
        after_warmup = trainer.export_parameters()
        trainer.step(TEXTS, TARGETS)
        after = trainer.export_parameters()
        for name in arrays:
            self.assertFalse(np.array_equal(after[name], after_warmup[name]), name)
            np.testing.assert_array_equal(arrays[name], before[name])

    def test_selected_autograd_entries_match_central_finite_differences(self):
        config, arrays = fixture()
        trainer = InHouseTransformerTrainer(config, arrays)
        trainer.step(TEXTS, TARGETS)
        _, grads = trainer.gradients(TEXTS, TARGETS)
        ids, mask = trainer.tensor_batch(TEXTS)
        for name in ("token_embedding", "layers.0.ffn.input.weight", "head.category.weight"):
            parameter = trainer.parameters[name]
            flat_index = int(grads[name].abs().argmax())
            index = np.unravel_index(flat_index, tuple(parameter.shape))
            old = float(parameter[index].detach())
            eps = .002
            with torch.no_grad():
                parameter[index] = old + eps
            plus = float(trainer.loss(ids, mask, TARGETS).detach())
            with torch.no_grad():
                parameter[index] = old - eps
            minus = float(trainer.loss(ids, mask, TARGETS).detach())
            with torch.no_grad():
                parameter[index] = old
            finite = (plus - minus) / (2 * eps)
            analytical = float(grads[name][index])
            self.assertAlmostEqual(finite, analytical, delta=max(.0008, abs(analytical) * .08))

    def test_head_only_scope_and_actual_loss_decline(self):
        config, arrays = fixture()
        trainer = InHouseTransformerTrainer(config, arrays, TrainingOptions(mode="head_only", learning_rate=.03, weight_decay=0))
        initial = float(trainer.loss(*trainer.tensor_batch(TEXTS), TARGETS).detach())
        for _ in range(25):
            trainer.step(TEXTS, TARGETS)
        final = float(trainer.loss(*trainer.tensor_batch(TEXTS), TARGETS).detach())
        self.assertLess(final, initial * .8)
        after = trainer.export_parameters()
        for name in arrays:
            if not name.startswith("head."):
                np.testing.assert_array_equal(after[name], arrays[name])
        self.assertTrue(any(not np.array_equal(after[n], arrays[n]) for n in arrays if n.startswith("head.")))

    def test_optimizer_and_export_copies_do_not_cross_arm_boundaries(self):
        config, arrays = fixture()
        first = InHouseTransformerTrainer(config, arrays)
        second = InHouseTransformerTrainer(config, arrays)
        first.step(TEXTS, TARGETS)
        self.assertTrue(first.optimizer_state()["state"])
        self.assertEqual(second.optimizer_state()["state"], {})
        for name, array in arrays.items():
            np.testing.assert_array_equal(second.export_parameters()[name], array)
        state = first.optimizer_state()
        next(iter(state["state"].values()))["exp_avg"].fill_(999)
        self.assertFalse(any((v["exp_avg"] == 999).all() for v in first.optimizer_state()["state"].values()))
        exported = first.export_parameters()
        exported["token_embedding"].fill(999)
        self.assertFalse((first.parameters["token_embedding"] == 999).all())

    def test_float32_export_reload_probabilities(self):
        config, arrays = fixture()
        trainer = InHouseTransformerTrainer(config, arrays)
        for _ in range(3):
            trainer.step(TEXTS, TARGETS)
        exported = trainer.export_parameters()
        self.assertTrue(all(a.dtype == np.float32 for a in exported.values()))
        # JSON-compatible numeric lists roundtrip through the legacy loader.
        import json
        payload = {"config": __import__("dataclasses").asdict(config), "parameters": {
            name: {"shape": list(a.shape), "values": a.ravel().tolist()} for name, a in exported.items()}}
        loaded = TinyTransformerModel.from_artifact(json.loads(json.dumps(payload)))
        logits = trainer.logits(*trainer.tensor_batch(TEXTS))
        for index, text in enumerate(TEXTS):
            prediction = loaded.predict(normalize_text(text))
            np.testing.assert_allclose(torch.softmax(logits["sensitivity"], -1)[index].detach().numpy(), prediction.sensitivity_probabilities, atol=2e-6)
            np.testing.assert_allclose(torch.sigmoid(logits["category"])[index].detach().numpy(), prediction.category_probabilities, atol=2e-6)

    def test_gradient_norm_clipping_is_effective(self):
        config, arrays = fixture()
        trainer = InHouseTransformerTrainer(config, arrays, TrainingOptions(max_gradient_norm=.0001))
        result = trainer.step(TEXTS, TARGETS)
        self.assertGreater(result["gradient_norm_before_clip"], .0001)
        clipped = torch.linalg.vector_norm(torch.stack([torch.linalg.vector_norm(p.grad) for p in trainer.parameters.values() if p.requires_grad]))
        self.assertLessEqual(float(clipped), .0001001)

    def test_invalid_targets_and_nonfinite_tensors_fail_without_update(self):
        config, arrays = fixture()
        trainer = InHouseTransformerTrainer(config, arrays)
        before = trainer.export_parameters()
        for targets in ((None, TARGETS[1]), (replace(TARGETS[0], sensitivity="present"), TARGETS[1]),
                        (replace(TARGETS[0], categories=("FINANCIAL", "FINANCIAL")), TARGETS[1])):
            with self.assertRaises(ValueError):
                trainer.step(TEXTS, targets)
        for name in before:
            np.testing.assert_array_equal(before[name], trainer.export_parameters()[name])
        arrays["token_embedding"][0, 0] = np.nan
        with self.assertRaises(ValueError):
            InHouseTransformerTrainer(config, arrays)
        with torch.no_grad():
            trainer.parameters["token_embedding"][0, 0] = float("nan")
        with self.assertRaises(ValueError):
            trainer.step(TEXTS, TARGETS)

    def test_optimizer_failure_restores_parameters_and_state(self):
        config, arrays = fixture()
        trainer = InHouseTransformerTrainer(config, arrays)
        before = trainer.export_parameters()
        def failure():
            with torch.no_grad():
                trainer.parameters["head.sensitivity.bias"].fill_(123)
            raise RuntimeError("synthetic optimizer failure")
        trainer._optimizer.step = failure
        with self.assertRaisesRegex(RuntimeError, "synthetic optimizer failure"):
            trainer.step(TEXTS, TARGETS)
        for name in before:
            np.testing.assert_array_equal(before[name], trainer.export_parameters()[name])
        self.assertEqual(trainer.optimizer_state()["state"], {})

    def test_invalid_padding_and_training_options_rejected(self):
        config, arrays = fixture()
        trainer = InHouseTransformerTrainer(config, arrays)
        ids, mask = trainer.tensor_batch(("short", "longer synthetic words"))
        mask[0, 0] = False
        with self.assertRaises(ValueError):
            trainer.logits(ids, mask)
        for options in (TrainingOptions(mode="binary"), TrainingOptions(learning_rate=float("nan")), TrainingOptions(max_gradient_norm=0)):
            with self.assertRaises(ValueError):
                InHouseTransformerTrainer(config, arrays, options)
        with self.assertRaises(ValueError):
            trainer.tensor_batch(["synthetic"] * 33)


if __name__ == "__main__":
    unittest.main()
