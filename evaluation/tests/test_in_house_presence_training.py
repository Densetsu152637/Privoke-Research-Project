"""Synthetic-only mechanics for the offline scratch presence trainer."""
from __future__ import annotations

import copy
import math
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SHARED_ROOT = Path(os.environ.get("PRIVOKE_SHARED_SOURCE_ROOT", ROOT / "shared/python"))
RUNTIME_ROOT = Path(os.environ.get("PRIVOKE_RUNTIME_SOURCE_ROOT", ROOT / "extension/client-runtime"))
for source_root in (ROOT / "evaluation", SHARED_ROOT, RUNTIME_ROOT, ROOT / "models"):
    if str(source_root) in sys.path:
        sys.path.remove(str(source_root))
    sys.path.insert(0, str(source_root))

import numpy as np
import torch

from generate_baseline import CATEGORIES, SENSITIVITIES, VISIBILITIES, initial_parameters
# generate_baseline deliberately prioritizes its own checkout's imports. Only
# the explicit cross-worktree host check needs module reloading; integrated
# Docker runs use one source tree and never purge test-process module state.
if SHARED_ROOT.resolve() != (ROOT / "shared/python").resolve() or RUNTIME_ROOT.resolve() != (ROOT / "extension/client-runtime").resolve():
    for module_name in tuple(sys.modules):
        if module_name == "privoke_model" or module_name.startswith("privoke_model."):
            del sys.modules[module_name]
        elif module_name == "src" or module_name.startswith("src."):
            del sys.modules[module_name]
    for source_root in (ROOT / "shared/python", ROOT / "extension/client-runtime"):
        if str(source_root) in sys.path:
            sys.path.remove(str(source_root))
    for source_root in (SHARED_ROOT, RUNTIME_ROOT):
        if str(source_root) in sys.path:
            sys.path.remove(str(source_root))
        sys.path.insert(0, str(source_root))

from privoke_model.artifact import artifact_checksum, validate_artifact
from privoke_model.fingerprint import parameter_fingerprint
from privoke_model.scratch_presence import (
    SCRATCH_PROFILES,
    scratch_presence_tensor_shapes,
    scratch_presence_trainable_names,
    validate_scratch_presence_config,
)
from privoke_model.training_data import training_text_key
from src.detection.preprocessing import normalize_text
from src.model import ModelConfig, _sigmoid
from src.transformer_encoder import EncoderConfig, NumpyTransformerEncoder, token_ids
from privoke_eval.in_house_presence_training import (
    MAX_GRAD_NORM,
    ScratchPresenceTrainer,
    create_paired_trainers,
    presence_config,
)


TEXTS = (
    "",
    "Ｓｙｎｔｈｅｔｉｃ Ａｌｉｃｅ [at] example.test 🧪",
    "Fictional weather over a sample region.",
    "Payment token is synthetic; no real account information.",
)
TARGETS = (False, True, False, True)


def _legacy_config(config):
    return ModelConfig(
        vocab_size=config["vocab_size"],
        hidden_size=config["hidden_size"],
        intermediate_size=config["intermediate_size"],
        max_tokens=config["max_tokens"],
        sensitivity_labels=SENSITIVITIES,
        visibility_labels=VISIBILITIES,
        category_labels=CATEGORIES,
        category_threshold=0.5,
        num_layers=config["num_layers"],
        num_attention_heads=config["num_attention_heads"],
    )


def _exported_arrays(payload):
    return {
        name: np.asarray(tensor["values"], dtype=np.float32).reshape(tensor["shape"])
        for name, tensor in payload["parameters"].items()
    }


def _numpy_probability(payload, text):
    """Compute the serialized model through the shared NumPy runtime encoder."""
    config = payload["config"]
    arrays = _exported_arrays(payload)
    encoder_config = EncoderConfig.from_mapping(config)
    encoder = NumpyTransformerEncoder(
        encoder_config,
        {name: array for name, array in arrays.items() if not name.startswith("head.")},
    )
    pooled = encoder.encode(normalize_text(text))
    logit = (pooled @ arrays["head.presence.weight"] + arrays["head.presence.bias"])[0]
    return float(_sigmoid(np.asarray([logit], dtype=np.float32))[0])


def _assert_optimizer_state_equal(test, left, right):
    test.assertEqual(set(left), set(right))
    for key in left:
        if isinstance(left[key], dict):
            _assert_optimizer_state_equal(test, left[key], right[key])
        elif isinstance(left[key], (tuple, list)):
            test.assertEqual(len(left[key]), len(right[key]))
            for left_item, right_item in zip(left[key], right[key], strict=True):
                if isinstance(left_item, dict):
                    _assert_optimizer_state_equal(test, left_item, right_item)
                else:
                    test.assertEqual(left_item, right_item)
        elif isinstance(left[key], torch.Tensor):
            torch.testing.assert_close(left[key], right[key], equal_nan=True, rtol=0, atol=0)
        elif isinstance(left[key], (int, float, str, bool)) or left[key] is None:
            test.assertEqual(left[key], right[key])
        else:
            test.assertEqual(type(left[key]), type(right[key]))


class ScratchPresenceTrainingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        torch.set_num_threads(1)

    def test_closed_profile_config_and_strict_targets(self):
        for profile in SCRATCH_PROFILES:
            for mode in ("head_only", "end_to_end"):
                config = presence_config(profile, mode)
                self.assertEqual(validate_scratch_presence_config(config), config)
        config = presence_config("efficient", "head_only")
        head, _ = create_paired_trainers("efficient")
        ids, mask = head.tensor_batch(("synthetic", "synthetic weather"))
        for bad in ((1, False), (None, True), (np.bool_(True), False), ("present", False)):
            with self.assertRaises(ValueError):
                head.loss(ids, mask, bad)
        bad_config = dict(config)
        bad_config["threshold"] = 0.6
        with self.assertRaises(ValueError):
            ScratchPresenceTrainer(bad_config, head.export_parameters())
        bad_config = dict(config)
        bad_config["sensitivity_labels"] = ["S0"]
        with self.assertRaises(ValueError):
            validate_scratch_presence_config(bad_config)

    def test_exact_original_initializer_and_paired_clone_independence(self):
        for profile in SCRATCH_PROFILES:
            with self.subTest(profile=profile):
                config = presence_config(profile, "end_to_end")
                rng = np.random.default_rng(12102026)
                original = initial_parameters(_legacy_config(config), rng)
                expected_head = rng.normal(0.0, 0.08, (config["hidden_size"], 1)).astype(np.float32)
                head, full = create_paired_trainers(profile)
                head_arrays, full_arrays = head.export_parameters(), full.export_parameters()
                self.assertEqual(head.initialization_sha256, full.initialization_sha256)
                for name, value in original.items():
                    if name.startswith("head."):
                        self.assertNotIn(name, head_arrays)
                    else:
                        np.testing.assert_array_equal(head_arrays[name], value)
                        np.testing.assert_array_equal(full_arrays[name], value)
                np.testing.assert_array_equal(head_arrays["head.presence.weight"], expected_head)
                np.testing.assert_array_equal(head_arrays["head.presence.weight"], full_arrays["head.presence.weight"])
                np.testing.assert_array_equal(head_arrays["head.presence.bias"], np.zeros(1, dtype=np.float32))
                for name in head.parameters:
                    self.assertNotEqual(head.parameters[name].data_ptr(), full.parameters[name].data_ptr())
                self.assertIsNot(head._optimizer, full._optimizer)
                self.assertEqual(
                    {name for name, value in head.parameters.items() if value.requires_grad},
                    set(scratch_presence_trainable_names(head.config)),
                )
                self.assertEqual(
                    {name for name, value in full.parameters.items() if value.requires_grad},
                    set(scratch_presence_trainable_names(full.config)),
                )
                self.assertEqual(head.optimizer_state()["state"], {})
                self.assertEqual(full.optimizer_state()["state"], {})

    def test_numpy_runtime_encoder_and_torch_logits_parity_all_profiles(self):
        for profile in SCRATCH_PROFILES:
            for mode in ("head_only", "end_to_end"):
                with self.subTest(profile=profile, mode=mode):
                    trainer = create_paired_trainers(profile)[0 if mode == "head_only" else 1]
                    ids, mask = trainer.tensor_batch(TEXTS)
                    logits = trainer.logits(ids, mask).detach().cpu().numpy()
                    arrays = trainer.export_parameters()
                    encoder_config = EncoderConfig.from_mapping(trainer.config)
                    encoder = NumpyTransformerEncoder(
                        encoder_config,
                        {name: value for name, value in arrays.items() if not name.startswith("head.")},
                    )
                    for row, text in enumerate(TEXTS):
                        normalized = normalize_text(text)
                        independently_tokenized = token_ids(normalized, encoder_config)
                        self.assertEqual(independently_tokenized[0], 0)
                        expected = encoder.encode(normalized) @ arrays["head.presence.weight"]
                        expected = expected + arrays["head.presence.bias"]
                        np.testing.assert_allclose(logits[row], expected, atol=2e-6, rtol=2e-5)

                    padded_ids = ids.numpy()
                    padded_mask = mask.numpy()
                    self.assertTrue(padded_mask[:, 0].all())
                    self.assertTrue(np.all(padded_ids[~padded_mask] == 0))
                    batch_pooled = encoder.encode_tokens(padded_ids, padded_mask)
                    for row, text in enumerate(TEXTS):
                        np.testing.assert_allclose(
                            batch_pooled[row], encoder.encode(normalize_text(text)), atol=2e-6, rtol=2e-5
                        )

    def test_full_encoder_gradients_reach_every_tensor_and_match_finite_differences(self):
        for profile in SCRATCH_PROFILES:
            with self.subTest(profile=profile):
                trainer = create_paired_trainers(profile)[1]
                loss, gradients = trainer.gradients(TEXTS, TARGETS)
                self.assertTrue(math.isfinite(loss))
                expected = set(scratch_presence_tensor_shapes(trainer.config))
                for name in expected:
                    self.assertIn(name, gradients)
                    self.assertTrue(torch.isfinite(gradients[name]).all(), name)
                    self.assertGreater(float(gradients[name].abs().max()), 0.0, name)

                _, finite_gradients = trainer.gradients(TEXTS[:2], TARGETS[:2])
                ids, mask = trainer.tensor_batch(TEXTS[:2])
                targets = TARGETS[:2]
                for name in (
                    "token_embedding",
                    "position_embedding",
                    "layers.0.attention.query.weight",
                    "layers.0.ffn.input.weight",
                    "head.presence.weight",
                ):
                    if name not in finite_gradients:
                        continue
                    parameter = trainer.parameters[name]
                    flat_index = int(finite_gradients[name].abs().argmax())
                    index = np.unravel_index(flat_index, tuple(parameter.shape))
                    original = float(parameter[index].detach())
                    epsilon = 0.002
                    with torch.no_grad():
                        parameter[index] = original + epsilon
                    plus = float(trainer.loss(ids, mask, targets).detach())
                    with torch.no_grad():
                        parameter[index] = original - epsilon
                    minus = float(trainer.loss(ids, mask, targets).detach())
                    with torch.no_grad():
                        parameter[index] = original
                    numerical = (plus - minus) / (2 * epsilon)
                    analytical = float(finite_gradients[name][index])
                    self.assertAlmostEqual(numerical, analytical, delta=max(0.001, abs(analytical) * 0.08))

    def test_head_only_freeze_clip_and_independent_arm_state(self):
        head, full = create_paired_trainers("efficient")
        head_before = head.export_parameters()
        full_before = full.export_parameters()
        head_metrics = head.step(TEXTS, TARGETS)
        full_metrics = full.step(TEXTS, TARGETS)
        self.assertGreaterEqual(head_metrics.loss, 0.0)
        self.assertGreaterEqual(full_metrics.loss, 0.0)
        self.assertEqual(head.successful_steps, 1)
        self.assertEqual(full.successful_steps, 1)
        head_after = head.export_parameters()
        full_after = full.export_parameters()
        for name in head_before:
            if name.startswith("head.presence."):
                self.assertFalse(np.array_equal(head_before[name], head_after[name]), name)
            else:
                self.assertEqual(head_before[name].tobytes(), head_after[name].tobytes(), name)
            self.assertTrue(np.isfinite(full_after[name]).all(), name)
        self.assertTrue(head.optimizer_state()["state"])
        self.assertTrue(full.optimizer_state()["state"])
        head_norm = torch.sqrt(sum(
            torch.sum(parameter.grad.detach() ** 2)
            for parameter in head.parameters.values()
            if parameter.requires_grad and parameter.grad is not None
        ))
        self.assertLessEqual(float(head_norm), MAX_GRAD_NORM + 1e-6)
        self.assertFalse(any(parameter.requires_grad for name, parameter in head.parameters.items()
                             if not name.startswith("head.presence.")))
        full_encoder_changed = any(
            not np.array_equal(full_before[name], full_after[name])
            for name in full_before if not name.startswith("head.presence.")
        )
        self.assertTrue(full_encoder_changed)

    def test_optimizer_parameter_and_populated_state_rollback(self):
        trainer = create_paired_trainers("efficient")[1]
        trainer.step(TEXTS, TARGETS)
        before_parameters = trainer.export_parameters()
        before_state = trainer.optimizer_state()
        original_step = trainer._optimizer.step

        def corrupt_optimizer_state(*args, **kwargs):
            result = original_step(*args, **kwargs)
            state = next(iter(trainer._optimizer.state.values()))
            state["exp_avg"].fill_(float("nan"))
            return result

        trainer._optimizer.step = corrupt_optimizer_state
        with self.assertRaisesRegex(ValueError, "non-finite state"):
            trainer.step(TEXTS, TARGETS)
        for name, old in before_parameters.items():
            self.assertEqual(old.tobytes(), trainer.export_parameters()[name].tobytes(), name)
        _assert_optimizer_state_equal(self, before_state, trainer.optimizer_state())

    def test_existing_nonfinite_optimizer_state_rejects_without_mutation(self):
        trainer = create_paired_trainers("efficient")[1]
        trainer.step(TEXTS, TARGETS)
        state = next(iter(trainer._optimizer.state.values()))
        state["exp_avg_sq"].view(-1)[0] = float("inf")
        before_parameters = {
            name: parameter.detach().cpu().numpy().copy()
            for name, parameter in trainer.parameters.items()
        }
        before_state = trainer.optimizer_state()
        with self.assertRaisesRegex(ValueError, "Existing optimizer state"):
            trainer.step(TEXTS, TARGETS)
        for name, old in before_parameters.items():
            self.assertEqual(old.tobytes(), trainer.parameters[name].detach().cpu().numpy().tobytes(), name)
        _assert_optimizer_state_equal(self, before_state, trainer.optimizer_state())

    def test_optimizer_exception_and_nonfinite_parameter_rollback(self):
        trainer = create_paired_trainers("efficient")[1]
        trainer.step(TEXTS, TARGETS)
        before_parameters = trainer.export_parameters()
        before_state = trainer.optimizer_state()
        selected = trainer.parameters["head.presence.bias"]

        def raise_after_partial_mutation(*args, **kwargs):
            with torch.no_grad():
                selected.fill_(123.0)
                state = trainer._optimizer.state[selected]
                state["exp_avg"].fill_(77.0)
            raise RuntimeError("synthetic optimizer failure")

        trainer._optimizer.step = raise_after_partial_mutation
        with self.assertRaisesRegex(RuntimeError, "synthetic optimizer failure"):
            trainer.step(TEXTS, TARGETS)
        for name, old in before_parameters.items():
            self.assertEqual(old.tobytes(), trainer.export_parameters()[name].tobytes(), name)
        _assert_optimizer_state_equal(self, before_state, trainer.optimizer_state())

        nonfinite = create_paired_trainers("efficient")[1]
        nonfinite.step(TEXTS, TARGETS)
        before_parameters = nonfinite.export_parameters()
        before_state = nonfinite.optimizer_state()
        original_step = nonfinite._optimizer.step

        def write_nonfinite_parameter(*args, **kwargs):
            result = original_step(*args, **kwargs)
            with torch.no_grad():
                nonfinite.parameters["head.presence.weight"].view(-1)[0] = float("inf")
            return result

        nonfinite._optimizer.step = write_nonfinite_parameter
        with self.assertRaisesRegex(ValueError, "non-finite parameters"):
            nonfinite.step(TEXTS, TARGETS)
        for name, old in before_parameters.items():
            self.assertEqual(old.tobytes(), nonfinite.export_parameters()[name].tobytes(), name)
        _assert_optimizer_state_equal(self, before_state, nonfinite.optimizer_state())

    def test_export_checksum_float32_fingerprint_and_runtime_probability_thresholds(self):
        trainer = create_paired_trainers("balanced")[1]
        trainer.step(TEXTS, TARGETS)
        payload = trainer.build_artifact(
            source_revision="1" * 40,
            study_plan_sha256="2" * 64,
            prepared_manifest_sha256="3" * 64,
            trainer_contract_sha256="4" * 64,
            checkpoint_epoch=1,
            generated_at_unix=1_800_000_000,
        )
        validate_artifact(payload)
        self.assertEqual(payload["checksum"], artifact_checksum({key: value for key, value in payload.items() if key != "checksum"}))
        arrays = _exported_arrays(payload)
        expected_shapes = scratch_presence_tensor_shapes(payload["config"])
        self.assertEqual(set(arrays), set(expected_shapes))
        self.assertTrue(all(value.dtype == np.float32 for value in arrays.values()))
        self.assertEqual(
            parameter_fingerprint(
                {name: array.ravel().tolist() for name, array in arrays.items()},
                expected_shapes,
            ),
            parameter_fingerprint(
                {name: np.asarray(tensor["values"], dtype=np.float32).ravel().tolist()
                 for name, tensor in payload["parameters"].items()},
                {name: tensor["shape"] for name, tensor in payload["parameters"].items()},
            ),
        )
        text = "Ｆｉｃｔｉｏｎａｌ name with synthetic values 🧪"
        probability = _numpy_probability(payload, text)
        self.assertTrue(math.isfinite(probability) and 0.0 <= probability <= 1.0)
        self.assertTrue(probability >= 0.0)
        self.assertEqual(probability >= 1.0, probability == 1.0)
        self.assertEqual(probability >= payload["config"]["threshold"], probability >= 0.5)
        below = math.nextafter(probability, 0.0)
        above = math.nextafter(probability, 1.0)
        if below < probability:
            self.assertTrue(probability >= below)
        self.assertTrue(probability >= probability)
        if above <= 1.0:
            self.assertFalse(probability >= above)
        copied = trainer.export_parameters()
        copied["head.presence.weight"].fill(100)
        self.assertFalse(bool((trainer.parameters["head.presence.weight"] == 100).all()))


if __name__ == "__main__":
    unittest.main()
