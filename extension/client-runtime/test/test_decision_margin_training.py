"""Offline synthetic tests for the versioned union decision-margin objective."""
import copy
import json
import math
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "generated", ROOT.parents[1] / "shared/python"):
    sys.path.insert(0, str(path))
from privoke_model.artifact import apply_parameter_update, float32
from privoke_model.contextual_training import (CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE as NEW,
    CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE as MEAN, CLASS_BALANCED_OBJECTIVE, LOCAL_SGD_1,
    LOCAL_SGD_4, LAST_BLOCK_STRATEGY, prepare_training_objective_artifact)
from privoke_model.fingerprint import parameter_fingerprint
from src.LLM.privoke import training
from src.LLM.privoke.supervised_training import supervised_last_block_deltas
from src.classification import Category, Sensitivity, Visibility, initialise_unpacked
import test_local_sgd_training as helpers
try:
    import torch
except ImportError:
    torch = None


class DecisionMarginTests(unittest.TestCase):
    def setUp(self):
        self.helper = helpers.LocalSGDTests()
        self.clean = initialise_unpacked(Sensitivity.S0, Visibility.PU, [])
        self.private = initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.HEALTH])
        self.category_only = initialise_unpacked(Sensitivity.S0, Visibility.PU, [Category.HEALTH])

    def toy(self, sensitivity, categories, threshold=.38, labels=("S0", "S1", "S2", "S3")):
        config = SimpleNamespace(sensitivity_labels=labels, visibility_labels=("PU", "P0"),
                                 category_labels=("HEALTH", "FINANCIAL"), category_threshold=threshold)
        parameters = {}
        for head, biases in (("sensitivity", sensitivity), ("visibility", [0., 0.]), ("category", categories)):
            parameters[f"head.{head}.weight"] = np.zeros((2, len(biases)), dtype=np.float32)
            parameters[f"head.{head}.bias"] = np.asarray(biases, dtype=np.float32)
        return SimpleNamespace(config=config, parameters=parameters), SimpleNamespace(pooled=(.25, -.75))

    def evaluate(self, model, prediction, target):
        return training._decision_margin_loss_and_head_deltas(model, prediction, target)

    def test_margin_finite_differences_severity_category_and_category_only_targets(self):
        cases = (([0., 2., -1., -2.], [-4., -5.], self.clean),
                 ([0., 2., -1., -2.], [-4., -5.], self.private),
                 ([3., 0., -1., -2.], [1., -5.], self.private),
                 ([3., 0., -1., -2.], [1., -5.], self.category_only))
        for sensitivity, categories, target in cases:
            model, prediction = self.toy(sensitivity, categories)
            _, direction = self.evaluate(model, prediction, target)
            for name, array in model.parameters.items():
                for index in range(array.size):
                    base = float(array.flat[index]); eps = 2e-3
                    array.flat[index] = base + eps
                    plus = self.evaluate(model, prediction, target)[0]
                    array.flat[index] = base - eps
                    minus = self.evaluate(model, prediction, target)[0]
                    array.flat[index] = base
                    numerical = -(plus - minus) / (2 * eps)
                    self.assertAlmostEqual(direction[name][index], numerical, delta=8e-5)
            self.assertTrue(all(value == 0 for name, values in direction.items()
                                if name.startswith("head.visibility.") for value in values))

    def test_first_winner_ties_use_configured_severity_then_category_order(self):
        for labels in (("S0", "S1", "S2", "S3"), ("S3", "S0", "S2", "S1")):
            model, prediction = self.toy([0.] * 4, [0., 0.], .5, labels)
            _, direction = self.evaluate(model, prediction, self.clean)
            first = next(i for i, label in enumerate(labels) if label != "S0")
            expected = [0.] * 4; expected[first] = -.5; expected[labels.index("S0")] = .5
            self.assertEqual(direction["head.sensitivity.bias"], tuple(expected))
            self.assertEqual(direction["head.category.bias"], (0., 0.))
        model, prediction = self.toy([4., 0., -1., -2.], [0., 0.], .5)
        _, direction = self.evaluate(model, prediction, self.clean)
        self.assertEqual(direction["head.category.bias"], (-.5, 0.))

    def test_actual_threshold_and_float32_boundary_are_used(self):
        for threshold in (.38, .5, .8):
            offset = np.float32(math.log(threshold) - math.log1p(-threshold))
            model, prediction = self.toy([4., 0., -1., -2.], [offset, offset - 2.], threshold)
            loss, direction = self.evaluate(model, prediction, self.category_only)
            self.assertAlmostEqual(loss, math.log(2), places=14)
            self.assertEqual(direction["head.category.bias"], (.5, 0.))
        model, prediction = self.toy([4., 0., -1., -2.], [0., -4.], .38)
        loss, direction = self.evaluate(model, prediction, self.clean)
        self.assertAlmostEqual(direction["head.category.bias"][0], -.62, places=6)
        self.assertGreater(loss, math.log(2))
        # This loss is a float32 margin surrogate: inference's probability threshold
        # and severity tie policies remain unchanged and need not agree at a tie.

    def test_stable_large_logits_and_nonfinite_margin_rejection(self):
        for value in (1000., -1000., 1e30, -1e30):
            # Make severity differences lower so the category term wins even at -1e30.
            model, prediction = self.toy([3e30, 0., 0., 0.], [value, value - abs(value)], .5)
            for target in (self.clean, self.category_only):
                loss, direction = self.evaluate(model, prediction, target)
                expected_margin = max(-float(np.float32(3e30)), float(np.float32(value)))
                expected = max(-expected_margin if target.is_sensitive() else expected_margin, 0.)
                self.assertTrue(math.isfinite(loss))
                self.assertAlmostEqual(loss, expected, delta=1e-10 if abs(value) < 1e10 else abs(expected) * 1e-12)
                self.assertTrue(all(math.isfinite(v) for values in direction.values() for v in values))
        model, prediction = self.toy([100., 0., 0., 0.], [50., 0.], .5)
        loss, direction = self.evaluate(model, prediction, self.category_only)
        self.assertGreater(direction["head.category.bias"][0], 0.)
        self.assertAlmostEqual(loss / math.exp(-50.), 1., places=12)
        self.assertAlmostEqual(direction["head.category.bias"][0] / math.exp(-50.), 1., places=6)
        model, prediction = self.toy([-3e38, 3e38, 0., 0.], [0., 0.])
        with self.assertRaisesRegex(ValueError, "differences must remain finite"):
            self.evaluate(model, prediction, self.clean)
        for value in (float("inf"), float("nan")):
            model, prediction = self.toy([0., 1., 2., 3.], [value, 0.])
            with self.assertRaisesRegex(ValueError, "logits must remain finite"):
                self.evaluate(model, prediction, self.clean)

    def test_auxiliary_category_is_added_after_mean_normalization(self):
        artifact = self.helper.artifact(objective=MEAN)
        control, wrapper = self.helper.batch(artifact)
        proposed, _ = self.helper.batch(prepare_training_objective_artifact(artifact, NEW))
        rows, _ = training._class_balanced_examples(tuple(replace(row, text=training.normalize_text(row.text))
                                                        for row in self.helper.examples()))
        expected = {name: [0.] * len(values) for name, values in wrapper.snapshot.parameters.items() if name in control.gradients}
        total = math.fsum(row.weight for row in rows)
        for row, prediction in zip(rows, wrapper.model.predict_many(tuple(row.text for row in rows))):
            _, auxiliary = self.evaluate(wrapper.model, prediction, row.target)
            typed = wrapper.model.classification_head_deltas_from_prediction(prediction,
                sensitivity=row.target.sensitivity().name, visibility=row.target.visibility().name,
                categories=[c.name for c in row.target.categories()])
            for name in expected:
                for index, value in enumerate(typed[name]):
                    if name.startswith("head.category."):
                        value /= len(wrapper.model.config.category_labels)
                    expected[name][index] += (value + auxiliary[name][index]) * (row.weight / total)
        expected = {name: tuple(float32(training._clamp(value * .003, -.05, .05)) for value in values)
                    for name, values in expected.items()}
        self.assertEqual(proposed.gradients, expected)
        self.assertEqual(proposed.gradients["head.visibility.bias"], control.gradients["head.visibility.bias"])
        self.assertNotEqual(proposed.gradients, control.gradients)
        self.assertEqual(set(proposed.metadata), set(control.metadata))
        self.assertEqual(set(proposed.metrics), set(control.metrics))

    def test_exact_guarded_transport_trace_and_frozen_parameters_for_all_profiles_steps(self):
        for profile in ("efficient", "balanced", "quality"):
            for optimizer in (LOCAL_SGD_1, LOCAL_SGD_4):
                artifact = self.helper.artifact(profile, NEW, optimizer=optimizer)
                heldout = tuple(replace(row, text=f"Distinct heldout synthetic row {i}", weight=11.+i)
                                for i, row in enumerate(self.helper.examples()[:2]))
                with patch.object(training, "_heldout_metrics", wraps=training._heldout_metrics) as guard:
                    batch, wrapper = self.helper.batch(artifact, heldout=heldout)
                trace = json.loads(batch.metadata["contextual_optimizer_trace"])
                self.assertEqual(trace["loss_columns"], ["sensitivity_ce", "visibility_ce", "category_bce", "decision_margin_bce", "objective"])
                self.assertEqual(trace["decision_margin_coefficient"], 1.)
                self.assertEqual(trace["decision_margin_rule"], "max_non_s0_or_category_logit_v1")
                self.assertEqual(trace["category_normalization"], "mean_per_label")
                self.assertLessEqual(len(batch.metadata["contextual_optimizer_trace"].encode()), 2048)
                for loss in trace["loss"]:
                    self.assertEqual(math.fsum(loss[:4]), loss[4])
                self.assertEqual(batch.metrics["supervised_objective_loss"], trace["loss"][0][-1])
                self.assertEqual([batch.metrics[f"supervised_{task}_loss"] for task in ("sensitivity_ce", "visibility_ce", "category_bce")], trace["loss"][0][:3])
                published = apply_parameter_update(artifact, base_version=artifact["version"], deltas=batch.gradients, source_id="unit")
                parameters = {name: tuple(float32(value) for value in tensor["values"]) for name, tensor in published["parameters"].items()}
                self.assertEqual(guard.call_args_list[1].args[1], parameters)
                self.assertEqual(guard.call_args_list[1].kwargs["reference_parameters"], wrapper.snapshot.parameters)
                self.assertEqual([row.weight for row in guard.call_args_list[1].args[2]], [11., 12.])
                self.assertEqual(trace["state_parameter_fingerprints"][-1], parameter_fingerprint(parameters, wrapper.snapshot.shapes))
                for name, tensor in artifact["parameters"].items():
                    if not tensor["trainable"]:
                        self.assertEqual(published["parameters"][name], tensor)
                    np.testing.assert_array_equal(wrapper.model.parameters[name].ravel(), np.asarray(tensor["values"], dtype=np.float32))
                self.assertTrue(all(abs(v) <= .05 for values in batch.gradients.values() for v in values))

    def test_full_head_objective_finite_difference_and_manual_four_step_states(self):
        artifact = self.helper.artifact(objective=NEW, optimizer=LOCAL_SGD_4)
        batch, wrapper = self.helper.batch(artifact)
        rows, _ = training._class_balanced_examples(tuple(replace(row, text=training.normalize_text(row.text))
                                                        for row in self.helper.examples()))
        total = math.fsum(row.weight for row in rows)
        names = set(batch.gradients)
        original = wrapper.model
        direction, _ = training._local_sgd_direction(original, rows, names, None, NEW)
        # Differentiate the actual complete objective at an active head coordinate.
        name, index = max(((name, i) for name in names for i in range(len(direction[name]))),
                          key=lambda item: abs(direction[item[0]][item[1]]))
        base = float(original.parameters[name].flat[index]); eps = 2e-3
        losses = []
        for sign in (1., -1.):
            original.parameters[name].flat[index] = base + sign * eps
            losses.append(training._local_training_losses(original, rows, NEW)[-1])
        original.parameters[name].flat[index] = base
        self.assertAlmostEqual(direction[name][index], -(losses[0]-losses[1])/(2*eps), delta=3e-4)
        accumulated = {name: tuple(0. for _ in wrapper.snapshot.parameters[name]) for name in names}
        parameters = wrapper.snapshot.parameters
        states = [parameter_fingerprint(parameters, wrapper.snapshot.shapes)]
        updates = []
        # Independently differentiate the logits/active margin; do not call a
        # runtime gradient or auxiliary helper for the manual transported states.
        for step in range(4):
            model = training.TinyTransformerModel(original.config, parameters, wrapper.snapshot.shapes)
            gradients = {name: [0.] * len(accumulated[name]) for name in names}
            for row, prediction in zip(rows, model.predict_many(tuple(row.text for row in rows))):
                pooled = np.asarray(prediction.pooled, dtype=np.float32)
                errors = {}
                for head in ("sensitivity", "visibility", "category"):
                    labels = getattr(model.config, f"{head}_labels")
                    if head == "category":
                        selected = {category.name for category in row.target.categories()}
                        target = np.asarray([float(label in selected) for label in labels], dtype=np.float32)
                    else:
                        target = np.asarray([float(label == getattr(row.target, head)().name) for label in labels], dtype=np.float32)
                    errors[head] = target - np.asarray(getattr(prediction, f"{head}_probabilities"), dtype=np.float32)
                s0 = model.config.sensitivity_labels.index("S0")
                alternatives = [i for i, label in enumerate(model.config.sensitivity_labels) if label != "S0"]
                sensitivity = pooled @ model.parameters["head.sensitivity.weight"] + model.parameters["head.sensitivity.bias"]
                category = pooled @ model.parameters["head.category.weight"] + model.parameters["head.category.bias"]
                offset = np.float32(math.log(model.config.category_threshold) - math.log1p(-model.config.category_threshold))
                margins = list(sensitivity[alternatives] - sensitivity[s0]) + list(category - offset)
                winner = max(range(len(margins)), key=lambda i: margins[i])
                margin = float(margins[winner])
                sigmoid = 1./(1.+math.exp(-margin)) if margin >= 0 else math.exp(margin)/(1.+math.exp(margin))
                auxiliary = {head: np.zeros_like(error) for head, error in errors.items()}
                negative_error = float(row.target.is_sensitive()) - sigmoid
                if winner < len(alternatives):
                    auxiliary["sensitivity"][alternatives[winner]] = negative_error
                    auxiliary["sensitivity"][s0] = -negative_error
                else:
                    auxiliary["category"][winner-len(alternatives)] = negative_error
                for head, error in errors.items():
                    for name, typed in ((f"head.{head}.weight", np.outer(pooled, error).ravel()),
                                        (f"head.{head}.bias", error)):
                        aux = np.outer(pooled, auxiliary[head]).ravel() if name.endswith("weight") else auxiliary[head]
                        for i, value in enumerate(typed):
                            if head == "category": value = float(value)/len(model.config.category_labels)
                            gradients[name][i] += (float(value) + float(aux[i])) * (row.weight/total)
            cap = training._inward_float32_bound(.05)
            raw = {name: tuple(value*.003 if step == 0 else prior + value*.003
                               for prior, value in zip(accumulated[name], gradients[name])) for name in names}
            accumulated = {name: tuple(float32(min(cap, max(-cap, value))) for value in values) for name, values in raw.items()}
            updates.append([math.hypot(*(v for name in sorted(names) for v in gradients[name])),
                            max(abs(v) for values in raw.values() for v in values),
                            sum(abs(v)>cap for values in raw.values() for v in values),
                            max(abs(v) for values in accumulated.values() for v in values)])
            parameters = training._transport_local_parameters(wrapper.snapshot.parameters, accumulated)
            states.append(parameter_fingerprint(parameters, wrapper.snapshot.shapes))
        trace = json.loads(batch.metadata["contextual_optimizer_trace"])
        self.assertEqual(batch.gradients, accumulated)
        self.assertEqual(trace["updates"], updates)
        self.assertEqual(trace["state_parameter_fingerprints"], states)

    def test_weight_rescaling_class_mass_and_cache_contract(self):
        for optimizer in (None, LOCAL_SGD_1, LOCAL_SGD_4):
            artifact = self.helper.artifact(objective=NEW, optimizer=optimizer)
            rows = tuple(replace(row, weight=1.) for row in self.helper.examples()[:2])
            ordinary, _ = self.helper.batch(artifact, rows)
            huge, _ = self.helper.batch(artifact, tuple(replace(row, weight=8e307) for row in rows))
            self.assertEqual(ordinary.gradients, huge.gradients)
            self.assertEqual(ordinary.metrics["supervised_objective_loss"], huge.metrics["supervised_objective_loss"])
            if optimizer:
                self.assertEqual(ordinary.metadata["contextual_optimizer_trace"], huge.metadata["contextual_optimizer_trace"])
            self.assertEqual(huge.metrics["clean_objective_mass"], .5)
            self.assertEqual(huge.metrics["sensitive_objective_mass"], .5)
            mean = helpers.snapshot(prepare_training_objective_artifact(artifact, MEAN))
            opted = helpers.snapshot(artifact)
            self.assertEqual(mean.fingerprint, opted.fingerprint)
            self.assertNotEqual(mean.cache_key, opted.cache_key)
        with self.assertRaisesRegex(ValueError, "explicit contextual targets"):
            self.helper.batch(self.helper.artifact(objective=NEW), (replace(rows[0], target=None), rows[1]))

    def test_new_objective_adds_no_standalone_metadata_even_with_quota_audits(self):
        heldout = tuple(replace(row, text=f"Reserved budget row {i}") for i, row in enumerate(self.helper.examples()[:2]))
        old, _ = self.helper.batch(self.helper.artifact(objective=MEAN, optimizer=LOCAL_SGD_4), heldout=heldout)
        new, _ = self.helper.batch(self.helper.artifact(objective=NEW, optimizer=LOCAL_SGD_4), heldout=heldout)
        self.assertEqual(set(old.metadata), set(new.metadata))
        self.assertEqual(set(old.metrics), set(new.metrics))
        self.assertNotIn("supervised_decision_margin_bce_loss", new.metadata)
        self.assertNotIn("supervised_decision_margin_bce_loss", new.metrics)
        # The existing quota synthetic publication shape independently checks 64/64.
        self.helper.test_mean_quota_publication_metadata_fits_last_available_slot()

    @unittest.skipIf(torch is None, "opt-in CPU Torch dependency unavailable on host")
    def test_weighted_autograd_head_parity_all_profiles_and_last_block_microbatch(self):
        for profile in ("efficient", "balanced", "quality"):
            artifact = self.helper.artifact(profile, NEW, LAST_BLOCK_STRATEGY)
            _, wrapper = self.helper.batch(self.helper.artifact(profile, NEW))
            input_rows = (*self.helper.examples(), replace(self.helper.examples()[1], text="Category-only public health subject", target=self.category_only, weight=.7))
            rows, _ = training._class_balanced_examples(tuple(replace(row, text=training.normalize_text(row.text))
                                                            for row in input_rows))
            names = set(name for name in wrapper.model.parameters if name.startswith("head."))
            analytic, denominator = training._local_sgd_direction(wrapper.model, rows, names, None, NEW)
            autograd, loss = supervised_last_block_deltas(wrapper.model, rows, names, objective=NEW)
            self.assertEqual(denominator, 1.)
            for name in names:
                np.testing.assert_allclose(analytic[name], autograd[name], rtol=3e-5, atol=2e-7)
            self.assertAlmostEqual(training._local_training_losses(wrapper.model, rows, NEW)[-1], loss, delta=3e-6)
            adapted = helpers.StreamedTransformerPrivacyModel(helpers.snapshot(artifact))
            names = {name for name, tensor in artifact["parameters"].items() if tensor["trainable"]}
            reference, loss = supervised_last_block_deltas(adapted.model, rows, names, objective=NEW, microbatch_size=32)
            for size in (1, 2):
                direction, other_loss = supervised_last_block_deltas(adapted.model, rows, names, objective=NEW, microbatch_size=size)
                for name in names:
                    np.testing.assert_allclose(direction[name], reference[name], rtol=3e-5, atol=3e-7)
                self.assertAlmostEqual(loss, other_loss, delta=3e-6)

    @unittest.skipIf(torch is None, "opt-in CPU Torch dependency unavailable on host")
    def test_torch_stable_large_margin_and_category_only_targets(self):
        artifact = self.helper.artifact(objective=NEW)
        _, wrapper = self.helper.batch(artifact)
        model = wrapper.model
        for name, array in model.parameters.items():
            if name.startswith("head."): array.fill(0.)
        names = {name for name in model.parameters if name.startswith("head.")}
        for margin in (-1000., -50., 50., 1000.):
            model.parameters["head.sensitivity.bias"].fill(-3000.)
            model.parameters["head.sensitivity.bias"][model.config.sensitivity_labels.index("S0")] = 0.
            model.parameters["head.category.bias"].fill(margin)
            for target in (self.clean, self.category_only):
                rows = (training.SemanticTrainingExample("Stable synthetic margin", target, 1.),)
                analytic, _ = training._local_sgd_direction(model, rows, names, None, NEW)
                autograd, loss = supervised_last_block_deltas(model, rows, names, objective=NEW)
                self.assertTrue(math.isfinite(loss))
                self.assertAlmostEqual(loss, training._local_training_losses(model, rows, NEW)[-1], delta=5e-4)
                for name in names:
                    np.testing.assert_allclose(analytic[name], autograd[name], rtol=3e-6, atol=2e-7)
        model.parameters["head.sensitivity.bias"].fill(0.)
        model.parameters["head.sensitivity.bias"][0] = -3e38
        model.parameters["head.sensitivity.bias"][1] = 3e38
        with self.assertRaisesRegex(ValueError, "differences must remain finite"):
            supervised_last_block_deltas(model, rows, names, objective=NEW)

    @unittest.skipIf(torch is None, "opt-in CPU Torch dependency unavailable on host")
    def test_torch_first_winner_ties_and_category_branch_match_analytic(self):
        for labels in (("S0", "S1", "S2", "S3"), ("S3", "S0", "S2", "S1")):
            artifact = self.helper.artifact(objective=NEW)
            artifact["config"]["sensitivity_labels"] = list(labels)
            artifact["config"]["category_threshold"] = .5
            for name, tensor in artifact["parameters"].items():
                if name.startswith("head."):
                    tensor["values"] = [0.] * len(tensor["values"])
            model = training.TinyTransformerModel(training.ModelConfig.from_mapping(artifact["config"]),
                {name: tensor["values"] for name, tensor in artifact["parameters"].items()},
                {name: tensor["shape"] for name, tensor in artifact["parameters"].items()})
            rows = (training.SemanticTrainingExample("Tie case", self.clean, 1.),)
            names = {name for name in model.parameters if name.startswith("head.")}
            analytic, _ = training._local_sgd_direction(model, rows, names, None, NEW)
            autograd, _ = supervised_last_block_deltas(model, rows, names, objective=NEW)
            for name in names:
                np.testing.assert_allclose(analytic[name], autograd[name], rtol=2e-6, atol=1e-7)
            first = next(i for i, label in enumerate(labels) if label != "S0")
            typed = model.classification_head_deltas_from_prediction(model.predict("Tie case"),
                sensitivity="S0", visibility="PU", categories=[])
            expected = np.zeros(4, dtype=np.float32); expected[first] = -.5; expected[labels.index("S0")] = .5
            np.testing.assert_array_equal(np.asarray(analytic["head.sensitivity.bias"]) - np.asarray(typed["head.sensitivity.bias"]), expected)
            # Category tie wins its first configured label when all severity margins are lower.
            model.parameters["head.sensitivity.bias"][labels.index("S0")] = 4.
            analytic, _ = training._local_sgd_direction(model, rows, names, None, NEW)
            autograd, _ = supervised_last_block_deltas(model, rows, names, objective=NEW)
            for name in names:
                np.testing.assert_allclose(analytic[name], autograd[name], rtol=2e-6, atol=1e-7)

    @unittest.skipIf(torch is None, "opt-in CPU Torch dependency unavailable on host")
    def test_last_block_finite_difference_transport_frozen_and_four_step_microbatch(self):
        for profile in ("efficient", "balanced", "quality"):
            artifact = self.helper.artifact(profile, NEW, LAST_BLOCK_STRATEGY, LOCAL_SGD_4)
            rows, _ = training._class_balanced_examples(tuple(replace(row, text=training.normalize_text(row.text))
                                                            for row in self.helper.examples()))
            wrapper = helpers.StreamedTransformerPrivacyModel(helpers.snapshot(artifact))
            names = {name for name, tensor in artifact["parameters"].items() if tensor["trainable"]}
            direction, _ = supervised_last_block_deltas(wrapper.model, rows, names, objective=NEW)
            block = sorted(name for name in names if not name.startswith("head."))
            name, index = max(((name, i) for name in block for i in range(len(direction[name]))),
                              key=lambda item: abs(direction[item[0]][item[1]]))
            original = float(wrapper.model.parameters[name].flat[index]); epsilon = 1e-3
            losses = []
            for sign in (1., -1.):
                wrapper.model.parameters[name].flat[index] = original + sign * epsilon
                losses.append(training._local_training_losses(wrapper.model, rows, NEW)[-1])
            wrapper.model.parameters[name].flat[index] = original
            self.assertAlmostEqual(direction[name][index], -(losses[0]-losses[1])/(2*epsilon), delta=8e-3)
            heldout = tuple(replace(row, text=f"Torch reserved guard {i}") for i, row in enumerate(self.helper.examples()[:2]))
            with patch.object(training, "_heldout_metrics", wraps=training._heldout_metrics) as guard:
                reference, serving = self.helper.batch(artifact, heldout=heldout)
            published = apply_parameter_update(artifact, base_version=artifact["version"], deltas=reference.gradients, source_id="unit")
            parameters = {name: tuple(float32(v) for v in tensor["values"]) for name, tensor in published["parameters"].items()}
            trace = json.loads(reference.metadata["contextual_optimizer_trace"])
            self.assertEqual(guard.call_args_list[1].args[1], parameters)
            self.assertEqual(trace["state_parameter_fingerprints"][-1], parameter_fingerprint(parameters, serving.snapshot.shapes))
            for name, tensor in artifact["parameters"].items():
                if not tensor["trainable"]:
                    self.assertEqual(published["parameters"][name], tensor)
                np.testing.assert_array_equal(serving.model.parameters[name].ravel(), np.asarray(tensor["values"],dtype=np.float32))
            original_function = supervised_last_block_deltas
            for size in (1, 2):
                def microbatch(*args, **kwargs):
                    kwargs["microbatch_size"] = size
                    return original_function(*args, **kwargs)
                with patch("src.LLM.privoke.supervised_training.supervised_last_block_deltas", side_effect=microbatch):
                    candidate, _ = self.helper.batch(artifact)
                for name in reference.gradients:
                    np.testing.assert_allclose(candidate.gradients[name], reference.gradients[name], rtol=5e-5, atol=3e-7)


if __name__ == "__main__":
    unittest.main()
