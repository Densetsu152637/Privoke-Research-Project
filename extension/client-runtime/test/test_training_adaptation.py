import copy
import json
import math
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import numpy as np

ROOT=Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "generated", ROOT.parents[1] / "shared/python"):
    sys.path.insert(0,str(path))
from privoke_model.artifact import apply_parameter_update, float32
from privoke_model.contextual_training import (HEAD_NAMES, LAST_BLOCK_STRATEGY, STRATEGY_KEY,
    contextual_trainable_names, prepare_contextual_training_artifact,
    prepare_training_objective_artifact, OBJECTIVE_KEY, CLASS_BALANCED_OBJECTIVE, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE)
from src.model import ModelConfig, TinyTransformerModel
from src.LLM.privoke.streamed_model import GLOBAL_STREAMED_MODEL_CACHE, StreamedTransformerPrivacyModel
from src.LLM.privoke.training import SemanticTrainingExample, compute_semantic_gradients, _parameter_fingerprint, _class_balanced_examples, _mean_category_loss_components
from src.LLM.privoke.supervised_training import supervised_last_block_deltas
from src.classification import Category, Sensitivity, Visibility, initialise_unpacked
from test_streamed_transformer import _snapshot
try:
    import torch
except ImportError:
    torch=None


def snapshot(artifact):
    result=_snapshot(artifact)
    return replace(result,metadata={**result.metadata, **artifact.get("metadata",{})})


class AdaptationContractTests(unittest.TestCase):
    def examples(self):
        clean = initialise_unpacked(Sensitivity.S0, Visibility.P0, [])
        private = initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.HEALTH])
        return (SemanticTrainingExample("Public generic health brochure", clean, .5),
                SemanticTrainingExample("My private diagnosis is cancer", private, 2.),
                SemanticTrainingExample("A blank medical form with generic headings", clean, 1.25))

    def test_class_balance_preserves_rows_ratios_and_sensitive_definition(self):
        examples = self.examples()
        adjusted, audit = _class_balanced_examples(examples)
        self.assertEqual([e.text for e in adjusted], [e.text for e in examples])
        self.assertEqual([e.target for e in adjusted], [e.target for e in examples])
        self.assertEqual([e.weight for e in examples], [.5, 2., 1.25])
        self.assertAlmostEqual(adjusted[0].weight / adjusted[2].weight, .5 / 1.25)
        self.assertEqual(audit["raw_clean_weight"], 1.75)
        self.assertEqual(audit["raw_sensitive_weight"], 2.)
        self.assertEqual(audit["training_clean_examples"], 2.)
        self.assertEqual(audit["training_sensitive_examples"], 1.)
        self.assertEqual(audit["effective_clean_weight"], 1.875)
        self.assertEqual(audit["effective_sensitive_weight"], 1.875)
        self.assertEqual(audit["clean_objective_mass"], .5)
        self.assertEqual(audit["sensitive_objective_mass"], .5)
        category_only = initialise_unpacked(Sensitivity.S0, Visibility.P0, [Category.HEALTH])
        _, audit = _class_balanced_examples((examples[0], replace(examples[1], target=category_only)))
        self.assertEqual(audit["training_sensitive_examples"], 1.)

    def test_balanced_objective_rejects_missing_classes_targets_and_invalid_weights(self):
        examples = self.examples()
        invalid = ((), (examples[0],), (examples[1],),
                   (replace(examples[0], target=None), examples[1]))
        for rows in invalid:
            with self.assertRaises(ValueError): _class_balanced_examples(rows)
        for weight in (0., -1., float("nan"), float("inf"), True, "1"):
            with self.assertRaises(ValueError):
                _class_balanced_examples((replace(examples[0], weight=weight), examples[1]))
        with self.assertRaises(ValueError):
            _class_balanced_examples((replace(examples[0], weight=1e308), replace(examples[1], weight=1e308)))

    def test_analytic_balanced_deltas_audit_cache_and_exact_candidate_all_profiles(self):
        examples = self.examples()
        adjusted, audit = _class_balanced_examples(examples)
        heldout = (replace(examples[0], text="Public anonymous weather information", weight=7.),
                   replace(examples[1], text="My doctor prescribed private medication", weight=.125))
        for profile in ("efficient", "balanced", "quality"):
            base = json.loads((ROOT.parents[1]/f"models/privoke-{profile}.json").read_text(encoding="utf-8"))
            artifact = prepare_training_objective_artifact(base, CLASS_BALANCED_OBJECTIVE)
            wrapper = StreamedTransformerPrivacyModel(snapshot(artifact))
            self.assertNotEqual(snapshot(base).cache_key, wrapper.snapshot.cache_key)
            expected = {n: np.zeros(len(wrapper.snapshot.parameters[n])) for n in HEAD_NAMES}
            # Match runtime accumulation, scaling and float32 publication order.
            total = sum(e.weight for e in adjusted)
            for row, prediction in zip(adjusted, wrapper.model.predict_many(tuple(e.text for e in adjusted))):
                values = wrapper.model.classification_head_deltas_from_prediction(prediction,
                    sensitivity=row.target.sensitivity().name, visibility=row.target.visibility().name,
                    categories=[c.name for c in row.target.categories()])
                for name in HEAD_NAMES: expected[name] += np.asarray(values[name]) * row.weight
            before = wrapper.model.predict_many(tuple(e.text for e in heldout))
            with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=wrapper):
                batch = compute_semantic_gradients(examples, model_id=artifact["model_id"],
                    learning_rate=.003, max_gradient=.0001, heldout_examples=heldout)
                # An omitted objective never invokes balancing, preserving legacy arithmetic.
                legacy = StreamedTransformerPrivacyModel(snapshot(base))
                with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=legacy), \
                     patch("src.LLM.privoke.training._class_balanced_examples", side_effect=AssertionError("legacy reweighted")):
                    control = compute_semantic_gradients(examples, model_id=base["model_id"], learning_rate=.003, max_gradient=.0001)
            for name in HEAD_NAMES:
                wanted = tuple(float32(max(-.0001, min(.0001, float(v) / total * .003))) for v in expected[name])
                self.assertEqual(batch.gradients[name], wanted)
            legacy_expected = {n: np.zeros(len(wrapper.snapshot.parameters[n])) for n in HEAD_NAMES}
            for row, prediction in zip(examples, legacy.model.predict_many(tuple(e.text for e in examples))):
                values = legacy.model.classification_head_deltas_from_prediction(prediction,
                    sensitivity=row.target.sensitivity().name, visibility=row.target.visibility().name,
                    categories=[c.name for c in row.target.categories()])
                for name in HEAD_NAMES: legacy_expected[name] += np.asarray(values[name]) * row.weight
            for name in HEAD_NAMES:
                wanted = tuple(float32(max(-.0001, min(.0001, float(v) / sum(e.weight for e in examples) * .003)))
                               for v in legacy_expected[name])
                self.assertEqual(control.gradients[name], wanted)
            self.assertEqual(batch.metrics["examples"], 3.)
            self.assertEqual(batch.metrics["heldout_examples"], 2.)
            for key, value in audit.items():
                self.assertEqual(batch.metrics[key], value)
                self.assertEqual(batch.metadata[key], str(value))
            self.assertEqual(batch.metadata[OBJECTIVE_KEY], CLASS_BALANCED_OBJECTIVE)
            self.assertNotIn(OBJECTIVE_KEY, control.metadata)
            self.assertEqual(before, wrapper.model.predict_many(tuple(e.text for e in heldout)))
            published = apply_parameter_update(artifact, base_version=artifact["version"], deltas=batch.gradients, source_id="test")
            params = {n: tuple(float32(v) for v in t["values"]) for n,t in published["parameters"].items()}
            self.assertEqual(batch.metadata["updated_parameter_fingerprint"], _parameter_fingerprint(params))
            for name,tensor in artifact["parameters"].items():
                if name not in HEAD_NAMES: self.assertEqual(published["parameters"][name], tensor)

    def test_mean_category_head_scaling_loss_audit_and_exact_candidate_all_profiles(self):
        examples = self.examples()
        adjusted, audit = _class_balanced_examples(examples)
        heldout = (replace(examples[0], text="Public anonymous weather information", weight=7.),
                   replace(examples[1], text="My doctor prescribed private medication", weight=.125))
        for profile in ("efficient", "balanced", "quality"):
            base = json.loads((ROOT.parents[1]/f"models/privoke-{profile}.json").read_text(encoding="utf-8"))
            batches = {}
            for objective in (CLASS_BALANCED_OBJECTIVE, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE):
                artifact = prepare_training_objective_artifact(base, objective)
                wrapper = StreamedTransformerPrivacyModel(snapshot(artifact))
                with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=wrapper):
                    batches[objective] = compute_semantic_gradients(examples, model_id=artifact["model_id"],
                        learning_rate=.003, max_gradient=.05, heldout_examples=heldout)
            summed, mean = batches[CLASS_BALANCED_OBJECTIVE], batches[CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE]
            self.assertNotEqual(summed.metadata["model_cache_key"], mean.metadata["model_cache_key"])
            count = len(wrapper.model.config.category_labels)
            expected = {n: [0.] * len(wrapper.snapshot.parameters[n]) for n in HEAD_NAMES}
            for row, prediction in zip(adjusted, wrapper.model.predict_many(tuple(e.text for e in adjusted))):
                values = wrapper.model.classification_head_deltas_from_prediction(prediction,
                    sensitivity=row.target.sensitivity().name, visibility=row.target.visibility().name,
                    categories=[c.name for c in row.target.categories()])
                for name in HEAD_NAMES:
                    for index, value in enumerate(values[name]):
                        expected[name][index] += (value / count if name.startswith("head.category.") else value) * (row.weight / math.fsum(e.weight for e in adjusted))
            for name in HEAD_NAMES:
                self.assertEqual(mean.gradients[name], tuple(float32(v * .003) for v in expected[name]))
                if name.startswith("head.category."):
                    np.testing.assert_allclose(mean.gradients[name], np.asarray(summed.gradients[name])/count, atol=1e-10, rtol=2e-7)
                else: self.assertEqual(mean.gradients[name], summed.gradients[name])
            self.assertAlmostEqual(mean.metrics["average_loss"], summed.metrics["average_loss"], places=12)
            self.assertEqual(mean.metrics["total_weight"], summed.metrics["total_weight"])
            self.assertEqual(mean.metrics["examples"], 3.)
            for key,value in audit.items(): self.assertEqual(mean.metrics[key], value)
            components = ("supervised_sensitivity_ce_loss", "supervised_visibility_ce_loss", "supervised_category_bce_loss")
            self.assertAlmostEqual(mean.metrics["supervised_objective_loss"], sum(mean.metrics[k] for k in components), places=12)
            for key in (*components, "supervised_objective_loss"):
                self.assertGreaterEqual(mean.metrics[key], 0.)
                self.assertTrue(math.isfinite(mean.metrics[key]))
                self.assertEqual(float(mean.metadata[key]), mean.metrics[key])
                self.assertNotIn(key, summed.metrics)
                self.assertNotIn(key, summed.metadata)
            self.assertEqual(mean.metadata["category_count"], str(count))
            self.assertEqual(mean.metadata["category_normalization"], "mean_per_label")
            self.assertEqual(mean.metadata["diagnostic_loss"], "weighted_classification_distance")
            self.assertEqual(mean.metrics["heldout_examples"], 2.)
            for key in summed.metrics:
                if key.startswith("heldout_"): self.assertEqual(mean.metrics[key], summed.metrics[key])
            published = apply_parameter_update(artifact, base_version=artifact["version"], deltas=mean.gradients, source_id="test")
            params = {n:tuple(float32(v) for v in t["values"]) for n,t in published["parameters"].items()}
            self.assertEqual(mean.metadata["updated_parameter_fingerprint"], _parameter_fingerprint(params))
            for n,tensor in artifact["parameters"].items():
                if n not in HEAD_NAMES: self.assertEqual(published["parameters"][n], tensor)

    def test_mean_category_large_finite_common_weight_rescaling_is_invariant(self):
        examples = tuple(replace(row, weight=1.) for row in self.examples()[:2])
        large = tuple(replace(row, weight=8e307) for row in examples)
        fields = ("average_loss", "supervised_sensitivity_ce_loss", "supervised_visibility_ce_loss",
                  "supervised_category_bce_loss", "supervised_objective_loss")
        for profile in ("efficient", "balanced", "quality"):
            base = json.loads((ROOT.parents[1]/f"models/privoke-{profile}.json").read_text(encoding="utf-8"))
            artifact = prepare_training_objective_artifact(base, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE)
            wrapper = StreamedTransformerPrivacyModel(snapshot(artifact))
            with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=wrapper):
                ordinary = compute_semantic_gradients(examples, model_id=artifact["model_id"], learning_rate=.003, max_gradient=.05)
                scaled = compute_semantic_gradients(large, model_id=artifact["model_id"], learning_rate=.003, max_gradient=.05)
            self.assertEqual(ordinary.gradients, scaled.gradients)
            self.assertEqual(ordinary.metadata["updated_parameter_fingerprint"], scaled.metadata["updated_parameter_fingerprint"])
            for key in fields:
                self.assertEqual(ordinary.metrics[key], scaled.metrics[key])
                self.assertTrue(math.isfinite(scaled.metrics[key]))
            self.assertEqual(scaled.metrics["total_weight"], 1.6e308)
            self.assertEqual(scaled.metrics["raw_total_weight"], 1.6e308)
            self.assertEqual(scaled.metrics["effective_clean_weight"], 8e307)
            self.assertEqual(scaled.metrics["effective_sensitive_weight"], 8e307)
            self.assertEqual(scaled.metrics["clean_objective_mass"], .5)
            self.assertEqual(scaled.metrics["sensitive_objective_mass"], .5)
            self.assertEqual(scaled.metadata["raw_total_weight"], str(1.6e308))
            self.assertTrue(all(math.isfinite(v) for values in scaled.gradients.values() for v in values))

    def test_mean_category_rejects_nonfinite_gradient_or_task_loss_before_clipping(self):
        base = json.loads((ROOT.parents[1]/"models/privoke-balanced.json").read_text(encoding="utf-8"))
        artifact = prepare_training_objective_artifact(base, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE)
        wrapper = StreamedTransformerPrivacyModel(snapshot(artifact))
        examples = self.examples()[:2]
        original = wrapper.model.classification_head_deltas_from_prediction
        def nonfinite(*args, **kwargs):
            result = original(*args, **kwargs)
            result["head.sensitivity.bias"] = (float("inf"),) + result["head.sensitivity.bias"][1:]
            return result
        with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=wrapper):
            with patch.object(wrapper.model, "classification_head_deltas_from_prediction", side_effect=nonfinite):
                with self.assertRaisesRegex(ValueError, "remain finite"):
                    compute_semantic_gradients(examples, model_id=artifact["model_id"], learning_rate=.003, max_gradient=.05)
            with patch("src.LLM.privoke.training._mean_category_loss_components",
                       return_value={"sensitivity": float("inf"), "visibility": 0., "category": 0.}):
                with self.assertRaisesRegex(ValueError, "remain finite"):
                    compute_semantic_gradients(examples, model_id=artifact["model_id"], learning_rate=.003, max_gradient=.05)

    def test_mean_category_analytic_head_finite_difference(self):
        examples = self.examples()
        adjusted, _ = _class_balanced_examples(examples)
        total = math.fsum(row.weight for row in adjusted)
        base = json.loads((ROOT.parents[1]/"models/privoke-balanced.json").read_text(encoding="utf-8"))
        artifact = prepare_training_objective_artifact(base, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE)
        wrapper = StreamedTransformerPrivacyModel(snapshot(artifact))
        with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=wrapper):
            batch = compute_semantic_gradients(examples, model_id=artifact["model_id"], learning_rate=.003, max_gradient=.05)
        for name in ("head.sensitivity.weight", "head.category.weight"):
            index = int(np.argmax(np.abs(batch.gradients[name])))
            epsilon = .001
            objectives = []
            for sign in (-1, 1):
                parameters = {n:v.copy() for n,v in wrapper.model.parameters.items()}
                parameters[name].flat[index] += sign * epsilon
                candidate = TinyTransformerModel(wrapper.model.config, {n:v.ravel() for n,v in parameters.items()},
                    {n:v.shape for n,v in parameters.items()}, device="cpu")
                objectives.append(math.fsum(math.fsum(_mean_category_loss_components(candidate,
                    candidate.predict(row.text), row.target).values()) * row.weight / total for row in adjusted))
            finite = (objectives[1] - objectives[0]) / (2 * epsilon)
            self.assertAlmostEqual(finite, -batch.gradients[name][index] / .003,
                delta=max(.0002, abs(finite)*.03))

    def test_true_mean_loss_matches_uniform_logits_and_extreme_logits_are_finite(self):
        base = json.loads((ROOT.parents[1]/"models/privoke-balanced.json").read_text(encoding="utf-8"))
        wrapper = StreamedTransformerPrivacyModel(snapshot(base))
        parameters = {n:v.copy() for n,v in wrapper.model.parameters.items()}
        for name in HEAD_NAMES: parameters[name][:] = 0.
        model = TinyTransformerModel(wrapper.model.config, {n:v.ravel() for n,v in parameters.items()},
            {n:v.shape for n,v in parameters.items()}, device="cpu")
        for row in self.examples():
            losses = _mean_category_loss_components(model, model.predict(row.text), row.target)
            self.assertAlmostEqual(losses["sensitivity"], math.log(len(model.config.sensitivity_labels)), places=12)
            self.assertAlmostEqual(losses["visibility"], math.log(len(model.config.visibility_labels)), places=12)
            self.assertAlmostEqual(losses["category"], math.log(2), places=12)
        for task in ("sensitivity", "visibility", "category"):
            parameters[f"head.{task}.bias"][:] = 1000.
            parameters[f"head.{task}.bias"][0] = -1000.
        model = TinyTransformerModel(wrapper.model.config, {n:v.ravel() for n,v in parameters.items()},
            {n:v.shape for n,v in parameters.items()}, device="cpu")
        row = self.examples()[0]
        losses = _mean_category_loss_components(model, model.predict(row.text), row.target)
        self.assertTrue(all(math.isfinite(v) and v >= 0 for v in losses.values()))

    def test_mean_category_requires_both_explicit_target_classes(self):
        base = json.loads((ROOT.parents[1]/"models/privoke-balanced.json").read_text(encoding="utf-8"))
        artifact = prepare_training_objective_artifact(base, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE)
        wrapper = StreamedTransformerPrivacyModel(snapshot(artifact))
        examples = self.examples()
        for rows in ((examples[0],), (examples[1],), (replace(examples[0], target=None), examples[1])):
            with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=wrapper), \
                 patch.object(wrapper.model, "predict_many", side_effect=AssertionError("invalid batch predicted")):
                with self.assertRaises(ValueError):
                    compute_semantic_gradients(rows, model_id=artifact["model_id"], learning_rate=.003, max_gradient=.05)

    def test_balanced_runtime_rejects_classes_and_targets_before_prediction(self):
        base = json.loads((ROOT.parents[1]/"models/privoke-balanced.json").read_text(encoding="utf-8"))
        artifact = prepare_training_objective_artifact(base, CLASS_BALANCED_OBJECTIVE)
        wrapper = StreamedTransformerPrivacyModel(snapshot(artifact))
        examples = self.examples()
        for rows in ((examples[0],), (examples[1],), (replace(examples[0], target=None), examples[1])):
            with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=wrapper), \
                 patch.object(wrapper.model, "predict_many", side_effect=AssertionError("invalid batch predicted")):
                with self.assertRaises(ValueError):
                    compute_semantic_gradients(rows, model_id=artifact["model_id"], learning_rate=.003, max_gradient=.05)

    def test_unknown_strategy_missing_targets_and_manifest_fail_closed(self):
        artifact=json.loads((ROOT.parents[1]/"models/privoke-balanced.json").read_text())
        adapted=prepare_contextual_training_artifact(artifact)
        model=StreamedTransformerPrivacyModel(snapshot(adapted))
        for metadata in ({STRATEGY_KEY:"unknown"}, {OBJECTIVE_KEY:"unknown"}, {OBJECTIVE_KEY:None},
                         {"trainable_parameters":"token_embedding"},
                         {"trainable_parameters":model.snapshot.metadata["trainable_parameters"]+",head.category.bias"}):
            bad=StreamedTransformerPrivacyModel(replace(model.snapshot,metadata={**model.snapshot.metadata,**metadata}))
            with patch.object(GLOBAL_STREAMED_MODEL_CACHE,"model_for_training",return_value=bad):
                with self.assertRaises(ValueError):
                    compute_semantic_gradients([SemanticTrainingExample("text",None,1)],model_id=adapted["model_id"],learning_rate=.003,max_gradient=.05)
        with patch.object(GLOBAL_STREAMED_MODEL_CACHE,"model_for_training",return_value=model):
            with self.assertRaisesRegex(ValueError,"explicit contextual"):
                compute_semantic_gradients([SemanticTrainingExample("text",None,1)],model_id=adapted["model_id"],learning_rate=.003,max_gradient=.05)
        self.assertNotEqual(snapshot(artifact).cache_key,snapshot(adapted).cache_key)


@unittest.skipIf(torch is None,"Opt-in CPU Torch dependency unavailable")
class SupervisedAdaptationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        torch.set_num_threads(1)
        cls.clean=initialise_unpacked(Sensitivity.S0,Visibility.P0,[])
        cls.private=initialise_unpacked(Sensitivity.S3,Visibility.PU,[Category.HEALTH])
        cls.examples=(SemanticTrainingExample("Public generic health brochure",cls.clean,.5),
                      SemanticTrainingExample("My private diagnosis is cancer",cls.private,2.0),
                      SemanticTrainingExample("A blank medical form with generic headings",cls.clean,1.25))

    def model(self,profile="balanced"):
        artifact=json.loads((ROOT.parents[1]/f"models/privoke-{profile}.json").read_text())
        adapted=prepare_contextual_training_artifact(artifact)
        return adapted,StreamedTransformerPrivacyModel(snapshot(adapted))

    def test_weighted_analytic_head_deltas_match_autograd_all_profiles(self):
        for profile in ("efficient","balanced","quality"):
            artifact, wrapper=self.model(profile)
            names=contextual_trainable_names(artifact["config"],LAST_BLOCK_STRATEGY)
            actual,loss=supervised_last_block_deltas(wrapper.model,self.examples,names)
            self.assertTrue(np.isfinite(loss))
            expected={n:np.zeros_like(np.asarray(actual[n])) for n in HEAD_NAMES}
            total=sum(item.weight for item in self.examples)
            for item in self.examples:
                values=wrapper.model.classification_head_deltas(item.text,
                    sensitivity=item.target.sensitivity().name,visibility=item.target.visibility().name,
                    categories=[c.name for c in item.target.categories()])
                for name in HEAD_NAMES: expected[name]+=np.asarray(values[name])*item.weight/total
            for name in HEAD_NAMES:
                np.testing.assert_allclose(actual[name],expected[name],atol=8e-6,rtol=2e-5,err_msg=profile+name)

    def test_balanced_analytic_autograd_head_parity_all_profiles(self):
        adjusted, _ = _class_balanced_examples(self.examples)
        for profile in ("efficient", "balanced", "quality"):
            artifact, wrapper = self.model(profile)
            names = contextual_trainable_names(artifact["config"], LAST_BLOCK_STRATEGY)
            actual, loss = supervised_last_block_deltas(wrapper.model, adjusted, names)
            self.assertTrue(np.isfinite(loss))
            expected = {n: np.zeros_like(np.asarray(actual[n])) for n in HEAD_NAMES}
            total = sum(item.weight for item in adjusted)
            for item in adjusted:
                values = wrapper.model.classification_head_deltas(item.text,
                    sensitivity=item.target.sensitivity().name, visibility=item.target.visibility().name,
                    categories=[c.name for c in item.target.categories()])
                for name in HEAD_NAMES: expected[name] += np.asarray(values[name]) * item.weight / total
            for name in HEAD_NAMES:
                np.testing.assert_allclose(actual[name], expected[name], atol=8e-6, rtol=2e-5, err_msg=profile+name)

    def test_balanced_microbatch_finite_difference_and_exact_candidate(self):
        artifact, original = self.model()
        artifact = prepare_training_objective_artifact(artifact, CLASS_BALANCED_OBJECTIVE)
        wrapper = StreamedTransformerPrivacyModel(snapshot(artifact))
        names = contextual_trainable_names(artifact["config"], LAST_BLOCK_STRATEGY)
        adjusted, audit = _class_balanced_examples(self.examples)
        directions, loss = supervised_last_block_deltas(wrapper.model, adjusted, names, microbatch_size=32)
        chunks, chunk_loss = supervised_last_block_deltas(wrapper.model, adjusted, names, microbatch_size=1)
        self.assertAlmostEqual(loss, chunk_loss, places=5)
        for name in names: np.testing.assert_allclose(directions[name], chunks[name], atol=8e-6, rtol=2e-5)
        name = "layers.1.ffn.input.weight"
        index = int(np.argmax(np.abs(directions[name])))
        epsilon = .001
        objectives = []
        for sign in (-1, 1):
            parameters = {n:v.copy() for n,v in wrapper.model.parameters.items()}
            parameters[name].flat[index] += sign * epsilon
            candidate = TinyTransformerModel(wrapper.model.config, {n:v.ravel() for n,v in parameters.items()},
                {n:v.shape for n,v in parameters.items()}, device="cpu")
            _, objective = supervised_last_block_deltas(candidate, adjusted, names)
            objectives.append(objective)
        finite = (objectives[1] - objectives[0]) / (2 * epsilon)
        self.assertAlmostEqual(finite, -directions[name][index], delta=max(.002, abs(finite)*.03))
        before = {n:v.copy() for n,v in wrapper.model.parameters.items()}
        heldout = (SemanticTrainingExample("Public anonymous weather information", self.clean, 7.),
                   SemanticTrainingExample("My doctor prescribed private medication", self.private, .125))
        with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=wrapper):
            batch = compute_semantic_gradients(self.examples, model_id=artifact["model_id"], learning_rate=.003,
                max_gradient=.0001, heldout_examples=heldout)
        for key,value in audit.items(): self.assertEqual(batch.metrics[key], value)
        self.assertEqual(batch.metadata[OBJECTIVE_KEY], CLASS_BALANCED_OBJECTIVE)
        published = apply_parameter_update(artifact, base_version=artifact["version"], deltas=batch.gradients, source_id="test")
        params = {n:tuple(float32(v) for v in t["values"]) for n,t in published["parameters"].items()}
        self.assertEqual(batch.metadata["updated_parameter_fingerprint"], _parameter_fingerprint(params))
        self.assertTrue(all(abs(v)<=float32(.0001) for vals in batch.gradients.values() for v in vals))
        self.assertTrue(any(v != 0 for n,vals in batch.gradients.items() if n.startswith("layers.") for v in vals))
        for n,v in before.items(): np.testing.assert_array_equal(v, wrapper.model.parameters[n])
        for n in ("token_embedding", "position_embedding", "layers.0.ffn.input.weight"):
            self.assertEqual(published["parameters"][n], artifact["parameters"][n])

    def test_mean_category_autograd_head_scaling_and_diagnostics_all_profiles(self):
        adjusted, _ = _class_balanced_examples(self.examples)
        for profile in ("efficient", "balanced", "quality"):
            artifact, wrapper = self.model(profile)
            names = contextual_trainable_names(artifact["config"], LAST_BLOCK_STRATEGY)
            default, old_loss = supervised_last_block_deltas(wrapper.model, adjusted, names)
            explicit, explicit_loss = supervised_last_block_deltas(wrapper.model, adjusted, names, objective=CLASS_BALANCED_OBJECTIVE)
            self.assertEqual(default, explicit)
            self.assertEqual(old_loss, explicit_loss)
            diagnostics = {}
            actual, loss = supervised_last_block_deltas(wrapper.model, adjusted, names,
                objective=CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE, diagnostics=diagnostics)
            count = len(wrapper.model.config.category_labels)
            expected = {n:np.zeros_like(np.asarray(actual[n])) for n in HEAD_NAMES}
            total = math.fsum(item.weight for item in adjusted)
            losses = {task:0. for task in ("sensitivity", "visibility", "category")}
            for row in adjusted:
                prediction = wrapper.model.predict(row.text)
                values = wrapper.model.classification_head_deltas_from_prediction(prediction,
                    sensitivity=row.target.sensitivity().name, visibility=row.target.visibility().name,
                    categories=[c.name for c in row.target.categories()])
                for name in HEAD_NAMES:
                    scale = count if name.startswith("head.category.") else 1
                    expected[name] += np.asarray(values[name]) / scale * row.weight / total
                for task,value in _mean_category_loss_components(wrapper.model, prediction, row.target).items():
                    losses[task] += value * row.weight / total
            for name in HEAD_NAMES:
                np.testing.assert_allclose(actual[name], expected[name], atol=8e-6, rtol=2e-5, err_msg=profile+name)
                factor = count if name.startswith("head.category.") else 1
                np.testing.assert_allclose(actual[name], np.asarray(default[name])/factor, atol=8e-6, rtol=2e-5)
            self.assertAlmostEqual(loss, sum(diagnostics.values()), places=5)
            for task,value in losses.items():
                key = f"supervised_{task}_{'bce' if task == 'category' else 'ce'}_loss"
                self.assertAlmostEqual(diagnostics[key], value, places=5)
            with self.assertRaises(ValueError):
                supervised_last_block_deltas(wrapper.model, adjusted, names, objective="unknown")

    def test_mean_category_final_block_large_common_weight_rescaling_is_invariant(self):
        examples = tuple(replace(row, weight=1.) for row in self.examples[:2])
        large = tuple(replace(row, weight=8e307) for row in examples)
        fields = ("average_loss", "supervised_sensitivity_ce_loss", "supervised_visibility_ce_loss",
                  "supervised_category_bce_loss", "supervised_objective_loss")
        for profile in ("efficient", "balanced", "quality"):
            artifact, _ = self.model(profile)
            artifact = prepare_training_objective_artifact(artifact, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE)
            wrapper = StreamedTransformerPrivacyModel(snapshot(artifact))
            before = {n:v.copy() for n,v in wrapper.model.parameters.items()}
            with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=wrapper):
                ordinary = compute_semantic_gradients(examples, model_id=artifact["model_id"], learning_rate=.003, max_gradient=.05)
                scaled = compute_semantic_gradients(large, model_id=artifact["model_id"], learning_rate=.003, max_gradient=.05)
            self.assertEqual(ordinary.gradients, scaled.gradients)
            self.assertEqual(ordinary.metadata["updated_parameter_fingerprint"], scaled.metadata["updated_parameter_fingerprint"])
            for key in fields:
                self.assertEqual(ordinary.metrics[key], scaled.metrics[key])
                self.assertTrue(math.isfinite(scaled.metrics[key]))
            self.assertEqual(scaled.metrics["total_weight"], 1.6e308)
            for name,values in before.items(): np.testing.assert_array_equal(values, wrapper.model.parameters[name])

    def test_mean_category_block_finite_difference_microbatch_frozen_exact_candidate(self):
        artifact, _ = self.model()
        artifact = prepare_training_objective_artifact(artifact, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE)
        wrapper = StreamedTransformerPrivacyModel(snapshot(artifact))
        names = contextual_trainable_names(artifact["config"], LAST_BLOCK_STRATEGY)
        examples = self.examples * 12
        adjusted, audit = _class_balanced_examples(examples)
        before = {n:v.copy() for n,v in wrapper.model.parameters.items()}
        diagnostics, chunk_diagnostics = {}, {}
        directions, loss = supervised_last_block_deltas(wrapper.model, adjusted, names,
            objective=CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE, diagnostics=diagnostics, microbatch_size=32)
        chunks, chunk_loss = supervised_last_block_deltas(wrapper.model, adjusted, names,
            objective=CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE, diagnostics=chunk_diagnostics, microbatch_size=3)
        self.assertAlmostEqual(loss, chunk_loss, places=5)
        for key in diagnostics: self.assertAlmostEqual(diagnostics[key], chunk_diagnostics[key], places=5)
        for name in names: np.testing.assert_allclose(directions[name], chunks[name], atol=8e-6, rtol=2e-5)
        for name in ("layers.1.ffn.input.weight", "head.category.weight"):
            index = int(np.argmax(np.abs(directions[name])))
            epsilon = .001
            objectives = []
            for sign in (-1, 1):
                parameters = {n:v.copy() for n,v in wrapper.model.parameters.items()}
                parameters[name].flat[index] += sign * epsilon
                candidate = TinyTransformerModel(wrapper.model.config, {n:v.ravel() for n,v in parameters.items()},
                    {n:v.shape for n,v in parameters.items()}, device="cpu")
                _, objective = supervised_last_block_deltas(candidate, adjusted, names, objective=CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE)
                objectives.append(objective)
            finite = (objectives[1] - objectives[0]) / (2 * epsilon)
            self.assertAlmostEqual(finite, -directions[name][index], delta=max(.002, abs(finite)*.03))
        heldout = (SemanticTrainingExample("Public anonymous weather information", self.clean, 7.),
                   SemanticTrainingExample("My doctor prescribed private medication", self.private, .125))
        with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=wrapper):
            batch = compute_semantic_gradients(examples, model_id=artifact["model_id"], learning_rate=.003,
                max_gradient=.0001, heldout_examples=heldout)
        for key,value in audit.items(): self.assertEqual(batch.metrics[key], value)
        for key,value in diagnostics.items(): self.assertEqual(batch.metrics[key], value)
        self.assertEqual(batch.metrics["supervised_objective_loss"], loss)
        self.assertEqual(batch.metadata[OBJECTIVE_KEY], CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE)
        published = apply_parameter_update(artifact, base_version=artifact["version"], deltas=batch.gradients, source_id="test")
        params = {n:tuple(float32(v) for v in t["values"]) for n,t in published["parameters"].items()}
        self.assertEqual(batch.metadata["updated_parameter_fingerprint"], _parameter_fingerprint(params))
        self.assertTrue(all(abs(v)<=float32(.0001) for vals in batch.gradients.values() for v in vals))
        self.assertTrue(any(v != 0 for n,vals in batch.gradients.items() if n.startswith("layers.") for v in vals))
        for n,v in before.items(): np.testing.assert_array_equal(v, wrapper.model.parameters[n])
        for n in ("token_embedding", "position_embedding", "layers.0.ffn.input.weight"):
            self.assertEqual(published["parameters"][n], artifact["parameters"][n])

    def test_microbatch_global_weights_and_frozen_parameters(self):
        artifact,wrapper=self.model()
        names=contextual_trainable_names(artifact["config"],LAST_BLOCK_STRATEGY)
        before={n:v.copy() for n,v in wrapper.model.parameters.items()}
        examples=self.examples*10
        whole,loss=supervised_last_block_deltas(wrapper.model,examples,names,microbatch_size=32)
        chunks,chunk_loss=supervised_last_block_deltas(wrapper.model,examples,names,microbatch_size=3)
        self.assertAlmostEqual(loss,chunk_loss,places=5)
        for name in names: np.testing.assert_allclose(whole[name],chunks[name],atol=8e-6,rtol=2e-5)
        for name,values in before.items(): np.testing.assert_array_equal(values,wrapper.model.parameters[name])
        self.assertNotIn("token_embedding",whole)
        self.assertNotIn("position_embedding",whole)
        self.assertNotIn("layers.0.ffn.input.weight",whole)
        self.assertTrue(all(np.max(np.abs(whole[n]))>0 for n in names))

    def test_block_finite_difference_and_exact_published_candidate(self):
        artifact,wrapper=self.model()
        names=contextual_trainable_names(artifact["config"],LAST_BLOCK_STRATEGY)
        directions,loss=supervised_last_block_deltas(wrapper.model,self.examples,names)
        name="layers.1.ffn.input.weight"
        index=int(np.argmax(np.abs(directions[name])))
        epsilon=.001
        objectives=[]
        for sign in (-1,1):
            parameters={n:v.copy() for n,v in wrapper.model.parameters.items()}
            parameters[name].flat[index]+=sign*epsilon
            candidate=TinyTransformerModel(wrapper.model.config,{n:v.ravel() for n,v in parameters.items()},
                {n:v.shape for n,v in parameters.items()},device="cpu")
            _,objective=supervised_last_block_deltas(candidate,self.examples,names)
            objectives.append(objective)
        finite=(objectives[1]-objectives[0])/(2*epsilon)
        self.assertAlmostEqual(finite,-directions[name][index],delta=max(.002,abs(finite)*.03))
        heldout=(SemanticTrainingExample("Public anonymous weather information",self.clean,1),
                 SemanticTrainingExample("My doctor prescribed private medication",self.private,1))
        before=wrapper.model.predict_many(tuple(e.text for e in heldout))
        with patch.object(GLOBAL_STREAMED_MODEL_CACHE,"model_for_training",return_value=wrapper):
            batch=compute_semantic_gradients(self.examples,model_id=artifact["model_id"],learning_rate=.003,max_gradient=.0001,heldout_examples=heldout)
        self.assertEqual(set(batch.gradients),names)
        self.assertTrue(all(abs(v)<=float32(.0001) for vals in batch.gradients.values() for v in vals))
        self.assertTrue(any(v!=0 for n,vals in batch.gradients.items() if n.startswith("layers.") for v in vals))
        published=apply_parameter_update(artifact,base_version=artifact["version"],deltas=batch.gradients,source_id="test")
        params={n:tuple(float32(v) for v in t["values"]) for n,t in published["parameters"].items()}
        self.assertEqual(batch.metadata["updated_parameter_fingerprint"],_parameter_fingerprint(params))
        self.assertEqual(before,wrapper.model.predict_many(tuple(e.text for e in heldout)))
        self.assertEqual(batch.metadata["strategy"],LAST_BLOCK_STRATEGY)
        self.assertGreater(batch.metrics["supervised_objective_loss"],0)
        for n in ("token_embedding","position_embedding","layers.0.ffn.input.weight"):
            self.assertEqual(published["parameters"][n],artifact["parameters"][n])

if __name__ == "__main__": unittest.main()
