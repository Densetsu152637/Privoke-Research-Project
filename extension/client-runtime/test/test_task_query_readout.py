"""Synthetic mechanics only: v2 migration, execution and output gradients."""
import copy
import json
import sys
from dataclasses import asdict, replace
from pathlib import Path
import unittest
from unittest.mock import patch

import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[3]
for path in (ROOT / "models", ROOT / "evaluation"):
    sys.path.insert(0, str(path))
from generate_baseline import initial_parameters, SENSITIVITIES, VISIBILITIES, CATEGORIES
from privoke_model.artifact import artifact_checksum, validate_artifact, apply_parameter_update
from privoke_model.contextual_training import (prepare_task_query_artifact, contextual_output_trainable_names,
    contextual_trainable_names, FULL_ENCODER_STRATEGY, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE)
from privoke_model.readout import QUERY_NAMES, TASK_QUERY_READOUT, TASKS
from src.model import ModelConfig, TinyTransformerModel
from src.task_readout import torch_readout
from src.classification import initialise_unpacked, Sensitivity, Visibility, Category
from src.LLM.privoke.supervised_training import supervised_last_block_deltas
from src.LLM.privoke.training import SemanticTrainingExample, _decision_margin_loss_and_head_deltas
from src.LLM.privoke.sensitive_retention_training import margin_and_gap
from src.LLM.privoke.streamed_model import StreamedTransformerPrivacyModel, GLOBAL_STREAMED_MODEL_CACHE
from src.hosting.grpc_server import PrivokeRuntimeService
from privoke.v1 import runtime_pb2
from test_training_adaptation import snapshot


def fixture(strategy=None):
    config = ModelConfig(32, 8, 16, 16, SENSITIVITIES, VISIBILITIES, CATEGORIES,
                         num_layers=1, num_attention_heads=2)
    rng = np.random.default_rng(19)
    arrays = initial_parameters(config, rng)
    for task in TASKS:
        arrays[f"head.{task}.weight"][:] = rng.normal(0, .1, arrays[f"head.{task}.weight"].shape)
    source = {"schema_version": 1, "architecture": "privoke_tiny_transformer_v1", "model_id": "query-fixture",
        "version": "v1", "generated_at_unix": 1, "config": config.to_mapping(), "metadata": {},
        "parameters": {n: {"shape": list(a.shape), "values": a.ravel().tolist(),
            "trainable": n.startswith("head.")} for n, a in arrays.items()}}
    source["checksum"] = artifact_checksum(source)
    migrated = prepare_task_query_artifact(source, version="v2", generated_at_unix=2,
        source_revision="a" * 40, strategy=strategy)
    return source, migrated


def model(artifact, device="cpu"):
    return TinyTransformerModel(ModelConfig.from_mapping(artifact["config"]),
        {n: t["values"] for n, t in artifact["parameters"].items()},
        {n: t["shape"] for n, t in artifact["parameters"].items()}, device=device)


class TaskQueryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        torch.set_num_threads(1)

    def test_migration_zero_parity_and_exact_scope(self):
        source, migrated = fixture()
        self.assertNotIn("readout", source["config"])
        self.assertEqual(set(migrated["parameters"]) - set(source["parameters"]), QUERY_NAMES)
        for name, tensor in source["parameters"].items():
            self.assertEqual(tensor, migrated["parameters"][name])
        self.assertEqual(sum(len(migrated["parameters"][n]["values"]) for n in QUERY_NAMES), 24)
        old, new = model(source), model(migrated)
        for text in ("", "alpha beta gamma", "synthetic delta"):
            before, after = old.predict(text), new.predict(text)
            np.testing.assert_array_equal(before.pooled, after.pooled)
            for a, b in zip(before.task_logits, after.task_logits):
                np.testing.assert_allclose(a, b, atol=2e-7, rtol=2e-6)
        self.assertEqual(contextual_trainable_names(migrated["config"]), contextual_output_trainable_names(migrated["config"]))
        self.assertEqual(contextual_trainable_names(migrated["config"], FULL_ENCODER_STRATEGY), set(migrated["parameters"]))

    def test_fail_closed_identity_manifest_and_shapes(self):
        _, migrated = fixture()
        mutations = [lambda a: a.update(architecture="privoke_tiny_transformer_v1"),
            lambda a: a["config"].pop("readout"), lambda a: a["config"].update(readout="unknown"),
            lambda a: a["parameters"].pop("readout.category.query"),
            lambda a: a["parameters"]["readout.category.query"].update(shape=[2, 4]),
            lambda a: a["parameters"]["readout.category.query"].update(trainable=False),
            lambda a: a["parameters"]["readout.category.query"]["values"].__setitem__(0, 1e100),
            lambda a: a["parameters"].update(extra={"shape": [1], "values": [0.], "trainable": False})]
        for mutate in mutations:
            bad = copy.deepcopy(migrated)
            mutate(bad)
            bad["checksum"] = artifact_checksum({k: v for k, v in bad.items() if k != "checksum"})
            with self.assertRaises(ValueError):
                validate_artifact(bad)
        bad = copy.deepcopy(migrated)
        bad["parameters"]["readout.category.query"]["values"][0] = float("inf")
        with self.assertRaisesRegex(ValueError, "non-finite"):
            validate_artifact(bad)
        with self.assertRaises(ValueError):
            TinyTransformerModel.from_artifact({**migrated, "architecture": "unknown"})

    def test_analytic_query_and_head_gradients_match_autograd(self):
        _, artifact = fixture()
        runtime = model(artifact)
        target = initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.HEALTH])
        row = SemanticTrainingExample("alpha beta gamma", target, 1.)
        names = contextual_output_trainable_names(artifact["config"])
        for random_queries in (False, True):
            if random_queries:
                for i, name in enumerate(sorted(QUERY_NAMES)):
                    runtime.parameters[name][:] = np.linspace(-.3, .4, 8) * (i + 1)
            prediction = runtime.predict(row.text)
            analytic = runtime.classification_head_deltas_from_prediction(prediction,
                sensitivity="S3", visibility="PU", categories=("HEALTH",))
            automatic, _ = supervised_last_block_deltas(runtime, (row,), names)
            for name in names:
                np.testing.assert_allclose(analytic[name], automatic[name], atol=4e-6, rtol=1e-4)
            self.assertTrue(any(abs(v) > 1e-6 for n in QUERY_NAMES for v in automatic[n]))
            # Independent central differences at one coordinate of every query.
            for task in TASKS:
                name = f"readout.{task}.query"
                original = runtime.parameters[name][0].copy()
                losses = []
                for sign in (1, -1):
                    runtime.parameters[name][0] = original + sign * .001
                    p = runtime.predict(row.text)
                    logits = runtime.prediction_logits(p, task)
                    if task == "category":
                        truth = np.asarray([float(t == "HEALTH") for t in CATEGORIES])
                        losses.append(float(np.sum(np.maximum(logits, 0) - truth * logits + np.log1p(np.exp(-np.abs(logits))))))
                    else:
                        index = getattr(runtime.config, f"{task}_labels").index("S3" if task == "sensitivity" else "PU")
                        losses.append(float(np.log(np.exp(logits - logits.max()).sum()) + logits.max() - logits[index]))
                runtime.parameters[name][0] = original
                self.assertAlmostEqual(-(losses[0] - losses[1]) / .002, analytic[name][0], delta=5e-4)
        mean, _ = supervised_last_block_deltas(runtime, (row,), names, objective=CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE)
        for name in ("head.category.weight", "head.category.bias", "readout.category.query"):
            np.testing.assert_allclose(mean[name], np.asarray(automatic[name]) / 10, atol=4e-6, rtol=1e-4)
        single = runtime.classification_head_deltas("", sensitivity="S3", visibility="PU", categories=("HEALTH",))
        for name in QUERY_NAMES:
            np.testing.assert_array_equal(single[name], np.zeros(8))

    def test_torch_forward_padding_and_nonzero_task_features(self):
        _, artifact = fixture()
        for i, name in enumerate(sorted(QUERY_NAMES)):
            artifact["parameters"][name]["values"] = (np.linspace(-1, 1, 8) * (i + 1)).tolist()
        cpu = model(artifact)
        texts = ("alpha beta gamma", "", "delta")
        expected = cpu.predict_many(texts)
        self.assertFalse(np.allclose(expected[0].task_features[0], expected[0].task_features[1]))
        for device in ("torch-cpu", "cuda"):
            if device == "cuda" and not torch.cuda.is_available():
                continue
            accelerated = model(artifact, "cpu" if device == "torch-cpu" else "cuda")
            if device == "torch-cpu":
                accelerated._torch = torch
                accelerated._torch_parameters = {n: torch.tensor(a) for n, a in accelerated.parameters.items()}
            actual = accelerated.predict_many(texts)
            for a, b in zip(expected, actual):
                for x, y in zip(a.task_logits, b.task_logits):
                    np.testing.assert_allclose(x, y, atol=5e-6, rtol=5e-5)
            solo = accelerated.predict(texts[0])
            np.testing.assert_allclose(solo.task_logits[0], actual[0].task_logits[0], atol=5e-6, rtol=5e-5)

    def test_true_logits_margin_and_encoder_gradient_zero_initialization(self):
        _, artifact = fixture()
        runtime = model(artifact)
        hidden = torch.tensor(runtime.encode_hidden("alpha beta gamma"), requires_grad=True)
        p = {n: torch.tensor(a, requires_grad=n in QUERY_NAMES) for n, a in runtime.parameters.items()}
        _, _, logits = torch_readout(hidden[None], torch.ones((1, len(hidden)), dtype=torch.bool), runtime.config, p, torch)
        logits["category"].sum().backward()
        upstream = runtime.parameters["head.category.weight"].sum(1)
        expected = np.tile(upstream * .5 / len(hidden), (len(hidden), 1))
        expected[0] += .5 * upstream
        np.testing.assert_allclose(hidden.grad.numpy(), expected, atol=1e-7, rtol=2e-6)
        runtime.parameters["readout.sensitivity.query"][:] = np.linspace(-2, 2, 8)
        prediction = runtime.predict("alpha beta gamma")
        stale = replace(prediction, pooled=tuple([999.] * 8))
        self.assertEqual(margin_and_gap(runtime, prediction), margin_and_gap(runtime, stale))
        target = initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.HEALTH])
        loss, delta = _decision_margin_loss_and_head_deltas(runtime, prediction, target)
        self.assertGreater(loss, 0)
        self.assertEqual(set(delta), contextual_output_trainable_names(artifact["config"]))
        parameters = {n: torch.tensor(a, requires_grad=n in delta) for n, a in runtime.parameters.items()}
        states = torch.tensor(prediction.token_states)
        _, _, output = torch_readout(states[None], torch.ones((1, len(states)), dtype=torch.bool), runtime.config, parameters, torch)
        margins = torch.cat((output["sensitivity"][:, 1:] - output["sensitivity"][:, :1], output["category"]), dim=1)
        torch.nn.functional.softplus(-margins.max(dim=1).values).sum().backward()
        for name in delta:
            gradient = parameters[name].grad
            expected = -gradient.numpy().ravel() if gradient is not None else np.zeros(len(delta[name]))
            np.testing.assert_allclose(delta[name], expected, atol=3e-6, rtol=3e-5)

    def test_semantic_rpc_stream_reconstruction_and_atomic_query_updates(self):
        _, artifact = fixture(FULL_ENCODER_STRATEGY)
        wrapper = StreamedTransformerPrivacyModel(snapshot(artifact))
        clean = initialise_unpacked(Sensitivity.S0, Visibility.PU, [])
        private = initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.HEALTH])
        def convert(text, target):
            return runtime_pb2.RuntimeTrainingExample(text=text,
                target=runtime_pb2.RuntimeClassification(packed=target.pack()), has_target=True, weight=1)
        request = runtime_pb2.ComputeSemanticGradientsRequest(model_id=artifact["model_id"],
            examples=[convert("alpha beta", clean), convert("gamma delta", private)],
            heldout_examples=[convert("epsilon weather", clean), convert("zeta private", private)],
            learning_rate=.003, max_gradient=.001, layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC])
        for endpoint in ("ComputeSemanticGradients", "ComputeUnderlyingModelGradients"):
            with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=wrapper):
                response = getattr(PrivokeRuntimeService(), endpoint)(request, None)
            self.assertFalse(response.error, response.error)
            self.assertEqual([e.phase for e in response.executions], ["training", "base_heldout", "candidate_heldout"])
            self.assertTrue(all(e.layer == runtime_pb2.DETECTION_LAYER_SEMANTIC and e.status == "ok" and e.examples == 2 for e in response.executions))
            parsed = type(response).FromString(response.SerializeToString())
            delta = {p.name: tuple(p.values) for p in parsed.gradients}
            self.assertTrue(QUERY_NAMES.issubset(delta))
            self.assertTrue(any(abs(v) > 0 for n in QUERY_NAMES for v in delta[n]))
            result = apply_parameter_update(artifact, base_version=artifact["version"], deltas=delta, source_id="synthetic")
            validate_artifact(result)
            reloaded = StreamedTransformerPrivacyModel(snapshot(result)).model
            direct = model(result)
            for name in QUERY_NAMES:
                np.testing.assert_array_equal(reloaded.parameters[name], direct.parameters[name])
            actual, expected = reloaded.predict("alpha gamma"), direct.predict("alpha gamma")
            for x, y in zip(actual.task_logits, expected.task_logits):
                np.testing.assert_allclose(x, y, atol=5e-6, rtol=5e-5)
            if endpoint == "ComputeSemanticGradients":
                for name in set(artifact["parameters"]) - contextual_output_trainable_names(artifact["config"]):
                    self.assertEqual(result["parameters"][name], artifact["parameters"][name])


if __name__ == "__main__":
    unittest.main()
