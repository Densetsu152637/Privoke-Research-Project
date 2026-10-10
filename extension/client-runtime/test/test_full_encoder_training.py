"""Full Tiny CPU mechanics: gradients, serialized updates and semantic-only RPC."""
import json
import importlib.util
from dataclasses import replace
from pathlib import Path
import unittest
from unittest.mock import patch

import numpy as np
try:
    import torch
except ImportError:
    torch = None

from privoke_model.artifact import apply_parameter_update, float32
from privoke_model.contextual_training import HEAD_NAMES, prepare_full_encoder_artifact
from src.LLM.privoke.streamed_model import StreamedTransformerPrivacyModel, GLOBAL_STREAMED_MODEL_CACHE
from src.LLM.privoke.training import SemanticTrainingExample, compute_semantic_gradients, compute_underlying_model_gradients, _parameter_fingerprint
from src.LLM.privoke.supervised_training import supervised_last_block_deltas
from src.model import TinyTransformerModel
from src.classification import initialise_unpacked, Sensitivity, Visibility, Category
from src.hosting.grpc_server import PrivokeRuntimeService
from privoke.v1 import runtime_pb2, parameters_pb2
from test_training_adaptation import snapshot

ROOT = Path(__file__).resolve().parents[3]


@unittest.skipUnless(torch is not None, "Optional CPU training dependency torch is unavailable")
class FullEncoderTrainingTests(unittest.TestCase):
    def test_pretty_streamed_config_is_canonical_and_actual_updates_pass_updater_validation(self):
        spec = importlib.util.spec_from_file_location("full_training_update_validation",
                    ROOT / "services/param-update-service/app/validation.py")
        validation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validation)
        pretty = json.dumps(self.artifact["config"], indent=2).replace("\n", "\r\n")
        streamed = snapshot(self.artifact)
        wrapper = StreamedTransformerPrivacyModel(replace(streamed,
                    metadata={**streamed.metadata, "model_config": pretty}))
        for trainer in (compute_semantic_gradients, compute_underlying_model_gradients):
            with self.subTest(trainer=trainer.__name__):
                with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=wrapper):
                    batch = trainer(self.rows, model_id=self.artifact["model_id"], learning_rate=.003,
                                    max_gradient=.0001, heldout_examples=self.heldout)
                metadata = {**batch.metadata, **{key: str(value) for key, value in batch.metrics.items()},
                            "request_id": "canonical-config", "request_source_id": "synthetic-test",
                            "requested_prompt_count": "2", "generated_prompt_count": "2",
                            "training_pipeline": "client_runtime_training", "training_request_fingerprint": "a"*64}
                request = parameters_pb2.ParameterUpdateRequest(source_id="test-fuzzer",
                    model_id=batch.model_id, base_version=batch.base_version, metadata=metadata,
                    gradients=[parameters_pb2.Parameter(name=name,shape=batch.shapes[name],values=values)
                               for name,values in batch.gradients.items()])
                self.assertEqual(json.loads(request.metadata["model_config"]), self.artifact["config"])
                validation.validate_parameter_update(request, expected_model_id=batch.model_id,
                    max_abs_gradient=.0001, artifact=self.artifact)
                self.assertEqual(request.metadata["model_config"],
                    json.dumps(self.artifact["config"], sort_keys=True, separators=(",", ":")))
                # The trust boundary remains strict: raw Go-style multiline
                # metadata is rejected even though its JSON contents are valid.
                request.metadata["model_config"] = pretty
                with self.assertRaisesRegex(ValueError, "control characters"):
                    validation.validate_parameter_update(request, expected_model_id=batch.model_id,
                        max_abs_gradient=.0001, artifact=self.artifact)

    def test_missing_or_unusable_torch_preflight_rejects_full_capable_head_and_full(self):
        for trainer in (compute_semantic_gradients, compute_underlying_model_gradients):
            for unusable in (False, True):
                with self.subTest(trainer=trainer.__name__, unusable=unusable):
                    with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=self.wrapper):
                        if unusable:
                            with patch("torch.tensor", side_effect=RuntimeError("unusable CPU autograd")):
                                with self.assertRaisesRegex(RuntimeError, "unusable"):
                                    trainer(self.rows, model_id=self.artifact["model_id"], learning_rate=.003,
                                            max_gradient=.0001, heldout_examples=self.heldout)
                        else:
                            with patch.dict("sys.modules", {"torch": None}):
                                with self.assertRaisesRegex(ValueError, "CPU training dependency"):
                                    trainer(self.rows, model_id=self.artifact["model_id"], learning_rate=.003,
                                            max_gradient=.0001, heldout_examples=self.heldout)

    def setUp(self):
        torch.set_num_threads(1)
        self.source = json.loads((ROOT / "models/privoke-balanced.json").read_text())
        self.artifact = prepare_full_encoder_artifact(self.source, version="v0.4.0+test", generated_at_unix=1,
                                                      source_revision="a" * 40)
        self.wrapper = StreamedTransformerPrivacyModel(snapshot(self.artifact))
        self.clean = initialise_unpacked(Sensitivity.S0, Visibility.PU, [])
        self.private = initialise_unpacked(Sensitivity.S3, Visibility.P4, [Category.HEALTH])
        self.rows = (SemanticTrainingExample("Synthetic public weather", self.clean, 1.),
                     SemanticTrainingExample("My private diagnosis is cancer", self.private, 2.))
        self.heldout = (SemanticTrainingExample("Anonymous public forecast", self.clean, 1.),
                        SemanticTrainingExample("My doctor prescribed medication", self.private, 1.))

    def test_full_autograd_finite_differences_embeddings_and_earlier_block(self):
        model = self.wrapper.model
        names = set(self.artifact["parameters"])
        direction, loss = supervised_last_block_deltas(model, self.rows, names)
        self.assertGreater(loss, 0)
        for name in ("token_embedding", "position_embedding", "layers.0.attention.query.weight", "layers.0.ffn.input.weight"):
            index = int(np.argmax(np.abs(direction[name])))
            self.assertNotEqual(direction[name][index], 0)
            losses = []
            for sign in (-1, 1):
                values = {key: value.copy() for key, value in model.parameters.items()}
                values[name].flat[index] += sign * .001
                perturbed = TinyTransformerModel(model.config, {key: value.ravel() for key, value in values.items()},
                    {key: value.shape for key, value in values.items()}, device="cpu")
                _, value = supervised_last_block_deltas(perturbed, self.rows, names)
                losses.append(value)
            derivative = (losses[1] - losses[0]) / .002
            self.assertAlmostEqual(derivative, -direction[name][index], delta=max(.003, abs(derivative) * .05))

    def test_full_transport_apply_and_head_only_frozen_encoder(self):
        before = self.wrapper.model.predict_many(tuple(row.text for row in self.heldout))
        with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=self.wrapper):
            full = compute_underlying_model_gradients(self.rows, model_id=self.artifact["model_id"],
                learning_rate=.003, max_gradient=.0001, heldout_examples=self.heldout)
            head = compute_semantic_gradients(self.rows, model_id=self.artifact["model_id"],
                learning_rate=.003, max_gradient=.0001, heldout_examples=self.heldout)
        self.assertEqual(set(full.gradients), set(self.artifact["parameters"]))
        self.assertEqual(set(head.gradients), HEAD_NAMES)
        self.assertEqual(full.executions, (("training", 2), ("base_heldout", 2), ("candidate_heldout", 2)))
        for batch in (full, head):
            wire = runtime_pb2.ComputeSemanticGradientsResponse(gradients=[runtime_pb2.RuntimeParameterDelta(
                name=name, shape=batch.shapes[name], values=values) for name, values in batch.gradients.items()])
            parsed = runtime_pb2.ComputeSemanticGradientsResponse.FromString(wire.SerializeToString())
            deltas = {item.name: tuple(item.values) for item in parsed.gradients}
            published = apply_parameter_update(self.artifact, base_version=self.artifact["version"], deltas=deltas, source_id="test")
            self.assertEqual(batch.metadata["updated_parameter_fingerprint"], _parameter_fingerprint(
                {name: tuple(float32(value) for value in tensor["values"]) for name, tensor in published["parameters"].items()}))
            for name in ("token_embedding", "position_embedding", "layers.0.ffn.input.weight", "layers.1.ffn.input.weight"):
                if batch is full:
                    self.assertNotEqual(published["parameters"][name]["values"], self.artifact["parameters"][name]["values"])
                else:
                    self.assertEqual(published["parameters"][name], self.artifact["parameters"][name])
            self.assertTrue(all(abs(value) <= .0001 for values in deltas.values() for value in values))
        self.assertEqual(before, self.wrapper.model.predict_many(tuple(row.text for row in self.heldout)))

    def test_original_double_bound_survives_float32_transport_and_publication(self):
        self.assertGreater(float32(.001), .001)  # The previous clipping path overflowed this request.
        for bound in (.001, .0001):
            for trainer in (compute_semantic_gradients, compute_underlying_model_gradients):
                with self.subTest(bound=bound, trainer=trainer.__name__):
                    with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=self.wrapper):
                        batch = trainer(self.rows, model_id=self.artifact["model_id"], learning_rate=1.,
                            max_gradient=bound, heldout_examples=self.heldout)
                    wire = runtime_pb2.ComputeSemanticGradientsResponse(gradients=[runtime_pb2.RuntimeParameterDelta(
                        name=name, shape=batch.shapes[name], values=values) for name, values in batch.gradients.items()])
                    parsed = runtime_pb2.ComputeSemanticGradientsResponse.FromString(wire.SerializeToString())
                    deltas = {item.name: tuple(item.values) for item in parsed.gradients}
                    magnitudes = [abs(value) for values in deltas.values() for value in values]
                    self.assertLessEqual(max(magnitudes), bound)
                    self.assertGreater(max(magnitudes), bound * .999)  # Exercise clipping, not tiny gradients.
                    published = apply_parameter_update(self.artifact, base_version=self.artifact["version"],
                        deltas=deltas, source_id="test")
                    self.assertEqual(batch.metadata["updated_parameter_fingerprint"], _parameter_fingerprint(
                        {name: tuple(float32(value) for value in tensor["values"])
                         for name, tensor in published["parameters"].items()}))

    def test_underlying_rpc_reports_actual_direct_training_and_candidate_phases(self):
        def convert(rows):
            return [runtime_pb2.RuntimeTrainingExample(text=row.text, target=runtime_pb2.RuntimeClassification(
                packed=row.target.pack()), has_target=True, weight=row.weight) for row in rows]
        request = runtime_pb2.ComputeSemanticGradientsRequest(model_id=self.artifact["model_id"],
            examples=convert(self.rows), heldout_examples=convert(self.heldout), learning_rate=.003,
            max_gradient=.0001, layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC])
        with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=self.wrapper):
            response = PrivokeRuntimeService().ComputeUnderlyingModelGradients(request, None)
        self.assertFalse(response.error)
        self.assertEqual(response.base_version, self.artifact["version"])
        self.assertEqual(response.metadata["training_scope"], "full_encoder")
        self.assertEqual([phase.phase for phase in response.executions], ["training", "base_heldout", "candidate_heldout"])
        self.assertTrue(all(phase.examples == 2 and phase.layer == runtime_pb2.DETECTION_LAYER_SEMANTIC
                            and phase.status == "ok" and not phase.error for phase in response.executions))

    def test_underlying_rejects_legacy_or_missing_explicit_target(self):
        legacy = StreamedTransformerPrivacyModel(snapshot(self.source))
        with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=legacy):
            with self.assertRaisesRegex(ValueError, "full Tiny"):
                compute_underlying_model_gradients(self.rows, model_id=self.source["model_id"], learning_rate=.003, max_gradient=.01)
        with self.assertRaisesRegex(ValueError, "unsupported"):
            compute_underlying_model_gradients(self.rows, model_id="privoke-pretrained-context-minilm", learning_rate=.003, max_gradient=.01)
        missing = (SemanticTrainingExample("unlabeled", None, 1.),)
        with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=self.wrapper):
            with self.assertRaisesRegex(ValueError, "explicit"):
                compute_underlying_model_gradients(missing, model_id=self.artifact["model_id"], learning_rate=.003, max_gradient=.01)
        from dataclasses import replace
        for checksum in ("", "unknown", "g" * 64):
            invalid = StreamedTransformerPrivacyModel(replace(self.wrapper.snapshot,
                metadata={**self.wrapper.snapshot.metadata, "artifact_checksum": checksum}))
            with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=invalid):
                for trainer in (compute_semantic_gradients, compute_underlying_model_gradients):
                    with self.assertRaisesRegex(ValueError, "checksum identity"):
                        trainer(self.rows, model_id=self.artifact["model_id"], learning_rate=.003, max_gradient=.01)

    def test_extended_context_short_parity_long_full_update_and_explicit_overflow(self):
        artifact = prepare_full_encoder_artifact(self.source, version="v0.4.0+long", generated_at_unix=1,
                                                 source_revision="a" * 40, max_tokens=256)
        extended = StreamedTransformerPrivacyModel(snapshot(artifact))
        short = "Synthetic short medical text"
        self.assertEqual(self.wrapper.model.predict(short), extended.model.predict(short))
        self.assertEqual(TinyTransformerModel.from_artifact(artifact).predict(short), extended.model.predict(short))
        boundary = "hello " * 255
        self.assertEqual(len(extended.model.token_ids(boundary)), 256)
        self.assertTrue(np.isfinite(extended.model.predict(boundary).pooled).all())
        with self.assertRaisesRegex(ValueError, "256-token"):
            extended.model.predict("hello " * 256)
        # Historical artifacts keep their original truncation behavior.
        self.assertEqual(len(StreamedTransformerPrivacyModel(snapshot(self.source)).model.token_ids(boundary)), 96)
        rows = (SemanticTrainingExample(boundary, self.private, 1.), self.rows[0])
        with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=extended):
            batch = compute_underlying_model_gradients(rows, model_id=artifact["model_id"], learning_rate=.003,
                max_gradient=.0001, heldout_examples=self.heldout)
        published = apply_parameter_update(artifact, base_version=artifact["version"], deltas=batch.gradients, source_id="test")
        self.assertNotEqual(published["parameters"]["position_embedding"]["values"][96*32:],
                            artifact["parameters"]["position_embedding"]["values"][96*32:])
        self.assertTrue(all(np.isfinite(values).all() for values in batch.gradients.values()))
        # Direct handlers enforce the artifact limit; FT5 covers network transport.
        service = PrivokeRuntimeService()
        for endpoint in (service.ComputeSemanticGradients, service.ComputeUnderlyingModelGradients):
            for content_tokens in (96, 255, 256):
                request = runtime_pb2.ComputeSemanticGradientsRequest(model_id=artifact["model_id"],
                    examples=[runtime_pb2.RuntimeTrainingExample(text="hello " * content_tokens,
                        target=runtime_pb2.RuntimeClassification(packed=self.private.pack()), has_target=True, weight=1)],
                    heldout_examples=[runtime_pb2.RuntimeTrainingExample(text=row.text,
                        target=runtime_pb2.RuntimeClassification(packed=row.target.pack()), has_target=True, weight=1)
                        for row in self.heldout], learning_rate=.003, max_gradient=.0001,
                    layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC])
                with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=extended):
                    response = endpoint(request, None)
                if content_tokens == 256:
                    self.assertIn("256-token", response.error)
                    self.assertFalse(response.executions)
                    self.assertFalse(response.gradients)
                else:
                    self.assertFalse(response.error)
                    self.assertEqual([(phase.phase, phase.examples, phase.layer, phase.status, phase.error)
                        for phase in response.executions], [("training", 1, runtime_pb2.DETECTION_LAYER_SEMANTIC, "ok", ""),
                        ("base_heldout", 2, runtime_pb2.DETECTION_LAYER_SEMANTIC, "ok", ""),
                        ("candidate_heldout", 2, runtime_pb2.DETECTION_LAYER_SEMANTIC, "ok", "")])
