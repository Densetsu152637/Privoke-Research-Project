"""Synthetic pretrained inference, cache, failure and semantic-only RPC contracts."""
from dataclasses import replace
import hashlib
import json
import math
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import Mock, patch

import numpy as np

ROOT = Path(__file__).resolve().parents[3]
for path in (ROOT / "shared/python", ROOT / "extension/client-runtime", ROOT / "extension/client-runtime/generated"):
    sys.path.insert(0, str(path))

from privoke.v1 import runtime_pb2
from privoke_model.pretrained_context import build_head_artifact, head_tensor_shapes, PRETRAINED_CONTEXT_MODEL_ID
from src.pretrained_context import FrozenPretrainedEncoder, INPUT_SIGNATURE, OUTPUT_SIGNATURE, _verified_bytes
from src.LLM.privoke.parameter_stream import ParameterSnapshot
from src.LLM.privoke.streamed_model import StreamedModelCache
from src.LLM.privoke.pretrained_context_model import StreamedPretrainedContextModel
from src.LLM.privoke.training import compute_semantic_gradients
from src.LLM.privoke_classifier import PriVokeClassifier
from src.hosting.grpc_server import PrivokeRuntimeService


class FeatureEncoder:
    def __init__(self, *, max_tokens=256):
        self.max_tokens = max_tokens

    def encode_normalized(self, text):
        if text == "overlength":
            raise ValueError("Pretrained contextual input exceeds its 256-token context including special tokens.")
        return np.full(384, 1 / np.sqrt(384), dtype=np.float32)


def snapshot_for(clean=False, checksum="a" * 64, max_tokens=256):
    parameters = {name: [0.] * math.prod(shape) for name, shape in head_tensor_shapes().items()}
    parameters["head.sensitivity.bias"][0 if clean else 2] = 10.
    parameters["head.visibility.bias"][5] = 10.
    parameters["head.category.bias"] = [-10.] * 10
    if not clean:
        parameters["head.category.bias"][4] = 10.
    artifact = build_head_artifact(parameters, version="v1.0.0+synthetic.1", generated_at_unix=1, metadata={}, max_tokens=max_tokens)
    return ParameterSnapshot(artifact["model_id"], artifact["version"], 1,
                             {n: tuple(t["values"]) for n, t in artifact["parameters"].items()},
                             {n: tuple(t["shape"]) for n, t in artifact["parameters"].items()},
                             {"architecture": artifact["architecture"], "model_config": json.dumps(artifact["config"]),
                              "trainable_parameters": "", "artifact_checksum": checksum})


def fake_dependencies(length=3, nonfinite=False, invalid_signature=False):
    tokenizer = SimpleNamespace(no_padding=lambda: None, no_truncation=lambda: None,
        encode=lambda text, add_special_tokens: SimpleNamespace(ids=list(range(length)), attention_mask=[1] * length, type_ids=[0] * length))
    signatures = [SimpleNamespace(name=n, type=t, shape=s) for n, t, s in INPUT_SIGNATURE]
    output = [SimpleNamespace(name=n, type=t, shape=s) for n, t, s in OUTPUT_SIGNATURE]
    session = SimpleNamespace(get_inputs=lambda: [] if invalid_signature else signatures,
        get_outputs=lambda: output, get_providers=lambda: ["CPUExecutionProvider"],
        run=Mock(return_value=[np.full((1, length, 384), np.nan if nonfinite else 1., dtype=np.float32)]))
    ort = SimpleNamespace(__version__="1.23.2", SessionOptions=SimpleNamespace, InferenceSession=lambda *args, **kwargs: session)
    tokens = SimpleNamespace(__version__="0.22.1", Tokenizer=SimpleNamespace(from_str=lambda raw: tokenizer))
    return {"onnxruntime": ort, "tokenizers": tokens}


class PretrainedContextRuntimeTests(unittest.TestCase):
    def test_context_boundaries_reject_before_onnx_and_invalid_limit_before_assets(self):
        for maximum, length, admitted in ((256, 256, True), (256, 257, False),
                                          (512, 256, True), (512, 257, True),
                                          (512, 512, True), (512, 513, False)):
            dependencies = fake_dependencies(length=length)
            session = dependencies["onnxruntime"].InferenceSession()
            with self.subTest(maximum=maximum, length=length), patch.dict(sys.modules, dependencies), \
                    patch("src.pretrained_context._verified_bytes", return_value=b"{}"), \
                    patch.object(np, "__version__", "2.2.6"):
                encoder = FrozenPretrainedEncoder("assets", max_tokens=maximum)
                self.assertEqual(encoder.max_tokens, maximum)
                with self.assertRaises(AttributeError):
                    encoder.max_tokens = 512
                if admitted:
                    self.assertEqual(encoder.encode("Synthetic").shape, (384,))
                    session.run.assert_called_once()
                else:
                    with self.assertRaisesRegex(ValueError, f"{maximum}-token"):
                        encoder.encode("Synthetic")
                    session.run.assert_not_called()
        with patch("src.pretrained_context._verified_bytes") as read:
            for invalid in (True, 512.0, 257, 513):
                with self.assertRaises(ValueError):
                    FrozenPretrainedEncoder("assets", max_tokens=invalid)
            read.assert_not_called()

    def test_cache_separates_limit_identity_reuses_each_encoder_and_rejects_mismatch(self):
        cache = StreamedModelCache(0)
        first_snapshot = snapshot_for()
        extended_snapshot = snapshot_for(max_tokens=512)
        # Deliberately hold every other identity field equal: the limit itself
        # must prevent reuse, even if a malformed upstream checksum is repeated.
        self.assertNotEqual(cache._semantic_cache_key(first_snapshot), cache._semantic_cache_key(extended_snapshot))
        with patch("src.LLM.privoke.pretrained_context_model.FrozenPretrainedEncoder", side_effect=FeatureEncoder) as load:
            first = cache._model_for_snapshot(first_snapshot)
            extended = cache._model_for_snapshot(extended_snapshot)
            self.assertEqual(extended.model.encoder.max_tokens, 512)
            self.assertIsNot(first.model.encoder, extended.model.encoder)
            returned = cache._model_for_snapshot(first_snapshot)
            self.assertIs(returned.model.encoder, first.model.encoder)
            self.assertEqual(load.call_count, 2)
            cache.clear()
            cache._model_for_snapshot(first_snapshot)
            self.assertEqual(load.call_count, 3)
        with self.assertRaisesRegex(ValueError, "max_tokens mismatch"):
            StreamedPretrainedContextModel(extended_snapshot, FeatureEncoder())

    def test_verified_byte_loader_hash_bounds_and_fixed_local_file(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "model.onnx"
            path.write_bytes(b"model")
            digest = hashlib.sha256(b"model").hexdigest()
            self.assertEqual(_verified_bytes(Path(temporary), "model.onnx", digest, 5), b"model")
            for expected, maximum in (("a" * 64, 5), (digest, 4)):
                with self.assertRaises(ValueError):
                    _verified_bytes(Path(temporary), "model.onnx", expected, maximum)
            path.unlink()
            with self.assertRaises(ValueError):
                _verified_bytes(Path(temporary), "model.onnx", digest, 5)

    def test_graph_pooling_norm_dependency_signature_overlength_and_nonfinite(self):
        for settings in ({}, {"length": 257}, {"nonfinite": True}, {"invalid_signature": True}):
            with self.subTest(settings=settings), \
                    patch.dict(sys.modules, fake_dependencies(**settings)), \
                    patch("src.pretrained_context._verified_bytes", return_value=b"{}"), \
                    patch.object(np, "__version__", "2.2.6"):
                if settings:
                    with self.assertRaises(ValueError):
                        FrozenPretrainedEncoder("local-assets").encode("Synthetic")
                else:
                    encoder = FrozenPretrainedEncoder("local-assets")
                    vector = encoder.encode("Synthetic")
                    self.assertEqual(vector.dtype, np.float32)
                    self.assertAlmostEqual(float(np.linalg.norm(vector)), 1., places=6)
                    np.testing.assert_array_equal(encoder.features(["Synthetic"])[0], vector)
        with patch.dict(sys.modules, {"onnxruntime": None}), patch("src.pretrained_context._verified_bytes", return_value=b"{}"):
            with self.assertRaisesRegex(RuntimeError, "dependencies"):
                FrozenPretrainedEncoder("local-assets")
        with patch.dict("os.environ", {}, clear=True), self.assertRaisesRegex(ValueError, "DIR"):
            FrozenPretrainedEncoder()

    def test_head_predictions_owned_weights_and_clean_envelope(self):
        snapshot = snapshot_for()
        wrapper = StreamedPretrainedContextModel(snapshot, FeatureEncoder())
        result = wrapper.classify("synthetic")[0]
        self.assertEqual(result.classification.to_dict(), {"sensitivity": "S2", "visibility": "PU", "categories": ["FINANCIAL"]})
        self.assertEqual(result.metadata["classifier"], "privoke_pretrained_context")
        self.assertEqual(result.metadata["artifact_checksum"], "a" * 64)
        with self.assertRaises(ValueError):
            wrapper.model.parameters["head.category.bias"][0] = 0.
        snapshot.metadata["artifact_checksum"] = "b" * 64
        self.assertEqual(wrapper.snapshot.metadata["artifact_checksum"], "a" * 64)
        self.assertEqual(StreamedPretrainedContextModel(snapshot_for(clean=True), FeatureEncoder()).classify("synthetic"), [])

    def test_cache_dispatch_both_entrypoints_checksum_refresh_encoder_reuse_latest_rejection(self):
        cache = StreamedModelCache(0)
        snapshot = snapshot_for()
        streamer = SimpleNamespace(target="synthetic", model_id=PRETRAINED_CONTEXT_MODEL_ID, fetch=lambda: snapshot)
        with patch("src.LLM.privoke.pretrained_context_model.FrozenPretrainedEncoder", return_value=FeatureEncoder()) as load:
            first = cache.semantic_model_for_streamer(streamer)
            self.assertIs(first, cache.semantic_model_for_streamer(streamer))
            for version in ("", "has space", "café", ".leading", "x" * 129):
                with self.subTest(version=version), self.assertRaisesRegex(ValueError, "version"):
                    StreamedPretrainedContextModel(replace(snapshot, version=version), FeatureEncoder())
            snapshot = replace(snapshot, metadata=dict(snapshot.metadata, artifact_checksum="b" * 64))
            second = cache.semantic_model_for_streamer(streamer)
            self.assertIsNot(first, second)
            self.assertIs(first.model.encoder, second.model.encoder)
            direct = cache._model_for_snapshot(snapshot)
            self.assertIsInstance(direct, StreamedPretrainedContextModel)
            with self.assertRaisesRegex(ValueError, "timestamp"):
                cache._model_for_snapshot(replace(snapshot, generated_at_unix=0))
            self.assertEqual(load.call_count, 1)
            with self.assertRaisesRegex(ValueError, "explicit"):
                cache.semantic_model_for_streamer(SimpleNamespace(target="synthetic", model_id="latest", fetch=lambda: snapshot))
            with self.assertRaisesRegex(ValueError, "unsupported"):
                cache.model_for_training(streamer)
        with patch("src.LLM.privoke.training.ModelParameterStreamer") as construct:
            with self.assertRaisesRegex(ValueError, "unsupported"):
                compute_semantic_gradients([], model_id=PRETRAINED_CONTEXT_MODEL_ID, learning_rate=.01, max_gradient=.01)
            construct.assert_not_called()

    def test_semantic_only_rpc_success_clean_and_visible_error(self):
        for clean, text in ((False, "Synthetic [at] example"), (True, "Synthetic"), (False, "overlength")):
            cache = StreamedModelCache(0)
            snapshot = snapshot_for(clean=clean)
            detector = PriVokeClassifier(model_id=PRETRAINED_CONTEXT_MODEL_ID)
            request = runtime_pb2.AnalyzePromptRequest(text=text, request_id="synthetic-test",
                layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC], semantic_model_id=PRETRAINED_CONTEXT_MODEL_ID,
                metadata={"privoke.pretrained_context.model_id": "spoofed"})
            with patch("src.pipeline.get_llm_choice", return_value=detector), \
                    patch("src.LLM.privoke.parameter_stream.ModelParameterStreamer.fetch", return_value=snapshot), \
                    patch("src.LLM.privoke_classifier.GLOBAL_STREAMED_MODEL_CACHE", cache), \
                    patch("src.LLM.privoke.streamed_model.GLOBAL_STREAMED_MODEL_CACHE", cache), \
                    patch("src.LLM.privoke.pretrained_context_model.FrozenPretrainedEncoder", return_value=FeatureEncoder()):
                response = PrivokeRuntimeService().AnalyzePrompt(request, None)
            if text == "overlength":
                self.assertIn("256-token", response.error)
            else:
                self.assertEqual(response.error, "")
            self.assertEqual(len(response.layers), 1)
            layer = response.layers[0]
            self.assertEqual(layer.layer, runtime_pb2.DETECTION_LAYER_SEMANTIC)
            self.assertEqual(response.metadata["privoke.pretrained_context.model_id"], PRETRAINED_CONTEXT_MODEL_ID)
            self.assertEqual(response.metadata["privoke.pretrained_context.artifact_checksum"], snapshot.metadata["artifact_checksum"])
            self.assertEqual(layer.status, "error" if text == "overlength" else "ok")
            if text == "overlength":
                self.assertIn("256-token", layer.error)
            else:
                self.assertEqual(layer.error, "")
                self.assertEqual(len(layer.results), 0 if clean else 1)
                if not clean:
                    self.assertEqual(layer.results[0].metadata["model_id"], PRETRAINED_CONTEXT_MODEL_ID)
                    self.assertEqual(layer.results[0].metadata["artifact_checksum"], snapshot.metadata["artifact_checksum"])

    def test_failed_asset_admission_never_returns_spoofed_identity(self):
        request = runtime_pb2.AnalyzePromptRequest(text="Synthetic", request_id="synthetic-test",
            layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC], semantic_model_id=PRETRAINED_CONTEXT_MODEL_ID,
            metadata={"privoke.pretrained_context.model_id": "spoofed"})
        with patch("src.pipeline.get_llm_choice", side_effect=ValueError("Missing verified assets")):
            response = PrivokeRuntimeService().AnalyzePrompt(request, None)
        self.assertEqual(len(response.layers), 1)
        self.assertEqual(response.layers[0].layer, runtime_pb2.DETECTION_LAYER_SEMANTIC)
        self.assertEqual(response.layers[0].status, "error")
        self.assertFalse(any(key.startswith("privoke.pretrained_context.") for key in response.metadata))

    def test_early_normalization_error_cannot_echo_reserved_identity(self):
        request = runtime_pb2.AnalyzePromptRequest(text="Synthetic", request_id="synthetic-test",
            layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC], semantic_model_id=PRETRAINED_CONTEXT_MODEL_ID,
            metadata={"privoke.pretrained_context.model_id": "spoofed", "caller_tag": "retained"})
        with patch("src.pipeline.normalize_with_offsets", side_effect=ValueError("Synthetic normalization failure")):
            response = PrivokeRuntimeService().AnalyzePrompt(request, None)
        self.assertEqual(len(response.layers), 1)
        self.assertEqual(response.layers[0].layer, runtime_pb2.DETECTION_LAYER_SEMANTIC)
        self.assertEqual(response.layers[0].status, "error")
        self.assertFalse(any(key.startswith("privoke.pretrained_context.") for key in response.metadata))


if __name__ == "__main__":
    unittest.main()
