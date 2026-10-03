from __future__ import annotations
import math
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PACKAGE_ROOT.parents[1]
for path in (PACKAGE_ROOT, REPO_ROOT / "shared/python"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from src.classification import (
    Category, ClassificationResult, Sensitivity, Visibility, initialise_unpacked,
)
from src.config import GLOBAL_CONFIG
from src.pipeline import (
    LayerExecution,
    SemanticPresenceGateRequest,
    _presence_model_for_semantic_detector,
    analyse_text,
)

try:
    from privoke.v1 import runtime_pb2
    from src.hosting.grpc_server import _semantic_presence_gate, _layer_execution
    from src.config import LLMChoice
except ImportError:
    runtime_pb2 = None
    _semantic_presence_gate = None
    _layer_execution = None
    LLMChoice = None


def finding(section, *, sensitivity=Sensitivity.S2, span=None):
    return ClassificationResult(
        classification=initialise_unpacked(sensitivity, Visibility.PU, [Category.IDENTITY]),
        section_of_text=section,
        reasoning="test finding",
        span=span,
        confidence=0.9,
    )


def fake_context_model(results):
    snapshot = SimpleNamespace(
        model_id="privoke-balanced",
        version="v-original",
        metadata={"artifact_checksum": "a" * 64},
        fingerprint="b" * 64,
    )
    return SimpleNamespace(snapshot=snapshot, classify=lambda text: results)


def fake_presence_model(probability, threshold=0.5, model_id="privoke-presence-balanced"):
    snapshot = SimpleNamespace(
        metadata={"artifact_checksum": "c" * 64},
        fingerprint="d" * 64,
    )
    return SimpleNamespace(
        model_id=model_id,
        version="v-presence",
        snapshot=snapshot,
        threshold=threshold,
        predict_probability=lambda text: probability,
    )


class SemanticPresenceGateTests(unittest.TestCase):
    def _analyze(self, probability, *, threshold=None, context_results=None, layers=None, regex_first=False):
        gate = SemanticPresenceGateRequest("privoke-presence-balanced", threshold)
        semantic_model = fake_context_model(context_results if context_results is not None else [finding("mail", span=(0, 4))])
        presence_model = fake_presence_model(probability)
        detector_results = {
            "regex": [finding("regex", sensitivity=Sensitivity.S1)],
            "ner": [finding("entity", sensitivity=Sensitivity.S1)],
        }
        def detector_for(layer, semantic_model_id=None):
            return lambda text: detector_results.get(layer, [])
        with (
            patch("src.pipeline.get_llm_choice", return_value=SimpleNamespace(streamer=SimpleNamespace(
                target="stream.example:50051", model_id="privoke-balanced", consumer_id="runtime-test", timeout_seconds=8.0
            ))),
            patch("src.pipeline._streamed_model_for_semantic_detector", return_value=semantic_model),
            patch("src.pipeline._presence_model_for_semantic_detector", return_value=presence_model),
            patch("src.pipeline._detector_for", side_effect=detector_for),
            patch.object(GLOBAL_CONFIG.threadpool, "map", side_effect=lambda fn, values: [fn(v) for v in values]),
        ):
            return analyse_text(
                "mail  text", layers=layers or ("regex", "ner", "semantic"),
                regex_first=regex_first, semantic_model_id="privoke-balanced",
                semantic_presence_gate=gate,
            )

    def test_absent_suppresses_only_semantic_contribution_and_keeps_trace_spans(self):
        analysis = self._analyze(0.49)
        by_layer = {layer.layer: layer for layer in analysis.layers}
        self.assertTrue(by_layer["regex"].results)
        self.assertTrue(by_layer["ner"].results)
        self.assertEqual(by_layer["semantic"].results, ())
        trace = by_layer["semantic"].semantic_presence_gate
        self.assertEqual(trace.status, "APPLIED")
        self.assertEqual(trace.predicted_label, "ABSENT")
        self.assertEqual(trace.semantic_results[0].span, (0, 4))
        self.assertEqual(trace.semantic_results[0].section_of_text, "mail")

    def test_present_keeps_original_semantic_findings_and_uses_snapshot_identity(self):
        analysis = self._analyze(0.5)
        semantic = next(layer for layer in analysis.layers if layer.layer == "semantic")
        self.assertEqual(len(semantic.results), 1)
        trace = semantic.semantic_presence_gate
        self.assertEqual(trace.status, "APPLIED")
        self.assertEqual(trace.predicted_label, "PRESENT")
        self.assertEqual(trace.contextual_model_id, "privoke-balanced")
        self.assertEqual(trace.contextual_model_version, "v-original")
        self.assertEqual(trace.contextual_artifact_checksum, "a" * 64)
        self.assertEqual(trace.contextual_parameter_fingerprint, "b" * 64)
        self.assertEqual(trace.semantic_results, semantic.results)

    def test_empty_safe_semantic_results_still_trace_contextual_model_identity(self):
        analysis = self._analyze(0.9, context_results=[])
        trace = next(layer for layer in analysis.layers if layer.layer == "semantic").semantic_presence_gate
        self.assertEqual(trace.semantic_results, ())
        self.assertEqual(trace.contextual_model_id, "privoke-balanced")
        self.assertEqual(trace.contextual_model_version, "v-original")

    def test_threshold_overrides_are_inclusive_at_zero_and_one(self):
        self.assertEqual(self._analyze(0.0, threshold=0.0).layers[-1].semantic_presence_gate.predicted_label, "PRESENT")
        self.assertEqual(self._analyze(1.0, threshold=1.0).layers[-1].semantic_presence_gate.predicted_label, "PRESENT")
        self.assertEqual(self._analyze(0.0, threshold=1.0).layers[-1].semantic_presence_gate.predicted_label, "ABSENT")

    def test_presence_failure_retains_semantic_results_and_fails_closed(self):
        semantic_model = fake_context_model([finding("mail", span=(0, 4))])
        detector = SimpleNamespace(streamer=SimpleNamespace())
        with (
            patch("src.pipeline.get_llm_choice", return_value=detector),
            patch("src.pipeline._streamed_model_for_semantic_detector", return_value=semantic_model),
            patch("src.pipeline._presence_model_for_semantic_detector", side_effect=RuntimeError("presence stream unavailable")),
        ):
            analysis = analyse_text(
                "mail text", layers=["semantic"], semantic_model_id="privoke-balanced",
                semantic_presence_gate=SemanticPresenceGateRequest("privoke-presence-efficient"),
            )
        layer = analysis.layers[0]
        self.assertEqual(layer.status, "error")
        self.assertEqual(len(layer.results), 1)
        self.assertEqual(layer.semantic_presence_gate.status, "ERROR")
        self.assertEqual(layer.semantic_presence_gate.semantic_results, layer.results)
        self.assertEqual(analysis.action.name, "WARN")
        self.assertEqual(layer.semantic_presence_gate.contextual_model_id, "privoke-balanced")
        self.assertIn("presence stream unavailable", layer.error)

    def test_context_model_failure_after_fetch_preserves_its_identity(self):
        model = fake_context_model([])
        model.classify = lambda text: (_ for _ in ()).throw(RuntimeError("semantic inference failed"))
        with (
            patch("src.pipeline.get_llm_choice", return_value=SimpleNamespace(streamer=object())),
            patch("src.pipeline._streamed_model_for_semantic_detector", return_value=model),
            patch("src.pipeline._presence_model_for_semantic_detector") as presence_fetch,
        ):
            analysis = analyse_text(
                "mail text", layers=["semantic"], semantic_model_id="privoke-balanced",
                semantic_presence_gate=SemanticPresenceGateRequest("privoke-presence-balanced"),
            )
        trace = analysis.layers[0].semantic_presence_gate
        self.assertEqual(trace.status, "NOT_RUN")
        self.assertEqual(trace.contextual_model_id, "privoke-balanced")
        self.assertIn("semantic inference failed", trace.error)
        presence_fetch.assert_not_called()

    def test_contextual_failure_is_not_hidden_and_gate_is_not_run(self):
        with patch("src.pipeline.get_llm_choice", side_effect=RuntimeError("context model unavailable")):
            analysis = analyse_text(
                "mail text", layers=["semantic"], semantic_model_id="privoke-balanced",
                semantic_presence_gate=SemanticPresenceGateRequest("privoke-presence-balanced"),
            )
        layer = analysis.layers[0]
        self.assertEqual(layer.status, "error")
        self.assertEqual(layer.semantic_presence_gate.status, "NOT_RUN")
        self.assertIn("context model unavailable", layer.error)
        self.assertEqual(analysis.action.name, "BLOCK")

    def test_invalid_presence_probabilities_fail_without_suppressing_semantics(self):
        for probability in (math.nan, math.inf, -0.01, 1.01):
            with self.subTest(probability=probability):
                semantic_model = fake_context_model([finding("mail", span=(0, 4))])
                presence_model = fake_presence_model(probability)
                with (
                    patch("src.pipeline.get_llm_choice", return_value=SimpleNamespace(streamer=object())),
                    patch("src.pipeline._streamed_model_for_semantic_detector", return_value=semantic_model),
                    patch("src.pipeline._presence_model_for_semantic_detector", return_value=presence_model),
                ):
                    analysis = analyse_text(
                        "mail text", layers=["semantic"], semantic_model_id="privoke-balanced",
                        semantic_presence_gate=SemanticPresenceGateRequest("privoke-presence-balanced"),
                    )
                layer = analysis.layers[0]
                self.assertEqual(layer.status, "error")
                self.assertEqual(len(layer.results), 1)
                self.assertEqual(layer.semantic_presence_gate.status, "ERROR")
                self.assertIn("probability must be finite", layer.error)

    def test_regex_first_block_short_circuits_gate_with_not_run_trace(self):
        block = finding("secret", sensitivity=Sensitivity.S3, span=(0, 6))
        with (
            patch("src.pipeline._detector_for", return_value=lambda text: [block]),
            patch("src.pipeline._streamed_model_for_semantic_detector") as semantic_fetch,
        ):
            analysis = analyse_text(
                "secret", layers=["regex", "semantic"], regex_first=True,
                semantic_model_id="privoke-balanced",
                semantic_presence_gate=SemanticPresenceGateRequest("privoke-presence-balanced"),
            )
        semantic = analysis.layers[1]
        self.assertEqual(semantic.status, "skipped")
        self.assertEqual(semantic.semantic_presence_gate.status, "NOT_RUN")
        semantic_fetch.assert_not_called()
        self.assertEqual(analysis.action.name, "BLOCK")

    def test_default_path_has_no_gate_trace_or_presence_fetch(self):
        result = finding("mail", span=(0, 4))
        with (
            patch("src.pipeline._detector_for", return_value=lambda text: [result]),
            patch("src.pipeline._presence_model_for_semantic_detector") as presence_fetch,
        ):
            analysis = analyse_text("mail text", layers=["semantic"], semantic_model_id="privoke-balanced")
        self.assertEqual(len(analysis.layers[0].results), 1)
        self.assertIsNone(analysis.layers[0].semantic_presence_gate)
        presence_fetch.assert_not_called()

    def test_gate_model_threshold_validation(self):
        for model_id in ("latest", "privoke-balanced", "privoke-presence-other", ""):
            with self.subTest(model_id=model_id), self.assertRaises(ValueError):
                SemanticPresenceGateRequest(model_id)
        for threshold in (True, -0.01, 1.01, math.nan, math.inf, "0.5"):
            with self.subTest(threshold=threshold), self.assertRaises(ValueError):
                SemanticPresenceGateRequest("privoke-presence-efficient", threshold)

    def test_presence_stream_uses_contextual_target_consumer_and_timeout(self):
        detector = SimpleNamespace(streamer=SimpleNamespace(
            target="configured-target:50051", model_id="privoke-balanced",
            consumer_id="caller-a", timeout_seconds=3.5,
        ))
        calls = {}
        def factory(**kwargs):
            calls.update(kwargs)
            return "presence-streamer"
        cache = SimpleNamespace(presence_model_for_streamer=lambda streamer: (streamer, "model"))
        self.assertEqual(
            _presence_model_for_semantic_detector(
                detector, SemanticPresenceGateRequest("privoke-presence-quality"),
                streamer_factory=factory, model_cache=cache,
            ),
            ("presence-streamer", "model"),
        )
        self.assertEqual(calls, {
            "target": "configured-target:50051", "model_id": "privoke-presence-quality",
            "consumer_id": "caller-a", "timeout_seconds": 3.5,
        })


@unittest.skipIf(runtime_pb2 is None, "Generated protobuf/grpc dependencies are supplied by the runtime test image.")
class SemanticPresenceGateRPCTests(unittest.TestCase):
    def _request(self, **kwargs):
        request = runtime_pb2.AnalyzePromptRequest(
            text="sample", semantic_model_id=kwargs.pop("semantic_model_id", "privoke-balanced"),
            layers=kwargs.pop("layers", [runtime_pb2.DETECTION_LAYER_SEMANTIC]),
        )
        gate = kwargs.pop("gate", True)
        if gate:
            model_id = kwargs.pop("model_id", "privoke-presence-balanced")
            threshold = kwargs.pop("threshold", None)
            request.semantic_presence_gate.model_id = model_id
            if threshold is not None:
                request.semantic_presence_gate.threshold = threshold
        return request

    def test_rpc_validation_requires_explicit_original_streamed_semantic_layer(self):
        with patch("src.hosting.grpc_server.GLOBAL_CONFIG.get_llm_config",
                   return_value=SimpleNamespace(choice=LLMChoice.Streamed)):
            self.assertEqual(_semantic_presence_gate(self._request(), ("semantic",)).model_id,
                             "privoke-presence-balanced")
            for request, layers, message in (
                (self._request(model_id="privoke-presence-other"), ("semantic",), "three supported"),
                (self._request(layers=[runtime_pb2.DETECTION_LAYER_REGEX]), ("regex",), "semantic layer"),
                (self._request(semantic_model_id="latest"), ("semantic",), "explicit semantic_model_id"),
            ):
                with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                    _semantic_presence_gate(request, layers)

    def test_rpc_validation_rejects_nonstreamed_backend_and_bad_threshold(self):
        with patch("src.hosting.grpc_server.GLOBAL_CONFIG.get_llm_config",
                   return_value=SimpleNamespace(choice=LLMChoice.Local)):
            with self.assertRaisesRegex(ValueError, "streamed backend"):
                _semantic_presence_gate(self._request(), ("semantic",))
        request = self._request(threshold=1.5)
        with patch("src.hosting.grpc_server.GLOBAL_CONFIG.get_llm_config",
                   return_value=SimpleNamespace(choice=LLMChoice.Streamed)):
            with self.assertRaisesRegex(ValueError, r"finite and in \[0, 1\]"):
                _semantic_presence_gate(request, ("semantic",))

    def test_runtime_layer_serializes_typed_gate_trace_and_contextual_identity(self):
        trace = SimpleNamespace(
            status="APPLIED", model_id="privoke-presence-quality", model_version="presence-v2",
            artifact_checksum="a"*64, parameter_fingerprint="b"*64, probability=0.25,
            model_threshold=0.4, decision_threshold=0.3, predicted_label="ABSENT",
            semantic_results=(), error=None, contextual_model_id="privoke-balanced",
            contextual_model_version="ctx-v5", contextual_artifact_checksum="c"*64,
            contextual_parameter_fingerprint="d"*64,
        )
        execution = LayerExecution("semantic", "ok", (), semantic_presence_gate=trace)
        response = _layer_execution(execution)
        self.assertTrue(response.HasField("semantic_presence_gate"))
        self.assertEqual(response.semantic_presence_gate.status,
                         runtime_pb2.SEMANTIC_PRESENCE_GATE_STATUS_APPLIED)
        self.assertEqual(response.semantic_presence_gate.predicted_label,
                         runtime_pb2.ANNOTATION_PRESENCE_ABSENT)
        self.assertEqual(response.semantic_presence_gate.contextual_model_id, "privoke-balanced")
        self.assertEqual(response.semantic_presence_gate.probability, 0.25)


if __name__ == "__main__":
    unittest.main()
