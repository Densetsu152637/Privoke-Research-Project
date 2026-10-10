"""Synthetic runtime/transport checks; actual generated protobuf is mandatory."""
from __future__ import annotations

import json
import math
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
for path in (PACKAGE_ROOT, PACKAGE_ROOT / "generated", PACKAGE_ROOT.parents[1] / "shared/python"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from privoke.v1 import parameters_pb2, runtime_pb2
from privoke_model.artifact import MAX_ARTIFACT_BYTES
from privoke_model.scratch_presence import (
    CONSTANT_CONFIG, DIMENSION_KEYS, SCRATCH_PRESENCE_ARCHITECTURE,
    SCRATCH_PRESENCE_MODEL_IDS, SCRATCH_PROFILES, scratch_presence_tensor_shapes,
    scratch_presence_trainable_names,
)
from src.LLM.privoke.parameter_stream import ModelParameterStreamer, ParameterSnapshot
from src.LLM.privoke.scratch_presence_model import StreamedScratchPresenceModel
from src.LLM.privoke.streamed_model import StreamedModelCache, StreamedTransformerPrivacyModel
from src.classification import ClassificationResult, Category, Sensitivity, Visibility, initialise_unpacked
from src.config import GLOBAL_CONFIG
from src.detection.preprocessing import normalize_text, normalize_with_offsets
from src.hosting.grpc_server import PrivokeRuntimeService, _layer_execution
from src.pipeline import SemanticPresenceGateRequest, analyse_text


def snapshot_for(profile="efficient", mode="head_only", bias=None):
    suffix = "head-only" if mode == "head_only" else "full-encoder"
    model_id = f"privoke-scratch-presence-{profile}-{suffix}"
    config = dict(CONSTANT_CONFIG, profile=profile, training_mode=mode, threshold=0.5,
                  **dict(zip(DIMENSION_KEYS, SCRATCH_PROFILES[profile])))
    shapes = scratch_presence_tensor_shapes(config)
    rng = np.random.default_rng(913)
    parameters = {name: tuple(float(value) for value in rng.normal(0, .08, math.prod(shape)).astype(np.float32))
                  for name, shape in shapes.items()}
    if bias is not None:
        parameters["head.presence.bias"] = (float(np.float32(bias)),)
        parameters["head.presence.weight"] = (0.0,) * config["hidden_size"]
    metadata = {"training_route": "offline_release_fit_v1", "source_revision": "a" * 40,
                "study_plan_sha256": "b" * 64, "prepared_manifest_sha256": "c" * 64,
                "initialization_sha256": "d" * 64, "trainer_contract_sha256": "e" * 64,
                "checkpoint_epoch": "1", "training_steps": "490", "training_seed": "12102026",
                "architecture": SCRATCH_PRESENCE_ARCHITECTURE, "model_config": json.dumps(config),
                "artifact_checksum": "1" * 64, "artifact_file_checksum": "2" * 64,
                "trainable_parameters": ",".join(scratch_presence_trainable_names(config)),
                "served_by": "model-streaming-service", "consumer_id": "runtime-test"}
    for stream, key in (("task", "task"), ("profile", "profile"), ("training_mode", "training_mode"),
                        ("text_normalization", "normalization"), ("tokenizer", "tokenizer"),
                        ("pooling", "pooling"), ("arithmetic", "arithmetic")):
        metadata[stream] = config[key]
    return ParameterSnapshot(model_id, "v1.0.0+epoch.1", 1, parameters, shapes, metadata)


def chunks_for(snapshot):
    chunks = []
    for name in sorted(snapshot.parameters):
        values = snapshot.parameters[name]
        for offset in range(0, len(values), 1024):
            chunks.append(parameters_pb2.ModelParameterChunk(
                model_id=snapshot.model_id, version=snapshot.version, generated_at_unix=snapshot.generated_at_unix,
                parameter=parameters_pb2.ParameterChunk(name=name, shape=snapshot.shapes[name], value_offset=offset,
                                                       values=values[offset:offset + 1024]),
                metadata=snapshot.metadata if not chunks else {}, chunk_index=len(chunks),
            ))
    for chunk in chunks:
        chunk.total_chunks = len(chunks)
    return chunks


def fetch_chunks(chunks, model_id):
    streamer = ModelParameterStreamer(target="127.0.0.1:50051", model_id=model_id)
    stub = SimpleNamespace(StreamModelParameters=lambda request, timeout: iter(chunks))
    with patch("src.LLM.privoke.parameter_stream.grpc_channel", return_value=nullcontext(object())), \
         patch("src.LLM.privoke.parameter_stream.parameters_pb2_grpc.ModelStreamingServiceStub", return_value=stub):
        return streamer.fetch()


def contextual_result():
    return ClassificationResult(initialise_unpacked(Sensitivity.S2, Visibility.P4, [Category.HEALTH]),
                                section_of_text="mail", reasoning="synthetic finding", span=(0, 4), confidence=.9)


def run_gate(model, threshold, *, text="mail", regex_block=False, detector_results=None, context_results=None):
    snapshot = SimpleNamespace(model_id="privoke-balanced", version="v-context",
                               metadata={"artifact_checksum": "a" * 64}, fingerprint="b" * 64)
    contextual = SimpleNamespace(snapshot=snapshot, classify=lambda text: [contextual_result()] if context_results is None else context_results)
    def detectors(layer, semantic_model_id=None):
        if regex_block and layer == "regex":
            result = ClassificationResult(initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.IDENTITY]),
                                          section_of_text="mail", reasoning="synthetic regex", span=(0, 4), confidence=.9)
            return lambda text: [result]
        return lambda text: (detector_results or {}).get(layer, [])
    with patch("src.pipeline.get_llm_choice", return_value=SimpleNamespace(streamer=object())), \
         patch("src.pipeline._streamed_model_for_semantic_detector", return_value=contextual), \
         patch("src.pipeline._presence_model_for_semantic_detector", return_value=model) as fetch, \
         patch("src.pipeline._detector_for", side_effect=detectors), \
         patch.object(GLOBAL_CONFIG.threadpool, "map", side_effect=lambda fn, values: [fn(v) for v in values]):
        result = analyse_text(text, layers=("regex", "ner", "semantic"), regex_first=regex_block,
                              semantic_model_id="privoke-balanced",
                              semantic_presence_gate=SemanticPresenceGateRequest(model.model_id, threshold))
    return result, fetch


class ScratchPresenceRuntimeTests(unittest.TestCase):
    def test_all_six_ids_are_binary_cpu_only_and_contextual_dispatch_rejects(self):
        for model_id in sorted(SCRATCH_PRESENCE_MODEL_IDS):
            profile = model_id.split("-")[3]
            mode = "head_only" if model_id.endswith("head-only") else "end_to_end"
            model = StreamedScratchPresenceModel(snapshot_for(profile, mode))
            self.assertEqual(model.model_id, model_id)
            self.assertEqual(model.threshold, .5)
            self.assertTrue(0 <= model.predict_probability("synthetic mail") <= 1)
            self.assertNotIn("head.sensitivity.weight", model.snapshot.parameters)
            with self.assertRaises(ValueError):
                StreamedTransformerPrivacyModel(model.snapshot)

    def test_owned_snapshot_and_arrays_cannot_be_changed(self):
        snapshot = snapshot_for()
        model = StreamedScratchPresenceModel(snapshot)
        probability = model.predict_probability("mail")
        snapshot.metadata["artifact_checksum"] = "9" * 64
        snapshot.parameters["head.presence.bias"] = (10.0,)
        self.assertEqual(model.predict_probability("mail"), probability)
        self.assertEqual(model.snapshot.metadata["artifact_checksum"], "1" * 64)
        with self.assertRaises(TypeError):
            model.snapshot.metadata["artifact_checksum"] = "9" * 64
        with self.assertRaises(FrozenInstanceError):
            model.snapshot = snapshot
        with self.assertRaises(ValueError):
            model._weight.setflags(write=True)

    def test_raw_and_canonical_boundaries_match_without_second_normalization(self):
        model = StreamedScratchPresenceModel(snapshot_for())
        for text in ("\u212a\ufb03 1 2\n\nMail [AT] EXAMPLE", "e\u0301 (at) name\t\tvalue", "\u0130\u00df 4 5"):
            canonical = normalize_with_offsets(text).text
            expected = model.predict_normalized_probability(canonical)
            with patch("src.LLM.privoke.scratch_presence_model.normalize_text", wraps=normalize_text) as normalize:
                self.assertEqual(model.predict_probability(text), expected)
                normalize.assert_called_once_with(text)
            with patch("src.LLM.privoke.scratch_presence_model.normalize_text", side_effect=AssertionError("double normalization")):
                analysis, _ = run_gate(model, .5, text=text)
            trace = analysis.layers[-1].semantic_presence_gate
            self.assertEqual(trace.status, "APPLIED")
            self.assertEqual(trace.probability, expected)

    def test_nonfinite_internal_encoder_and_logit_fail_instead_of_clean_prediction(self):
        for tensor in ("attention.query.weight", "head.presence.weight"):
            snapshot = snapshot_for()
            snapshot.parameters[tensor] = (float(np.finfo(np.float32).max),) * len(snapshot.parameters[tensor])
            model = StreamedScratchPresenceModel(snapshot)
            with np.errstate(over="ignore", invalid="ignore"), self.assertRaises(ValueError):
                model.predict_probability("overflow")

    def test_cache_coalesces_concurrent_fetch_and_refreshes_provenance(self):
        snapshot = snapshot_for()
        calls = []
        streamer = SimpleNamespace(target="synthetic:50051", model_id=snapshot.model_id,
                                   fetch=lambda: calls.append(1) or snapshot)
        cache = StreamedModelCache(refresh_interval_seconds=60)
        with ThreadPoolExecutor(max_workers=8) as pool:
            models = list(pool.map(lambda _: cache.annotation_presence_model_for_streamer(streamer), range(16)))
        self.assertEqual(len(calls), 1)
        self.assertTrue(all(model is models[0] for model in models))
        first = models[0]
        snapshot = replace(snapshot, metadata=dict(snapshot.metadata, artifact_checksum="3" * 64, source_revision="f" * 40))
        refreshed = cache.annotation_presence_model_for_streamer(streamer, force_refresh=True)
        self.assertIsNot(refreshed, first)
        self.assertEqual(first.snapshot.metadata["artifact_checksum"], "1" * 64)
        self.assertEqual(first.predict_probability("mail"), refreshed.predict_probability("mail"))
        self.assertEqual(first.snapshot.fingerprint, refreshed.snapshot.fingerprint)
        self.assertEqual(len(calls), 2)
        cache.clear()
        self.assertIsNot(cache.annotation_presence_model_for_streamer(streamer), refreshed)

    def test_cache_isolates_modes_and_denies_bad_refresh_even_same_fingerprint(self):
        cache = StreamedModelCache(refresh_interval_seconds=60)
        head = snapshot_for()
        full = snapshot_for(mode="end_to_end")
        models = [cache.annotation_presence_model_for_streamer(SimpleNamespace(target="same", model_id=s.model_id, fetch=lambda s=s:s))
                  for s in (head, full)]
        self.assertIsNot(models[0], models[1])
        self.assertEqual(models[0].snapshot.fingerprint, models[1].snapshot.fingerprint)
        invalid = replace(head, metadata=dict(head.metadata, training_seed="bad"))
        streamer = SimpleNamespace(target="same", model_id=head.model_id, fetch=lambda:invalid)
        with self.assertRaises(ValueError):
            cache.annotation_presence_model_for_streamer(streamer, force_refresh=True)
        self.assertEqual(models[0].snapshot.metadata["training_seed"], "12102026")
        mismatch = SimpleNamespace(target="same", model_id=head.model_id, fetch=lambda:full)
        with self.assertRaises(RuntimeError):
            cache.annotation_presence_model_for_streamer(mismatch, force_refresh=True)
        with self.assertRaises(ValueError):
            cache.presence_model_for_training(SimpleNamespace(target="other", model_id=head.model_id, fetch=lambda:head))

    def test_complete_stream_replays_exact_float32_shapes_and_metadata(self):
        for profile in SCRATCH_PROFILES:
            snapshot = snapshot_for(profile)
            result = fetch_chunks(chunks_for(snapshot), snapshot.model_id)
            self.assertEqual(result.parameters, snapshot.parameters)
            self.assertEqual(result.shapes, snapshot.shapes)
            self.assertEqual(result.metadata, snapshot.metadata)
            self.assertEqual(result.fingerprint, snapshot.fingerprint)
            StreamedScratchPresenceModel(result)

    def test_first_metadata_guard_runs_before_parameter_access(self):
        class First:
            chunk_index, total_chunks, generated_at_unix = 0, 1, 1
            model_id, version = snapshot_for().model_id, "v1.0.0+epoch.1"
            metadata = {"architecture": "privoke_tiny_transformer_v1"}
            @property
            def parameter(self):
                raise AssertionError("tensor accessed before first metadata validation")
        with self.assertRaises(ValueError):
            fetch_chunks([First()], First.model_id)

    def test_later_nonempty_metadata_rejected_before_merging(self):
        snapshot = snapshot_for()
        for change in ({"artifact_checksum": "1" * 64}, {"architecture": "privoke_tiny_transformer_v1"},
                       {"model_config": snapshot.metadata["model_config"]}, {"unrecognized": "x"}):
            chunks = chunks_for(snapshot)
            chunks[1].metadata.update(change)
            with self.assertRaisesRegex(RuntimeError, "only on the first"):
                fetch_chunks(chunks, snapshot.model_id)

    def test_architecture_cannot_escape_requested_identity_or_late_discriminator(self):
        snapshot = snapshot_for()
        for requested in ("latest", "privoke-balanced", "privoke-scratch-presence-other"):
            with self.assertRaises(RuntimeError):
                fetch_chunks(chunks_for(snapshot), requested)
        for first_metadata in ({}, {"architecture": "privoke_tiny_transformer_v1"}):
            chunks = chunks_for(snapshot)
            chunks[0].metadata.clear()
            chunks[0].metadata.update(first_metadata)
            with self.assertRaises(ValueError):
                fetch_chunks(chunks, snapshot.model_id)
        # A legacy first chunk cannot acquire the scratch discriminator afterward.
        chunks = chunks_for(snapshot)
        for chunk in chunks:
            chunk.model_id = "privoke-balanced"
        chunks[0].metadata.clear()
        chunks[0].metadata["architecture"] = "privoke_tiny_transformer_v1"
        chunks[1].metadata["architecture"] = SCRATCH_PRESENCE_ARCHITECTURE
        with self.assertRaisesRegex(RuntimeError, "first chunk"):
            fetch_chunks(chunks, "privoke-balanced")

    def test_stream_rejects_counts_shapes_offsets_nonfinite_and_truncation(self):
        snapshot = snapshot_for()
        def change_count(chunks): chunks[0].total_chunks += 1
        def change_shape(chunks): chunks[0].parameter.shape[0] += 1
        def change_offset(chunks): chunks[0].parameter.value_offset = 1
        def change_nan(chunks): chunks[0].parameter.values[0] = math.nan
        def change_name(chunks): chunks[0].parameter.name = "unknown"
        def change_size(chunks): chunks[0].parameter.values.append(0)
        def change_order(chunks): chunks[1].chunk_index = 0
        def change_version(chunks): chunks[1].version = "v1.0.0+epoch.2"
        for mutate in (change_count, change_shape, change_offset, change_nan, change_name,
                       change_size, change_order, change_version):
            chunks = chunks_for(snapshot)
            mutate(chunks)
            with self.assertRaises(RuntimeError):
                fetch_chunks(chunks, snapshot.model_id)
        with self.assertRaises(RuntimeError):
            fetch_chunks(chunks_for(snapshot)[:-1], snapshot.model_id)

    def test_stream_total_byte_budget_is_checked_before_append(self):
        snapshot = snapshot_for()
        chunks = chunks_for(snapshot)
        class Oversized:
            def __getattr__(self, name): return getattr(chunks[0], name)
            def ByteSize(self): return MAX_ARTIFACT_BYTES + 1
        with self.assertRaisesRegex(RuntimeError, "byte budget"):
            fetch_chunks([Oversized()], snapshot.model_id)

    def test_legacy_stream_metadata_merge_behavior_remains(self):
        chunks = [parameters_pb2.ModelParameterChunk(model_id="legacy", version="v1", generated_at_unix=1,
                    total_chunks=2, chunk_index=index,
                    parameter=parameters_pb2.ParameterChunk(name="test", shape=[2], value_offset=index, values=[1.0]),
                    metadata={"a": "old"} if index == 0 else {"a": "new"}) for index in range(2)]
        self.assertEqual(fetch_chunks(chunks, "legacy").metadata, {"a": "new"})

    def test_rpc_inference_accepts_all_ids_and_gradients_deny_before_fetch(self):
        for model_id in sorted(SCRATCH_PRESENCE_MODEL_IDS):
            profile = model_id.split("-")[3]
            mode = "head_only" if model_id.endswith("head-only") else "end_to_end"
            model = StreamedScratchPresenceModel(snapshot_for(profile, mode))
            with patch("src.hosting.grpc_server.ModelParameterStreamer"), \
                 patch.object(StreamedModelCache, "annotation_presence_model_for_streamer", return_value=model):
                response = PrivokeRuntimeService().DetectAnnotationPresence(runtime_pb2.DetectAnnotationPresenceRequest(
                    request_id="synthetic-1", text="mail", model_id=model_id, layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC]), None)
            self.assertFalse(response.error)
            self.assertEqual(response.model_id, model_id)
            self.assertEqual(response.probability, model.predict_probability("mail"))
            self.assertEqual(response.threshold, .5)
            self.assertEqual(response.artifact_checksum, model.snapshot.metadata["artifact_checksum"])
            self.assertEqual(response.parameter_fingerprint, model.snapshot.fingerprint)
            with patch("src.hosting.grpc_server.compute_presence_gradients") as gradients:
                failed = PrivokeRuntimeService().ComputePresenceGradients(runtime_pb2.ComputePresenceGradientsRequest(
                    request_id="synthetic-training", model_id=model_id, layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC]), None)
            self.assertTrue(failed.error)
            gradients.assert_not_called()
        failed = PrivokeRuntimeService().DetectAnnotationPresence(runtime_pb2.DetectAnnotationPresenceRequest(
            request_id="failure", text="mail", model_id="privoke-scratch-presence-unknown", layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC]), None)
        self.assertTrue(failed.error)
        self.assertEqual(failed.predicted_label, runtime_pb2.ANNOTATION_PRESENCE_UNSPECIFIED)

    def test_gate_threshold_neighbors_use_actual_runtime_probability(self):
        for profile in SCRATCH_PROFILES:
            model = StreamedScratchPresenceModel(snapshot_for(profile))
            probability = model.predict_normalized_probability("mail")
            for threshold in (0.0, 1.0, probability, math.nextafter(probability, 0), math.nextafter(probability, 1)):
                analysis, _ = run_gate(model, threshold)
                layer = analysis.layers[-1]
                trace = layer.semantic_presence_gate
                self.assertEqual(trace.status, "APPLIED")
                self.assertEqual(trace.probability, probability)
                self.assertEqual(trace.model_threshold, .5)
                self.assertEqual(trace.decision_threshold, threshold)
                self.assertEqual(trace.predicted_label, "PRESENT" if probability >= threshold else "ABSENT")
                self.assertEqual(bool(layer.results), probability >= threshold)
                self.assertEqual(len(trace.semantic_results), 1)
                self.assertEqual(trace.model_id, model.model_id)
                self.assertEqual(trace.parameter_fingerprint, model.snapshot.fingerprint)
                wire = _layer_execution(layer).semantic_presence_gate
                for field in ("probability", "model_threshold", "decision_threshold"):
                    self.assertTrue(wire.HasField(field))
            saturated = StreamedScratchPresenceModel(snapshot_for(profile, bias=30))
            self.assertEqual(saturated.predict_probability("mail"), 1.0)
            self.assertEqual(run_gate(saturated, 1.0)[0].layers[-1].semantic_presence_gate.predicted_label, "PRESENT")

    def test_scratch_gate_does_not_change_nonsemantic_findings_or_enforcement(self):
        regex = ClassificationResult(initialise_unpacked(Sensitivity.S1, Visibility.PU, [Category.IDENTITY]),
                                     section_of_text="mail", reasoning="synthetic regex", span=(0, 4), confidence=.9)
        ner = ClassificationResult(initialise_unpacked(Sensitivity.S3, Visibility.P4, [Category.HEALTH]),
                                   section_of_text="mail", reasoning="synthetic NER", span=(0, 4), confidence=.9)
        outcomes = []
        for bias in (-30, 30):
            model = StreamedScratchPresenceModel(snapshot_for("balanced", "end_to_end", bias=bias))
            analysis, _ = run_gate(model, .5, detector_results={"regex": [regex], "ner": [ner]})
            outcomes.append(analysis)
            self.assertEqual(analysis.action.name, "BLOCK")
        self.assertFalse(outcomes[0].layers[-1].results)
        self.assertTrue(outcomes[1].layers[-1].results)
        for index in (0, 1):
            self.assertEqual(outcomes[0].layers[index], outcomes[1].layers[index])

    def test_regex_shortcut_has_no_fetch_or_manufactured_optionals(self):
        model = StreamedScratchPresenceModel(snapshot_for())
        analysis, fetch = run_gate(model, 0.0, regex_block=True)
        fetch.assert_not_called()
        trace = _layer_execution(analysis.layers[-1]).semantic_presence_gate
        self.assertEqual(trace.status, runtime_pb2.SEMANTIC_PRESENCE_GATE_STATUS_NOT_RUN)
        self.assertEqual(trace.model_id, model.model_id)
        self.assertTrue(trace.HasField("decision_threshold"))
        self.assertEqual(trace.decision_threshold, 0)
        self.assertFalse(trace.HasField("probability"))
        self.assertFalse(trace.HasField("model_threshold"))
        self.assertEqual(trace.predicted_label, runtime_pb2.ANNOTATION_PRESENCE_UNSPECIFIED)
        self.assertFalse(trace.model_version or trace.artifact_checksum or trace.parameter_fingerprint)

    def test_scratch_gate_failure_preserves_semantic_findings_and_visible_error(self):
        model = StreamedScratchPresenceModel(snapshot_for())
        with patch.object(StreamedScratchPresenceModel, "predict_normalized_probability", side_effect=ValueError("synthetic failure")):
            analysis, _ = run_gate(model, .5)
        layer = analysis.layers[-1]
        self.assertEqual(layer.status, "error")
        self.assertEqual(len(layer.results), 1)
        self.assertTrue(analysis.errors)
        self.assertEqual(layer.semantic_presence_gate.status, "ERROR")
        wire = _layer_execution(layer).semantic_presence_gate
        self.assertFalse(wire.HasField("probability"))
        self.assertFalse(wire.HasField("model_threshold"))
        with patch.object(StreamedScratchPresenceModel, "predict_normalized_probability", side_effect=ValueError("synthetic failure")):
            otherwise_clean, _ = run_gate(model, .5, context_results=[])
        self.assertEqual(otherwise_clean.action.name, "BLOCK")
        self.assertTrue(otherwise_clean.errors)


if __name__ == "__main__":
    unittest.main()
