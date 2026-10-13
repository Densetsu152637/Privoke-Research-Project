"""Immutable CPU semantic admission into the maintained native product cascade."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import threading
import time
from types import SimpleNamespace

from . import pipeline_v1_v3 as core


class V3SemanticAdapter:
    """Only adapts native V3 findings to the native semantic cache interface."""
    def __init__(self, model, identity):
        self.model, self.identity = model, dict(identity)
        self.snapshot = SimpleNamespace(model_id=identity["model_id"], version=identity["model_version"],
            fingerprint=identity["parameter_fingerprint"], metadata={"artifact_checksum": identity["artifact_checksum"]})

    def classify(self, text):
        return self.model.findings(text, self.identity)


def disabled(request, context):
    import grpc
    context.abort(grpc.StatusCode.UNIMPLEMENTED, "PIPE3 server is inference-only")


def load_semantic(entry):
    from src.LLM.privoke.parameter_stream import ParameterSnapshot
    from src.LLM.privoke.streamed_model import StreamedTransformerPrivacyModel
    if entry["family"] == "v3":
        from src.v3.model import PretrainedV3
        directory = Path(entry["directory"])
        manifest = core.read(directory / "manifest.json")
        model = PretrainedV3.load(manifest, directory / "model.safetensors", directory / "config.json", directory / "vocab.txt", device="cpu")
        model.eval()
        for parameter in model.parameters():
            parameter.requires_grad_(False)
        return V3SemanticAdapter(model, entry["identity"])
    from privoke_model.artifact import load_artifact, float32
    path = Path(entry["directory"]) / next(iter(entry["assets"]))
    artifact = load_artifact(path)
    parameters = {name: tuple(float32(v) for v in tensor["values"]) for name, tensor in artifact["parameters"].items()}
    shapes = {name: tuple(tensor["shape"]) for name, tensor in artifact["parameters"].items()}
    metadata = dict(artifact["metadata"], architecture=artifact["architecture"], artifact_checksum=artifact["checksum"],
                    model_config=json.dumps(artifact["config"], separators=(",", ":")), trainable_parameters=json.dumps(sorted(parameters)))
    snapshot = ParameterSnapshot(artifact["model_id"], artifact["version"], artifact["generated_at_unix"], parameters, shapes, metadata)
    model = StreamedTransformerPrivacyModel(snapshot)
    core.require(model.model.compute_device == "cpu" and model.model._torch is None, "V1 requires native NumPy CPU")
    identity = {"model_id": snapshot.model_id, "model_version": snapshot.version,
                "artifact_checksum": artifact["checksum"], "parameter_fingerprint": snapshot.fingerprint}
    core.require(identity == entry["identity"], "Reconstructed native V1 identity differs")
    return model


def adapter_parity(protocol, entry, adapter):
    """Compare adapter findings with the unchanged V3 native RPC on NEW VAL."""
    if entry["family"] != "v3":
        return {"status": "not_applicable", "reason": "V1 uses unchanged native streamed model"}
    from privoke.v1 import runtime_pb2
    from runtime_server import RuntimeServer
    from src.detection.preprocessing import normalize_with_offsets
    manifest = core.read(Path(entry["directory"]) / "manifest.json")

    class FixedNative(RuntimeServer):
        def __init__(self):
            self.lock = threading.RLock()
            self.cache = {entry["identity"]["artifact_checksum"]: (manifest, adapter.model)}
        def load(self, sha):
            core.require(sha == entry["identity"]["artifact_checksum"], "Parity snapshot differs")
            return manifest, adapter.model

    native = FixedNative()
    captures = []
    for index, row in enumerate(core.rows_for(protocol, "validation")[:16]):
        normalized = normalize_with_offsets(row["text"]).text
        request = runtime_pb2.AnalyzePromptRequest(request_id="pipe3-parity-" + str(index), text=normalized,
            layers=[4], semantic_model_id=entry["identity"]["model_id"], metadata={"v3_checkpoint": entry["identity"]["artifact_checksum"]})
        response = native.AnalyzePrompt(request, None)
        core.require(not response.error and [v.layer for v in response.layers] == [4]
                     and response.layers[0].status == "ok", "Native semantic parity RPC failed")
        findings = adapter.classify(normalized)
        from runtime_server import detection
        expected = [detection(f).SerializeToString(deterministic=True) for f in findings]
        actual = [f.SerializeToString(deterministic=True) for f in response.layers[0].results]
        core.require(expected == actual, "Adapter differs from unchanged native V3 semantic RPC")
        import base64
        captures.append({"id": row["id"], "original_text_sha256": core.digest(row["text"].encode()),
                         "request_pb": base64.b64encode(request.SerializeToString(deterministic=True)).decode(),
                         "response_pb": base64.b64encode(response.SerializeToString(deterministic=True)).decode(),
                         "adapter_findings_pb": [base64.b64encode(p).decode() for p in expected],
                         "request_sha256": core.digest(request.SerializeToString(deterministic=True)),
                         "native_response_sha256": core.digest(response.SerializeToString(deterministic=True)),
                         "finding_sha256": [core.digest(p) for p in actual]})
    return {"status": "passed", "rows": len(captures), "captures": captures,
            "meaning": "bounded native semantic RPC versus adapter findings, not product accuracy"}


def service(entry, semantic):
    import grpc
    from src.config import GLOBAL_CONFIG
    from src.LLM.privoke.parameter_stream import ModelParameterStreamer
    from src.LLM.privoke.streamed_model import GLOBAL_STREAMED_MODEL_CACHE, _CachedModel
    from src.hosting.grpc_server import PrivokeRuntimeService
    GLOBAL_CONFIG.llm_choice = "streamed"
    # The immutable local cache is the deployment binding; no remote streamer is required.
    streamer = ModelParameterStreamer(model_id=entry["identity"]["model_id"])
    cache_identity = (streamer.target, streamer.model_id)
    GLOBAL_STREAMED_MODEL_CACHE.clear()
    GLOBAL_STREAMED_MODEL_CACHE._models[cache_identity] = _CachedModel(entry["identity"]["parameter_fingerprint"], semantic, time.monotonic())
    core.require(GLOBAL_STREAMED_MODEL_CACHE.refresh_interval_seconds == 604800 and GLOBAL_CONFIG.wait_for_regex,
                 "Native cache/cascade configuration differs")

    class ReadOnlyProduct(PrivokeRuntimeService):
        def AnalyzePrompt(self, request, context):
            if (list(request.layers) != core.LAYERS or request.regex_execution_order != 1
                    or request.semantic_model_id != entry["identity"]["model_id"] or request.visibility_hint
                    or request.HasField("semantic_presence_gate")):
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Sealed explicit product layers/model/FIRST/no-hints required")
            cached = GLOBAL_STREAMED_MODEL_CACHE._models.get(cache_identity)
            if cached is None or cached.model is not semantic or time.monotonic() - cached.refreshed_at >= 604680:
                context.abort(grpc.StatusCode.FAILED_PRECONDITION, "Immutable semantic cache unavailable; remote fallback prohibited")
            return super().AnalyzePrompt(request, context)
        ComputeSemanticGradients = staticmethod(disabled)
        ComputeUnderlyingModelGradients = staticmethod(disabled)
        ComputePresenceGradients = staticmethod(disabled)
        DetectAnnotationPresence = staticmethod(disabled)
    return ReadOnlyProduct()


def serve(results, name, port, ready_file):
    import grpc
    from privoke.v1 import runtime_pb2_grpc
    core.require(type(port) is int and 1024 <= port <= 65535, "Invalid loopback port")
    protocol = core.validate(results)
    core.configure_numeric()
    core.require(core.environment() == protocol["environment"], "Actual server environment differs from preparation")
    entry = next(e for e in protocol["entries"] if e["name"] == name)
    started, resources = time.perf_counter_ns(), {"before_load": core.resource_snapshot()}
    import spacy
    spacy.require_cpu()
    from src.NER.ner_detector import EntityNERDetector
    ner = EntityNERDetector()
    core.require(ner.backend_name == "spacy" and ner.model_name == "en_core_web_sm" and "ner" in ner.nlp.pipe_names,
                 "Real NER model readiness failed")
    from src.regex.rule_detector import RuleDetector
    regex = RuleDetector()
    core.require(bool(regex.rules), "Actual regex rules missing")
    effective_rules = core.rules_inventory(regex)
    core.require(effective_rules == protocol["effective_regex_rules"]
                 and core.digest(core.canonical(effective_rules)) == protocol["effective_regex_rules_sha256"],
                 "Loaded effective regex rules differ from prepared protocol")
    semantic = load_semantic(entry)
    resources["after_load"] = core.resource_snapshot()
    parity = adapter_parity(protocol, entry, semantic)
    native = service(entry, semantic)
    server = grpc.server(ThreadPoolExecutor(max_workers=1))
    runtime_pb2_grpc.add_PrivokeRuntimeServiceServicer_to_server(native, server)
    def resource_rpc(request, context):
        if request != b"resources":
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Expected resource probe")
        return core.canonical(core.resource_snapshot())
    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler("privoke.research.PipelineEvidence", {
        "Resources": grpc.unary_unary_rpc_method_handler(resource_rpc)}),))
    core.require(server.add_insecure_port("127.0.0.1:" + str(port)), "Cannot bind private loopback port")
    server.start()
    ready = {"study_id": core.STUDY_ID, "name": name, "identity": entry["identity"], "port": port, "pid": os.getpid(),
             "protocol_sha256": core.file_hash(Path(results) / "protocol.json"), "source_closure": protocol["source_closure"],
             "training_disabled": True, "native_product_pipeline": True, "environment": core.environment(),
             "adapter": "native_v3_findings_to_semantic_cache" if entry["family"] == "v3" else "native_streamed_transformer",
             "adapter_parity": parity, "regex_rule_count": len(regex.rules),
             "effective_regex_rules": effective_rules, "effective_regex_rules_sha256": core.digest(core.canonical(effective_rules)),
             "ner": {"backend": ner.backend_name, "model": ner.model_name, "meta": ner.nlp.meta, "pipe_names": ner.nlp.pipe_names},
             "load_and_parity_ms": (time.perf_counter_ns() - started) / 1e6, "resources": resources,
             "loading": "model and real NER preloaded before ready; accuracy warmups are separate"}
    try:
        core.retain(ready_file, ready)
        print("PIPE3 native product ready " + name, flush=True)
        server.wait_for_termination()
    finally:
        server.stop(grace=2).wait()
        core.retain(Path(ready_file).with_suffix(".shutdown.json"), {"name": name, "pid": os.getpid(), "resources": core.resource_snapshot()})
