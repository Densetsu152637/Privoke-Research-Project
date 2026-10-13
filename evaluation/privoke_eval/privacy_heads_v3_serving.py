"""Research-only PH3 asset admission around unchanged native inference methods."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import importlib.metadata
import json
import os
from pathlib import Path
import threading
import time
from . import privacy_heads_v3 as core
from . import privacy_heads_v3_comparison as comparison


def disabled(request,context):
    import grpc
    context.abort(grpc.StatusCode.UNIMPLEMENTED,"PH3 comparison server is inference-only")


def v3_service(results,entry):
    """Substitute only immutable asset loading; native AnalyzePrompt is unchanged."""
    from runtime_server import RuntimeServer,preflight
    admitted = core.validate_export(results,entry["tier"])
    core.require(admitted["manifest_sha256"]==entry["manifest_sha256"],"PH3 serving admission differs")
    from src.v3.model import PretrainedV3
    directory = Path(admitted["directory"])
    manifest = admitted["manifest"]
    loaded = PretrainedV3.load(manifest,directory/"model.safetensors",directory/"config.json",
                              directory/"vocab.txt",device="cpu")
    class ReadOnlyV3(RuntimeServer):
        def __init__(self):
            self.capabilities = preflight("cpu")
            self.device = "cpu"
            self.lock = threading.RLock()
            self.cache = {entry["manifest_sha256"]:(manifest,loaded)}
        def load(self,sha):
            core.require(sha==entry["manifest_sha256"],"Unregistered PH3 snapshot requested")
            return manifest,loaded
        def AnalyzePrompt(self,request,context):
            import grpc
            if (list(request.layers)!=[4] or request.semantic_model_id!=manifest["model_id"]
                    or request.metadata.get("v3_checkpoint")!=entry["manifest_sha256"]
                    or request.HasField("semantic_presence_gate")):
                context.abort(grpc.StatusCode.INVALID_ARGUMENT,"Explicit sealed PH3 semantic identity required")
            return super().AnalyzePrompt(request,context)
        FitCandidate = staticmethod(disabled)
        GetFitStatus = staticmethod(disabled)
    return ReadOnlyV3()


def tiny_service(entry):
    """Byte-identical V1 snapshot in the native streamed model cache; no network refresh."""
    from privoke_model.artifact import load_artifact,float32
    from src.LLM.privoke.parameter_stream import ParameterSnapshot,ModelParameterStreamer
    from src.LLM.privoke.streamed_model import (
        StreamedTransformerPrivacyModel,GLOBAL_STREAMED_MODEL_CACHE,_CachedModel)
    from src.config import GLOBAL_CONFIG
    from src.hosting.grpc_server import PrivokeRuntimeService
    path = Path(entry["directory"])/"artifact.json"
    core.require(core.file_hash(path)==entry["file_sha256"],"V1 serving bytes changed")
    artifact = load_artifact(path)
    parameters = {k:tuple(float32(v) for v in tensor["values"]) for k,tensor in artifact["parameters"].items()}
    shapes = {k:tuple(tensor["shape"]) for k,tensor in artifact["parameters"].items()}
    metadata = dict(artifact["metadata"],architecture=artifact["architecture"],artifact_checksum=artifact["checksum"],
                    model_config=json.dumps(artifact["config"],separators=(",",":")),
                    trainable_parameters=json.dumps(sorted(parameters)))
    snapshot = ParameterSnapshot(artifact["model_id"],artifact["version"],artifact["generated_at_unix"],
                                 parameters,shapes,metadata)
    identity = {"model_id":snapshot.model_id,"model_version":snapshot.version,
                "artifact_checksum":artifact["checksum"],"parameter_fingerprint":snapshot.fingerprint}
    core.require(identity==entry["identity"],"Reconstructed V1 identity differs")
    model = StreamedTransformerPrivacyModel(snapshot)
    core.require(model.model.compute_device=="cpu" and model.model._torch is None,"V1 native NumPy backend required")
    GLOBAL_CONFIG.llm_choice = "streamed"
    streamer = ModelParameterStreamer(model_id=snapshot.model_id)
    GLOBAL_STREAMED_MODEL_CACHE.refresh_interval_seconds = 604800
    GLOBAL_STREAMED_MODEL_CACHE._models[(streamer.target,streamer.model_id)] = _CachedModel(
        snapshot.cache_key,model,time.monotonic())
    class ReadOnlyTiny(PrivokeRuntimeService):
        def AnalyzePrompt(self,request,context):
            import grpc
            if (list(request.layers)!=[4] or request.semantic_model_id!=entry["identity"]["model_id"]
                    or request.HasField("semantic_presence_gate")):
                context.abort(grpc.StatusCode.INVALID_ARGUMENT,"Explicit sealed V1 semantic identity required")
            return super().AnalyzePrompt(request,context)
        ComputeSemanticGradients = staticmethod(disabled)
        ComputeUnderlyingModelGradients = staticmethod(disabled)
        ComputePresenceGradients = staticmethod(disabled)
        DetectAnnotationPresence = staticmethod(disabled)
    return ReadOnlyTiny(telemetry_reporter=None)


def serve(results,name,port,ready_file):
    import grpc
    from privoke.v1 import runtime_pb2_grpc
    registry,binding = comparison.validate_registry(results)
    entry = next(e for e in registry["entries"] if e["name"]==name)
    core.require(type(port) is int and 1024<=port<=65535,"Invalid loopback port")
    os.environ["V3_TORCH_THREADS"] = str(core.read(Path(results)/"protocol.json")["threads"])
    service = v3_service(results,entry) if entry["family"]=="v3" else tiny_service(entry)
    server = grpc.server(ThreadPoolExecutor(max_workers=1))
    # Register only the inference service, never the experimental fit service.
    runtime_pb2_grpc.add_PrivokeRuntimeServiceServicer_to_server(service,server)
    core.require(server.add_insecure_port("127.0.0.1:"+str(port))!=0,"Cannot bind PH3 loopback server")
    server.start()
    ready = {"schema":1,"study_id":core.STUDY_ID,"name":name,"identity":entry["identity"],
             "registry_sha256":core.file_hash(Path(results)/"comparison/registry.json"),
             "source_closure":registry["source_closure"],"server_helper_sha256":core.file_hash(__file__),
             "pid":os.getpid(),"port":port,"native_inference":True,"training_disabled":True,
             "publication":"research_only","environment":core.environment(),
             "capabilities":getattr(service,"capabilities",{"backend":"native_numpy_cpu","cache_ttl":604800})}
    try:
        core.retain(ready_file,ready)
        print("PH3 native inference ready "+name,flush=True)
        server.wait_for_termination()
    except BaseException:
        server.stop(grace=2).wait()
        raise
