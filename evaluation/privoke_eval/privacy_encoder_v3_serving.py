"""Research-only EN3 full-model admission around unchanged native CPU inference."""
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import threading

from . import privacy_encoder_v3 as en
from . import privacy_encoder_v3_comparison as comparison


def disabled(request, context):
    import grpc
    context.abort(grpc.StatusCode.UNIMPLEMENTED, "EN3 research server is inference-only")


def service(results, entry):
    from runtime_server import RuntimeServer, preflight
    # Native preflight enforces the actual old CPU-serving Torch contract.
    capabilities = preflight("cpu")
    en.verify_export(results, entry["tier"])
    manifest, loaded = en.load_model(entry["directory"])
    loaded.eval()
    for parameter in loaded.parameters():
        parameter.requires_grad_(False)

    class ReadOnly(RuntimeServer):
        def __init__(self):
            self.capabilities = capabilities
            self.device = "cpu"
            self.lock = threading.RLock()
            self.cache = {entry["manifest_sha256"]: (manifest, loaded)}

        def load(self, sha):
            en.require(sha == entry["manifest_sha256"], "Unregistered EN3 checkpoint")
            return manifest, loaded

        def AnalyzePrompt(self, request, context):
            import grpc
            if (list(request.layers) != [4] or request.semantic_model_id != manifest["model_id"]
                    or request.metadata.get("v3_checkpoint") != entry["manifest_sha256"]
                    or request.HasField("semantic_presence_gate")):
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Explicit sealed EN3 semantic identity required")
            return super().AnalyzePrompt(request, context)

        FitCandidate = staticmethod(disabled)
        GetFitStatus = staticmethod(disabled)
    return ReadOnly()


def serve(results, tier, port, ready_file):
    import grpc
    from privoke.v1 import runtime_pb2_grpc
    en.require(type(port) is int and 1024 <= port <= 65535, "Invalid loopback port")
    protocol = en.read(Path(results)/"protocol.json")
    binding = en.read(Path(results)/"bindings.json")
    en.configure(binding["repository"], "cpu", protocol["threads"])
    os.environ["V3_TORCH_THREADS"] = str(protocol["threads"])
    registry, _ = comparison.validate_registry(results)
    entry = next(e for e in registry["entries"] if e["tier"] == tier)
    native = service(results, entry)
    server = grpc.server(ThreadPoolExecutor(max_workers=1))
    runtime_pb2_grpc.add_PrivokeRuntimeServiceServicer_to_server(native, server)
    en.require(server.add_insecure_port("127.0.0.1:"+str(port)) != 0, "Cannot bind EN3 loopback")
    server.start()
    ready = {"study_id": en.STUDY_ID, "name": entry["name"], "identity": entry["identity"],
             "registry_sha256": en.file_hash(Path(results)/"comparison/registry.json"),
             "source_closure": registry["source_closure"], "pid": os.getpid(), "port": port,
             "training_disabled": True, "native_inference": True, "environment": en.environment("cpu"),
             "capabilities": native.capabilities}
    try:
        en.retain(ready_file, ready)
        print("EN3 native inference ready "+tier, flush=True)
        server.wait_for_termination()
    finally:
        server.stop(grace=2).wait()
