"""AU3 research admission around unchanged native CPU AnalyzePrompt."""
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import threading

from . import audience_v3 as core
from . import audience_v3_comparison as comparison


def disabled(request, context):
    import grpc
    context.abort(grpc.StatusCode.UNIMPLEMENTED, "AU3 research server is inference-only")


def service(results, entry):
    import grpc
    from runtime_server import RuntimeServer, preflight
    capabilities = preflight("cpu")
    manifest = core.check_assets(entry["directory"], entry["manifest_sha256"])
    core.require(comparison.model_identity(manifest, entry["manifest_sha256"]) == entry["identity"], "Native admitted identity differs")
    _, loaded = core.en.load_model(entry["directory"])
    loaded.eval()
    for parameter in loaded.parameters():
        parameter.requires_grad_(False)

    class ReadOnly(RuntimeServer):
        def __init__(self):
            self.capabilities, self.device = capabilities, "cpu"
            self.lock = threading.RLock()
            self.cache = {entry["manifest_sha256"]: (manifest, loaded)}

        def load(self, sha):
            core.require(sha == entry["manifest_sha256"], "Unregistered AU3 checkpoint")
            return manifest, loaded

        def AnalyzePrompt(self, request, context):
            if (list(request.layers) != [4] or request.semantic_model_id != manifest["model_id"]
                    or request.metadata.get("v3_checkpoint") != entry["manifest_sha256"]
                    or request.visibility_hint or request.HasField("semantic_presence_gate")):
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Explicit sealed semantic identity and empty hints required")
            return super().AnalyzePrompt(request, context)

        FitCandidate = staticmethod(disabled)
        GetFitStatus = staticmethod(disabled)
    return ReadOnly()


def serve(results, name, port, ready_file):
    import grpc
    from privoke.v1 import runtime_pb2_grpc
    core.require(type(port) is int and 1024 <= port <= 65535, "Invalid loopback port")
    binding = core.read(Path(results) / "bindings.json")
    core.en.configure(binding["repository"], "cpu", 4)
    os.environ["V3_TORCH_THREADS"] = "4"
    registry, _ = comparison.validate_registry(results)
    entry = next(e for e in registry["entries"] if e["name"] == name)
    native = service(results, entry)
    server = grpc.server(ThreadPoolExecutor(max_workers=1))
    runtime_pb2_grpc.add_PrivokeRuntimeServiceServicer_to_server(native, server)
    core.require(server.add_insecure_port("127.0.0.1:" + str(port)) != 0, "Cannot bind AU3 loopback")
    server.start()
    ready = {"study_id": core.STUDY_ID, "name": name, "identity": entry["identity"],
             "registry_sha256": core.file_hash(Path(results) / "comparison/registry.json"),
             "source_closure": registry["source_closure"], "pid": os.getpid(), "port": port,
             "training_disabled": True, "native_inference": True, "environment": core.en.environment("cpu"),
             "capabilities": native.capabilities}
    try:
        core.retain(ready_file, ready)
        print("AU3 native ready " + name, flush=True)
        server.wait_for_termination()
    finally:
        server.stop(grace=2).wait()
