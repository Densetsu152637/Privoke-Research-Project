"""Comparison-only launch configuration around unmodified native servicers.

PID 1 owns one immutable model. This file executes only as a model server.
"""
from __future__ import annotations

import os
for _name in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "NUMEXPR_NUM_THREADS", "BLIS_NUM_THREADS"):
    if os.environ.get(_name) != "1":
        raise RuntimeError("Thread environment must be pinned before imports: " + _name)

import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import sys
import time

sys.path.insert(0, "/app/services/pretrained-v3/src")
import common
from common import canonical, runtime_pb2_grpc


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def actual_threadpools():
    """Query already-loaded numeric libraries; never install runtime dependencies."""
    try:
        from threadpoolctl import threadpool_info
    except ImportError:
        import ctypes
        paths = {line.split()[-1] for line in Path("/proc/self/maps").read_text().splitlines() if "/" in line and any(name in line.lower() for name in ("openblas", "libgomp", "libiomp"))}
        pools = []
        for path in sorted(paths):
            library = ctypes.CDLL(path)
            symbols = ("openblas_get_num_threads64_", "openblas_get_num_threads", "openblas_get_num_threads_64_") if "openblas" in path.lower() else ("omp_get_max_threads",)
            for symbol in symbols:
                try:
                    function = getattr(library, symbol)
                except AttributeError:
                    continue
                function.restype = ctypes.c_int
                pools.append({"filepath": path, "num_threads": function(), "symbol": symbol, "mechanism": "ctypes already-loaded library"})
                break
            else:
                raise ValueError("Cannot attest actual loaded numeric library threads: " + path)
        if not pools:
            raise ValueError("No actual BLAS/OpenMP thread attestation available")
    else:
        pools = threadpool_info()
    if not pools or any(pool["num_threads"] != 1 for pool in pools):
        raise ValueError("Actual BLAS/OpenMP pools must be single threaded")
    return pools


def main():
    state = Path("/state")
    entry = json.loads((state / "entry.json").read_bytes())
    module_pins = json.loads((state / "server-inputs.json").read_bytes())
    mounted_modules = {name: sha(Path("/app") / name) for name in module_pins}
    if mounted_modules != module_pins:
        raise ValueError("Mounted maintained generated telemetry modules differ")
    if common.source_identity() != "126878ce5ebf0896a91b9f878abe444e76453b44aadcc284c4a3e61e42aec95a":
        raise ValueError("Copied server closure differs")
    if entry["server_family"] == "tiny":
        from privoke_model.artifact import load_artifact, float32
        from src.LLM.privoke.parameter_stream import ParameterSnapshot, ModelParameterStreamer
        from src.LLM.privoke.streamed_model import StreamedTransformerPrivacyModel, GLOBAL_STREAMED_MODEL_CACHE, _CachedModel
        from src.config import GLOBAL_CONFIG
        from src.hosting.grpc_server import create_grpc_server
        artifact_path = Path("/assets/artifact.json")
        if sha(artifact_path) != entry["file_sha256"]:
            raise ValueError("Private Tiny artifact bytes differ")
        artifact = load_artifact(artifact_path)
        parameters = {name: tuple(float32(v) for v in tensor["values"]) for name, tensor in artifact["parameters"].items()}
        shapes = {name: tuple(tensor["shape"]) for name, tensor in artifact["parameters"].items()}
        metadata = dict(artifact["metadata"], architecture=artifact["architecture"], artifact_checksum=artifact["checksum"], model_config=json.dumps(artifact["config"], separators=(",", ":")), trainable_parameters=json.dumps(sorted(parameters)))
        snapshot = ParameterSnapshot(artifact["model_id"], artifact["version"], artifact["generated_at_unix"], parameters, shapes, metadata)
        identity = {"model_id": snapshot.model_id, "model_version": snapshot.version, "artifact_checksum": artifact["checksum"], "parameter_fingerprint": snapshot.fingerprint}
        if identity != entry["identity"]:
            raise ValueError("Reconstructed Tiny identity differs")
        model = StreamedTransformerPrivacyModel(snapshot)
        if model.model.compute_device != "cpu" or model.model._torch is not None:
            raise ValueError("Tiny must execute native NumPy CPU backend")
        GLOBAL_CONFIG.llm_choice = "streamed"
        streamer = ModelParameterStreamer(model_id=snapshot.model_id)
        GLOBAL_STREAMED_MODEL_CACHE._models[(streamer.target, streamer.model_id)] = _CachedModel(snapshot.cache_key, model, time.monotonic())
        if GLOBAL_STREAMED_MODEL_CACHE.refresh_interval_seconds != 604800:
            raise ValueError("Tiny cache TTL differs")
        server = create_grpc_server(max_workers=1)
        capabilities = {"backend": "numpy", "compute_device": model.model.compute_device, "cache_ttl_seconds": 604800}
    else:
        import grpc
        from concurrent.futures import ThreadPoolExecutor
        from runtime_server import RuntimeServer
        service = RuntimeServer("checkpoint:50273", state / "runtime", device="cpu")
        snapshot_sha = entry["identity"]["artifact_checksum"]
        manifest, model = service.load(snapshot_sha)
        if model.device_name != "cpu" or service.capabilities["threads"] != "1":
            raise ValueError("V3 actual CPU/thread preflight differs")
        service.cache[snapshot_sha] = (manifest, model)
        server = grpc.server(ThreadPoolExecutor(max_workers=1), options=common.OPTIONS)
        # Inference only: the physical training servicer is never registered here.
        runtime_pb2_grpc.add_PrivokeRuntimeServiceServicer_to_server(service, server)
        identity = entry["identity"]
        capabilities = dict(service.capabilities, backend="torch", autograd_preflight="passed")
    if not server.add_insecure_port("0.0.0.0:50271"):
        raise ValueError("Comparison runtime port bind failed")
    server.start()
    pools = actual_threadpools()
    attestation = {"identity": identity, "device": "cpu", "threads": 1, "thread_env": {name: os.environ[name] for name in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "NUMEXPR_NUM_THREADS", "BLIS_NUM_THREADS")},
                   "threadpools": pools, "capabilities": capabilities, "source_closure": common.source_identity(), "helper_sha256": sha(__file__), "mounted_modules": mounted_modules, "pid": os.getpid(), "platform": platform.platform(),
                   "packages": {dist.metadata["Name"]: dist.version for dist in importlib.metadata.distributions()}, "cpuinfo": Path("/proc/cpuinfo").read_text(),
                   "loading": "immutable local snapshot preloaded before readiness; first RPC is already loaded"}
    with (state / "ready.json").open("xb") as handle:
        handle.write(canonical(attestation))
        handle.flush()
        os.fsync(handle.fileno())
    print("comparison runtime ready " + entry["name"], flush=True)
    server.wait_for_termination()


if __name__ == "__main__":
    main()
