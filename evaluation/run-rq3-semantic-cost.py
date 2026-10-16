"""Host loopback timing of one immutable AU3 model; no training or dataset access."""
from __future__ import annotations
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "evaluation"))
from host_environment import configure_imports, python_environment
configure_imports()
import grpc
from privoke.v1 import runtime_pb2 as pb, runtime_pb2_grpc as rpc

MODEL = ROOT / "models/experiments/audience_v3_20261013/runs/cpu-02/exports/balanced/selected"
PIN = "99b36171056bb0398584a0b0556d9d7ff2640d0acac4b124a126327451a80589"
MODEL_ID = "privoke-v3-balanced"
PROMPT = "Please explain the steps in this process."


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def assets():
    if sha(MODEL / "manifest.json") != PIN:
        raise ValueError("AU3 balanced manifest pin differs")
    manifest = json.loads((MODEL / "manifest.json").read_bytes())
    for name, key in (("model.safetensors", "blob"), ("config.json", "config"), ("vocab.txt", "vocab")):
        if sha(MODEL / name) != manifest[key]:
            raise ValueError("AU3 asset bytes differ")
    if manifest["model_id"] != MODEL_ID or manifest["blob"] != "e48e7c1aa46310b3b7b1f6422f7aa8902c70cf6ff861f7540a7c4be151de4df2":
        raise ValueError("Unexpected AU3 selected package")
    return manifest


def serve(args):
    for name in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "NUMEXPR_NUM_THREADS", "BLIS_NUM_THREADS"):
        os.environ[name] = "4"
    os.environ["V3_TORCH_THREADS"] = "4"
    sys.path.insert(0, str(ROOT / "extension/client-runtime"))
    sys.path.insert(0, str(ROOT / "services/pretrained-v3/src"))
    from runtime_server import RuntimeServer, preflight
    from src.v3.model import PretrainedV3
    capabilities = preflight("cpu")
    manifest = assets()
    model = PretrainedV3.load(manifest, MODEL / "model.safetensors", MODEL / "config.json", MODEL / "vocab.txt", device="cpu")
    model.eval()
    for parameter in model.parameters():
        parameter.requires_grad_(False)

    class ImmutableInference(RuntimeServer):
        def __init__(self):
            self.lock = threading.RLock()
            self.cache = {PIN: (manifest, model)}
        def load(self, checkpoint):
            raise ValueError("Remote loading is forbidden for this immutable component study")

    server = grpc.server(ThreadPoolExecutor(max_workers=1))
    rpc.add_PrivokeRuntimeServiceServicer_to_server(ImmutableInference(), server)
    port = server.add_insecure_port("127.0.0.1:0")
    if not port:
        raise RuntimeError("Native semantic server failed loopback bind")
    server.start()
    save(args.ready, {"target": f"127.0.0.1:{port}", "pid": os.getpid(), "capabilities": capabilities,
                      "manifest_sha256": PIN, "training_service_registered": False})
    server.wait_for_termination()


def summary(values):
    import math
    values = sorted(values)
    return {"n": len(values), **{k: values[math.ceil(q * len(values)) - 1]
                                for k, q in (("p50", .5), ("p95", .95), ("max", 1))}}


def run(args):
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "protocol.md").write_bytes(args.protocol.read_bytes())
    manifest = assets()
    sources = [Path(__file__).resolve()]
    for prefix in ("shared/python", "shared/proto", "extension/client-runtime/src",
                   "extension/client-runtime/generated", "services/pretrained-v3/src", "services/privoke-fuzzer/src"):
        sources.extend(path for path in (ROOT / prefix).rglob("*") if path.is_file()
                       and path.suffix in (".py", ".proto") and "__pycache__" not in path.parts)
    source_hashes = {str(path.relative_to(ROOT)): sha(path) for path in sources}
    receipt = {"protocol": "rq3-au3-component-v1", "protocol_sha256": sha(args.protocol),
               "model_manifest_sha256": PIN, "model_blob": manifest["blob"], "source_hashes": source_hashes,
               "source_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
               "boundary": "host gRPC versus native server elapsed; no browser or installed AU3 integration",
               "status": "running", "sessions": []}
    child = None
    try:
        for session in (1, 2):
            ready = args.output / f"ready-{session}.json"
            log = (args.output / f"server-{session}.log").open("xb")
            with log:
                child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--serve", "--ready", str(ready)],
                                         cwd=ROOT, env=python_environment(), stdout=log, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 90
                while not ready.exists():
                    if child.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("Native AU3 component failed readiness within ninety seconds")
                    time.sleep(.1)
                readiness = json.loads(ready.read_bytes())
                if readiness["pid"] != child.pid:
                    raise AssertionError("Native AU3 service PID mismatch")
                state = {"session": session, "readiness": readiness, "records": []}
                receipt["sessions"].append(state)
                with grpc.insecure_channel(readiness["target"]) as channel:
                    grpc.channel_ready_future(channel).result(timeout=5)
                    stub = rpc.PrivokeRuntimeServiceStub(channel)
                    for index in range(35):
                        request = pb.AnalyzePromptRequest(request_id=f"rq3-au3-{session}-{index}", text=PROMPT,
                            source="rq3_controlled_component", target_app="local_fixture", layers=[4],
                            semantic_model_id=MODEL_ID, metadata={"v3_checkpoint": PIN})
                        row = {"phase": "warmup" if index < 5 else "measured", "index": index,
                               "request_pb": base64.b64encode(request.SerializeToString(deterministic=True)).decode()}
                        state["records"].append(row)
                        started = time.perf_counter()
                        try:
                            response = stub.AnalyzePrompt(request, timeout=10)
                            row["host_rpc_ms"] = (time.perf_counter() - started) * 1000
                            row["response_pb"] = base64.b64encode(response.SerializeToString(deterministic=True)).decode()
                            row["server_elapsed_ms"] = response.elapsed_ms
                            if not math.isfinite(response.elapsed_ms) or response.elapsed_ms < 0:
                                raise AssertionError("Native semantic timing is invalid")
                            if response.error or response.request_id != request.request_id or [v.layer for v in response.layers] != [4] or response.layers[0].status != "ok":
                                raise AssertionError("Native semantic actual execution failed")
                            for field, expected in (("model_id", MODEL_ID), ("artifact_checksum", PIN), ("model_version", PIN), ("parameter_fingerprint", manifest["blob"])):
                                if response.metadata.get("privoke.semantic." + field) != expected:
                                    raise AssertionError("Native semantic response identity differs")
                            row["status"] = "passed"
                        except Exception as error:
                            row["status"] = "failed"
                            row["error_type"] = type(error).__name__
                            raise
                        finally:
                            save(args.output / "receipt.json", receipt)
                child.terminate()
                child.wait(timeout=5)
                state["reaped_exit_code"] = child.returncode
                child = None
                measured = [row for row in state["records"] if row["phase"] == "measured"]
                state["host_rpc_ms"] = summary([r["host_rpc_ms"] for r in measured])
                state["server_elapsed_ms"] = summary([r["server_elapsed_ms"] for r in measured])
        receipt["status"] = "complete"
    except Exception as error:
        receipt["status"] = "failed"
        receipt["failure"] = {"type": type(error).__name__, "message": str(error)[:500]}
        raise
    finally:
        if child is not None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
                receipt["status"] = "failed"
                receipt["emergency_cleanup"] = True
        receipt["children_reaped"] = child is None or child.poll() is not None
        if source_hashes != {str(path.relative_to(ROOT)): sha(path) for path in sources} or sha(args.protocol) != receipt["protocol_sha256"]:
            receipt["status"] = "failed"
            receipt["source_or_protocol_changed"] = True
        receipt["artifact_hashes"] = {str(path.relative_to(args.output)): sha(path)
            for path in args.output.rglob("*") if path.is_file() and path.name != "receipt.json"}
        save(args.output / "receipt.json", receipt)
    return 0 if receipt["status"] == "complete" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--protocol", type=Path)
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--ready", type=Path)
    args = parser.parse_args()
    if args.serve:
        serve(args)
    else:
        if args.output is None or args.protocol is None:
            parser.error("--output and --protocol are required")
        raise SystemExit(run(args))
