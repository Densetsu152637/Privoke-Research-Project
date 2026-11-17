#!/usr/bin/env python
"""Capture the worker-frames conformance set (stage W1 of docs/plans/rust-server-rewrite.md).

For every case the exact request frame the controller sends is stored in hex, together with
the worker's response (kind, method, SHA-256 and length of the response payload with the
wall-clock fields cleared) and whether the existing gRPC server path produced the same
bytes. Later stages (the Rust pool, the Rust analysis microservice, the spaCy worker's
framing) replay the request frames against the Python worker or against a Rust worker and
compare the response digests.

Run from the repository root with the host environment, for example:

    evaluation/.venv-v1-v3-pipeline/Scripts/python.exe tests/conformance/worker-frames/capture_worker_frames.py

Models are read-only: the four tracked legacy artifacts under models/, the pinned V3 package
from models/standard-releases (the main checkout when this is a worktree), and a training
root written to a temporary directory. Capture is deterministic given the same torch build
(one thread, CPU).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
RUNTIME = ROOT / "extension" / "client-runtime"
for path in (RUNTIME, RUNTIME / "test", RUNTIME / "generated", ROOT / "shared" / "python", ROOT / "models"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from src import worker_protocol as proto  # noqa: E402
import worker_cases as cases  # noqa: E402
from worker_harness import LEGACY_MODEL_ROOT, V3_MODEL_ID, GrpcOracle, WorkerProcess, normalised, v3_model_root  # noqa: E402

SCHEMA = 1


def dump(value) -> bytes:
    return (json.dumps(value, indent=1, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_cases(worker, oracle, selection, first_id):
    records = []
    for offset, case in enumerate(selection):
        request_id = first_id + offset
        payload = proto.encode_metadata(case.metadata) + case.payload if case.metadata else case.payload
        flags = proto.FLAG_METADATA if case.metadata else 0
        frame = proto.encode_frame(proto.Kind.REQUEST, case.method, request_id, payload, flags=flags)
        worker.send_raw(frame)
        answer = worker.read_frame()
        record = {"label": case.label, "scope": case.scope, "method": proto.GRPC_METHOD_NAMES[case.method],
                  "method_tag": int(case.method), "request_id": request_id, "request_frame_hex": frame.hex(),
                  "response_kind": int(answer.kind)}
        if answer.kind == proto.Kind.RESPONSE:
            body = normalised(case.method, answer.payload)
            record.update(response_payload_sha256=sha256(body), response_payload_bytes=len(body))
            if oracle is not None:
                record["grpc_path_identical"] = body == normalised(case.method, oracle.call(
                    case.method, case.payload, metadata=case.metadata))
        else:
            record["error"] = proto.decode_error(answer)
        records.append(record)
    return records


def protocol_cases(worker, first_id):
    """Malformed frames: raw bytes in, error code out, worker alive afterwards."""
    health = cases.health_case()
    specs = [
        ("unknown-method", proto.HEADER.pack(3, 1, 1, 0xEE, 0, 0, 0) + b"abc"),
        ("unsupported-version", proto.HEADER.pack(3, 9, 1, 3, 0, 0, 0) + b"abc"),
        ("response-kind-as-request", proto.HEADER.pack(3, 1, 2, 3, 0, 0, 0) + b"abc"),
        ("unknown-flags", proto.HEADER.pack(3, 1, 1, 3, 0x40, 0, 0) + b"abc"),
        ("oversized-health-payload", proto.HEADER.pack(5000, 1, 1, 3, 0, 0, 0) + bytes(5000)),
        ("malformed-metadata", proto.HEADER.pack(4, 1, 1, 4, 1, 0, 0) + b"\xff\xff\xff\xff"),
        ("protobuf-garbage", proto.HEADER.pack(6, 1, 1, 1, 0, 0, 0) + b"\xff" * 6),
        ("empty-layer-list", proto.encode_frame(proto.Kind.REQUEST, proto.Method.ANALYZE_PROMPT, 0,
                                                cases.pb.AnalyzePromptRequest(text="hello").SerializeToString())),
        ("runtime-layer-value", proto.encode_frame(proto.Kind.REQUEST, proto.Method.ANALYZE_PROMPT, 0,
                                                   cases.pb.AnalyzePromptRequest(
                                                       text="hello", layers=[cases.pb.DETECTION_LAYER_RUNTIME]).SerializeToString())),
    ]
    records = []
    for index, (label, raw) in enumerate(specs):
        request_id = first_id + index
        raw = raw[:8] + request_id.to_bytes(8, "big") + raw[16:]  # request_id field of the header
        worker.send_raw(raw)
        answer = worker.read_frame()
        follow = worker.call(health.method, health.payload)
        records.append({"label": label, "request_frame_hex": raw.hex(), "response_kind": int(answer.kind),
                        "error": proto.decode_error(answer), "worker_alive_after": follow.kind == proto.Kind.RESPONSE})
    return records


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=HERE)
    parser.add_argument("--skip-v3", action="store_true", help="Do not capture the pretrained-V3 cases.")
    args = parser.parse_args(argv)
    import torch

    v3_root = None if args.skip_v3 else v3_model_root()
    out = {"analysis.json": None, "training.json": None, "protocol.json": None}

    roots = [LEGACY_MODEL_ROOT] + ([v3_root] if v3_root else [])
    warm = ["--warm-semantic-model", cases.TINY_MODEL] + (["--warm-semantic-model", V3_MODEL_ID] if v3_root else [])
    with WorkerProcess(roots, arguments=warm) as worker:
        ready = json.loads(worker.wait_ready().payload)
        oracle = GrpcOracle(roots)
        try:
            analysis = run_cases(worker, oracle, [cases.health_case()] + cases.analyze_cases(v3_root is not None), 1000)
        finally:
            oracle.close()
        protocol = protocol_cases(worker, 9000)
    limits = ready["limits"]

    with tempfile.TemporaryDirectory() as directory:
        root = cases.build_training_root(Path(directory))
        with WorkerProcess([root], arguments=["--warm-layers", ""]) as worker:
            worker.wait_ready()
            oracle = GrpcOracle([root])
            try:
                training = run_cases(worker, oracle, cases.training_cases() + cases.presence_cases(), 5000)
            finally:
                oracle.close()

    out["analysis.json"] = {"schema": SCHEMA, "cases": analysis}
    out["training.json"] = {"schema": SCHEMA, "cases": training}
    out["protocol.json"] = {"schema": SCHEMA, "cases": protocol}
    files = {}
    for name, value in out.items():
        data = dump(value)
        (args.out / name).write_bytes(data)
        files[name] = {"bytes": len(data), "cases": len(value["cases"]), "sha256": sha256(data)}

    everything = analysis + training
    compared = [item for item in everything if "grpc_path_identical" in item]
    manifest = {
        "schema": SCHEMA,
        "prompts_file": "prompts.json",
        "prompts_sha256": sha256((HERE / "prompts.json").read_bytes()),
        "stage_0_prompts": "None: the stage 0 corpus holds no PrivokeRuntimeService prompt bodies; prompts.json supplies them.",
        "environment": {"python": sys.version.split()[0], "torch": torch.__version__, "torch_threads": 1,
                        "v3_package_captured": bool(v3_root)},
        "comparison": "Responses are compared as serialized protobuf bytes (deterministic maps) with elapsed_ms and "
                      "metadata['elapsed_ms'] cleared on both paths; nothing else is normalised.",
        "grpc_path_identical": {"compared": len(compared), "identical": sum(item["grpc_path_identical"] for item in compared)},
        "by_scope": {scope: {"compared": sum(1 for item in compared if item["scope"] == scope),
                             "identical": sum(1 for item in compared if item["scope"] == scope and item["grpc_path_identical"])}
                     for scope in ("llm_only", "detector_ablation", "product_pipeline")},
        "scope_note": "llm_only = semantic layer or semantic-only RPCs. detector_ablation and product_pipeline cases include "
                      "regex or NER and are never LLM-only evidence.",
        "limits": limits,
        "files": files,
    }
    (args.out / "manifest.json").write_bytes(dump(manifest))
    print(json.dumps({"files": files, "grpc_path_identical": manifest["grpc_path_identical"],
                      "by_scope": manifest["by_scope"]}, indent=1))
    return 0 if manifest["grpc_path_identical"]["compared"] == manifest["grpc_path_identical"]["identical"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
