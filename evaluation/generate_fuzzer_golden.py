"""Golden generator for the Rust fuzzer service (`rust/services/fuzzer`, stage 21).

Historical (stage V3-R8b): the Rust consumer of this golden, `rust/services/fuzzer`, was deleted when V1 training was retired,
so the output path below no longer exists in the tree. The module stays because `generate_v3_fuzzer_golden.py` imports its fake channel and context.

The oracle is the maintained Python fuzzer, `services/privoke-fuzzer/src/fuzzer_service.py`, run in process on the host.
Its two network dependencies are replaced by recorded answers, so no stack, model or analysis service is needed and no
detector layer runs (the cycle only requests the semantic layer, and the recorded response says so):

* the client runtime is replaced by the response bytes that a real recorded cycle received
  (`execution_evidence.response_protobuf_base64` in retained `training-cycles` evidence), and
* the parameter-update service is replaced by a fake that reports no earlier request and acknowledges a submission with
  the recorded acknowledgement.

Every wire message that crosses either boundary is captured, together with the cycle's response or abort, the durable
evidence files and the reservation rows, so the Rust service can be replayed against the same bytes.

Subcommands (host Python, for example `evaluation/.venv-v1-v3-pipeline`; `--generated` names the generated protobuf
clients, for example `<main checkout>/services/privoke-fuzzer/generated`):

  recorded    legacy-sampler head cycles (retained study cells) replayed from recorded runtime responses
  curriculum  two fixed-curriculum cycles over a durable SQLite cursor state, with the synthetic curriculum fixture

Usage:
  python evaluation/generate_fuzzer_golden.py all --results <main checkout>/evaluation/results --generated <dir>
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "rust/services/fuzzer/tests/fixtures/fuzzer_cycles_golden.json"
CURRICULUM_MANIFEST = ROOT / "rust/crates/privoke-curriculum/tests/fixtures/curriculum/manifest.json"
TAXONOMY_DATASET = ROOT / "rust/crates/privoke-curriculum/tests/fixtures/bc01/taxonomy-coverage-v1.json"
TAXONOMY = "taxonomy_coverage_v1"
STUDY_V2 = "accelerated_all_surfaces_20261010/execution-study-v2/cells/main-baseline-heads-42"
STUDY_V3 = "accelerated_all_surfaces_20261010/execution-study-v3/cells/curriculum-balanced-dual-42"
SEED_CANDIDATES = (42, 43, 44, 0, 1337)
RUNTIME_PATHS = {
    "heads": "/privoke.v1.PrivokeRuntimeService/ComputeSemanticGradients",
    "full_encoder": "/privoke.v1.PrivokeRuntimeService/ComputeUnderlyingModelGradients",
}
STATUS_PATH = "/privoke.v1.ParamUpdateService/GetParameterUpdateStatus"
SUBMIT_PATH = "/privoke.v1.ParamUpdateService/SubmitParameterUpdate"
BASE_ENV = {
    "PARAM_UPDATE_TARGET": "param-update-service:50052",
    "PRIVOKE_RUNTIME_TARGET": "client-runtime:50054",
    "MODEL_ID": "privoke-baseline",
    "FUZZER_ID": "privoke-fuzzer",
    "FUZZ_CONTEXTUAL_SAMPLING_STRATEGY": "legacy_random_v1",
    "FUZZ_SEED": "1337",
}


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def bootstrap(generated: Path) -> None:
    for path in (ROOT / "shared" / "python", ROOT / "services" / "privoke-fuzzer" / "src", generated):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))


class Aborted(Exception):
    """What `context.abort` raises in the real server."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


class Context:
    def abort(self, code, message):
        raise Aborted(code, message)

    def is_active(self):
        return True


class FakeChannel:
    """A gRPC channel that answers each method from a table and records every request's deterministic bytes."""

    def __init__(self, handlers, log):
        self.handlers = handlers
        self.log = log

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def unary_unary(self, path, *args, **kwargs):
        def call(request, timeout=None, metadata=None):
            self.log.append((path, request.SerializeToString(deterministic=True)))
            return self.handlers[path](request)

        return call


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def collect_dump(directory: Path) -> dict:
    """Retained evidence under `training-cycles` (final text of every file) and the reservation rows."""
    evidence = {}
    for path in sorted((directory / "training-cycles").rglob("*.json")) if (directory / "training-cycles").exists() else []:
        evidence[path.relative_to(directory).as_posix()] = path.read_text(encoding="utf-8")
    reservations = []
    database = directory / "training-reservations.sqlite3"
    if database.exists():
        connection = sqlite3.connect(database)
        try:
            reservations = [list(row) for row in connection.execute("SELECT identity, fingerprint FROM requests ORDER BY identity")]
        finally:
            connection.close()
    return {"evidence": evidence, "reservations": reservations}


def collect_curriculum(path: Path) -> dict:
    if not path.exists():
        return {}
    connection = sqlite3.connect(path)
    try:
        batches = [[identity, fingerprint, json.loads(allocation)]
                   for identity, fingerprint, allocation in connection.execute("SELECT identity, fingerprint, allocation FROM batches ORDER BY identity")]
        cursors = [list(row) for row in connection.execute("SELECT identity, position FROM cursors ORDER BY identity")]
    finally:
        connection.close()
    return {"batches": batches, "cursors": cursors}


def run_sequence(label, env, cycles, generated: Path) -> dict:
    """Run `cycles` (request, scope, runtime_response_bytes, ack_bytes) in order against one fresh durable state."""
    bootstrap(generated)
    from privoke.v1 import parameters_pb2, runtime_pb2  # noqa: PLC0415
    import fuzzer_service  # noqa: PLC0415
    import runtime_client  # noqa: PLC0415
    import privoke_service.stack_connection as stack  # noqa: PLC0415
    from config import FuzzerConfig  # noqa: PLC0415

    results = []
    with tempfile.TemporaryDirectory() as scratch:
        scratch_path = Path(scratch)
        dump = scratch_path / "dump"
        full_env = {**BASE_ENV, **env, "PRIVOKE_FUZZER_DUMP_DIR": str(dump)}
        if "taxonomy" in label:
            full_env["FUZZ_PROMPT_DATASET_PATH"] = str(TAXONOMY_DATASET)
        if "curriculum" in label:
            full_env["FUZZ_CURRICULUM_MANIFEST_PATH"] = str(CURRICULUM_MANIFEST)
            full_env["FUZZ_CURRICULUM_STATE_PATH"] = str(scratch_path / "curriculum.sqlite3")
        saved = dict(os.environ)
        os.environ.update(full_env)
        try:
            config = FuzzerConfig.from_env()
            for request, scope, runtime_bytes, ack_bytes in cycles:
                log = []
                runtime_path = RUNTIME_PATHS[scope]
                handlers = {
                    runtime_path: lambda _request, raw=runtime_bytes: runtime_pb2.ComputeSemanticGradientsResponse.FromString(raw),
                    STATUS_PATH: lambda _request: parameters_pb2.ParameterUpdateStatus(found=False),
                    SUBMIT_PATH: lambda _request, raw=ack_bytes: parameters_pb2.ParameterUpdateAck.FromString(raw),
                }

                def channel(target, *args, **kwargs):
                    return FakeChannel(handlers, log)

                originals = (fuzzer_service.service_channel, runtime_client.service_channel, stack.service_channel)
                fuzzer_service.service_channel = runtime_client.service_channel = stack.service_channel = channel
                try:
                    service = fuzzer_service.FuzzerTrainingService(config)
                    method = service.RunUnderlyingTrainingCycle if scope == "full_encoder" else service.RunTrainingCycle
                    try:
                        response = method(request, Context())
                        outcome = {"ok": b64(response.SerializeToString(deterministic=True))}
                    except Aborted as exc:
                        outcome = {"abort": [exc.code.name, exc.message]}
                finally:
                    fuzzer_service.service_channel, runtime_client.service_channel, stack.service_channel = originals
                wire = {path: b64(raw) for path, raw in log}
                results.append({
                    "scope": scope,
                    "request": b64(request.SerializeToString(deterministic=True)),
                    "runtime_rpc": runtime_path,
                    "runtime_request": wire.get(runtime_path),
                    "runtime_response": b64(runtime_bytes),
                    "status_request": wire.get(STATUS_PATH),
                    "submit_request": wire.get(SUBMIT_PATH),
                    "ack": b64(ack_bytes),
                    "calls": [path for path, _ in log],
                    "outcome": outcome,
                })
            snapshot = collect_dump(dump)
            snapshot["curriculum"] = collect_curriculum(scratch_path / "curriculum.sqlite3")
        finally:
            os.environ.clear()
            os.environ.update(saved)
    return {"label": label, "env": {**BASE_ENV, **env}, "cycles": results, **snapshot}


def recorded_records(results: Path, cell: str):
    for path in sorted((results / cell / "fuzzer-state" / "training-cycles").glob("*/*.json")):
        yield json.loads(path.read_text(encoding="utf-8"))


def build_request(parameters_pb2, record, seed: int):
    metadata = {"initiator": "param-update-service", "require_full_capability": "true"}
    if record["training_stage"] == "full_encoder":
        metadata["expected_base_version"] = record["base_version"]
    return parameters_pb2.FuzzerTrainingRequest(
        request_id=record["request_id"],
        source_id=record.get("original_source_id", record["source_id"]),
        model_id=record["model_id"],
        prompt_count=32,
        seed=seed,
        metadata=metadata,
    )


def ack_bytes_for(parameters_pb2, record) -> bytes:
    ack = record.get("ack") or {"accepted": True, "model_id": record["model_id"], "applied_version": record["base_version"] + ".1", "message": ""}
    return parameters_pb2.ParameterUpdateAck(**ack).SerializeToString(deterministic=True)


def recorded_golden(results: Path, generated: Path) -> list:
    bootstrap(generated)
    from privoke.v1 import parameters_pb2  # noqa: PLC0415

    sequences = []
    wanted = {"passed": None, "rejected": None}
    for record in recorded_records(results, STUDY_V2):
        key = "passed" if record["gate_passed"] and record.get("ack") else "rejected" if not record["gate_passed"] else None
        if key and wanted[key] is None and record["training_stage"] == "heads":
            wanted[key] = record
    for name, record in wanted.items():
        if record is None:
            continue
        runtime_bytes = base64.b64decode(record["execution_evidence"]["response_protobuf_base64"])
        recorded_request = base64.b64decode(record["execution_evidence"]["request_protobuf_base64"])
        chosen = None
        for seed in SEED_CANDIDATES:
            request = build_request(parameters_pb2, record, seed)
            sequence = run_sequence(f"recorded-{name}", {}, [(request, "heads", runtime_bytes, ack_bytes_for(parameters_pb2, record))], generated)
            matches = base64.b64decode(sequence["cycles"][0]["runtime_request"] or "") == recorded_request
            if matches or chosen is None:
                chosen = (seed, sequence, matches)
            if matches:
                break
        seed, sequence, matches = chosen
        sequence["recorded"] = {"cell": STUDY_V2, "request_id": record["request_id"], "seed": seed,
                                "runtime_request_matches_recorded": matches,
                                "recorded_runtime_request_sha256": hashlib.sha256(recorded_request).hexdigest(),
                                "recorded_gate_passed": record["gate_passed"]}
        sequences.append(sequence)
    return sequences


def curriculum_golden(results: Path, generated: Path) -> list:
    bootstrap(generated)
    from privoke.v1 import parameters_pb2, runtime_pb2  # noqa: PLC0415

    record = next(r for r in recorded_records(results, STUDY_V3)
                  if r["training_stage"] == "heads" and r["gate_passed"] and r.get("ack"))
    runtime_bytes = base64.b64decode(record["execution_evidence"]["response_protobuf_base64"])
    ack = ack_bytes_for(parameters_pb2, record)
    cycles = []
    for index in (1, 2):
        request = build_request(parameters_pb2, {**record, "request_id": f"curriculum-cycle-{index}"}, 42)
        request.model_id = record["model_id"]
        # The recorded response names the recorded request; the synthetic cycles carry their own identifiers.
        response = runtime_pb2.ComputeSemanticGradientsResponse.FromString(runtime_bytes)
        response.request_id = request.request_id
        cycles.append((request, "heads", response.SerializeToString(deterministic=True), ack))
    # The first request again: the durable reservation answers it without a second allocation.
    cycles.append((cycles[0][0], "heads", cycles[0][2], ack))
    sequence = run_sequence("curriculum-sqlite", {"MODEL_ID": record["model_id"]}, cycles, generated)
    sequence["recorded"] = {"cell": STUDY_V3, "request_id": record["request_id"],
                            "note": "runtime response of a recorded curriculum cycle; the request is generated from the synthetic fixture manifest"}
    return [sequence]


def taxonomy_golden(results: Path, generated: Path) -> list:
    """Taxonomy-coverage cycles (RUST-S21C): the sampler, its audit, the dataset pin and the replay identity over the fixture."""
    bootstrap(generated)
    from privoke.v1 import parameters_pb2, runtime_pb2  # noqa: PLC0415

    record = next(r for r in recorded_records(results, STUDY_V2)
                  if r["training_stage"] == "heads" and r["gate_passed"] and r.get("ack"))
    runtime_bytes = base64.b64decode(record["execution_evidence"]["response_protobuf_base64"])
    ack = ack_bytes_for(parameters_pb2, record)

    def make(index, prompt_count=32, **metadata):
        metadata = {"contextual_sampling_strategy": TAXONOMY, **metadata}
        request = build_request(parameters_pb2, {**record, "request_id": f"taxonomy-cycle-{index}"}, 42)
        request.model_id = record["model_id"]
        request.prompt_count = prompt_count
        request.metadata.update(metadata)
        response = runtime_pb2.ComputeSemanticGradientsResponse.FromString(runtime_bytes)
        response.request_id = request.request_id
        return (request, "heads", response.SerializeToString(deterministic=True), ack)

    first = make(1)
    cycles = [first, make(2), first,
              make(3, taxonomy_dataset_sha256="0" * 64), make(4, prompt_count=16)]
    return [run_sequence("taxonomy-sampler", {"MODEL_ID": record["model_id"]}, cycles, generated)]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("recorded", "curriculum", "taxonomy", "all"))
    parser.add_argument("--results", type=Path, required=True, help="evaluation/results of a checkout holding the retained studies")
    parser.add_argument("--generated", type=Path, required=True, help="directory with the generated protobuf clients (privoke/v1)")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    sequences = []
    if args.command in ("recorded", "all"):
        sequences += recorded_golden(args.results, args.generated)
    if args.command in ("curriculum", "all"):
        sequences += curriculum_golden(args.results, args.generated)
    if args.command in ("taxonomy", "all"):
        sequences += taxonomy_golden(args.results, args.generated)
    document = {"schema": 1, "oracle": "services/privoke-fuzzer/src/fuzzer_service.py", "python": sys.version.split()[0],
                "normalisation": "tests/conformance/normalization.toml: no timestamp or generated identifier appears in these records",
                "sequences": sequences}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"sequences": [s["label"] for s in sequences], "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
