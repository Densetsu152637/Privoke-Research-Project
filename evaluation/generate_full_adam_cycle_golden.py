"""Golden generator for the Rust fuzzer's FULL Adam policy cycle (`rust/services/fuzzer`, stage 21, RUST-S21F item 1).

The oracle is the maintained Python fuzzer, `services/privoke-fuzzer/src/fuzzer_service.py`, run in process on the host exactly as
`generate_fuzzer_golden.py` does: the client runtime is replaced by the response bytes of a real retained cycle, and the
parameter-update service by a fake that reports no earlier request. Here the retained cycles are the FULL projected Adam cycles of the
iterative fuzzer study (`full_projected_adam64_v1`, `execution_evidence` with the raw runtime response and its 64-step trace).
The study's prompt dataset is not in the repository, so the sampler runs over the committed taxonomy fixture and the recorded
response is replayed for the request the oracle builds (the response is validated against its own configuration, trace and
counts, not against the prompts).

The published metadata binds the retained cycle by `training_evidence_sha256`, a hash over a record that names the attempt file by absolute
path, so the hash depends on the oracle's scratch directory: the golden keeps the oracle's raw path per cycle, and the Rust replay
recomputes the hash over its own retained record with that path substituted (and compares the rest of the message without it).

The cycle writes more than the legacy one: the physical attempt reservation (`full-adam-runtime/<identity>/started.json`), the immutable
attempt record and its admission verdict (`backtracking-attempts/<digest>/{attempts,admission}/<ns>.json`), a reservation rejection, and the
complete cycle record, whose `execution_evidence` names the attempt file by absolute path. File names carry nanosecond timestamps and
paths carry the scratch directory, so both are normalised (`tests/conformance/normalization.toml` lists timestamps): a timestamp
file name becomes its ordinal in its directory and the dump directory becomes `<DUMP>`. Nothing else is normalised.

Usage (host Python, for example `evaluation/.venv-v1-v3-pipeline`):
  python evaluation/generate_full_adam_cycle_golden.py --results <main checkout>/evaluation/results --generated <dir>
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import generate_fuzzer_golden as base  # noqa: E402

ROOT = base.ROOT
OUTPUT = ROOT / "rust/services/fuzzer/tests/fixtures/full_adam_cycles_golden.json"
STUDY = "iterative_fuzzer_20261011"
OBJECTIVE = "class_balanced_contextual_sum_category_decision_margin_v1"
POLICY = "full_projected_adam64_v1"
ELIGIBILITY = "candidate_train_exact_eligibility_v1"
RETENTION_GATE_POLICY = "full_projected_adam64_original_train_gate_v1"
RETENTION_GATE_OBJECTIVE = "class_balanced_contextual_sum_margin_original_gate_v1"
RETENTION_ELIGIBILITY = "candidate_train_exact_original_target_capped_v1"
HEADER = "x-privoke-training-admission-v1"
TIMESTAMP_NAME = re.compile(r"^\d{15,}\.json$")


def full_adam_env():
    return {"FUZZ_TRAINING_LEARNING_RATE": "0.003", "FUZZ_UNDERLYING_TRAINING_LEARNING_RATE": "0.003", "FUZZ_TRAINING_MAX_GRADIENT": "0.05"}


class MetadataChannel(base.FakeChannel):
    """The base fake channel, and the invocation metadata and deadline of every call."""

    def __init__(self, handlers, log, calls):
        super().__init__(handlers, log)
        self.calls = calls

    def unary_unary(self, path, *args, **kwargs):
        def call(request, timeout=None, metadata=None):
            self.log.append((path, request.SerializeToString(deterministic=True)))
            self.calls.append({"path": path, "timeout": timeout, "metadata": [list(pair) for pair in (metadata or ())]})
            return self.handlers[path](request)

        return call


def policy_metadata(canonical, config, **overrides):
    metadata = {
        "expected_contextual_training_objective": OBJECTIVE,
        "expected_contextual_training_optimizer": POLICY,
        "expected_contextual_candidate_eligibility": ELIGIBILITY,
        "expected_full_projected_adam_config_v1": canonical(config),
        "expected_contextual_training_scope": "full_encoder",
    }
    metadata.update(overrides)
    return metadata


def normalised_dump(directory: Path) -> dict:
    """Every file of the dump with timestamp names replaced by ordinals and the dump path by `<DUMP>`."""
    files = sorted(path for path in directory.rglob("*") if path.is_file() and not path.name.startswith("training-reservations.sqlite3"))
    renamed = {}
    for folder in sorted({path.parent for path in files}):
        stamped = sorted(path for path in files if path.parent == folder and TIMESTAMP_NAME.match(path.name))
        for ordinal, path in enumerate(stamped):
            renamed[path] = f"{ordinal:04d}.json"
    texts = {}
    for path in files:
        relative = path.relative_to(directory)
        name = renamed.get(path, path.name)
        texts[path] = ("/".join(relative.parent.parts + (name,)), path.read_text(encoding="utf-8"))
    result = {}
    for path, (key, text) in texts.items():
        for other, (other_key, _) in texts.items():
            escaped = json.dumps(str(other))[1:-1]
            text = text.replace(escaped, "<DUMP>/" + other_key)
        result[key] = text
    # Python writes these records in text mode, so on a Windows host every line ends in CRLF while `read_text` shows LF; the hash an
    # admission verdict keeps of its attempt file is then the hash of the CRLF bytes. The Linux bytes (LF) are what Rust writes.
    for path, (key, text) in texts.items():
        if key.endswith("/admission/attempts/" + Path(key).name) and "physical_attempt_sha256" in text:
            old = json.loads(text)["physical_attempt_sha256"]
            attempt = next(other_text for other, (other_key, other_text) in texts.items()
                           if other_key == key.replace("/admission/attempts/", "/attempts/"))
            result[key] = result[key].replace(old, hashlib.sha256(attempt.encode("utf-8")).hexdigest())
    return result


def raw_physical_attempt(dump: Path, request):
    """The unnormalised `execution_evidence.physical_attempt` of the retained cycle of this request, which `training_evidence_sha256` binds."""
    for path in sorted((dump / "training-cycles").rglob("*.json")) if (dump / "training-cycles").exists() else []:
        record = json.loads(path.read_text(encoding="utf-8"))
        if record["request_id"] == request.request_id:
            return record["execution_evidence"].get("physical_attempt")
    return None


def raw_evidence_paths(dump: Path, request):
    """Every absolute path of the retained cycle's `execution_evidence` (the attempt, the retained sampling audit, the retention release),
    unnormalised: `training_evidence_sha256` hashes them, so the replay recomputes the hash over its own record with these."""
    paths = {}
    for path in sorted((dump / "training-cycles").rglob("*.json")) if (dump / "training-cycles").exists() else []:
        record = json.loads(path.read_text(encoding="utf-8"))
        if record["request_id"] != request.request_id:
            continue
        evidence = record["execution_evidence"]
        if "physical_attempt" in evidence:
            paths["physical_attempt"] = evidence["physical_attempt"]
        for name in ("rehearsal_audit", "benign_audit", "retention_release", "window_inputs"):
            if name in evidence:
                paths[name] = evidence[name]["path"]
        return paths
    return paths


def raw_evidence_hashes(dump: Path, request):
    """The recorded sha256 of every retained reference of the cycle's `execution_evidence` that Python wrote in text mode: only the
    window inputs (the other references are hashed over bytes Python wrote in binary mode). Unnormalised, like the paths."""
    for path in sorted((dump / "training-cycles").rglob("*.json")) if (dump / "training-cycles").exists() else []:
        record = json.loads(path.read_text(encoding="utf-8"))
        if record["request_id"] == request.request_id:
            evidence = record["execution_evidence"]
            return {name: evidence[name]["sha256"] for name in ("window_inputs",) if name in evidence}
    return {}


def reservations(directory: Path):
    database = directory / "training-reservations.sqlite3"
    if not database.exists():
        return []
    connection = sqlite3.connect(database)
    try:
        return [list(row) for row in connection.execute("SELECT identity, fingerprint FROM requests ORDER BY identity")]
    finally:
        connection.close()


def run_sequence(label, env, cycles, generated: Path) -> dict:
    """`cycles` is a list of (request, scope, runtime_response_bytes, ack_bytes) run in order against one fresh durable state."""
    base.bootstrap(generated)
    from privoke.v1 import parameters_pb2, runtime_pb2  # noqa: PLC0415
    import fuzzer_service  # noqa: PLC0415
    import runtime_client  # noqa: PLC0415
    import privoke_service.stack_connection as stack  # noqa: PLC0415
    from config import FuzzerConfig  # noqa: PLC0415

    results = []
    with tempfile.TemporaryDirectory() as scratch:
        scratch_path = Path(scratch)
        dump = scratch_path / "dump"
        # A sequence may name its own taxonomy dataset (the window cycle reads the study's); the dump and the state stay scratch.
        full_env = {**base.BASE_ENV, "FUZZ_PROMPT_DATASET_PATH": str(base.TAXONOMY_DATASET), **env,
                    "PRIVOKE_FUZZER_DUMP_DIR": str(dump), "FUZZ_CURRICULUM_STATE_PATH": str(scratch_path / "curriculum.sqlite3")}
        saved = dict(os.environ)
        os.environ.update(full_env)
        try:
            config = FuzzerConfig.from_env()
            for request, scope, runtime_bytes, ack_bytes in cycles:
                log, calls, answers = [], [], []
                runtime_path = base.RUNTIME_PATHS[scope]

                def runtime_answer(_request, raw=runtime_bytes):
                    # A cycle may script its answer as a function of the request the oracle built (the response of a policy cycle
                    # carries counts derived from that request).
                    data = raw(_request) if callable(raw) else raw
                    answers.append(data)
                    return runtime_pb2.ComputeSemanticGradientsResponse.FromString(data)

                handlers = {
                    runtime_path: runtime_answer,
                    base.STATUS_PATH: lambda _request: parameters_pb2.ParameterUpdateStatus(found=False),
                    base.SUBMIT_PATH: lambda _request, raw=ack_bytes: parameters_pb2.ParameterUpdateAck.FromString(raw),
                }

                def channel(target, *args, **kwargs):
                    return MetadataChannel(handlers, log, calls)

                originals = (fuzzer_service.service_channel, runtime_client.service_channel, stack.service_channel)
                fuzzer_service.service_channel = runtime_client.service_channel = stack.service_channel = channel
                try:
                    service = fuzzer_service.FuzzerTrainingService(config)
                    method = service.RunUnderlyingTrainingCycle if scope == "full_encoder" else service.RunTrainingCycle
                    try:
                        response = method(request, base.Context())
                        outcome = {"ok": base.b64(response.SerializeToString(deterministic=True))}
                    except base.Aborted as exc:
                        outcome = {"abort": [exc.code.name, exc.message]}
                    except Exception as exc:  # an uncaught handler exception: gRPC answers UNKNOWN with this text
                        outcome = {"abort": ["UNKNOWN", f"Exception calling application: {exc}"]}
                finally:
                    fuzzer_service.service_channel, runtime_client.service_channel, stack.service_channel = originals
                wire = {path: base.b64(raw) for path, raw in log}
                results.append({
                    "physical_attempt_raw": raw_physical_attempt(dump, request),
                    "evidence_paths_raw": raw_evidence_paths(dump, request),
                    "evidence_sha256_raw": raw_evidence_hashes(dump, request),
                    "scope": scope,
                    "request": base.b64(request.SerializeToString(deterministic=True)),
                    "runtime_rpc": runtime_path,
                    "runtime_request": wire.get(runtime_path),
                    "runtime_response": base.b64(answers[-1] if answers else (b"" if callable(runtime_bytes) else runtime_bytes)),
                    "runtime_calls": [call for call in calls if call["path"] == runtime_path],
                    "status_request": wire.get(base.STATUS_PATH),
                    "submit_request": wire.get(base.SUBMIT_PATH),
                    "submit_metadata_keys": sorted(parameters_pb2.ParameterUpdateRequest.FromString(
                        base64.b64decode(wire[base.SUBMIT_PATH])).metadata) if base.SUBMIT_PATH in wire else None,
                    "ack": base.b64(ack_bytes),
                    "calls": [path for path, _ in log],
                    "outcome": outcome,
                })
            diagnostics = scratch_path / "gate-diagnostics"
            snapshot = {"files": normalised_dump(dump), "reservations": reservations(dump),
                        "gate_diagnostics": {path.name: path.read_text(encoding="utf-8") for path in sorted(diagnostics.glob("*.json"))}}
        finally:
            os.environ.clear()
            os.environ.update(saved)
    return {"label": label, "env": {**base.BASE_ENV, **env}, "cycles": results, **snapshot}


def full_records(results: Path):
    study = results / STUDY
    passed = rejected = None
    for path in sorted(study.glob("block*/*/*/fuzzer/training-cycles/*/*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        meta = record["metadata"]
        if (record["training_stage"] != "full_encoder" or meta.get("contextual_training_optimizer") != POLICY
                or meta.get("contextual_sampling_strategy") != base.TAXONOMY):
            continue
        if record["gate_passed"] and record.get("ack") and passed is None:
            passed = record
        if not record["gate_passed"] and rejected is None:
            rejected = record
        if passed and rejected:
            break
    if passed is None or rejected is None:
        raise SystemExit(f"{study} holds no retained FULL Adam taxonomy cycles")
    return passed, rejected


def golden(results: Path, generated: Path) -> dict:
    base.bootstrap(generated)
    from privoke.v1 import parameters_pb2, runtime_pb2  # noqa: PLC0415
    from privoke_model.full_adam import CONFIG, canonical  # noqa: PLC0415

    passed, rejected = full_records(results)

    def response_bytes(record, request_id=None, mutate=None):
        raw = base64.b64decode(record["execution_evidence"]["response_protobuf_base64"])
        response = runtime_pb2.ComputeSemanticGradientsResponse.FromString(raw)
        if request_id is not None:
            response.request_id = request_id
        if mutate:
            mutate(response)
        return response.SerializeToString(deterministic=True)

    def build(record, request_id=None, scope_metadata=None, **extra):
        metadata = {"initiator": "param-update-service", "require_full_capability": "true",
                    "expected_base_version": record["base_version"], "contextual_sampling_strategy": base.TAXONOMY,
                    **policy_metadata(canonical, CONFIG), **(scope_metadata or {}), **extra}
        return parameters_pb2.FuzzerTrainingRequest(
            request_id=request_id or record["request_id"], source_id=record.get("original_source_id", record["source_id"]),
            model_id=record["model_id"], prompt_count=32, seed=42, metadata=metadata)

    ack = base.ack_bytes_for(parameters_pb2, passed)
    first = (build(passed), "full_encoder", response_bytes(passed), ack)
    second = (build(rejected), "full_encoder", response_bytes(rejected), base.ack_bytes_for(parameters_pb2, rejected))

    def corrupt_objective(response):
        response.metadata["executed_contextual_training_objective"] = "legacy_sum_category"

    def corrupt_summary(response):
        response.metadata["full_projected_adam_summary_v1"] = "{}"

    bad_objective = build(passed, request_id="full-adam-bad-objective")
    bad_summary = build(passed, request_id="full-adam-bad-summary")
    heads_scope = build(passed, request_id="full-adam-heads-header")
    retention = build(passed, request_id="full-adam-retention", scope_metadata={
        "expected_contextual_training_objective": RETENTION_GATE_OBJECTIVE,
        "expected_contextual_training_optimizer": RETENTION_GATE_POLICY,
        "expected_contextual_candidate_eligibility": RETENTION_ELIGIBILITY,
        "expected_original_train_retention_manifest_sha256": "0" * 64})
    diagnostics = {"study_gate_diagnostics": "v1"}
    cycles = [
        first,
        second,
        # The first request again: the durable reservation allows it, the physical attempt reservation refuses a second call.
        first,
        (bad_objective, "full_encoder", response_bytes(passed, "full-adam-bad-objective", corrupt_objective), ack),
        (bad_summary, "full_encoder", response_bytes(passed, "full-adam-bad-summary", corrupt_summary), ack),
        # The header names the full encoder but the cycle is the heads RPC: refused before any reservation.
        (heads_scope, "heads", response_bytes(passed, "full-adam-heads-header"), ack),
        (retention, "full_encoder", response_bytes(passed, "full-adam-retention"), ack),
        # The study's gate diagnostics record, for a published update and for one the guard refuses.
        (build(passed, request_id="full-adam-diagnostics-passed", **diagnostics), "full_encoder",
         response_bytes(passed, "full-adam-diagnostics-passed"), ack),
        (build(rejected, request_id="full-adam-diagnostics-refused", **diagnostics), "full_encoder",
         response_bytes(rejected, "full-adam-diagnostics-refused"), ack),
    ]
    sequence = run_sequence("full-adam-taxonomy", {"MODEL_ID": passed["model_id"], **full_adam_env()}, cycles, generated)
    sequence["recorded"] = {
        "study": STUDY, "passed_request_id": passed["request_id"], "rejected_request_id": rejected["request_id"],
        "note": "runtime responses of retained FULL Adam cycles replayed for the requests the oracle builds over the taxonomy fixture"}
    return {"schema": 1, "oracle": "services/privoke-fuzzer/src/fuzzer_service.py", "python": sys.version.split()[0],
            "normalisation": "timestamp file names become ordinals; the dump directory becomes <DUMP>", "sequences": [sequence]}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results", type=Path, required=True, help="evaluation/results of a checkout holding the retained iterative study")
    parser.add_argument("--generated", type=Path, required=True, help="directory with the generated protobuf clients (privoke/v1)")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    document = golden(args.results, args.generated)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    outcomes = [cycle["outcome"].get("abort", ["ok"])[:2] for cycle in document["sequences"][0]["cycles"]]
    print(json.dumps({"output": str(args.output), "outcomes": outcomes, "files": len(document["sequences"][0]["files"]),
                      "gate_diagnostics": len(document["sequences"][0]["gate_diagnostics"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
