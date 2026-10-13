"""Durable actual semantic execution evidence for generated training cycles."""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import sqlite3
import tempfile
import time
from pathlib import Path


def cycle_identity(request, stage):
    return hashlib.sha256(json.dumps([stage, request.source_id, request.request_id],
                                    separators=(",", ":")).encode()).hexdigest()


def persist_policy_attempt(request, response, *, scope, expectations, error=None):
    """Retain immutable physical RPC evidence, including unadmitted and unknown outcomes."""
    directory = os.getenv("PRIVOKE_FUZZER_DUMP_DIR")
    if not directory:
        raise ValueError("Training policy attempts require durable PRIVOKE_FUZZER_DUMP_DIR.")
    wire = request.SerializeToString(deterministic=True)
    record = {"schema_version": 1, "training_stage": scope, "request_id": request.request_id,
        "model_id": request.model_id, "expectations": expectations,
        "request_protobuf_base64": base64.b64encode(wire).decode("ascii"),
        "request_protobuf_sha256": hashlib.sha256(wire).hexdigest(),
        "compute_status": "response_received_unadmitted" if response is not None else "transport_outcome_unknown",
        "admission_status": "rejected" if error else "accepted",
        "error_type": type(error).__name__ if error else None,
        "error": str(error)[:512] if isinstance(error, ValueError) or type(error).__name__ == "RuntimeAnalysisError" else ("Runtime transport failed; execution outcome unknown." if error else None)}
    if response is not None:
        record["response_protobuf_base64"] = base64.b64encode(response.SerializeToString(deterministic=True)).decode("ascii")
        record["declared_executions"] = [{"phase": e.phase, "layer": e.layer, "status": e.status,
                                          "examples": e.examples} for e in response.executions]
        if not error:
            record["compute_status"] = "semantic_execution_validated"
    parent = Path(directory) / "policy-attempts" / record["request_protobuf_sha256"]
    _write_presence_attempt(parent, record)


def persist_backtracking_attempt(request, response, *, scope, expectations, invocation_metadata, error=None):
    """One immutable header-admitted attempt, committed before response admission."""
    directory = os.getenv("PRIVOKE_FUZZER_DUMP_DIR")
    if not directory:
        raise ValueError("Backtracking requires durable PRIVOKE_FUZZER_DUMP_DIR.")
    wire = request.SerializeToString(deterministic=True)
    digest = hashlib.sha256(wire).hexdigest()
    record = {"schema_version": 1, "record_kind": "physical_compute_attempt", "training_stage": scope,
        "request_id": request.request_id, "model_id": request.model_id, "expectations": expectations,
        "invocation_metadata": list(invocation_metadata), "request_protobuf_sha256": digest,
        "request_protobuf_base64": base64.b64encode(wire).decode("ascii"),
        "compute_status": "response_received_unadmitted" if response is not None else "transport_outcome_unknown",
        "gradient_fits": None, "error_type": type(error).__name__ if error else None}
    if response is not None:
        record["response_protobuf_base64"] = base64.b64encode(response.SerializeToString(deterministic=True)).decode("ascii")
    return _write_presence_attempt(Path(directory) / "backtracking-attempts" / digest, record)


def persist_backtracking_admission(attempt, response, *, status, error=None):
    record = {"schema_version": 1, "record_kind": "admission_verdict", "physical_attempt": str(attempt),
        "physical_attempt_sha256": hashlib.sha256(attempt.read_bytes()).hexdigest(), "status": status,
        "gradient_fits": 1 if status in ("accepted", "known_train_rejection") else None,
        "error_type": type(error).__name__ if error else None,
        "error": str(error)[:512] if error else None}
    if status in ("accepted", "known_train_rejection"):
        from privoke_model.contextual_training import full_encoder_tensor_shapes, contextual_output_trainable_names
        scope = json.loads(attempt.read_text())["training_stage"]
        config = json.loads(response.metadata["model_config"])
        shapes = full_encoder_tensor_shapes(config)
        if scope == "heads":
            shapes = {name: shape for name, shape in shapes.items() if name in contextual_output_trainable_names(config)}
        elif scope != "full_encoder":
            raise ValueError("Unknown admitted training scope.")
        if status == "accepted" and {p.name: tuple(p.shape) for p in response.gradients} != shapes:
            raise ValueError("Admitted response tensor inventory differs from its training scope.")
        record["raw_gradient_shapes"] = shapes
    return _write_presence_attempt(attempt.parent.parent / "admission", record)


def reserve_training_request(request, stage, fingerprint):
    directory = os.getenv("PRIVOKE_FUZZER_DUMP_DIR")
    if not directory:
        if request.metadata.get("require_full_capability") == "true":
            raise ValueError("Automatic dual training requires durable PRIVOKE_FUZZER_DUMP_DIR.")
        return
    parent = Path(directory)
    parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(parent / "training-reservations.sqlite3", timeout=30)
    try:
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("CREATE TABLE IF NOT EXISTS requests (identity TEXT PRIMARY KEY, fingerprint TEXT NOT NULL)")
        connection.execute("BEGIN IMMEDIATE")
        identity = cycle_identity(request, stage)
        existing = connection.execute("SELECT fingerprint FROM requests WHERE identity=?", (identity,)).fetchone()
        if existing and existing[0] != fingerprint:
            raise ValueError("request_id belongs to different effective training settings or data.")
        connection.execute("INSERT OR IGNORE INTO requests VALUES (?,?)", (identity, fingerprint))
        connection.commit()
    finally:
        connection.close()


def recover_cycle_evidence_ack(request, stage, previous):
    directory = os.getenv("PRIVOKE_FUZZER_DUMP_DIR")
    if not directory:
        return
    parent = Path(directory) / "training-cycles" / cycle_identity(request, stage)
    if not parent.exists():
        return
    for path in parent.glob("*.json"):
        record = json.loads(path.read_text(encoding="utf-8"))
        if record["base_version"] == previous.base_version:
            record["ack"] = {"accepted": previous.ack.accepted, "model_id": previous.ack.model_id,
                             "applied_version": previous.ack.applied_version, "message": previous.ack.message}
            record["ack_source"] = "updater_receipt"
            _write_atomic(path, record)


def persist_cycle_evidence(request, update, stage, *, gate_passed, ack=None, gate_diagnostics=None):
    directory = os.getenv("PRIVOKE_FUZZER_DUMP_DIR")
    if not directory:
        if request.metadata.get("require_full_capability") == "true":
            raise ValueError("Automatic dual training requires durable PRIVOKE_FUZZER_DUMP_DIR.")
        return
    identity = cycle_identity(request, stage)
    parent = Path(directory) / "training-cycles" / identity
    parent.mkdir(parents=True, exist_ok=True)
    path = parent / (update.metadata["base_parameter_fingerprint"] + ".json")
    record = {"schema_version": 1, "training_stage": stage,
              "request_id": request.request_id, "source_id": request.source_id,
              "original_source_id": request.metadata.get("original_request_source_id", request.source_id),
              "model_id": update.model_id, "base_version": update.base_version,
              "metadata": update.metadata, "metrics": update.metrics,
              "execution_evidence": update.execution_evidence, "gate_passed": gate_passed}
    if gate_diagnostics is not None:
        record["gate_diagnostics"] = gate_diagnostics
    if stage == "presence":
        wire = update.execution_evidence.get("request_protobuf_base64", "")
        record["request_protobuf_sha256"] = hashlib.sha256(base64.b64decode(wire, validate=True)).hexdigest()
        record["compute_status"] = "execution_validated"
        record["metrics"] = {k: v if math.isfinite(v) else str(v) for k, v in update.metrics.items()}
        if gate_diagnostics is not None:
            record["gate_diagnostics"] = {**gate_diagnostics, "metrics": record["metrics"]}
    if ack is not None:
        record["ack"] = {"accepted": ack.accepted, "model_id": ack.model_id,
                         "applied_version": ack.applied_version, "message": ack.message}
    if stage == "presence":
        _write_presence_attempt(parent, record)
    _write_atomic(path, record)


def _write_presence_attempt(parent, record):
    """Atomically commit complete immutable JSON; a collision never overwrites evidence."""
    serialized = json.dumps(record, sort_keys=True, allow_nan=False) + "\n"
    attempts = parent / "attempts"
    attempts.mkdir(parents=True, exist_ok=True)
    path = attempts / f"{time.time_ns()}.json"
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=attempts,
                                         suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        # Same-directory hard-link creation is atomic and fails if the final name exists.
        # Unlike replace/rename, it cannot erase a prior immutable attempt on collision.
        os.link(temporary, path)
        temporary.unlink()
        temporary = None
        if hasattr(os, "O_DIRECTORY"):
            descriptor = os.open(attempts, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return path
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def persist_presence_runtime_attempt(request, response, execution_evidence, *, status, error=""):
    directory = os.getenv("PRIVOKE_FUZZER_DUMP_DIR")
    if not directory:
        return
    raw = request.SerializeToString(deterministic=True)
    parent = Path(directory) / "presence-runtime" / hashlib.sha256(raw).hexdigest()
    _write_presence_attempt(parent, {"schema_version": 1, "request_id": request.request_id,
        "model_id": request.model_id, "base_version": response.base_version,
        "request_protobuf_sha256": hashlib.sha256(raw).hexdigest(),
        "base_parameter_fingerprint": response.metadata.get("base_parameter_fingerprint", ""),
        "compute_status": status, "validation_error": error, "execution_evidence": execution_evidence})


def _write_atomic(path, record):
    parent = path.parent
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=parent,
                                         suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(record, stream, sort_keys=True, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if hasattr(os, "O_DIRECTORY"):
            descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
