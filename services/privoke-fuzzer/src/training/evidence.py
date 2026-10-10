"""Durable actual semantic execution evidence for generated training cycles."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import sqlite3
from pathlib import Path


def cycle_identity(request, stage):
    return hashlib.sha256(json.dumps([stage, request.source_id, request.request_id],
                                    separators=(",", ":")).encode()).hexdigest()


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


def persist_cycle_evidence(request, update, stage, *, gate_passed, ack=None):
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
    if ack is not None:
        record["ack"] = {"accepted": ack.accepted, "model_id": ack.model_id,
                         "applied_version": ack.applied_version, "message": ack.message}
    _write_atomic(path, record)


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
