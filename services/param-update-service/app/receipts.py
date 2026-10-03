"""Durable update receipts, recovered from the atomically committed model.

The model stores its latest receipt in the same rename as the weights. Before any
subsequent update, that receipt is reconciled into SQLite. This closes the crash
window between publishing weights and recording the RPC outcome without keeping
an ever-growing receipt history in the streamed artifact.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path

from privoke_model import ModelArtifactError

RECEIPT_METADATA_KEY = "last_update_receipt"


def receipt_key(source_id, request_id, request_source_id=""):
    return hashlib.sha256(json.dumps(
        [source_id, request_source_id, request_id], separators=(",", ":")
    ).encode("utf-8")).hexdigest()


def request_receipt(request, applied_version):
    request_id = request.metadata.get("request_id", "")
    if not request_id:
        return None
    return {
        "key": receipt_key(request.source_id, request_id, request.metadata.get("request_source_id", "")),
        "payload_digest": hashlib.sha256(request.SerializeToString(deterministic=True)).hexdigest(),
        "request_fingerprint": request.metadata.get("training_request_fingerprint", ""),
        "model_id": request.model_id,
        "base_version": request.base_version,
        "applied_version": applied_version,
        "prompts_generated": int(request.metadata.get("generated_prompt_count", "0")),
    }


class UpdateReceipts:
    """Serialize model writers across processes and retain all update outcomes."""

    def __init__(self, audit_path: Path):
        self.path = audit_path.with_name(audit_path.name + ".receipts.sqlite3")
        self.connection = None

    def __enter__(self):
        if self.path.is_symlink():
            raise OSError("Update receipt database must not be a symbolic link.")
        flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags, 0o600)
        os.close(descriptor)
        self.connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            self.connection.execute("PRAGMA synchronous=FULL")
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS update_receipts (key TEXT PRIMARY KEY, receipt TEXT NOT NULL)"
            )
            self.connection.execute("BEGIN IMMEDIATE")
        except BaseException:
            self.connection.close()
            self.connection = None
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if self.connection.in_transaction:
                self.connection.execute("COMMIT" if exc_type is None else "ROLLBACK")
        finally:
            self.connection.close()

    def get(self, key):
        row = self.connection.execute(
            "SELECT receipt FROM update_receipts WHERE key = ?", (key,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def recover(self, artifact):
        raw = artifact.get("metadata", {}).get(RECEIPT_METADATA_KEY)
        if not raw:
            return False
        try:
            receipt = json.loads(raw)
            if receipt["model_id"] != artifact["model_id"] or receipt["applied_version"] != artifact["version"]:
                raise ValueError("Receipt does not match the committed model.")
            missing = self.get(receipt["key"]) is None
            self.put(receipt)
            return missing
        except (TypeError, ValueError, KeyError) as exc:
            raise ModelArtifactError("Committed model update receipt is invalid.") from exc

    def checkpoint(self):
        """Durably record an older outcome before replacing its recovery marker.

        Callers must reload the artifact after reacquiring the writer lock, since
        another process may have published during the transaction boundary.
        """
        self.connection.execute("COMMIT")
        self.connection.execute("BEGIN IMMEDIATE")

    def put(self, receipt):
        existing = self.get(receipt["key"])
        if existing is not None and existing != receipt:
            raise ModelArtifactError("Update receipt conflicts with an existing request.")
        self.connection.execute(
            "INSERT OR IGNORE INTO update_receipts(key, receipt) VALUES (?, ?)",
            (receipt["key"], json.dumps(receipt, sort_keys=True, separators=(",", ":"))),
        )
