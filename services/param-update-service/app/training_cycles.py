"""Persistent sequential head/encoder requests; each publication is independent."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from pathlib import Path


def config_fingerprint(config):
    # Transport/cadence changes do not alter the training payload. Training
    # settings do: fail closed on an in-flight payload change after restart.
    names = ("model_id", "source_id", "prompt_count", "seed", "curriculum_sampler_policy",
             "curriculum_sampler_seed", "train_underlying")
    return hashlib.sha256(json.dumps({key: getattr(config, key) for key in names},
                                    sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class TrainingCycles:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, timeout=120, isolation_level=None)
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute("CREATE TABLE IF NOT EXISTS cycles (sequence INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL, state TEXT NOT NULL, record TEXT NOT NULL)")

    def close(self):
        self.connection.close()

    def reserve(self, config, *, limit=None, stages=None, request_metadata=None):
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute("SELECT sequence,fingerprint,state,record FROM cycles ORDER BY sequence DESC LIMIT 1").fetchone()
            fingerprint = config_fingerprint(config)
            if limit is not None:
                if type(limit) is not int or limit < 1:
                    raise ValueError("Bounded cycles require a positive fixed limit.")
                fingerprint = hashlib.sha256(json.dumps({"config": fingerprint,
                    "limit": limit, "stages": stages, "metadata": request_metadata or {}},
                    sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if row and row[2] == "pending":
                if row[1] != fingerprint:
                    raise ValueError("Pending automatic training cycle belongs to different training settings; resume its original settings first.")
                record = json.loads(row[3])
            elif row and row[1] != fingerprint and limit is not None:
                raise ValueError("Bounded journal belongs to a different protocol.")
            elif row and limit is not None and row[0] + 1 >= limit:
                record = None
            elif row and limit is None and row[1] == fingerprint and config.interval_seconds <= 0:
                record = None  # A completed one-shot stays completed on restart.
            elif row and limit is None and row[1] == fingerprint and time.time() < json.loads(row[3]).get("finished_at", 0) + config.interval_seconds:
                record = json.loads(row[3])
            else:
                sequence = row[0] + 1 if row else 0
                seed = (config.seed + sequence - 1) % 0xFFFFFFFF + 1
                identity = "dual-" + uuid.uuid4().hex
                record = {"schema_version": 1, "sequence": sequence, "cycle_id": identity,
                          "fingerprint": fingerprint, "seed": seed, "model_id": config.model_id,
                          "source_id": config.source_id, "state": "pending",
                          "created_at": time.time(), "stages": {
                              stage: {"request_id": identity + "-" + stage, "state": "pending"}
                              for stage in (stages or (("heads", "full_encoder") if config.train_underlying else ("heads",)))}}
                self.connection.execute("INSERT INTO cycles VALUES (?,?,?,?)",
                                        (sequence, fingerprint, "pending", json.dumps(record, sort_keys=True)))
            self.connection.execute("COMMIT")
            return record
        except BaseException:
            self.connection.execute("ROLLBACK")
            raise

    def save(self, record):
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self.connection.execute("UPDATE cycles SET state=?,record=? WHERE sequence=? AND fingerprint=?",
                                    (record["state"], json.dumps(record, sort_keys=True), record["sequence"], record["fingerprint"]))
            self.connection.execute("COMMIT")
        except BaseException:
            self.connection.execute("ROLLBACK")
            raise
