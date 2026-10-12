"""Immutable content-addressed snapshots and transactional publication receipts."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
from common import canonical, digest
from privoke_model.v3_contract import (MAX_BLOB_BYTES, check_sha, parse, publication_passes,
                                      validate_manifest, validate_execution, tensor_changes, TIERS)

class CheckpointStore:
    def __init__(self, directory, initial=None):
        self.directory = Path(directory)
        self.blobs = self.directory / "blobs"; self.blobs.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.directory / "catalog.sqlite", check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL"); self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS current(model TEXT PRIMARY KEY, manifest TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS receipts(id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, payload BLOB NOT NULL)")
        if initial is not None:
            try: self.bootstrap(Path(initial))
            except BaseException:
                self.db.close()
                raise

    def put(self, payload):
        if not payload or len(payload) > MAX_BLOB_BYTES: raise ValueError("Blob exceeds v3 bound.")
        sha = digest(payload); path = self.blobs / sha
        with self.lock:
            if path.exists():
                if digest(path.read_bytes()) != sha: raise ValueError("Existing immutable blob corrupted.")
                return sha
            fd, temp = tempfile.mkstemp(prefix="stage-", dir=self.blobs)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(payload); handle.flush(); os.fsync(handle.fileno())
                os.replace(temp, path)
                if os.name != "nt":
                    directory_fd = os.open(self.blobs, os.O_RDONLY | os.O_DIRECTORY)
                    try: os.fsync(directory_fd)
                    finally: os.close(directory_fd)
            finally:
                if os.path.exists(temp): os.unlink(temp)
        return sha

    def read(self, sha):
        check_sha(sha); payload = (self.blobs / sha).read_bytes()
        if digest(payload) != sha: raise ValueError("Immutable blob hash mismatch.")
        return payload

    def manifest(self, sha):
        return validate_manifest(parse(self.read(sha)))

    def resolve(self, model):
        with self.lock:
            row = self.db.execute("SELECT manifest FROM current WHERE model=?", (model,)).fetchone()
        if row is None: raise ValueError("Model is not in this private catalog.")
        return row[0]

    def verify_checkpoint(self, manifest):
        from safetensors import safe_open
        import numpy as np
        blob = self.blobs / manifest["blob"]
        self.read(manifest["blob"])
        actual = {}
        with safe_open(blob, framework="np") as handle:
            for name in handle.keys():
                value = handle.get_tensor(name)
                if value.dtype != np.float32 or not np.isfinite(value).all(): raise ValueError("Snapshot tensors must be finite float32.")
                actual[name] = {"shape": list(value.shape), "dtype": "F32", "sha256": hashlib.sha256(value.tobytes()).hexdigest()}
        if actual != manifest["tensors"]: raise ValueError("Safetensors inventory differs from manifest.")

    def bootstrap(self, directory):
        payload = (directory / "manifest.json").read_bytes(); manifest = validate_manifest(parse(payload))
        if manifest["scope"] != "original": raise ValueError("Bootstrap requires independently prepared ORIGINAL.")
        for name, key in (("model.safetensors", "blob"), ("config.json", "config"), ("vocab.txt", "vocab")):
            if self.put((directory / name).read_bytes()) != manifest[key]: raise ValueError("ORIGINAL asset identity mismatch.")
        self.verify_checkpoint(manifest)
        sha = self.put(payload)
        with self.lock:
            self.db.execute("INSERT OR IGNORE INTO current VALUES (?,?)", (manifest["model_id"], sha))

    def admit_candidate(self, manifest):
        """One complete admission path shared by staging and transactional commit."""
        validate_manifest(manifest)
        if manifest["scope"] == "original":
            raise ValueError("Candidates cannot claim ORIGINAL scope.")
        parent = self.manifest(manifest["parent"])
        original_sha = parent["original"] or manifest["parent"]
        original = self.manifest(original_sha)
        if original["scope"] != "original" or manifest["original"] != original_sha:
            raise ValueError("Candidate ORIGINAL binding mismatch.")
        for ancestor in (parent, original):
            for key in ("model_id", "tier", "source", "config", "vocab", "parameter_count"):
                if manifest[key] != ancestor[key]:
                    raise ValueError("Candidate changed immutable model provenance/config.")
        expected = {k: (v["shape"], v["dtype"]) for k, v in original["tensors"].items()}
        if {k: (v["shape"], v["dtype"]) for k, v in manifest["tensors"].items()} != expected:
            raise ValueError("Candidate changed admitted tensor inventory.")
        for key in ("config", "vocab"):
            self.read(manifest[key])
        self.verify_checkpoint(manifest)
        evidence = validate_execution(parse(self.read(manifest["evidence"]), MAX_BLOB_BYTES))
        from fuzzer_training import validate_source_evidence
        validate_source_evidence(evidence)
        if (evidence["base"] != manifest["parent"] or evidence["candidate_blob"] != manifest["blob"]
                or evidence["scope"] != manifest["scope"] or evidence["model_id"] != manifest["model_id"]):
            raise ValueError("Candidate evidence differs from snapshot identity/scope.")
        changed, changes = tensor_changes(parent["tensors"], manifest["tensors"], TIERS[manifest["tier"]]["num_hidden_layers"])
        if changed != sorted(evidence["changed_tensors"]) or changes != evidence["changes"]:
            raise ValueError("Reported changes differ from actual checkpoint tensors.")
        if manifest["scope"] == "heads" and any(not name.startswith("heads.") for name in changed):
            raise ValueError("HEADS candidate changed pretrained encoder/pooler bytes.")
        return evidence

    def stage(self, payload, manifest_payload):
        if not manifest_payload:
            # Finalized execution evidence is the only manifest-free transport object.
            validate_execution(parse(payload, MAX_BLOB_BYTES))
            return self.put(payload)
        manifest = validate_manifest(parse(manifest_payload))
        if manifest["blob"] != digest(payload):
            raise ValueError("Candidate snapshot identity mismatch.")
        self.put(payload)
        self.admit_candidate(manifest)
        return self.put(manifest_payload)

    def status(self, request_id):
        with self.lock:
            row = self.db.execute("SELECT payload FROM receipts WHERE id=?", (request_id,)).fetchone()
        return parse(bytes(row[0])) if row else {"status": "unknown", "request_id": request_id}

    def commit(self, request):
        value = {k: getattr(request, k) for k in ("request_id", "model_id", "expected_base", "candidate", "evidence")}
        if not value["request_id"] or len(value["request_id"]) > 200: raise ValueError("Explicit bounded request identity required.")
        for key in ("expected_base", "candidate", "evidence"): check_sha(value[key])
        fingerprint = digest(canonical(value))
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                prior = self.db.execute("SELECT fingerprint,payload FROM receipts WHERE id=?", (value["request_id"],)).fetchone()
                if prior:
                    if prior[0] != fingerprint: raise ValueError("Request ID reused with different commit content.")
                    self.db.execute("COMMIT"); return parse(bytes(prior[1]))
                manifest = self.manifest(value["candidate"])
                evidence = self.admit_candidate(manifest)
                if (manifest["parent"] != value["expected_base"] or manifest["evidence"] != value["evidence"]
                        or manifest["model_id"] != value["model_id"] or evidence["request_id"] != value["request_id"]):
                    raise ValueError("Commit identity differs from candidate/fit evidence.")
                current = self.resolve(value["model_id"])
                reason = "stale_base" if current != value["expected_base"] else "guard_rejected" if not publication_passes(evidence) else ""
                receipt = {"status": "rejected" if reason else "applied", "request_id": value["request_id"],
                    "model_id": value["model_id"], "base": value["expected_base"], "candidate": value["candidate"], "reason": reason}
                if not reason:
                    self.db.execute("UPDATE current SET manifest=? WHERE model=? AND manifest=?", (value["candidate"], value["model_id"], value["expected_base"]))
                self.db.execute("INSERT INTO receipts VALUES (?,?,?)", (value["request_id"], fingerprint, canonical(receipt)))
                self.db.execute("COMMIT"); return receipt
            except BaseException:
                if self.db.in_transaction: self.db.execute("ROLLBACK")
                raise
