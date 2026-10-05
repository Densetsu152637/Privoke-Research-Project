"""Confined review exports and authenticated complete-set assembly.

Only the protected operator reads preparation manifests. Each annotator receives
one flat export directory and a separate exclusive response destination. Actor
and producer identities are external root commitments, not authentication by ID.
Assembly requires the genuine reconstructed pool; it never constructs pool
members or consensus review responses from exported packages.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat

from privoke_eval.advpii_review import MAX_REVIEW_POOL, RUBRIC_SHA256, SOURCE_SHA256, PROTOCOL_SHA256
from privoke_eval.in_house_advpii_review import (
    InHouseReviewBindings, InHouseReviewPool, PLAN_SHA256,
    validate_in_house_review_pool,
)
from privoke_eval.in_house_dual_review import consume_dual_reviews

MAX_BYTES = 64 * 1024 * 1024
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_CHUNK_SIZE = 150
MAX_EXPORT_BYTES = 256 * 1024 * 1024
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_PACKAGE_FIELDS = {"review_id", "text", "text_sha256", "rubric_sha256", "native_spans"}
_NATIVE = {"email", "phone_number", "ssn", "iban", "credit_card_number"}
_MANIFEST_FIELDS = {
    "schema_version", "kind", "status", "scope", "source_revision",
    "preparation_identity", "review_pool_sha256", "bindings", "input_raw_sha256",
    "input_consumed_sha256", "execution_code_raw_sha256", "source_audit_sha256",
    "parquet_sha256", "protocol_sha256", "rubric_sha256", "counts", "review_status",
    "no_allocation", "no_model_scoring", "not_authorized_for_fitting",
    "review_packages_file", "review_packages_sha256", "private_review_map_file",
    "private_review_map_sha256", "legacy_pool_sha256", "graph_membership_sha256",
    "private_members_sha256", "private_directory_mode", "private_file_mode", "platform",
}
_CHUNK_FIELDS = {
    "schema_version", "kind", "set_id", "ensemble_id", "index", "actor_id", "producer_id",
    "chunk_size", "preparation_identity", "review_pool_sha256", "source_sha256",
    "legacy_pool_sha256", "rubric_sha256", "rubric_raw_sha256", "manifest_raw_sha256",
    "assignments_raw_sha256", "packages_raw_sha256", "count", "response_file",
}


def _fail():
    raise ValueError("Review chunk boundary failed validation.") from None


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _hash(value):
    if type(value) is not str or _HASH.fullmatch(value) is None:
        _fail()
    return value


def _chunk_name(set_id, index):
    if set_id not in {"A", "B"} or type(index) is not int or not 0 <= index < MAX_REVIEW_POOL:
        _fail()
    return f"{set_id}-{index:05d}"


def _closed(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        _fail()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _constant(_value):
    _fail()


def decode_pinned(raw, expected, limit=MAX_BYTES):
    """Authenticate bounded raw bytes before any decoding or JSON parsing."""
    if type(raw) is not bytes or not raw or len(raw) > limit or digest(raw) != _hash(expected):
        _fail()
    try:
        return json.loads(raw.decode("utf-8", errors="strict"),
                          object_pairs_hook=_pairs, parse_constant=_constant)
    except Exception:
        _fail()


@dataclass(frozen=True)
class ExportTrust:
    """Metadata-only exact commitments supplied by the protected operator."""
    manifest_sha256: str
    packages_sha256: str
    rubric_raw_sha256: str
    bindings_sha256: str
    preparation_identity: str
    review_pool_sha256: str
    legacy_pool_sha256: str
    assignments_sha256: str
    source_revision: str
    pool_size: int

    def validate(self):
        for key, value in vars(self).items():
            if key not in {"source_revision", "pool_size"}:
                _hash(value)
        if (type(self.source_revision) is not str
                or re.fullmatch("[0-9a-f]{40}", self.source_revision) is None
                or type(self.pool_size) is not int or not 0 < self.pool_size <= MAX_REVIEW_POOL):
            _fail()


@dataclass(frozen=True)
class ChunkExport:
    name: str
    packages: bytes = field(repr=False)
    rubric: bytes = field(repr=False)
    assignment: bytes = field(repr=False)


def _packages(raw, trust):
    if type(raw) is not bytes or not raw or len(raw) > MAX_BYTES or digest(raw) != trust.packages_sha256:
        _fail()
    if not raw.endswith(b"\n"):
        _fail()
    packages = []
    seen = set()
    for line in raw.splitlines(keepends=True):
        if not line.endswith(b"\n") or not line.strip():
            _fail()
        item = decode_pinned(line, digest(line))
        _closed(item, _PACKAGE_FIELDS)
        review_id = _hash(item["review_id"])
        if review_id in seen or type(item["text"]) is not str:
            _fail()
        seen.add(review_id)
        if (digest(item["text"].encode("utf-8")) != _hash(item["text_sha256"])
                or item["rubric_sha256"] != RUBRIC_SHA256
                or type(item["native_spans"]) is not list):
            _fail()
        for span in item["native_spans"]:
            _closed(span, {"entity_type", "start", "end"})
            if (span["entity_type"] not in _NATIVE or type(span["start"]) is not int
                    or type(span["end"]) is not int
                    or not 0 <= span["start"] < span["end"] <= len(item["text"])
                    or not item["text"][span["start"]:span["end"]].strip()):
                _fail()
        packages.append(item)
        if len(packages) > trust.pool_size:
            _fail()
    if len(packages) != trust.pool_size:
        _fail()
    return packages


def _assignments(raw, trust):
    value = decode_pinned(raw, trust.assignments_sha256, MAX_METADATA_BYTES)
    _closed(value, {"schema_version", "kind", "preparation_identity", "review_pool_sha256", "chunk_size", "sets"})
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["kind"] != "privoke-in-house-review-assignments-v1"
            or value["preparation_identity"] != trust.preparation_identity
            or value["review_pool_sha256"] != trust.review_pool_sha256
            or type(value["chunk_size"]) is not int or not 1 <= value["chunk_size"] <= MAX_CHUNK_SIZE):
        _fail()
    _closed(value["sets"], {"A", "B"})
    identities, ensembles = set(), set()
    count = math.ceil(trust.pool_size / value["chunk_size"])
    for set_id in ("A", "B"):
        entry = value["sets"][set_id]
        _closed(entry, {"ensemble_id", "chunks"})
        ensemble = entry["ensemble_id"]
        if type(ensemble) is not str or _ID.fullmatch(ensemble) is None or ensemble in ensembles:
            _fail()
        ensembles.add(ensemble)
        if type(entry["chunks"]) is not list or len(entry["chunks"]) != count:
            _fail()
        for index, chunk in enumerate(entry["chunks"]):
            _closed(chunk, {"index", "actor_id", "producer_id"})
            if type(chunk["index"]) is not int or chunk["index"] != index:
                _fail()
            for role in ("actor_id", "producer_id"):
                identity = chunk[role]
                if (type(identity) is not str or _ID.fullmatch(identity) is None
                        or (role, identity) in identities):
                    _fail()
                identities.add((role, identity))
    return value


def export_review_chunks(manifest_bytes, packages_bytes, rubric_bytes, assignments_bytes, *, trust):
    """Return two fixed contiguous package sets, without private source mappings."""
    try:
        if type(trust) is not ExportTrust:
            _fail()
        trust.validate()
        manifest = decode_pinned(manifest_bytes, trust.manifest_sha256, MAX_METADATA_BYTES)
        _closed(manifest, _MANIFEST_FIELDS)
        if (type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1
                or manifest["kind"] != "privoke-in-house-blind-review-preparation-v1"
                or manifest["status"] != "complete" or manifest["scope"] != "review_preparation_only"
                or manifest["source_revision"] != trust.source_revision
                or manifest["preparation_identity"] != trust.preparation_identity
                or manifest["review_pool_sha256"] != trust.review_pool_sha256
                or manifest["legacy_pool_sha256"] != trust.legacy_pool_sha256
                or manifest["review_packages_file"] != "review-packages.jsonl"
                or manifest["private_review_map_file"] != "private-review-map.jsonl"
                or manifest["review_packages_sha256"] != trust.packages_sha256
                or manifest["rubric_sha256"] != RUBRIC_SHA256
                or manifest["private_directory_mode"] != "0700"
                or manifest["private_file_mode"] != "0600" or manifest["platform"] != "posix"
                or any(manifest[key] is not True for key in
                       ("no_allocation", "no_model_scoring", "not_authorized_for_fitting"))
                or digest(canonical(manifest["bindings"])) != trust.bindings_sha256
                or manifest["bindings"].get("study_plan_lf_sha256") != PLAN_SHA256
                or type(manifest["counts"]) is not dict
                or type(manifest["counts"].get("pool_size")) is not int
                or manifest["counts"]["pool_size"] != trust.pool_size):
            _fail()
        decode_pinned(rubric_bytes, trust.rubric_raw_sha256, MAX_METADATA_BYTES)
        legacy = manifest["bindings"]["legacy"]
        if (legacy["source_revision"] != trust.source_revision
                or legacy["source_sha256"] != SOURCE_SHA256
                or legacy["protocol_sha256"] != PROTOCOL_SHA256
                or legacy["rubric_sha256"] != RUBRIC_SHA256
                or manifest["parquet_sha256"] != SOURCE_SHA256
                or manifest["protocol_sha256"] != PROTOCOL_SHA256):
            _fail()
        if digest(rubric_bytes.replace(b"\r\n", b"\n")) != RUBRIC_SHA256:
            _fail()
        packages = _packages(packages_bytes, trust)
        assignments = _assignments(assignments_bytes, trust)
        size = assignments["chunk_size"]
        exports = []
        for set_id in ("A", "B"):
            entry = assignments["sets"][set_id]
            for chunk in entry["chunks"]:
                start = chunk["index"] * size
                subset = packages[start:start + size]
                payload = b"".join(canonical(item) + b"\n" for item in subset)
                metadata = {
                    "schema_version": 1, "kind": "privoke-in-house-review-chunk-v1",
                    "set_id": set_id, "ensemble_id": entry["ensemble_id"], **chunk,
                    "chunk_size": size,
                    "preparation_identity": trust.preparation_identity,
                    "review_pool_sha256": trust.review_pool_sha256,
                    "source_sha256": manifest["parquet_sha256"],
                    "legacy_pool_sha256": trust.legacy_pool_sha256,
                    "rubric_sha256": RUBRIC_SHA256, "rubric_raw_sha256": trust.rubric_raw_sha256,
                    "manifest_raw_sha256": trust.manifest_sha256,
                    "assignments_raw_sha256": trust.assignments_sha256,
                    "packages_raw_sha256": digest(payload), "count": len(subset),
                    "response_file": "responses.json",
                }
                exports.append(ChunkExport(_chunk_name(set_id, chunk["index"]), payload, rubric_bytes,
                                           canonical(metadata) + b"\n"))
        if sum(len(e.packages) + len(e.rubric) + len(e.assignment) for e in exports) > MAX_EXPORT_BYTES:
            _fail()
        return tuple(exports)
    except Exception:
        _fail()


@dataclass(frozen=True)
class ChunkSubmission:
    """Bytes plus root-established producer receipt hash; no self-authentication."""
    assignment_bytes: bytes = field(repr=False)
    response_bytes: bytes = field(repr=False)
    producer_receipt_bytes: bytes = field(repr=False)


@dataclass(frozen=True)
class AssemblyResult:
    first_envelope_bytes: bytes = field(repr=False)
    second_envelope_bytes: bytes = field(repr=False)
    first_raw_sha256: str
    second_raw_sha256: str
    consensus: object = field(repr=False)
    provenance_sha256: str


def assemble_review_chunks(pool, exports, submissions, commitments_bytes, *,
                           commitments_sha256, trusted_bindings):
    """Authenticate every assigned producer before genuine whole-pool validation.

    The root supplies the exact commitment bytes after observing real independent
    actors. Receipt contents join those commitments; this API does not authenticate
    a process or human, and never claims human agreement or truth.
    """
    try:
        if type(pool) is not InHouseReviewPool or type(trusted_bindings) is not InHouseReviewBindings:
            _fail()
        validate_in_house_review_pool(pool, trusted_bindings=trusted_bindings)
        claims = decode_pinned(commitments_bytes, commitments_sha256, MAX_METADATA_BYTES)
        _closed(claims, {"schema_version", "kind", "preparation_identity", "review_pool_sha256", "chunks"})
        if (type(claims["schema_version"]) is not int or claims["schema_version"] != 1
                or claims["kind"] != "privoke-in-house-review-producer-commitments-v1"
                or claims["preparation_identity"] != pool.preparation_identity
                or claims["review_pool_sha256"] != pool.review_pool_sha256
                or type(claims["chunks"]) is not dict
                or type(exports) is not tuple or not exports
                or not isinstance(submissions, Mapping)):
            _fail()
        export_by_name = {item.name: item for item in exports if type(item) is ChunkExport}
        if len(export_by_name) != len(exports) or set(export_by_name) != set(submissions) or set(export_by_name) != set(claims["chunks"]):
            _fail()
        if (len(exports) > 2 * MAX_REVIEW_POOL
                or sum(len(e.packages) + len(e.rubric) + len(e.assignment) for e in exports) > MAX_EXPORT_BYTES
                or any(type(s) is not ChunkSubmission for s in submissions.values())
                or sum(len(s.response_bytes) for s in submissions.values()) > 2 * MAX_BYTES):
            _fail()
        package_by_id = {item.review_id: item for item in pool.core.packages}
        responses = {"A": [], "B": []}
        ensembles, seen, actors, producers = {}, {"A": set(), "B": set()}, set(), set()
        shared_binding = None
        indices = {"A": [], "B": []}
        for name in sorted(export_by_name):
            export = export_by_name[name]
            claim = claims["chunks"][name]
            _closed(claim, {"assignment_sha256", "response_sha256", "producer_receipt_sha256"})
            assignment = decode_pinned(export.assignment, claim["assignment_sha256"], MAX_METADATA_BYTES)
            _closed(assignment, _CHUNK_FIELDS)
            # Reconstruct only export package records, never private pool members.
            if (type(assignment["schema_version"]) is not int or assignment["schema_version"] != 1
                    or assignment["kind"] != "privoke-in-house-review-chunk-v1"
                    or assignment["preparation_identity"] != pool.preparation_identity
                    or assignment["review_pool_sha256"] != pool.review_pool_sha256
                    or assignment["source_sha256"] != pool.core.bindings.source_sha256
                    or assignment["legacy_pool_sha256"] != pool.core.pool_sha256
                    or assignment["rubric_sha256"] != RUBRIC_SHA256
                    or assignment["response_file"] != "responses.json"
                    or type(assignment["index"]) is not int or assignment["index"] < 0
                    or type(assignment["chunk_size"]) is not int
                    or not 1 <= assignment["chunk_size"] <= MAX_CHUNK_SIZE
                    or type(assignment["count"]) is not int):
                _fail()
            for key in ("ensemble_id", "actor_id", "producer_id"):
                if type(assignment[key]) is not str or _ID.fullmatch(assignment[key]) is None:
                    _fail()
            binding = tuple(assignment[key] for key in
                            ("chunk_size", "manifest_raw_sha256", "assignments_raw_sha256", "rubric_raw_sha256"))
            if shared_binding is None:
                shared_binding = binding
            elif binding != shared_binding:
                _fail()
            for key in ("manifest_raw_sha256", "assignments_raw_sha256", "packages_raw_sha256", "rubric_raw_sha256"):
                _hash(assignment[key])
            set_id = assignment["set_id"]
            if set_id not in responses or name != _chunk_name(set_id, assignment["index"]):
                _fail()
            indices[set_id].append(assignment["index"])
            ensemble = assignment["ensemble_id"]
            if set_id in ensembles and ensembles[set_id] != ensemble:
                _fail()
            ensembles[set_id] = ensemble
            for role, known in (("actor_id", actors), ("producer_id", producers)):
                if assignment[role] in known:
                    _fail()
                known.add(assignment[role])
            if (not export.packages or not export.packages.endswith(b"\n")
                    or digest(export.packages) != assignment["packages_raw_sha256"]
                    or digest(export.rubric) != assignment["rubric_raw_sha256"]
                    or digest(export.rubric.replace(b"\r\n", b"\n")) != RUBRIC_SHA256):
                _fail()
            expected_ids = []
            for line in export.packages.splitlines(keepends=True):
                item = decode_pinned(line, digest(line))
                _closed(item, _PACKAGE_FIELDS)
                review_id = item["review_id"]
                package = package_by_id.get(review_id)
                if package is None or review_id in seen[set_id]:
                    _fail()
                actual = {"review_id": package.review_id, "text": package.text,
                          "text_sha256": package.text_sha256, "rubric_sha256": package.rubric_sha256,
                          "native_spans": [{"entity_type": s.entity_type, "start": s.start, "end": s.end}
                                           for s in package.native_spans]}
                if item != actual:
                    _fail()
                seen[set_id].add(review_id)
                expected_ids.append(review_id)
            if len(expected_ids) != assignment["count"]:
                _fail()
            start = assignment["index"] * assignment["chunk_size"]
            if expected_ids != [p.review_id for p in pool.core.packages[start:start + assignment["chunk_size"]]]:
                _fail()
            submission = submissions[name]
            if type(submission) is not ChunkSubmission or submission.assignment_bytes != export.assignment:
                _fail()
            receipt = decode_pinned(submission.producer_receipt_bytes, claim["producer_receipt_sha256"], MAX_METADATA_BYTES)
            _closed(receipt, {"schema_version", "kind", "actor_id", "producer_id", "assignment_sha256", "response_sha256"})
            if (type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1
                    or receipt["kind"] != "privoke-in-house-review-producer-receipt-v1"
                    or any(receipt[key] != assignment[key] for key in ("actor_id", "producer_id"))
                    or any(receipt[key] != claim[key] for key in ("assignment_sha256", "response_sha256"))):
                _fail()
            body = decode_pinned(submission.response_bytes, claim["response_sha256"])
            _closed(body, {"schema_version", "kind", "assignment_sha256", "set_id", "ensemble_id", "actor_id", "producer_id", "blinding", "responses"})
            _closed(body["blinding"], {"no_private_map", "no_peer_judgments"})
            if (type(body["schema_version"]) is not int or body["schema_version"] != 1
                    or body["kind"] != "privoke-in-house-review-chunk-responses-v1"
                    or body["assignment_sha256"] != claim["assignment_sha256"]
                    or any(body[key] != assignment[key] for key in ("set_id", "ensemble_id", "actor_id", "producer_id"))
                    or any(value is not True for value in body["blinding"].values())
                    or type(body["responses"]) is not list
                    or len(body["responses"]) != len(expected_ids)):
                _fail()
            ids = [item.get("review_id") if type(item) is dict else None for item in body["responses"]]
            if len(set(ids)) != len(ids) or set(ids) != set(expected_ids) or any(item.get("reviewer_id") != ensemble for item in body["responses"]):
                _fail()
            responses[set_id].extend(body["responses"])
        if set(ensembles) != {"A", "B"} or ensembles["A"] == ensembles["B"] or any(ids != set(package_by_id) for ids in seen.values()):
            _fail()
        expected_indices = list(range(math.ceil(pool.core.pool_size / shared_binding[0])))
        if any(values != expected_indices for values in indices.values()):
            _fail()
        envelopes = []
        for set_id in ("A", "B"):
            envelopes.append(canonical({
                "schema_version": 1, "kind": "privoke-in-house-blind-review-responses-v1",
                "preparation_identity": pool.preparation_identity, "review_pool_sha256": pool.review_pool_sha256,
                "responses": sorted(responses[set_id], key=lambda item: item["review_id"]),
            }) + b"\n")
        hashes = [digest(raw) for raw in envelopes]
        consensus = consume_dual_reviews(pool, *envelopes, trusted_bindings=trusted_bindings,
            expected_preparation_identity=pool.preparation_identity,
            expected_first_reviewer_id=ensembles["A"], expected_second_reviewer_id=ensembles["B"],
            expected_first_raw_sha256=hashes[0], expected_second_raw_sha256=hashes[1])
        return AssemblyResult(*envelopes, *hashes, consensus, commitments_sha256)
    except Exception:
        _fail()


def _posix():
    if (os.name != "posix" or not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_DIRECTORY") or not hasattr(os, "geteuid")
            or os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd):
        _fail()


def _identity(info):
    return info.st_dev, info.st_ino


def _file_state(info):
    # Access time may legitimately change while reading. All mutation-relevant
    # metadata, inode identity and authenticated content remain fixed.
    return (_identity(info), info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _private_directory(info):
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != os.geteuid()):
        _fail()


class _HeldDirectory:
    """Hold and recheck every path component; pathname substitution rejects."""
    def __init__(self, path, *, private=False):
        self.path = Path(path)
        self.private = private
        self.handles = []

    def __enter__(self):
        _posix()
        if not self.path.is_absolute() or any(p in {".", ".."} for p in self.path.parts):
            _fail()
        try:
            fd = os.open(self.path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.handles.append((fd, None, _identity(os.fstat(fd))))
            for name in self.path.parts[1:]:
                parent = self.handles[-1][0]
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(before.st_mode):
                    _fail()
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                self.handles.append((fd, name, _identity(before)))
                if _identity(os.fstat(fd)) != _identity(before):
                    _fail()
            self.verify()
            return self
        except Exception:
            self.__exit__(None, None, None)
            _fail()

    @property
    def fd(self):
        return self.handles[-1][0]

    def verify(self):
        for index, (fd, name, identity) in enumerate(self.handles):
            if _identity(os.fstat(fd)) != identity:
                _fail()
            if index:
                info = os.stat(name, dir_fd=self.handles[index - 1][0], follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode) or _identity(info) != identity:
                    _fail()
        leaf = os.lstat(self.path)
        if not stat.S_ISDIR(leaf.st_mode) or _identity(leaf) != self.handles[-1][2]:
            _fail()
        if self.private:
            _private_directory(os.fstat(self.fd))
            _private_directory(leaf)

    def __exit__(self, *_args):
        for fd, _name, _info in reversed(self.handles):
            os.close(fd)
        self.handles = []


def read_pinned_file(path, expected_sha256, *, private=True, limit=MAX_BYTES, _expected_identity=None):
    """Read one bounded regular inode through held nofollow parents."""
    try:
        path = Path(path)
        with _HeldDirectory(path.parent, private=private) as parent:
            parent_info = os.fstat(parent.fd)
            if private and (stat.S_IMODE(parent_info.st_mode) != 0o700 or parent_info.st_uid != os.geteuid()):
                _fail()
            info = os.stat(path.name, dir_fd=parent.fd, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid() or not 0 < info.st_size <= limit
                    or (private and stat.S_IMODE(info.st_mode) != 0o600)):
                _fail()
            if _expected_identity is not None and _identity(info) != _expected_identity:
                _fail()
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent.fd)
            try:
                if _identity(os.fstat(fd)) != _identity(info):
                    _fail()
                pieces, total = [], 0
                while True:
                    chunk = os.read(fd, min(1024 * 1024, limit + 1 - total))
                    if not chunk:
                        break
                    pieces.append(chunk)
                    total += len(chunk)
                    if total > limit:
                        _fail()
                raw = b"".join(pieces)
                after = os.fstat(fd)
                named = os.stat(path.name, dir_fd=parent.fd, follow_symlinks=False)
                parent.verify()
                if (_file_state(after) != _file_state(info) or _file_state(named) != _file_state(info) or len(raw) != info.st_size
                        or digest(raw) != _hash(expected_sha256)):
                    _fail()
                return raw
            finally:
                os.close(fd)
    except Exception:
        _fail()


def write_exclusive_response(directory, raw):
    """Write only the assigned responses.json, never overwrite another judgment."""
    return _write_private(directory, "responses.json", raw)


def _write_private(directory, filename, raw, *, _return_identity=False):
    try:
        if filename not in {"responses.json", "packages.jsonl", "rubric.json", "assignment.json"}:
            _fail()
        if type(raw) is not bytes or not raw or len(raw) > MAX_BYTES:
            _fail()
        with _HeldDirectory(directory, private=True) as held:
            directory_info = os.fstat(held.fd)
            if stat.S_IMODE(directory_info.st_mode) != 0o700 or directory_info.st_uid != os.geteuid():
                _fail()
            fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=held.fd)
            try:
                os.fchmod(fd, 0o600)
                position = 0
                while position < len(raw):
                    written = os.write(fd, raw[position:])
                    if written <= 0:
                        _fail()
                    position += written
                os.fsync(fd)
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                        or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_size != len(raw)):
                    _fail()
                held.verify()
                if os.stat(filename, dir_fd=held.fd, follow_symlinks=False) != info:
                    _fail()
            finally:
                os.close(fd)
            os.fsync(held.fd)
            held.verify()
        # Verify content and inode through independently reopened held parents.
        read_pinned_file(Path(directory) / filename, digest(raw), _expected_identity=_identity(info))
        return (digest(raw), _identity(info)) if _return_identity else digest(raw)
    except Exception:
        _fail()


def publish_review_chunks(output, exports):
    """Create a fresh private tree; each flat child is the only reviewer input."""
    try:
        _posix()
        output = Path(output)
        if type(exports) is not tuple or not exports:
            _fail()
        names = set()
        for export in exports:
            if (type(export) is not ChunkExport or re.fullmatch("[AB]-[0-9]{5}", export.name) is None
                    or export.name != _chunk_name(export.name[0], int(export.name[2:]))
                    or export.name in names):
                _fail()
            names.add(export.name)
        with _HeldDirectory(output.parent) as parent:
            os.mkdir(output.name, 0o700, dir_fd=parent.fd)
            fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent.fd)
            try:
                os.fchmod(fd, 0o700)
                identity = _identity(os.fstat(fd))
                def verify_root():
                    parent.verify()
                    opened = os.fstat(fd)
                    named = os.stat(output.name, dir_fd=parent.fd, follow_symlinks=False)
                    path_info = os.lstat(output)
                    for info in (opened, named, path_info):
                        _private_directory(info)
                        if _identity(info) != identity:
                            _fail()
                verify_root()
                identities = {}
                for export in exports:
                    verify_root()
                    os.mkdir(export.name, 0o700, dir_fd=fd)
                    child_fd = os.open(export.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.fchmod(child_fd, 0o700)
                    os.close(child_fd)
                    for name, raw in (("packages.jsonl", export.packages), ("rubric.json", export.rubric), ("assignment.json", export.assignment)):
                        _sha, file_identity = _write_private(output / export.name, name, raw, _return_identity=True)
                        identities[(export.name, name)] = file_identity
                verify_root()
                if set(os.listdir(fd)) != names or _identity(os.lstat(output)) != identity:
                    _fail()
                for export in exports:
                    with _HeldDirectory(output / export.name, private=True) as child:
                        if set(os.listdir(child.fd)) != {"packages.jsonl", "rubric.json", "assignment.json"}:
                            _fail()
                    for name, raw in (("packages.jsonl", export.packages), ("rubric.json", export.rubric), ("assignment.json", export.assignment)):
                        read_pinned_file(output / export.name / name, digest(raw), _expected_identity=identities[(export.name, name)])
                os.fsync(fd)
                os.fsync(parent.fd)
                verify_root()
            finally:
                os.close(fd)
        return {export.name: digest(export.assignment) for export in exports}
    except Exception:
        _fail()
