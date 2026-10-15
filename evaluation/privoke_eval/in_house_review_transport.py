"""Assigned-chunk transport; semantic judgments must come explicitly from actors.

The operator authenticates real agent/container identity and separate assignments.
This boundary authenticates bytes and local semantic structure, not human truth,
reviewer independence, or whether an actor actually understood a full prompt.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import stat

from privoke_eval import in_house_review_chunks as chunks
from privoke_eval.advpii_review import SOURCE_SHA256, RUBRIC_SHA256

MAX_REQUEST_BYTES = 8 * 1024 * 1024
MAX_PAGE_BYTES = 8 * 1024 * 1024
BLIND_FIELDS = {
    "no_detector_outputs", "no_model_scores_or_vocabularies", "no_partition_roles",
    "no_private_map", "no_peer_judgments",
}
CATEGORIES = {
    "HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL", "SEXUAL", "CHILD",
    "LOCATION", "IDENTITY", "THIRD_PARTY",
}
NATIVE_CATEGORIES = {
    "credit_card_number": "FINANCIAL", "iban": "FINANCIAL", "phone_number": "IDENTITY",
    "email": "IDENTITY", "ssn": "IDENTITY",
}
SEMANTIC_FIELDS = {"review_id", "decision", "categories", "evidence", "uncertainty_reason"}
RESPONSE_FILES = {"semantic-request.json", "responses.json", "producer-receipt.json"}


def _fail():
    raise ValueError("Assigned review transport failed validation.") from None


def _chunk_directory(directory):
    with chunks._HeldDirectory(directory, private=True) as held:
        held.verify()
        if set(os.listdir(held.fd)) != {"packages.jsonl", "rubric.json", "assignment.json"}:
            _fail()
        return chunks._identity(os.fstat(held.fd))


def _load(directory, assignment_sha256):
    """Authenticate the three original files through stable private parents."""
    directory = Path(directory)
    identity = _chunk_directory(directory)
    with chunks._HeldDirectory(directory, private=True) as held:
        states = {name: chunks._file_state(os.stat(name, dir_fd=held.fd, follow_symlinks=False))
                  for name in ("assignment.json", "packages.jsonl", "rubric.json")}
    assignment_raw = chunks.read_pinned_file(directory / "assignment.json", assignment_sha256,
                                             limit=chunks.MAX_METADATA_BYTES, _expected_identity=states["assignment.json"][0])
    assignment = chunks.decode_pinned(assignment_raw, assignment_sha256, chunks.MAX_METADATA_BYTES)
    chunks._closed(assignment, chunks._CHUNK_FIELDS)
    if (type(assignment["schema_version"]) is not int or assignment["schema_version"] != 1
            or assignment["kind"] != "privoke-in-house-review-chunk-v1"
            or assignment["set_id"] not in {"A", "B"}
            or type(assignment["index"]) is not int
            or not 0 <= assignment["index"] < chunks.MAX_REVIEW_POOL
            or type(assignment["chunk_size"]) is not int
            or not 1 <= assignment["chunk_size"] <= chunks.MAX_CHUNK_SIZE
            or type(assignment["count"]) is not int
            or not 0 < assignment["count"] <= assignment["chunk_size"]
            or assignment["source_sha256"] != SOURCE_SHA256
            or assignment["rubric_sha256"] != RUBRIC_SHA256
            or assignment["response_file"] != "responses.json"):
        _fail()
    for field in ("actor_id", "producer_id", "ensemble_id"):
        if type(assignment[field]) is not str or chunks._ID.fullmatch(assignment[field]) is None:
            _fail()
    for field in ("preparation_identity", "review_pool_sha256", "source_sha256", "legacy_pool_sha256",
                  "rubric_sha256", "rubric_raw_sha256", "manifest_raw_sha256", "assignments_raw_sha256", "packages_raw_sha256"):
        chunks._hash(assignment[field])
    packages_raw = chunks.read_pinned_file(directory / "packages.jsonl", assignment["packages_raw_sha256"],
                                         _expected_identity=states["packages.jsonl"][0])
    rubric_raw = chunks.read_pinned_file(directory / "rubric.json", assignment["rubric_raw_sha256"],
                                       limit=chunks.MAX_METADATA_BYTES, _expected_identity=states["rubric.json"][0])
    rubric = chunks.decode_pinned(rubric_raw, assignment["rubric_raw_sha256"], chunks.MAX_METADATA_BYTES)
    if chunks.digest(rubric_raw.replace(b"\r\n", b"\n")) != RUBRIC_SHA256 or not packages_raw.endswith(b"\n"):
        _fail()
    packages, seen = [], set()
    for line in packages_raw.splitlines(keepends=True):
        if not line.endswith(b"\n") or not line.strip():
            _fail()
        package = chunks.decode_pinned(line, chunks.digest(line))
        chunks._closed(package, chunks._PACKAGE_FIELDS)
        review_id = chunks._hash(package["review_id"])
        if (review_id in seen or type(package["text"]) is not str
                or chunks.digest(package["text"].encode("utf-8")) != chunks._hash(package["text_sha256"])
                or package["rubric_sha256"] != RUBRIC_SHA256
                or type(package["native_spans"]) is not list):
            _fail()
        seen.add(review_id)
        for span in package["native_spans"]:
            chunks._closed(span, {"entity_type", "start", "end"})
            if (span["entity_type"] not in NATIVE_CATEGORIES or type(span["start"]) is not int
                    or type(span["end"]) is not int
                    or not 0 <= span["start"] < span["end"] <= len(package["text"])
                    or not package["text"][span["start"]:span["end"]].strip()):
                _fail()
        packages.append(package)
        if len(packages) > assignment["count"]:
            _fail()
    if len(packages) != assignment["count"] or _chunk_directory(directory) != identity:
        _fail()
    # Reopen and authenticate every file after all parsing; no path substitution
    # or in-place content/mode change may be accepted between the three reads.
    for name, raw, expected in (("assignment.json", assignment_raw, assignment_sha256),
                               ("packages.jsonl", packages_raw, assignment["packages_raw_sha256"]),
                               ("rubric.json", rubric_raw, assignment["rubric_raw_sha256"])):
        if chunks.read_pinned_file(directory / name, expected, _expected_identity=states[name][0]) != raw:
            _fail()
    if _chunk_directory(directory) != identity:
        _fail()
    with chunks._HeldDirectory(directory, private=True) as held:
        if any(chunks._file_state(os.stat(name, dir_fd=held.fd, follow_symlinks=False)) != state
               for name, state in states.items()):
            _fail()
    return assignment, packages, rubric, (identity, states)


def read_chunk_page(directory, *, assignment_sha256, start=0, count=10):
    """Emit whole original prompts only, never split text to fit a page limit."""
    try:
        assignment, packages, rubric, _states = _load(directory, assignment_sha256)
        if (type(start) is not int or type(count) is not int or not 0 <= start < len(packages)
                or not 1 <= count <= chunks.MAX_CHUNK_SIZE):
            _fail()
        end = min(start + count, len(packages))
        raw = chunks.canonical({
            "schema_version": 1, "kind": "privoke-in-house-assigned-review-page-v1",
            "assignment": assignment, "assignment_sha256": assignment_sha256,
            "rubric": rubric, "start": start, "end": end,
            "next_start": end if end < len(packages) else None,
            "packages": packages[start:end],
        }) + b"\n"
        if len(raw) > MAX_PAGE_BYTES:
            _fail()
        return raw
    except Exception:
        _fail()


def _semantic_response(item, package):
    chunks._closed(item, SEMANTIC_FIELDS)
    if item["review_id"] != package["review_id"]:
        _fail()
    categories, evidence, reason = item["categories"], item["evidence"], item["uncertainty_reason"]
    if type(categories) is not list or type(evidence) is not list:
        _fail()
    if any(type(c) is not str or c not in CATEGORIES for c in categories) or len(set(categories)) != len(categories):
        _fail()
    for span in evidence:
        chunks._closed(span, {"category", "start", "end"})
        if (type(span["category"]) is not str or span["category"] not in CATEGORIES
                or type(span["start"]) is not int or type(span["end"]) is not int
                or not 0 <= span["start"] < span["end"] <= len(package["text"])
                or not package["text"][span["start"]:span["end"]].strip()):
            _fail()
    decision = item["decision"]
    if decision == "present":
        if not categories or not evidence or set(categories) != {s["category"] for s in evidence} or reason not in (None, ""):
            _fail()
        for native in package["native_spans"]:
            category = NATIVE_CATEGORIES[native["entity_type"]]
            if category not in categories or not any(
                s["category"] == category and s["start"] < native["end"] and s["end"] > native["start"] for s in evidence
            ):
                _fail()
    elif decision == "absent":
        if categories or evidence or reason not in (None, "") or package["native_spans"]:
            _fail()
    elif decision == "uncertain":
        if categories or evidence or type(reason) is not str or not reason.strip():
            _fail()
    else:
        _fail()
    return item


def _exclusive(directory, filename, raw):
    """Create one closed-name private file and return its inode commitment."""
    if filename not in RESPONSE_FILES or type(raw) is not bytes or not raw or len(raw) > chunks.MAX_BYTES:
        _fail()
    with chunks._HeldDirectory(directory, private=True) as held:
        fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=held.fd)
        try:
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                if written <= 0:
                    _fail()
                offset += written
            os.fsync(fd)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != len(raw)):
                _fail()
            held.verify()
            if chunks._file_state(os.stat(filename, dir_fd=held.fd, follow_symlinks=False)) != chunks._file_state(info):
                _fail()
        finally:
            os.close(fd)
        os.fsync(held.fd)
        held.verify()
    chunks.read_pinned_file(Path(directory) / filename, chunks.digest(raw), _expected_identity=chunks._identity(info))
    return chunks._identity(info)


def write_chunk_response(input_directory, output_directory, request_bytes, *, assignment_sha256):
    """Persist actor-supplied judgments, real repeated bindings and provenance."""
    try:
        assignment, packages, _rubric, input_states = _load(input_directory, assignment_sha256)
        if type(request_bytes) is not bytes or len(request_bytes) > MAX_REQUEST_BYTES:
            _fail()
        request_sha = chunks.digest(request_bytes)
        request = chunks.decode_pinned(request_bytes, request_sha, MAX_REQUEST_BYTES)
        chunks._closed(request, {"schema_version", "kind", "assignment_sha256", "full_prompt_reviewed", "blinding_attestation", "responses"})
        chunks._closed(request["blinding_attestation"], BLIND_FIELDS)
        if (type(request["schema_version"]) is not int or request["schema_version"] != 1
                or request["kind"] != "privoke-in-house-review-semantic-request-v1"
                or request["assignment_sha256"] != assignment_sha256
                or request["full_prompt_reviewed"] is not True
                or any(value is not True for value in request["blinding_attestation"].values())
                or type(request["responses"]) is not list or len(request["responses"]) != len(packages)):
            _fail()
        package_by_id = {p["review_id"]: p for p in packages}
        seen, semantic = set(), []
        for item in request["responses"]:
            if type(item) is not dict or type(item.get("review_id")) is not str:
                _fail()
            review_id = item["review_id"]
            if review_id in seen or review_id not in package_by_id:
                _fail()
            seen.add(review_id)
            semantic.append(_semantic_response(item, package_by_id[review_id]))
        if seen != set(package_by_id):
            _fail()
        timestamp = datetime.now(timezone.utc).isoformat()
        legacy_blinding = {k: request["blinding_attestation"][k] for k in
                           ("no_detector_outputs", "no_model_scores_or_vocabularies", "no_partition_roles")}
        responses = []
        for item in semantic:
            package = package_by_id[item["review_id"]]
            responses.append({**item, "source_sha256": assignment["source_sha256"],
                "pool_sha256": assignment["legacy_pool_sha256"], "rubric_sha256": assignment["rubric_sha256"],
                "text_sha256": package["text_sha256"], "reviewer_id": assignment["ensemble_id"],
                "reviewed_at": timestamp, "full_prompt_reviewed": request["full_prompt_reviewed"],
                "blinding_attestation": legacy_blinding})
        response_raw = chunks.canonical({"schema_version": 1, "kind": "privoke-in-house-review-chunk-responses-v1",
            "assignment_sha256": assignment_sha256,
            **{k: assignment[k] for k in ("set_id", "ensemble_id", "actor_id", "producer_id")},
            "blinding": {k: request["blinding_attestation"][k] for k in ("no_private_map", "no_peer_judgments")},
            "responses": responses}) + b"\n"
        response_sha = chunks.digest(response_raw)
        receipt_raw = chunks.canonical({"schema_version": 1, "kind": "privoke-in-house-review-producer-receipt-v1",
            **{k: assignment[k] for k in ("actor_id", "producer_id")},
            "assignment_sha256": assignment_sha256, "response_sha256": response_sha}) + b"\n"
        output_directory = Path(output_directory)
        with chunks._HeldDirectory(output_directory, private=True) as held:
            output_identity = chunks._identity(os.fstat(held.fd))
            if os.listdir(held.fd):
                _fail()
            request_identity = _exclusive(output_directory, "semantic-request.json", request_bytes)
            held.verify()
            response_identity = _exclusive(output_directory, "responses.json", response_raw)
            held.verify()
            receipt_identity = _exclusive(output_directory, "producer-receipt.json", receipt_raw)
            held.verify()
            if set(os.listdir(held.fd)) != RESPONSE_FILES:
                _fail()
            for name, raw, identity in (("semantic-request.json", request_bytes, request_identity),
                                        ("responses.json", response_raw, response_identity),
                                        ("producer-receipt.json", receipt_raw, receipt_identity)):
                chunks.read_pinned_file(output_directory / name, chunks.digest(raw), _expected_identity=identity)
            held.verify()
            if chunks._identity(os.lstat(output_directory)) != output_identity:
                _fail()
        # Input remains authenticated through the end of the write operation.
        final_assignment, _packages, _rubric, final_states = _load(input_directory, assignment_sha256)
        if final_assignment != assignment or final_states != input_states:
            _fail()
        with chunks._HeldDirectory(output_directory, private=True) as final_output:
            if chunks._identity(os.fstat(final_output.fd)) != output_identity or set(os.listdir(final_output.fd)) != RESPONSE_FILES:
                _fail()
            for name, raw, identity in (("semantic-request.json", request_bytes, request_identity),
                                        ("responses.json", response_raw, response_identity),
                                        ("producer-receipt.json", receipt_raw, receipt_identity)):
                chunks.read_pinned_file(output_directory / name, chunks.digest(raw), _expected_identity=identity)
            final_output.verify()
        return {"status": "complete", "count": len(responses), "assignment_sha256": assignment_sha256,
                "semantic_request_sha256": request_sha, "response_sha256": response_sha,
                "producer_receipt_sha256": chunks.digest(receipt_raw)}
    except Exception:
        _fail()
