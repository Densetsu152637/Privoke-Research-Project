"""Retention release/source bindings retained independently before runtime compute."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from privoke_model import sensitive_retention as contract


def persist_release(release, model_id):
    contract.validate_release(release, model_id=model_id)
    directory = os.getenv("PRIVOKE_FUZZER_DUMP_DIR")
    if not directory:
        raise ValueError("Retention requires durable release evidence before compute.")
    path = Path(directory) / "original-train-retention" / release.sha256 / "release.json"
    payload = contract.canonical_bytes({"schema": 1, "manifest_sha256": release.sha256,
        "bank": base64.b64encode(release.bank_payload).decode(), "references": base64.b64encode(release.reference_payload).decode(),
        "manifest": base64.b64encode(release.manifest_payload).decode(), "teacher_path": release.teacher_path})
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise ValueError("Existing immutable retention release evidence differs.")
    else:
        with path.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    return {"path": str(path), "sha256": contract.sha256(payload), "manifest_sha256": release.sha256}


def retained_release(evidence, model_id):
    if set(evidence) != {"path", "sha256", "manifest_sha256"}:
        raise ValueError("Missing retained ORIGINAL release identity.")
    payload = Path(evidence["path"]).read_bytes()
    if contract.sha256(payload) != evidence["sha256"]:
        raise ValueError("Retained ORIGINAL release bytes differ.")
    raw = contract.parse_canonical(payload)
    if set(raw) != {"schema", "manifest_sha256", "bank", "references", "manifest", "teacher_path"} or raw["schema"] != 1:
        raise ValueError("Retained ORIGINAL release schema differs.")
    release = contract.RetentionRelease(*(base64.b64decode(raw[k], validate=True) for k in ("bank", "references", "manifest")), raw["teacher_path"])
    contract.validate_release(release, model_id=model_id, expected_sha256=evidence["manifest_sha256"])
    if raw["manifest_sha256"] != release.sha256:
        raise ValueError("Retained ORIGINAL release manifest differs.")
    return release


def validate_source_bindings(metadata, release):
    """Reject changed membership/gold/ORIGINAL baseline, even if aggregate counts pass."""
    contract.validate_release(release, expected_sha256=metadata[contract.MANIFEST_KEY])
    trace = json.loads(metadata[contract.TRACE_KEY])
    eligible = release.eligible
    for safety in (trace["base_safety"], trace["safety"]):
        if len(safety) != len(eligible):
            raise ValueError("Retention actual safety membership differs from immutable eligible TRAIN.")
        for row, (source, reference) in zip(safety, eligible):
            if (row["id"] != source["id"] or row["gold"] != source["packed_classification"]
                    or row["original"] != reference["packed"] or row["original_confidence"] != reference["confidence"]
                    or row["original_margin"] != reference["margin"]):
                raise ValueError("Retention actual ordered TRAIN/gold/ORIGINAL baseline differs.")
