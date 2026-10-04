"""Pure protection add-on for the reviewed contextual regression fixture.

This module consumes captured bytes only. It does not open files, inspect model
outputs, infer labels, or perform source graph construction. The fixture's
family identifiers and labels are intentionally excluded from protection keys.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Mapping

from privoke_eval.clean_augmentation_grouping import ProtectedKeys, opaque_exclusion_key
from privoke_contracts.classification import Category
from privoke_model.training_data import training_text_key


FIXTURE_SHA256 = "d6c7d5d87235cd6b0f9d24eac43b30c3ace9f0bf4f421ef5d5d812de79827a17"
RUBRIC_SHA256 = "30ce98dbac3de4943839123d9e8de41c6c5190124399c6e5821cfe5f391e6d56"
REVIEW_SHA256 = "27ad3e81d3bd4752a465f9cd98b46762cb0492b0f23343a1a217d1eb811fd426"
ADDON_KIND = "privoke-contextual-fixture-addon-v1"
RECEIPT_KIND = "privoke-contextual-fixture-addon-receipt-v1"
ADDON_FILENAME = "contextual-fixture-addon.json"
ADDON_DOMAIN = "privoke-contextual-fixture-addon-content-v1"
COMBINED_DOMAIN = "privoke-in-house-combined-protection-v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_MAX_FIXTURE_BYTES = 1_048_576
_MAX_RUBRIC_BYTES = 262_144
_MAX_REVIEW_BYTES = 65_536
_KEY_FIELDS = ("ids", "groups", "exact_text_sha256", "normalized_texts")
_REVIEW_FIELDS = {
    "status", "case_file", "case_file_sha256", "rubric_file", "rubric_sha256",
    "reviewer", "label_review_sha256", "label_review_note_sha256",
    "source_draft_cases_sha256", "source_draft_rubric_sha256",
    "source_draft_builder_sha256", "source_revision", "professor_confirmation", "case_counts",
    "normalized_text_collision_check",
}
_CASE_REQUIRED = {
    "case_id", "family_id", "text", "required_sensitive", "expected_sensitivity",
    "expected_visibility", "expected_categories", "expected_action", "minimum_action",
    "ambiguous", "label_status", "provisional_annotation_rationale",
}
_CASE_ALLOWED = _CASE_REQUIRED | {
    "allowed_actions", "context_truth_eligible", "action_accuracy_eligible", "visibility_hint",
}
_ACTIONS = {"ALLOW", "WARN", "BLOCK"}
_SENSITIVITY = {"S0", "S1", "S2", "S3"}
_VISIBILITY = {"P0", "P1", "P2", "P3", "P4", "PU"}
_CATEGORIES = {item.name for item in Category}
_REVIEW_COUNTS = {
    "total": 48,
    "families": 12,
    "controls": 24,
    "disclosure_candidates": 17,
    "ambiguous_excluded": 7,
    "context_truth_eligible": 41,
    "action_accuracy_eligible": 41,
    "visibility_hints": 4,
}


class FixtureProtectionError(ValueError):
    """Sanitized validation failure; messages never include input values."""


@dataclass(frozen=True)
class FixtureProtectionPolicy:
    """Byte and composition pins; overrides are intended for synthetic tests only."""

    fixture_sha256: str = FIXTURE_SHA256
    rubric_sha256: str = RUBRIC_SHA256
    review_sha256: str = REVIEW_SHA256
    review_counts: Mapping[str, int] = field(default_factory=lambda: dict(_REVIEW_COUNTS))
    max_fixture_bytes: int = _MAX_FIXTURE_BYTES
    max_rubric_bytes: int = _MAX_RUBRIC_BYTES
    max_review_bytes: int = _MAX_REVIEW_BYTES

    def __post_init__(self) -> None:
        for value in (self.fixture_sha256, self.rubric_sha256, self.review_sha256):
            if not isinstance(value, str) or not _SHA256.fullmatch(value):
                raise FixtureProtectionError("Invalid frozen input commitment.")
        if not isinstance(self.review_counts, Mapping):
            raise FixtureProtectionError("Invalid frozen review composition.")
        counts = dict(self.review_counts)
        if set(counts) != set(_REVIEW_COUNTS) or any(type(value) is not int or value < 0 for value in counts.values()):
            raise FixtureProtectionError("Invalid frozen review composition.")
        if counts != _REVIEW_COUNTS:
            # Synthetic tests may provide alternative counts only through a
            # private test policy constructed with matching schema below.
            if not (self.fixture_sha256 != FIXTURE_SHA256 and self.rubric_sha256 != RUBRIC_SHA256):
                raise FixtureProtectionError("Invalid frozen review composition.")
        object.__setattr__(self, "review_counts", MappingProxyType(counts))
        if any(type(size) is not int or size <= 0 for size in
               (self.max_fixture_bytes, self.max_rubric_bytes, self.max_review_bytes)):
            raise FixtureProtectionError("Invalid bounded input policy.")


DEFAULT_POLICY = FixtureProtectionPolicy()


def _fail() -> None:
    raise FixtureProtectionError("Fixture protection evidence failed validation.")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        _fail()


def _json_load(data: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                _fail()
            result[key] = value
        return result

    try:
        return json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=pairs,
                          parse_constant=lambda _value: _fail())
    except FixtureProtectionError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError):
        _fail()


def _canonical_lf_sha(data: bytes) -> str:
    try:
        text = data.decode("utf-8", errors="strict")
        return _sha(text.replace("\r\n", "\n").encode("utf-8"))
    except UnicodeError:
        _fail()


def _digest_map(value: object, expected_names: set[str]) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != expected_names:
        _fail()
    result: dict[str, str] = {}
    for name, digest in value.items():
        if not isinstance(name, str) or not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            _fail()
        result[name] = digest
    return result


def _validate_bindings(source_revision: str, helper_source_hashes: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(source_revision, str) or not _REVISION.fullmatch(source_revision):
        _fail()
    if not isinstance(helper_source_hashes, Mapping):
        _fail()
    hashes = _digest_map(dict(helper_source_hashes), {"grouping", "normalizer", "fixture_validator"})
    return hashes


def _decode_text(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail()
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError:
        _fail()
    return value


def _parse_cases(data: bytes, policy: FixtureProtectionPolicy) -> tuple[list[dict[str, Any]], dict[str, int]]:
    if not isinstance(data, bytes) or not data or len(data) > policy.max_fixture_bytes:
        _fail()
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeError:
        _fail()
    lines = text.split("\n")
    if lines and lines[-1] == "" and text.endswith("\n"):
        lines.pop()
    lines = [line[:-1] if line.endswith("\r") else line for line in lines]
    if not lines or any(not line.strip() for line in lines):
        _fail()
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in lines:
        try:
            line_bytes = line.encode("utf-8", errors="strict")
        except UnicodeError:
            _fail()
        row = _json_load(line_bytes)
        if not isinstance(row, dict) or not _CASE_REQUIRED <= set(row) or set(row) - _CASE_ALLOWED:
            _fail()
        case_id = _decode_text(row.get("case_id"))
        _decode_text(row.get("family_id"))
        prompt = _decode_text(row.get("text"))
        if case_id in seen:
            _fail()
        seen.add(case_id)
        if type(row.get("required_sensitive")) not in (bool, type(None)):
            _fail()
        if type(row.get("ambiguous")) is not bool:
            _fail()
        if row.get("expected_sensitivity") is not None and (
                not isinstance(row["expected_sensitivity"], str) or row["expected_sensitivity"] not in _SENSITIVITY):
            _fail()
        if row.get("expected_visibility") is not None and (
                not isinstance(row["expected_visibility"], str) or row["expected_visibility"] not in _VISIBILITY):
            _fail()
        categories = row.get("expected_categories")
        if categories is not None and (not isinstance(categories, list) or
                                       any(not isinstance(item, str) or item not in _CATEGORIES for item in categories) or
                                       len(categories) != len(set(categories))):
            _fail()
        for field in ("expected_action", "minimum_action"):
            if row.get(field) is not None and (not isinstance(row[field], str) or row[field] not in _ACTIONS):
                _fail()
        allowed = row.get("allowed_actions")
        if allowed is not None and (not isinstance(allowed, list) or not allowed or
                                    any(not isinstance(item, str) or item not in _ACTIONS for item in allowed) or
                                    len(allowed) != len(set(allowed))):
            _fail()
        for field in ("context_truth_eligible", "action_accuracy_eligible"):
            if field in row and type(row[field]) is not bool:
                _fail()
        if row["ambiguous"] and (row["required_sensitive"] is not None or allowed is not None or
                                 any(row.get(field, False) for field in
                                     ("context_truth_eligible", "action_accuracy_eligible"))):
            _fail()
        if row.get("visibility_hint") is not None and (
                not isinstance(row["visibility_hint"], str) or row["visibility_hint"] not in _VISIBILITY):
            _fail()
        _decode_text(row.get("label_status"))
        _decode_text(row.get("provisional_annotation_rationale"))
        # Store only the two permitted key inputs in the derivation path.
        rows.append({"case_id": case_id, "text": prompt, "family_id": row["family_id"],
                     "required_sensitive": row["required_sensitive"], "ambiguous": row["ambiguous"],
                     "allowed_actions": allowed, "context_truth_eligible": row.get("context_truth_eligible", not row["ambiguous"]),
                     "action_accuracy_eligible": row.get("action_accuracy_eligible", not row["ambiguous"]),
                     "visibility_hint": row.get("visibility_hint")})
    counts = {
        "total": len(rows),
        "families": len({row["family_id"] for row in rows}),
        "controls": sum(not row["ambiguous"] and row["required_sensitive"] is False for row in rows),
        "disclosure_candidates": sum(not row["ambiguous"] and row["required_sensitive"] is True for row in rows),
        "ambiguous_excluded": sum(row["ambiguous"] for row in rows),
        "context_truth_eligible": sum(row["context_truth_eligible"] for row in rows),
        "action_accuracy_eligible": sum(row["action_accuracy_eligible"] for row in rows),
        "visibility_hints": sum(row["visibility_hint"] is not None for row in rows),
    }
    if counts != dict(policy.review_counts):
        _fail()
    return rows, counts


def _validate_review(data: bytes, fixture_sha: str, rubric_sha: str,
                     counts: Mapping[str, int], policy: FixtureProtectionPolicy) -> dict[str, Any]:
    if not isinstance(data, bytes) or not data or len(data) > policy.max_review_bytes:
        _fail()
    review = _json_load(data)
    if not isinstance(review, dict) or set(review) != _REVIEW_FIELDS:
        _fail()
    if (review.get("status") != "reviewed" or review.get("case_file_sha256") != fixture_sha or
            review.get("rubric_sha256") != rubric_sha or review.get("professor_confirmation") != "pending" or
            review.get("reviewer") != "assistant independent review" or
            review.get("case_counts") != dict(counts)):
        _fail()
    if not isinstance(review.get("source_revision"), str) or not _REVISION.fullmatch(review["source_revision"]):
        _fail()
    if not isinstance(review.get("case_file"), str) or not isinstance(review.get("rubric_file"), str):
        _fail()
    if not isinstance(review.get("normalized_text_collision_check"), dict):
        _fail()
    return review


def _derive_keys(rows: list[dict[str, Any]]) -> ProtectedKeys:
    ids = set()
    exact = set()
    normalized = set()
    try:
        for row in rows:
            case_id = row["case_id"]
            text = row["text"]
            ids.add(opaque_exclusion_key("id", case_id))
            exact.add(_sha(text.encode("utf-8", errors="strict")))
            normalized.add(opaque_exclusion_key("text_key", training_text_key(text)))
        return ProtectedKeys(ids=frozenset(ids), groups=frozenset(),
                             exact_text_sha256=frozenset(exact), normalized_texts=frozenset(normalized))
    except (UnicodeError, TypeError, ValueError):
        _fail()


def _key_lists(keys: ProtectedKeys) -> dict[str, list[str]]:
    return {field: sorted(getattr(keys, field)) for field in _KEY_FIELDS}


def _content_digest(artifact_without_digest: Mapping[str, Any]) -> str:
    return _sha(_canonical_bytes({"domain": ADDON_DOMAIN, "artifact": artifact_without_digest}))


def _prepare_inputs(fixture_bytes: bytes, rubric_bytes: bytes, review_bytes: bytes,
                    policy: FixtureProtectionPolicy) -> tuple[str, str, str, list[dict[str, Any]], dict[str, int], ProtectedKeys]:
    for data, limit in ((fixture_bytes, policy.max_fixture_bytes), (rubric_bytes, policy.max_rubric_bytes),
                        (review_bytes, policy.max_review_bytes)):
        if not isinstance(data, bytes) or not data or len(data) > limit:
            _fail()
    # Hash every captured input before parsing any of them.
    fixture_sha, rubric_sha, review_sha = _sha(fixture_bytes), _sha(rubric_bytes), _sha(review_bytes)
    if (fixture_sha != policy.fixture_sha256 or rubric_sha != policy.rubric_sha256 or
            review_sha != policy.review_sha256):
        _fail()
    try:
        rubric_bytes.decode("utf-8", errors="strict")
    except UnicodeError:
        _fail()
    rows, counts = _parse_cases(fixture_bytes, policy)
    _validate_review(review_bytes, fixture_sha, rubric_sha, counts, policy)
    return fixture_sha, rubric_sha, review_sha, rows, counts, _derive_keys(rows)


def build_fixture_addon(fixture_bytes: bytes, rubric_bytes: bytes, review_bytes: bytes, *,
                        source_revision: str, helper_source_hashes: Mapping[str, str],
                        policy: FixtureProtectionPolicy = DEFAULT_POLICY) -> tuple[bytes, bytes]:
    """Return canonical artifact/receipt bytes from frozen captured inputs.

    Production callers must use ``DEFAULT_POLICY``. The optional policy exists
    for isolated synthetic unit tests and must never be exposed as a CLI override.
    """
    helper_hashes = _validate_bindings(source_revision, helper_source_hashes)
    fixture_sha, rubric_sha, review_sha, _rows, counts, keys = _prepare_inputs(
        fixture_bytes, rubric_bytes, review_bytes, policy)
    artifact_base: dict[str, Any] = {
        "schema_version": 1,
        "kind": ADDON_KIND,
        "fixture_sha256": fixture_sha,
        "rubric_sha256": rubric_sha,
        "fixture_review_sha256": review_sha,
        "review_status": "reviewed",
        "review_counts": counts,
        "key_algorithm": {
            "opaque_key_domain": "privoke-external-exclusion-v1",
            "id_key": "opaque_exclusion_key(id,case_id)",
            "exact_text_key": "sha256(exact_utf8_text_bytes)",
            "normalized_text_key": "opaque_exclusion_key(text_key,training_text_key(text))",
            "group_policy": "empty; fixture family IDs are not source aliases",
        },
        "helper_source_hashes": helper_hashes,
        "coverage_counts": {field: len(getattr(keys, field)) for field in _KEY_FIELDS},
        "keys": _key_lists(keys),
    }
    artifact = dict(artifact_base)
    artifact["addon_content_sha256"] = _content_digest(artifact_base)
    artifact_bytes = _canonical_bytes(artifact) + b"\n"
    receipt = {
        "schema_version": 1,
        "kind": RECEIPT_KIND,
        "status": "fixture_protection_addon_built",
        "source_revision": source_revision,
        "artifact_file": ADDON_FILENAME,
        "artifact_sha256": _sha(artifact_bytes),
        "addon_content_sha256": artifact["addon_content_sha256"],
        "fixture_sha256": fixture_sha,
        "rubric_sha256": rubric_sha,
        "fixture_review_sha256": review_sha,
        "input_raw_sha256": {"fixture": fixture_sha, "rubric": rubric_sha, "review": review_sha},
        "input_canonical_lf_sha256": {
            "fixture": _canonical_lf_sha(fixture_bytes), "rubric": _canonical_lf_sha(rubric_bytes),
            "review": _canonical_lf_sha(review_bytes),
        },
        "helper_source_hashes": helper_hashes,
        "coverage_counts": artifact["coverage_counts"],
        "review_status": "reviewed",
    }
    return artifact_bytes, _canonical_bytes(receipt) + b"\n"


def validate_fixture_addon(fixture_bytes: bytes, rubric_bytes: bytes, review_bytes: bytes,
                           artifact_bytes: bytes, receipt_bytes: bytes, *,
                           expected_receipt_sha256: str, expected_source_revision: str,
                           expected_helper_source_hashes: Mapping[str, str],
                           policy: FixtureProtectionPolicy = DEFAULT_POLICY) -> ProtectedKeys:
    """Validate a captured add-on using a receipt SHA pinned outside the receipt."""
    if (not isinstance(receipt_bytes, bytes) or len(receipt_bytes) > 262_144 or
            not isinstance(expected_receipt_sha256, str) or
            not _SHA256.fullmatch(expected_receipt_sha256) or _sha(receipt_bytes) != expected_receipt_sha256):
        _fail()
    if not isinstance(artifact_bytes, bytes) or not artifact_bytes or len(artifact_bytes) > 4_194_304:
        _fail()
    # Validate original inputs and their immutable policy pins before parsing.
    fixture_sha, rubric_sha, review_sha, rows, counts, keys = _prepare_inputs(
        fixture_bytes, rubric_bytes, review_bytes, policy)
    helper_hashes = _validate_bindings(expected_source_revision, expected_helper_source_hashes)
    # Only the externally pinned receipt is parsed; its artifact binding is
    # checked before the artifact itself is parsed.
    receipt = _json_load(receipt_bytes)
    if not isinstance(receipt, dict) or receipt.get("artifact_sha256") != _sha(artifact_bytes):
        _fail()
    expected_artifact, expected_receipt = build_fixture_addon(
        fixture_bytes, rubric_bytes, review_bytes, source_revision=expected_source_revision,
        helper_source_hashes=helper_hashes, policy=policy)
    if artifact_bytes != expected_artifact or receipt_bytes != expected_receipt:
        _fail()
    # Parsing after exact-byte and recomputation checks gives a useful schema
    # invariant without allowing artifact-supplied keys to drive the union.
    parsed_artifact = _json_load(artifact_bytes)
    if not isinstance(parsed_artifact, dict) or parsed_artifact.get("keys") != _key_lists(keys):
        _fail()
    return keys


def combine_protected_keys(historical: ProtectedKeys, addon: ProtectedKeys) -> ProtectedKeys:
    """Fieldwise union without altering the historical protection helpers."""
    if not isinstance(historical, ProtectedKeys) or not isinstance(addon, ProtectedKeys):
        _fail()
    return ProtectedKeys(**{
        field: frozenset(getattr(historical, field)) | frozenset(getattr(addon, field))
        for field in _KEY_FIELDS
    })


def combined_protection_digest(keys: ProtectedKeys) -> str:
    """Plan-specific combined-set identity, distinct from legacy helper digests."""
    if not isinstance(keys, ProtectedKeys):
        _fail()
    payload = {
        "schema": COMBINED_DOMAIN,
        "keys": {
            "exact_text_sha256": sorted(keys.exact_text_sha256),
            "groups": sorted(keys.groups),
            "ids": sorted(keys.ids),
            "normalized_texts": sorted(keys.normalized_texts),
        },
    }
    return _sha(_canonical_bytes(payload))
