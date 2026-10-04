"""Aggregate-only structural scan helpers for pinned AdvPIIBench rows."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from privoke_eval.advpii_native import ParsedNativeRow
from privoke_eval.advpii_native import parse_native_row
from privoke_eval.clean_augmentation_grouping import GroupingResult, ProtectedKeys, build_components


SOURCE_AUDIT_SHA256 = "c6506b40c8c5f94d4c8634f0cb212cf1de5cb10a91bf924c059eacdbd85d2e3b"
PARQUET_SHA256 = "e97f6a32132e7fa058919798c030fca54aaad3318c47954d281717a435bfeb69"
PARQUET_SIZE = 4_258_476
PARQUET_ROWS = 104_728
DATASET_REVISION = "02741d9f99a91b8fdcf48f4316a2c73be7a7449a"
PROTOCOL_SHA256 = "3991777aedadc8d50b7395a9ce8ef2aebfec946603229b823f1b6c118a16cbdf"
RUBRIC_SHA256 = "203f37b4c77789a0f9c0838905954b9e1b76acf4f7906ab7717849e94616fcd7"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")

_EXPECTED_COMMITMENTS = {
    "prepared_manifest_sha256": "2b8a63b168d72510ce4e61e03748bf5f7858bdc33b41d15f0095780164658e1c",
    "exclusion_index_sha256": "c0700613a965e26b85a2511c8a721b2f808536f215b8fe6f18f0d3890634fc2d",
    "reference_train_sha256": "da9a1b095587264714c5ae99c8a0f92329a04f6fc237a8ace7d71e837ede429d",
    "reference_validation_sha256": "d2d0c538e49f5bbc7a8f85887b9b8cfddb188a5ab9aae55c69ce26ae932be6d1",
    "bootstrap_source_sha256": "75422c421d1a80d0cc3321979fb049f1045f02f334586d6fe62d8832f8a5a7dd",
    "partition_sha256": {
        "train": "d762747b88e1c55e0877c64e7f0760efac49670a1c3fb33712dba00e29374c8b",
        "validation": "d2d0c538e49f5bbc7a8f85887b9b8cfddb188a5ab9aae55c69ce26ae932be6d1",
        "nemotron_heldout": "e55595a9b91f160788422a1ca274577b7fc7383380de2be57915f17e06326a44",
        "meddies_heldout": "cfff4d0ddd694b82c3e3399ccebe800f05c785331d3ec1380cef133cc430073a",
    },
}
_FIXED_COVERAGE = {
    "saved_selection_records": 1000,
    "saved_selection_groups": 929,
    "reference_train_rows": 3832,
    "reference_validation_rows": 968,
    "bootstrap_text_rows": 43,
    "external_train_rows_including_original_prefix": 19993,
    "external_training_nemotron_rows": 13168,
    "external_training_meddies_rows": 2993,
    "nemotron_heldout_rows": 1000,
    "meddies_heldout_rows": 999,
}
_UNION_KEY_FIELDS = ("ids", "groups", "exact_text_sha256", "normalized_texts")
_DYNAMIC_COVERAGE = {
    "saved_selection_id_keys_including_aliases",
    "union_id_keys",
    "union_group_keys",
    "union_exact_text_hashes",
    "union_normalized_text_keys",
}


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_lf_sha256(path: str | Path) -> str:
    raw = Path(path).read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Bound text artifact is not UTF-8.") from None
    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def require_frozen_text_inputs(protocol_path: str | Path, rubric_path: str | Path) -> dict[str, str]:
    protocol_sha = canonical_lf_sha256(protocol_path)
    rubric_sha = canonical_lf_sha256(rubric_path)
    if protocol_sha != PROTOCOL_SHA256 or rubric_sha != RUBRIC_SHA256:
        raise ValueError("Protocol or rubric differs from the frozen scanner contract.")
    return {"protocol_sha256": protocol_sha, "rubric_sha256": rubric_sha}


def validate_source_audit(path: str | Path) -> dict[str, Any]:
    if sha256_file(path) != SOURCE_AUDIT_SHA256:
        raise ValueError("Source audit bytes do not match the frozen audit commitment.")
    try:
        audit = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ValueError("Source audit manifest is unreadable.") from None
    if not isinstance(audit, dict):
        raise ValueError("Source audit manifest has an unexpected structure.")
    parquet = audit.get("parquet")
    if (
        audit.get("status") != "metadata_audited"
        or audit.get("repo_id") != "roei-ar/AdvPIIBench"
        or audit.get("revision") != DATASET_REVISION
        or audit.get("dataset_row_buffers_read") != 0
        or not isinstance(parquet, dict)
        or parquet.get("path") != "data/train-00000-of-00001.parquet"
        or parquet.get("size_bytes") != PARQUET_SIZE
        or parquet.get("row_count") != PARQUET_ROWS
        or parquet.get("lfs_sha256") != PARQUET_SHA256
    ):
        raise ValueError("Source audit manifest does not bind the expected immutable dataset.")
    return {"source_audit_sha256": SOURCE_AUDIT_SHA256, "dataset_revision": DATASET_REVISION}


def _require_sha(value: object) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def _validate_commitments(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value != _EXPECTED_COMMITMENTS:
        raise ValueError("Protected-union source commitments differ from the frozen references.")
    return value


def validate_protected_union(
    union_path: str | Path,
    receipt_path: str | Path,
    expected_receipt_sha256: str,
) -> tuple[ProtectedKeys, dict[str, Any]]:
    """Validate the exact union payload, direct keys, and trusted build receipt."""
    if not _require_sha(expected_receipt_sha256):
        raise ValueError("Protection receipt SHA-256 argument is malformed.")
    union_file, receipt_file = Path(union_path), Path(receipt_path)
    if sha256_file(receipt_file) != expected_receipt_sha256:
        raise ValueError("Protection receipt bytes do not match the caller-supplied commitment.")
    try:
        union = json.loads(union_file.read_text(encoding="utf-8"))
        receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ValueError("Protected-union artifact or receipt is unreadable.") from None
    if not isinstance(union, dict) or set(union) != {
        "schema_version", "kind", "union_sha256", "coverage_counts", "verified_commitments", "keys",
    }:
        raise ValueError("Protected-union artifact schema is invalid.")
    if union_file.name != "protected-union.json":
        raise ValueError("Protected-union artifact must use the frozen filename.")
    if (
        type(union.get("schema_version")) is not int
        or union.get("schema_version") != 1
        or union.get("kind") != "privoke-clean-protected-union"
    ):
        raise ValueError("Protected-union artifact identity is invalid.")
    commitments = _validate_commitments(union.get("verified_commitments"))
    keys_raw = union.get("keys")
    if not isinstance(keys_raw, dict) or set(keys_raw) != set(_UNION_KEY_FIELDS):
        raise ValueError("Protected-union key schema is invalid.")
    key_sets: dict[str, frozenset[str]] = {}
    for field in _UNION_KEY_FIELDS:
        values = keys_raw[field]
        if (
            not isinstance(values, list)
            or not values
            or any(not _require_sha(item) for item in values)
            or values != sorted(set(values))
        ):
            raise ValueError("Protected-union key list is malformed, empty, or unsorted.")
        key_sets[field] = frozenset(values)
    coverage = union.get("coverage_counts")
    if not isinstance(coverage, dict) or set(coverage) != set(_FIXED_COVERAGE) | _DYNAMIC_COVERAGE:
        raise ValueError("Protected-union coverage counts are malformed.")
    for name, expected in _FIXED_COVERAGE.items():
        value = coverage.get(name)
        if type(value) is not int or value != expected:
            raise ValueError("Protected-union source coverage is incomplete.")
    alias_count = coverage.get("saved_selection_id_keys_including_aliases")
    if type(alias_count) is not int or alias_count < 1000:
        raise ValueError("Protected-union selected-ID alias coverage is insufficient.")
    for coverage_name, key_field in (
        ("union_id_keys", "ids"),
        ("union_group_keys", "groups"),
        ("union_exact_text_hashes", "exact_text_sha256"),
        ("union_normalized_text_keys", "normalized_texts"),
    ):
        value = coverage.get(coverage_name)
        if type(value) is not int or value != len(key_sets[key_field]):
            raise ValueError("Protected-union key coverage does not match its key lists.")

    digest_payload = {
        "schema_version": union["schema_version"],
        "verified_commitments": commitments,
        "keys": {name: keys_raw[name] for name in _UNION_KEY_FIELDS},
    }
    calculated_union_sha = hashlib.sha256(canonical_json_bytes(digest_payload)).hexdigest()
    if union.get("union_sha256") != calculated_union_sha:
        raise ValueError("Protected-union content digest is invalid.")
    if not isinstance(receipt, dict) or receipt.get("status") != "protected_union_built":
        raise ValueError("Protection receipt does not attest a completed union build.")
    if (
        receipt.get("artifact_file") != union_file.name
        or receipt.get("artifact_sha256") != sha256_file(union_file)
        or receipt.get("union_sha256") != calculated_union_sha
        or receipt.get("coverage_counts") != coverage
        or receipt.get("verified_commitments") != commitments
    ):
        raise ValueError("Protection receipt and union artifact disagree.")
    protected = ProtectedKeys(
        ids=key_sets["ids"],
        groups=key_sets["groups"],
        exact_text_sha256=key_sets["exact_text_sha256"],
        normalized_texts=key_sets["normalized_texts"],
    )
    metadata = {
        "union_sha256": calculated_union_sha,
        "receipt_sha256": expected_receipt_sha256,
        "artifact_sha256": sha256_file(union_file),
        "coverage_counts": {name: coverage[name] for name in sorted(coverage)},
        "verified_commitments": commitments,
    }
    return protected, metadata


def verify_parquet_bytes(path: str | Path) -> str:
    source_path = Path(path)
    if source_path.stat().st_size != PARQUET_SIZE:
        raise ValueError("Local Parquet size differs from the source audit.")
    digest = sha256_file(source_path)
    if digest != PARQUET_SHA256:
        raise ValueError("Local Parquet bytes differ from the pinned full-file digest.")
    return digest


def open_verified_parquet(path: str | Path) -> Any:
    """Verify full-file size/hash before importing or opening the Parquet reader."""
    verify_parquet_bytes(path)
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:  # pragma: no cover - environment-specific
        raise RuntimeError("PyArrow is required for the bounded AdvPIIBench scan.") from exc
    return pq.ParquetFile(path)


def parse_unique_batches(batches: Iterable[Any]) -> Iterable[ParsedNativeRow]:
    """Parse source batches while enforcing UID uniqueness across boundaries."""
    seen_uids: set[int] = set()
    for batch in batches:
        for raw_row in batch.to_pylist():
            parsed = parse_native_row(raw_row)
            uid = parsed.grouping_row.uid
            if uid in seen_uids:
                raise ValueError("Duplicate UID in full source scan.")
            seen_uids.add(uid)
            yield parsed


def _component_is_protected(component: object) -> bool:
    return any(reason.startswith("protected_") for reason in component.exclusion_reasons)


def aggregate_scan(
    parsed_rows: Iterable[ParsedNativeRow],
    protected: ProtectedKeys,
    *,
    expected_rows: int = PARQUET_ROWS,
) -> tuple[dict[str, Any], GroupingResult]:
    """Close the full graph, then return aggregate-only source-category ceilings."""
    rows = tuple(parsed_rows)
    if len(rows) != expected_rows:
        raise ValueError("Scanned row count differs from the pinned source manifest.")
    grouping = build_components((row.grouping_row for row in rows), protected)
    if grouping.row_count != expected_rows:
        raise ValueError("Grouping graph row count differs from the complete source scan.")

    reason_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    span_counts: Counter[str] = Counter()
    few_shot_rows = 0
    unrecoverable_positive_rows = 0
    structurally_eligible_by_uid: dict[str, set[int]] = {"positive": set(), "negative": set(), "hard_negative": set()}
    parsed_by_uid = {row.grouping_row.uid: row for row in rows}
    if len(parsed_by_uid) != expected_rows:
        raise ValueError("Parsed native source contains duplicate UIDs.")
    for row in rows:
        reason_counts.update(row.structural_reasons)
        if row.native_category is not None:
            category_counts[row.native_category] += 1
            if row.grouping_row.eligible:
                structurally_eligible_by_uid[row.native_category].add(row.grouping_row.uid)
        span_counts.update(row.native_span_types)
        few_shot_rows += int(row.few_shot_excluded)
        unrecoverable_positive_rows += int(
            row.native_category == "positive" and row.recoverable_identifier_count == 0
        )

    available_component_uids: set[int] = set()
    available_component_ids: dict[str, set[str]] = {name: set() for name in structurally_eligible_by_uid}
    protected_component_count = 0
    component_size_histogram: Counter[int] = Counter()
    for component in grouping.components:
        component_size_histogram[len(component.member_uids)] += 1
        if _component_is_protected(component):
            protected_component_count += 1
            continue
        for uid in component.member_uids:
            parsed = parsed_by_uid[uid]
            if parsed.grouping_row.eligible and parsed.native_category is not None:
                available_component_uids.add(uid)
                available_component_ids[parsed.native_category].add(component.component_id)

    ceilings = {
        category: sum(uid in available_component_uids for uid in members)
        for category, members in structurally_eligible_by_uid.items()
    }
    component_ceilings = {
        category: len(available_component_ids[category])
        for category in sorted(available_component_ids)
    }
    proposed_native_quotas = {"positive": 4000, "negative": 3200, "hard_negative": 900}
    quota_ceiling_check = {
        category: {
            "proposed_source_category_rows": proposed_native_quotas[category],
            "structural_ceiling": ceilings[category],
            "below_target_can_reject": ceilings[category] < proposed_native_quotas[category],
            "above_target_means_feasible": False,
        }
        for category in ("positive", "negative", "hard_negative")
    }
    hist = {str(size): count for size, count in sorted(component_size_histogram.items())}
    report = {
        "schema_version": 1,
        "status": "complete",
        "interpretation": (
            "native source-category structural ceilings only; broad reviewed labels and fit eligibility are unknown"
        ),
        "row_count": expected_rows,
        "uid_unique_count": len(parsed_by_uid),
        "native_category_row_counts": {
            name: category_counts[name] for name in ("positive", "negative", "hard_negative")
        },
        "valid_native_span_type_counts": {
            name: span_counts[name] for name in ("credit_card_number", "phone_number", "iban", "email", "ssn")
        },
        "structural_reason_row_counts": {name: reason_counts[name] for name in sorted(reason_counts)},
        "few_shot_excluded_rows": few_shot_rows,
        "positive_rows_without_recoverable_native_value": unrecoverable_positive_rows,
        "component_count": grouping.component_count,
        "protected_component_count": protected_component_count,
        "component_size_histogram": hist,
        "native_category_row_ceilings_after_structure_and_protection": ceilings,
        "native_category_component_ceilings_after_structure_and_protection": component_ceilings,
        "proposed_native_category_quota_ceiling_check": quota_ceiling_check,
        "proposed_validation_test_class_component_floor": {
            "components_per_class_per_partition": 200,
            "status": "not_assessed_without_reviewed_broad_truth_and_partition_assignment",
        },
        "quota_use": (
            "A ceiling below a proposed quota may reject feasibility; a ceiling above it does not establish "
            "reviewed target counts, class-group floors, or independent template families."
        ),
    }
    return report, grouping
