"""Restricted I/O boundary for blinded AdvPIIBench review packages.

This module only verifies pinned inputs, closes the complete source graph, and
serializes a review pool plus a restricted identity map. It never assigns
review labels, allocates partitions, fits, predicts, or scores a model.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
from typing import Any, Callable

from privoke_eval.advpii_native import parse_native_row, validate_arrow_schema
from privoke_eval.advpii_review import (
    ReviewBindings,
    ValidatedNativeSpanInput,
    build_review_pool,
    protected_keys_digest,
)
from privoke_eval.advpii_structure import (
    PARQUET_ROWS,
    aggregate_scan,
    canonical_json_bytes,
    canonical_lf_sha256,
    open_verified_parquet,
    require_frozen_text_inputs,
    sha256_file,
    validate_protected_union,
    validate_source_audit,
    validate_training_data_source,
    verify_parquet_bytes,
)
from privoke_eval.clean_augmentation_grouping import ProtectedKeys


_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_PIN_SCHEMA = {"schema_version", "source_revision", "files"}
_PIN_FILES = {
    "scanner": "evaluation/scan-advpii-structure.py",
    "structure": "evaluation/privoke_eval/advpii_structure.py",
    "parser": "evaluation/privoke_eval/advpii_native.py",
    "grouping": "evaluation/privoke_eval/clean_augmentation_grouping.py",
    "protection_io": "evaluation/privoke_eval/clean_augmentation_protection_io.py",
    "protection_core": "evaluation/privoke_eval/clean_augmentation_protection.py",
    "review_helper": "evaluation/privoke_eval/advpii_review.py",
    "normalizer": "shared/python/privoke_model/training_data.py",
    "review_io": "evaluation/privoke_eval/advpii_review_io.py",
    "cli": "evaluation/prepare-advpii-review.py",
}
_CAPTURE_FIELDS = (
    "parquet", "source_audit", "protocol", "rubric", "protected_union",
    "protection_receipt", "pin_manifest",
)
_MAX_CAPTURE_FILE_BYTES = 64 * 1024 * 1024
_MAX_CAPTURE_TOTAL_BYTES = 128 * 1024 * 1024


@dataclass(frozen=True)
class ReviewIOPaths:
    parquet: Path
    source_audit: Path
    protocol: Path
    rubric: Path
    protected_union: Path
    protection_receipt: Path
    pin_manifest: Path
    output: Path


def _safe_error(stage: str, code: str = "preparation_failed") -> dict[str, object]:
    # Deliberately excludes exception text, paths, source values, and traceback.
    return {
        "schema_version": 1,
        "status": "failed",
        "stage": stage,
        "error_code": code,
        "run_id": secrets.token_hex(12),
    }


def _exclusive_bytes(path: Path, payload: bytes) -> str:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(12)}.pending")
    with temporary.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    # A hard link publishes atomically while refusing to replace any existing
    # name on both Windows and POSIX. Keep the pending file if publication fails.
    os.link(temporary, path)
    temporary.unlink()
    return hashlib.sha256(payload).hexdigest()


def _exclusive_json(path: Path, value: object) -> str:
    return _exclusive_bytes(path, canonical_json_bytes(value) + b"\n")


def _canonical_hash(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Pinned source file is not UTF-8.") from None
    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def _no_symlink_file(path: Path) -> None:
    if _is_link_or_junction(path) or not path.is_file():
        raise ValueError("A required input is not a regular non-symlink file.")


def _is_link_or_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or (callable(is_junction) and is_junction())


def _code_digests(repository_root: Path) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for name, relative in _PIN_FILES.items():
        path = repository_root / relative
        _no_symlink_file(path)
        raw = path.read_bytes()
        result[name] = {
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "canonical_lf_sha256": _canonical_hash(raw),
        }
    return result


def validate_pin_manifest(
    path: Path,
    expected_sha256: str,
    source_revision: str,
    repository_root: Path,
) -> tuple[dict[str, dict[str, str]], str]:
    """Verify host-trusted raw pins against actual code before source access."""
    if not isinstance(expected_sha256, str) or _HEX64.fullmatch(expected_sha256) is None:
        raise ValueError("Code pin manifest commitment is malformed.")
    _no_symlink_file(path)
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != expected_sha256:
        raise ValueError("Code pin manifest bytes do not match the host commitment.")
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Code pin manifest is malformed.") from None
    if not isinstance(manifest, dict) or set(manifest) != _PIN_SCHEMA:
        raise ValueError("Code pin manifest identity or file inventory is invalid.")
    files = manifest.get("files")
    if (
        type(manifest.get("schema_version")) is not int
        or manifest.get("schema_version") != 1
        or manifest.get("source_revision") != source_revision
        or not isinstance(files, dict)
        or set(files) != set(_PIN_FILES)
    ):
        raise ValueError("Code pin manifest identity or file inventory is invalid.")
    expected_files = files
    for name, digests in expected_files.items():
        if (
            not isinstance(digests, dict)
            or set(digests) != {"raw_sha256", "canonical_lf_sha256"}
            or any(not isinstance(value, str) or _HEX64.fullmatch(value) is None for value in digests.values())
        ):
            raise ValueError("Code pin manifest contains malformed file digests.")
    actual = _code_digests(repository_root)
    if actual != expected_files:
        raise ValueError("Code source files differ from their host-trusted pin manifest.")
    return actual, digest


def _safe_output_directory(output: Path, results_root: Path) -> None:
    root = results_root.resolve(strict=True)
    if ".." in output.parts:
        raise ValueError("Output path may not contain parent traversal.")
    if output.exists() or _is_link_or_junction(output):
        raise FileExistsError("Output path already exists; prior evidence is immutable.")
    parent = output.parent.resolve(strict=True)
    if parent != root or output.name in {"", ".", ".."}:
        raise ValueError("Output must be a new direct child of the approved results directory.")
    # Resolve parent before mkdir and reject a symlink/reparse point in the target's ancestry.
    current = output.parent
    while current != current.parent:
        if _is_link_or_junction(current):
            raise ValueError("Output ancestry contains a symlink or reparse point.")
        if current == root:
            break
        current = current.parent
    output.mkdir(mode=0o700, parents=False, exist_ok=False)


@contextmanager
def _capture_inputs(paths: ReviewIOPaths):
    """Capture every caller-controlled input once for validators and scanning."""
    total = 0
    with tempfile.TemporaryDirectory(prefix="privoke-advpii-review-") as temporary:
        root = Path(temporary)
        try:
            os.chmod(root, 0o700)
        except OSError:
            pass  # Windows ACLs are operator-provisioned; POSIX gets private mode.
        captured_paths: dict[str, Path] = {}
        captured_hashes: dict[str, str] = {}
        for name in _CAPTURE_FIELDS:
            source = getattr(paths, name)
            _no_symlink_file(source)
            if source.stat().st_size > _MAX_CAPTURE_FILE_BYTES:
                raise ValueError("A verified input exceeds the bounded snapshot size.")
            with source.open("rb") as handle:
                raw = handle.read(_MAX_CAPTURE_FILE_BYTES + 1)
            if len(raw) > _MAX_CAPTURE_FILE_BYTES:
                raise ValueError("A verified input exceeds the bounded snapshot size.")
            total += len(raw)
            if total > _MAX_CAPTURE_TOTAL_BYTES:
                raise ValueError("Verified inputs exceed the bounded total snapshot size.")
            directory = root / name
            directory.mkdir(mode=0o700)
            destination = directory / source.name
            with destination.open("xb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.chmod(destination, 0o600)
            except OSError:
                pass  # Windows ACLs are operator-provisioned; do not claim mode proof.
            captured_paths[name] = destination
            captured_hashes[name] = hashlib.sha256(raw).hexdigest()
        yield replace(paths, **captured_paths), captured_hashes


def _verify_original_inputs(paths: ReviewIOPaths, captured_hashes: Mapping[str, str]) -> None:
    """Reject any pathname replacement relative to the original byte snapshot."""
    for name in _CAPTURE_FIELDS:
        path = getattr(paths, name)
        _no_symlink_file(path)
        if sha256_file(path) != captured_hashes[name]:
            raise ValueError("An original input pathname no longer matches its captured bytes.")


def _validated_span_inputs(raw: Mapping[str, object], parsed: Any) -> tuple[ValidatedNativeSpanInput, ...]:
    """Adapt one parser-eligible row's exact native spans for helper revalidation."""
    spans = raw.get("pii_spans")
    if not isinstance(spans, list):
        raise ValueError("Eligible source row has malformed span data.")
    converted: list[ValidatedNativeSpanInput] = []
    for span in spans:
        if not isinstance(span, Mapping):
            raise ValueError("Eligible source row has malformed span data.")
        value = span.get("value")
        fuzzy = span.get("value_fuzzy")
        literal = fuzzy if isinstance(fuzzy, str) and fuzzy else value
        if not isinstance(literal, str):
            raise ValueError("Eligible source row has malformed span data.")
        converted.append(ValidatedNativeSpanInput(
            entity_type=span.get("type"),
            start=span.get("start"),
            end=span.get("end"),
            literal=literal,
            base_value=value if isinstance(value, str) else None,
        ))
    if len(converted) != parsed.valid_span_count:
        raise ValueError("Eligible source row span count differs from parser validation.")
    return tuple(converted)


def _spans_for_eligible_rows(raw_rows: Iterable[Mapping[str, object]], parsed_rows: tuple[Any, ...]) -> dict[int, tuple[ValidatedNativeSpanInput, ...]]:
    """Build strict span inputs for eligible rows only; excluded bridges remain parsed."""
    raw_by_uid: dict[int, Mapping[str, object]] = {}
    for raw in raw_rows:
        uid = raw.get("uid")
        if type(uid) is not int or uid in raw_by_uid:
            raise ValueError("Source UID coverage is malformed or duplicated.")
        raw_by_uid[uid] = raw
    return {
        parsed.grouping_row.uid: _validated_span_inputs(raw_by_uid[parsed.grouping_row.uid], parsed)
        for parsed in parsed_rows
        if parsed.grouping_row.eligible
    }


def _iter_rows(parquet: Any, batch_size: int = 256) -> Iterable[tuple[Mapping[str, object], Any]]:
    seen: set[int] = set()
    for batch in parquet.iter_batches(batch_size=batch_size):
        validate_arrow_schema(batch.schema)
        for row in batch.to_pylist():
            if not isinstance(row, Mapping):
                raise ValueError("Parquet batch contains a malformed row.")
            parsed = parse_native_row(row)
            uid = parsed.grouping_row.uid
            if uid in seen:
                raise ValueError("Pinned source contains a duplicate UID across batches.")
            seen.add(uid)
            yield row, parsed


def prepare_review_pool(
    paths: ReviewIOPaths,
    *,
    source_revision: str,
    pin_manifest_sha256: str,
    protection_receipt_sha256: str,
    repository_root: Path,
    results_root: Path,
    parquet_opener: Callable[[Path], Any] = open_verified_parquet,
) -> int:
    """Verify all inputs, close the full graph, and write a private review pool."""
    output = paths.output
    stage_ref = ["validate_output_path"]
    output_created = False
    try:
        _safe_output_directory(output, results_root)
        output_created = True
        stage_ref[0] = "capture_verified_inputs"
        with _capture_inputs(paths) as (captured, captured_hashes):
            return _prepare_captured_review_pool(
                original_paths=paths,
                captured_paths=captured,
                captured_hashes=captured_hashes,
                source_revision=source_revision,
                pin_manifest_sha256=pin_manifest_sha256,
                protection_receipt_sha256=protection_receipt_sha256,
                repository_root=repository_root,
                stage_ref=stage_ref,
                parquet_opener=parquet_opener,
            )
    except Exception:
        if output_created:
            try:
                _exclusive_json(output / "failure.json", _safe_error(stage_ref[0], f"{stage_ref[0]}_failed"))
            except OSError:
                pass
        # Output-path failures return a fixed status without printing a traceback
        # or attempting to write outside an approved, newly created directory.
        return 1


def _artifact_protected_keys(path: Path) -> tuple[ProtectedKeys, dict[str, object]]:
    try:
        artifact = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ValueError("Captured protection artifact is malformed.") from None
    if (
        not isinstance(artifact, dict)
        or set(artifact) != {"schema_version", "kind", "union_sha256", "coverage_counts", "verified_commitments", "keys"}
        or type(artifact.get("schema_version")) is not int
        or artifact.get("schema_version") != 1
        or artifact.get("kind") != "privoke-clean-protected-union"
        or not isinstance(artifact.get("union_sha256"), str)
        or _HEX64.fullmatch(artifact["union_sha256"]) is None
        or not isinstance(artifact.get("coverage_counts"), dict)
        or not isinstance(artifact.get("verified_commitments"), dict)
        or not isinstance(artifact.get("keys"), dict)
    ):
        raise ValueError("Captured protection artifact is malformed.")
    raw_keys = artifact["keys"]
    if set(raw_keys) != {"ids", "groups", "exact_text_sha256", "normalized_texts"}:
        raise ValueError("Captured protection artifact key schema is invalid.")
    for values in raw_keys.values():
        if (
            not isinstance(values, list)
            or not values
            or any(not isinstance(value, str) or _HEX64.fullmatch(value) is None for value in values)
            or values != sorted(set(values))
        ):
            raise ValueError("Captured protection artifact key list is invalid.")
    payload = {
        "schema_version": artifact["schema_version"],
        "verified_commitments": artifact["verified_commitments"],
        "keys": raw_keys,
    }
    if hashlib.sha256(canonical_json_bytes(payload)).hexdigest() != artifact["union_sha256"]:
        raise ValueError("Captured protection artifact content digest is invalid.")
    protected = ProtectedKeys(
        ids=frozenset(raw_keys["ids"]),
        groups=frozenset(raw_keys["groups"]),
        exact_text_sha256=frozenset(raw_keys["exact_text_sha256"]),
        normalized_texts=frozenset(raw_keys["normalized_texts"]),
    )
    return protected, artifact


def _prepare_captured_review_pool(
    *,
    original_paths: ReviewIOPaths,
    captured_paths: ReviewIOPaths,
    captured_hashes: Mapping[str, str],
    source_revision: str,
    pin_manifest_sha256: str,
    protection_receipt_sha256: str,
    repository_root: Path,
    stage_ref: list[str],
    parquet_opener: Callable[[Path], Any],
) -> int:
    output = original_paths.output
    try:
        if not isinstance(source_revision, str) or _HEX40.fullmatch(source_revision) is None:
            raise ValueError("Source revision must be a full lowercase Git commit SHA.")
        stage_ref[0] = "verify_code_pins"
        if captured_hashes["pin_manifest"] != pin_manifest_sha256:
            raise ValueError("Code pin manifest differs from its host commitment.")
        if captured_hashes["protection_receipt"] != protection_receipt_sha256:
            raise ValueError("Protection receipt differs from its host commitment.")

        code_digests, pin_digest = validate_pin_manifest(
            captured_paths.pin_manifest, pin_manifest_sha256, source_revision, repository_root
        )
        stage_ref[0] = "verify_source_audit"
        source_audit = validate_source_audit(captured_paths.source_audit)
        if source_audit.get("source_audit_sha256") != captured_hashes["source_audit"]:
            raise ValueError("Source-audit validator digest differs from the captured bytes.")
        stage_ref[0] = "verify_frozen_text_inputs"
        text_bindings = require_frozen_text_inputs(captured_paths.protocol, captured_paths.rubric)
        if (
            canonical_lf_sha256(captured_paths.protocol) != text_bindings["protocol_sha256"]
            or canonical_lf_sha256(captured_paths.rubric) != text_bindings["rubric_sha256"]
        ):
            raise ValueError("Frozen text validator digests differ from captured bytes.")
        stage_ref[0] = "verify_normalizer"
        normalizer_digest = validate_training_data_source(repository_root / "shared/python/privoke_model/training_data.py")
        stage_ref[0] = "verify_protection_artifact"
        protected, protection_metadata = validate_protected_union(
            captured_paths.protected_union, captured_paths.protection_receipt, protection_receipt_sha256
        )
        stage_ref[0] = "bind_captured_protection_bytes"
        artifact_keys, artifact = _artifact_protected_keys(captured_paths.protected_union)
        if (
            protected != artifact_keys
            or protection_metadata.get("artifact_sha256") != captured_hashes["protected_union"]
            or protection_metadata.get("receipt_sha256") != captured_hashes["protection_receipt"]
            or protection_metadata.get("union_sha256") != artifact.get("union_sha256")
            or protection_metadata.get("verified_commitments") != artifact.get("verified_commitments")
        ):
            raise ValueError("Protection validator result differs from the captured artifact and receipt bytes.")
        stage_ref[0] = "verify_receipt_helpers"
        receipt_helpers = protection_metadata["helper_source_hashes"]
        expected_receipt_helpers = {
            "protection_io_sha256": code_digests["protection_io"]["raw_sha256"],
            "protection_core_sha256": code_digests["protection_core"]["raw_sha256"],
            "grouping_core_sha256": code_digests["grouping"]["raw_sha256"],
            "training_data_sha256": code_digests["normalizer"]["raw_sha256"],
        }
        if receipt_helpers != expected_receipt_helpers:
            raise ValueError("Protection receipt helper-source hashes differ from the pinned execution code.")
        protected_digest = protected_keys_digest(protected)
        if protected_keys_digest(artifact_keys) != protected_digest:
            raise ValueError("Captured artifact keys differ from the validated protected-key identity.")

        # Validators consumed immutable snapshots. Confirm original paths still
        # name those exact bytes before a Parquet reader or row parser is opened.
        stage_ref[0] = "verify_original_inputs_before_reader"
        _verify_original_inputs(original_paths, captured_hashes)
        stage_ref[0] = "verify_source_bytes"
        parquet_digest = verify_parquet_bytes(captured_paths.parquet)
        if parquet_digest != captured_hashes["parquet"]:
            raise ValueError("Parquet validator digest differs from the captured bytes.")
        stage_ref[0] = "validate_parquet_schema"
        parquet = parquet_opener(captured_paths.parquet)
        validate_arrow_schema(parquet.schema_arrow)
        if parquet.metadata.num_rows != PARQUET_ROWS:
            raise ValueError("Parquet row count differs from the frozen source audit.")

        _verify_original_inputs(original_paths, captured_hashes)
        stage_ref[0] = "scan_full_source"
        parsed_rows: list[Any] = []
        span_map: dict[int, tuple[ValidatedNativeSpanInput, ...]] = {}
        for raw, parsed in _iter_rows(parquet):
            parsed_rows.append(parsed)
            if parsed.grouping_row.eligible:
                span_map[parsed.grouping_row.uid] = _validated_span_inputs(raw, parsed)
        if len(parsed_rows) != PARQUET_ROWS:
            raise ValueError("Full source scan row count differs from frozen metadata.")

        _verify_original_inputs(original_paths, captured_hashes)
        stage_ref[0] = "close_full_graph"
        _, graph = aggregate_scan(parsed_rows, protected, expected_rows=PARQUET_ROWS)
        bindings = ReviewBindings(
            source_revision=source_revision,
            source_sha256=parquet_digest,
            protocol_sha256=text_bindings["protocol_sha256"],
            rubric_sha256=text_bindings["rubric_sha256"],
            parser_sha256=code_digests["parser"]["raw_sha256"],
            grouping_sha256=code_digests["grouping"]["raw_sha256"],
            normalizer_sha256=normalizer_digest,
            protected_union_sha256=protection_metadata["union_sha256"],
            protected_keys_sha256=protected_digest,
        )
        stage_ref[0] = "build_blind_pool"
        pool = build_review_pool(tuple(parsed_rows), graph, bindings, protected, span_map)

        stage_ref[0] = "recheck_pins"
        after_code, after_pin_digest = validate_pin_manifest(
            captured_paths.pin_manifest, pin_manifest_sha256, source_revision, repository_root
        )
        if after_code != code_digests or after_pin_digest != pin_digest:
            raise ValueError("Pinned source files changed during the scan.")
        _verify_original_inputs(original_paths, captured_hashes)

        stage_ref[0] = "write_private_artifacts"
        package_payloads = []
        map_payloads = []
        for package, member in zip(pool.packages, pool._members, strict=True):
            package_payloads.append(canonical_json_bytes({
                "review_id": package.review_id,
                "text": package.text,
                "text_sha256": package.text_sha256,
                "rubric_sha256": package.rubric_sha256,
                "native_spans": [
                    {"entity_type": span.entity_type, "start": span.start, "end": span.end}
                    for span in package.native_spans
                ],
            }) + b"\n")
            map_payloads.append(canonical_json_bytes({
                "review_id": member.review_id,
                "source_uid": member.uid,
                "component_id": member.component_id,
                "source_text_sha256": member.exact_text_sha256,
                "native_category": member.native_category,
                "structural_eligible": member.structural_eligible,
                "native_span_types": [span.entity_type for span in member.native_spans],
            }) + b"\n")
        packages_sha = _exclusive_bytes(output / "review-packages.jsonl", b"".join(package_payloads))
        mapping_sha = _exclusive_bytes(output / "private-review-map.jsonl", b"".join(map_payloads))
        manifest = {
            "schema_version": 1,
            "status": "complete",
            "scope": "review_preparation_only",
            "no_allocation": True,
            "no_model_scoring": True,
            "not_authorized_for_fitting": True,
            "run_id": secrets.token_hex(12),
            "source_revision": source_revision,
            "dataset_revision": source_audit["dataset_revision"],
            "source_row_count": len(parsed_rows),
            "parquet_sha256": parquet_digest,
            "source_audit_sha256": source_audit["source_audit_sha256"],
            "protocol_sha256": text_bindings["protocol_sha256"],
            "rubric_sha256": text_bindings["rubric_sha256"],
            "protection": protection_metadata,
            "protected_keys_sha256": protected_digest,
            "pin_manifest_sha256": pin_digest,
            "code_sha256": code_digests,
            "pool_sha256": pool.pool_sha256,
            "graph_membership_sha256": pool.graph_membership_sha256,
            "private_members_sha256": pool.private_members_sha256,
            "pool_size": pool.pool_size,
            "selection_streams": list(pool.selection_streams),
            "review_packages_sha256": packages_sha,
            "private_review_map_sha256": mapping_sha,
            "review_packages_file": "review-packages.jsonl",
            "private_review_map_file": "private-review-map.jsonl",
        }
        _exclusive_json(output / "manifest.json", manifest)
        return 0
    except Exception:
        stage_ref[0] = stage_ref[0] or "prepare_review_pool"
        raise


def build_pin_manifest(repository_root: Path, source_revision: str) -> dict[str, object]:
    """Host-side utility for making the explicitly reviewed pin manifest."""
    if not isinstance(source_revision, str) or _HEX40.fullmatch(source_revision) is None:
        raise ValueError("Source revision must be a full lowercase Git commit SHA.")
    return {"schema_version": 1, "source_revision": source_revision, "files": _code_digests(repository_root)}


__all__ = [
    "ReviewIOPaths",
    "build_pin_manifest",
    "prepare_review_pool",
    "validate_pin_manifest",
]
