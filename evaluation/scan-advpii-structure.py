#!/usr/bin/env python3
"""Count-only structural scan of the pinned local AdvPIIBench Parquet file."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import hashlib
import json
from pathlib import Path
import re
import sys

EVALUATION_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = EVALUATION_ROOT.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "shared/python"))

from privoke_eval.advpii_native import validate_arrow_schema  # noqa: E402
from privoke_eval.advpii_structure import (  # noqa: E402
    PARQUET_ROWS,
    aggregate_scan,
    canonical_json_bytes,
    open_verified_parquet,
    parse_unique_batches,
    require_frozen_text_inputs,
    sha256_file,
    validate_protected_union,
    validate_source_audit,
    verify_parquet_bytes,
)


_HEX40 = re.compile(r"[0-9a-f]{40}\Z")


def _write_exclusive_json(path: Path, value: object) -> str:
    data = canonical_json_bytes(value) + b"\n"
    with path.open("xb") as handle:
        handle.write(data)
    return hashlib.sha256(data).hexdigest()


def _safe_failure(output: Path, stage: str, error: BaseException) -> None:
    record = {
        "schema_version": 1,
        "status": "failed",
        "stage": stage,
        "error_class": type(error).__name__,
        "error_code": f"{stage}_failed",
    }
    _write_exclusive_json(output / "failure.json", record)


def scan(args: argparse.Namespace) -> int:
    output = Path(args.output)
    if output.exists() or output.is_symlink():
        raise FileExistsError("Output path already exists; failed evidence will not be overwritten.")
    output.mkdir(parents=True, exist_ok=False)
    stage = "validate_bindings"
    try:
        if not _HEX40.fullmatch(args.source_revision):
            raise ValueError("Source revision must be a full lowercase Git commit SHA.")
        source_audit = validate_source_audit(args.source_audit)
        text_bindings = require_frozen_text_inputs(args.protocol, args.rubric)
        protected, protection_metadata = validate_protected_union(
            args.protected_union,
            args.protection_receipt,
            args.protection_receipt_sha256,
        )

        stage = "verify_parquet_bytes"
        parquet_digest = verify_parquet_bytes(args.parquet)
        stage = "validate_parquet_schema"
        parquet = open_verified_parquet(args.parquet)
        validate_arrow_schema(parquet.schema_arrow)
        if parquet.metadata.num_rows != PARQUET_ROWS:
            raise ValueError("Parquet row count differs from the frozen source audit.")

        stage = "scan_full_source"
        parsed_rows = []
        for parsed in parse_unique_batches(parquet.iter_batches(batch_size=256)):
            parsed_rows.append(parsed)
        scanned_rows = len(parsed_rows)
        if scanned_rows != PARQUET_ROWS:
            raise ValueError("Full source scan row count differs from frozen metadata.")

        stage = "aggregate_complete_graph"
        report, graph = aggregate_scan(parsed_rows, protected, expected_rows=PARQUET_ROWS)
        report_sha = _write_exclusive_json(output / "aggregate-report.json", report)
        code_files = {
            "scanner_sha256": sha256_file(Path(__file__)),
            "parser_sha256": sha256_file(REPOSITORY_ROOT / "evaluation/privoke_eval/advpii_native.py"),
            "grouping_sha256": sha256_file(REPOSITORY_ROOT / "evaluation/privoke_eval/clean_augmentation_grouping.py"),
            "aggregation_sha256": sha256_file(REPOSITORY_ROOT / "evaluation/privoke_eval/advpii_structure.py"),
        }
        run_manifest = {
            "schema_version": 1,
            "status": "complete",
            "source_revision": args.source_revision,
            "dataset_revision": source_audit["dataset_revision"],
            "row_count": scanned_rows,
            "source_audit_sha256": source_audit["source_audit_sha256"],
            "parquet_sha256": parquet_digest,
            "protocol_sha256": text_bindings["protocol_sha256"],
            "rubric_sha256": text_bindings["rubric_sha256"],
            "protection": protection_metadata,
            "code_sha256": code_files,
            "aggregate_report_sha256": report_sha,
            "component_count": graph.component_count,
        }
        _write_exclusive_json(output / "run-manifest.json", run_manifest)
        return 0
    except Exception as exc:
        try:
            _safe_failure(output, stage, exc)
        except OSError:
            pass
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parquet", required=True, type=Path)
    parser.add_argument("--source-audit", required=True, type=Path)
    parser.add_argument("--protocol", required=True, type=Path)
    parser.add_argument("--rubric", required=True, type=Path)
    parser.add_argument("--protected-union", required=True, type=Path)
    parser.add_argument("--protection-receipt", required=True, type=Path)
    parser.add_argument("--protection-receipt-sha256", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return scan(args)


if __name__ == "__main__":
    raise SystemExit(main())
