#!/usr/bin/env python3
"""Run the frozen in-house blind-review protection preflight or preparation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Sequence

EVALUATION_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = EVALUATION_ROOT.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "shared/python"))
sys.path.insert(0, str(EVALUATION_ROOT))

from privoke_eval.in_house_advpii_review import EXECUTION_CODE_ROLES  # noqa: E402
from privoke_eval.in_house_advpii_review_io import (  # noqa: E402
    InHousePreparationTrust, InHouseReviewIOPaths, InHousePreparationError,
    prepare_in_house_protection_bindings, prepare_in_house_review_pool,
)

_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _digest_argument(value: str) -> tuple[str, str]:
    if not isinstance(value, str) or "=" not in value:
        raise argparse.ArgumentTypeError("expected ROLE=sha256")
    role, digest = value.split("=", 1)
    if not role or _HEX64.fullmatch(digest) is None:
        raise argparse.ArgumentTypeError("expected ROLE=sha256")
    return role, digest


def _closed_map(values: Sequence[tuple[str, str]], roles: set[str], name: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for role, digest in values:
        if role not in roles or role in result:
            raise ValueError(f"invalid {name} role map")
        result[role] = digest
    if set(result) != roles:
        raise ValueError(f"incomplete {name} role map")
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=("protection-preflight", "prepare"), required=True)
    parser.add_argument("--parquet", type=Path, required=True)
    parser.add_argument("--source-audit", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--rubric", type=Path, required=True)
    parser.add_argument("--protected-union", type=Path, required=True)
    parser.add_argument("--protection-receipt", type=Path, required=True)
    parser.add_argument("--pin-manifest", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--fixture-rubric", type=Path, required=True)
    parser.add_argument("--fixture-review", type=Path, required=True)
    parser.add_argument("--addon-artifact", type=Path, required=True)
    parser.add_argument("--addon-receipt", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument("--results-root", type=Path, default=EVALUATION_ROOT / "results")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--pin-manifest-sha256", required=True)
    parser.add_argument("--historical-receipt-sha256", required=True)
    parser.add_argument("--addon-receipt-sha256", required=True)
    parser.add_argument("--addon-producer-revision", required=True)
    parser.add_argument("--study-plan-lf-sha256", required=True)
    parser.add_argument("--preparation-design-sha256", required=True)
    parser.add_argument("--allocator-design-sha256", required=True)
    parser.add_argument("--input-sha256", action="append", type=_digest_argument, default=[])
    parser.add_argument("--execution-code-sha256", action="append", type=_digest_argument, default=[])
    parser.add_argument("--addon-helper-sha256", action="append", type=_digest_argument, default=[])
    parser.add_argument("--expected-protection-bindings-json")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if _HEX40.fullmatch(args.source_revision) is None or _HEX40.fullmatch(args.addon_producer_revision) is None:
            raise ValueError("invalid source revision")
        for value in (args.pin_manifest_sha256, args.historical_receipt_sha256, args.addon_receipt_sha256):
            if _HEX64.fullmatch(value) is None:
                raise ValueError("invalid digest")
        for value in (args.study_plan_lf_sha256, args.preparation_design_sha256, args.allocator_design_sha256):
            if _HEX64.fullmatch(value) is None:
                raise ValueError("invalid design digest")
        inputs = _closed_map(args.input_sha256, {
            "parquet", "source_audit", "protocol", "rubric", "protected_union", "protection_receipt",
            "pin_manifest", "fixture", "fixture_rubric", "fixture_review", "addon_artifact", "addon_receipt",
        }, "input")
        code = _closed_map(args.execution_code_sha256, set(EXECUTION_CODE_ROLES), "execution code")
        addon_helpers = _closed_map(args.addon_helper_sha256,
                                    {"grouping", "normalizer", "fixture_validator"}, "add-on helper")
        expected = args.expected_protection_bindings_json
        if args.stage == "prepare" and expected is None:
            raise ValueError("expected frozen protection bindings are required")
        if args.stage == "protection-preflight" and expected is not None:
            raise ValueError("protection preflight does not accept expected bindings")
        paths = InHouseReviewIOPaths(
            parquet=args.parquet, source_audit=args.source_audit, protocol=args.protocol, rubric=args.rubric,
            protected_union=args.protected_union, protection_receipt=args.protection_receipt,
            pin_manifest=args.pin_manifest, fixture=args.fixture, fixture_rubric=args.fixture_rubric,
            fixture_review=args.fixture_review, addon_artifact=args.addon_artifact,
            addon_receipt=args.addon_receipt, output=args.output,
        )
        trust = InHousePreparationTrust(
            source_revision=args.source_revision, input_raw_sha256=inputs,
            pin_manifest_raw_sha256=args.pin_manifest_sha256,
            historical_receipt_raw_sha256=args.historical_receipt_sha256,
            addon_receipt_raw_sha256=args.addon_receipt_sha256,
            addon_producer_revision=args.addon_producer_revision,
            addon_helper_raw_sha256=addon_helpers, execution_code_raw_sha256=code,
            study_plan_lf_sha256=args.study_plan_lf_sha256,
            preparation_design_sha256=args.preparation_design_sha256,
            allocator_design_sha256=args.allocator_design_sha256,
            expected_protection_bindings=expected,
        )
        if args.stage == "protection-preflight":
            result = prepare_in_house_protection_bindings(paths, trust=trust, source_root=args.source_root)
            print(json.dumps({
                "status": "protection_preflight_complete",
                "bindings": result.bindings.to_dict(),
                "coverage_counts": dict(result.coverage_counts),
                "input_raw_sha256": dict(result.input_raw_sha256),
                "execution_code_raw_sha256": dict(result.execution_code_raw_sha256),
                "professor_confirmation": "pending",
            }, sort_keys=True, separators=(",", ":")))
            return 0
        result = prepare_in_house_review_pool(paths, trust=trust, source_root=args.source_root,
                                               results_root=args.results_root)
        print(json.dumps({
            "status": result.status, "preparation_identity": result.preparation_identity,
            "review_pool_sha256": result.review_pool_sha256,
            "output_sha256": dict(result.output_sha256), "counts": dict(result.counts),
            "output_directory_name": result.output_directory.name,
        }, sort_keys=True, separators=(",", ":")))
        return 0
    except (ValueError, OSError):
        print(json.dumps({"status": "failed", "error_code": "preparation_failed"}, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
