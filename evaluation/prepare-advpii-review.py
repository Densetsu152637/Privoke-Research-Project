#!/usr/bin/env python3
"""Prepare restricted blinded review packages from the pinned local source."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Sequence

EVALUATION_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = EVALUATION_ROOT.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "shared/python"))
sys.path.insert(0, str(EVALUATION_ROOT))

from privoke_eval.advpii_review_io import ReviewIOPaths, prepare_review_pool  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parquet", type=Path, required=True)
    parser.add_argument("--source-audit", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--rubric", type=Path, required=True)
    parser.add_argument("--protected-union", type=Path, required=True)
    parser.add_argument("--protection-receipt", type=Path, required=True)
    parser.add_argument("--protection-receipt-sha256", required=True)
    parser.add_argument("--pin-manifest", type=Path, required=True)
    parser.add_argument("--pin-manifest-sha256", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None, *, _results_root: Path | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = ReviewIOPaths(
        parquet=args.parquet,
        source_audit=args.source_audit,
        protocol=args.protocol,
        rubric=args.rubric,
        protected_union=args.protected_union,
        protection_receipt=args.protection_receipt,
        pin_manifest=args.pin_manifest,
        output=args.output,
    )
    return prepare_review_pool(
        paths,
        source_revision=args.source_revision,
        pin_manifest_sha256=args.pin_manifest_sha256,
        protection_receipt_sha256=args.protection_receipt_sha256,
        repository_root=REPOSITORY_ROOT,
        results_root=EVALUATION_ROOT / "results" if _results_root is None else _results_root,
    )


if __name__ == "__main__":
    raise SystemExit(main())
