"""Export confined review chunks only; no labeling, allocation or fitting."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "evaluation"), str(ROOT / "shared/python")]
from privoke_eval.in_house_review_chunks import (  # noqa: E402
    ExportTrust, MAX_METADATA_BYTES, decode_pinned, digest,
    export_review_chunks, publish_review_chunks, read_pinned_file,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("trust", "trust-sha256", "manifest", "packages", "rubric", "assignments", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        raw = read_pinned_file(args.trust, args.trust_sha256, limit=MAX_METADATA_BYTES)
        value = decode_pinned(raw, args.trust_sha256, MAX_METADATA_BYTES)
        if type(value) is not dict or set(value) != {"schema_version", "kind", "trust"}:
            raise ValueError()
        if type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["kind"] != "privoke-in-house-review-export-trust-v1":
            raise ValueError()
        if type(value["trust"]) is not dict or set(value["trust"]) != set(ExportTrust.__dataclass_fields__):
            raise ValueError()
        trust = ExportTrust(**value["trust"])
        trust.validate()
        exports = export_review_chunks(
            read_pinned_file(args.manifest, trust.manifest_sha256, limit=MAX_METADATA_BYTES),
            read_pinned_file(args.packages, trust.packages_sha256),
            read_pinned_file(args.rubric, trust.rubric_raw_sha256, private=False, limit=MAX_METADATA_BYTES),
            read_pinned_file(args.assignments, trust.assignments_sha256, limit=MAX_METADATA_BYTES),
            trust=trust,
        )
        receipts = publish_review_chunks(Path(args.output), exports)
        # Counts and hashes only: no prompts, labels, IDs, actor names or paths.
        import json
        print(json.dumps({"status": "complete", "chunk_count": len(receipts),
                          "assignments_sha256": trust.assignments_sha256,
                          "manifest_sha256": trust.manifest_sha256,
                          "export_receipts_sha256": digest(json.dumps(receipts, sort_keys=True, separators=(",", ":")).encode("ascii"))}))
        return 0
    except Exception:
        print('{"status":"failed","error_code":"review_chunk_boundary_failed"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
