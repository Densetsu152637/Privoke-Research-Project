"""Prepare reviewed ordinary-benign TRAIN using existing opaque exclusions only.

The separately authorized frozen development file is consumed for membership only.
Never dereference assessment/safety/protected payload paths or regenerate endpoint keys.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "services/privoke-fuzzer/src", ROOT / "services/privoke-fuzzer/generated", ROOT / "shared/python", ROOT / "evaluation"):
    sys.path.insert(0, str(path))

from privoke_model.training_data import training_text_key
from privoke_eval.synthetic_curriculum import verify_exclusions
from prompt_generation import benign_coverage as benign, taxonomy_coverage as legacy


def read_pinned(path, expected):
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != expected:
        raise ValueError("Frozen membership/provenance input changed.")
    return payload


def prepare(pool, dataset, label_review_bytes, label_rationales_bytes, exclusion_bytes,
            context_bytes, fixture_bytes, validation_bytes, protocol_bytes):
    """Pure proof construction after input hashes and review; no model or selection feedback."""
    benign.validate_pool(pool)
    review = json.loads(label_review_bytes)
    labels = [{"id": r.metadata["benign_row_id"], "classification": r.expected_classification.to_dict(),
        "packed_classification": r.expected_packed_classification,
        "sensitivity_rationale": r.metadata["sensitivity_rationale"],
        "visibility_rationale": r.metadata["visibility_rationale"],
        "category_rationale": r.metadata["category_rationale"]} for r in pool.rows]
    if (label_rationales_bytes != legacy.canonical_bytes(labels) or review.get("status") != "accepted"
            or review.get("pool_sha256") != pool.sha256
            or review.get("label_rationales_sha256") != hashlib.sha256(label_rationales_bytes).hexdigest()):
        raise ValueError("Independent label admission does not bind the exact frozen pool/targets/rationales.")
    expected = dataset.exclusion_validation
    endpoints = {r["role"]: r for r in expected["endpoints"]}
    commitments = ((exclusion_bytes, expected["exclusion_index_sha256"]),
        (context_bytes, endpoints["assessment"]["opaque_artifact_sha256"]),
        (fixture_bytes, endpoints["safety"]["opaque_artifact_sha256"]),
        (validation_bytes, endpoints["development_validation"]["sha256"]),
        (protocol_bytes, expected["block_protocol_sha256"]))
    if any(hashlib.sha256(payload).hexdigest() != pin for payload, pin in commitments):
        raise ValueError("Existing frozen exclusion/endpoint commitments changed.")
    rows = json.loads(pool.payload)["rows"]
    variants = [{**r, "text": text} for r in rows for text in legacy.transform_variants(r["text"])]
    index = json.loads(exclusion_bytes)
    verify_exclusions({"train": variants}, index)
    if index["all_exclusion_key_sets_sha256"] != expected["protected_union_digest"]:
        raise ValueError("Protected opaque union commitment changed.")
    # Reuse the accepted narrow opaque-set validator; loading this module performs no preparation.
    tc = runpy.run_path(str(ROOT / "evaluation/prepare-taxonomy-coverage.py"))
    context, fixture, protocol = json.loads(context_bytes), json.loads(fixture_bytes), json.loads(protocol_bytes)
    if (context["endpoints"]["context"]["sha256"] != endpoints["assessment"]["sha256"]
            or fixture["role_refs"]["fixed_context_fixture"]["sha256"] != endpoints["safety"]["source_sha256"]
            or protocol["endpoints"]["assessment"]["sha256"] != endpoints["assessment"]["sha256"]
            or protocol["endpoints"]["safety"]["sha256"] != endpoints["safety"]["sha256"]
            or protocol["endpoints"]["validation"]["sha256"] != endpoints["development_validation"]["sha256"]):
        raise ValueError("Opaque endpoint role commitments differ.")
    assessment = tc["opaque_overlap"](variants, context["canonical_endpoint_key_sets"]["context"],
                                       {"texts": 320, "groups": 40, "ids": 360})
    safety = tc["opaque_overlap"](variants, fixture["role_key_sets"]["fixed_context_fixture"],
                                   {"texts": 48, "groups": 12, "ids": 60})
    # Only this frozen64 input is authorized, and only membership is retained/output.
    validation = [json.loads(line) for line in validation_bytes.decode().splitlines() if line.strip()]
    if len(validation) != 64:
        raise ValueError("Expected frozen64 validation membership.")
    candidate = {"ids": {r["id"] for r in rows}, "groups": {r["metadata"]["group_id"] for r in rows},
                 "texts": {training_text_key(r["text"]) for r in variants}}
    keys = {"ids": {r.get("id", r.get("case_id")) for r in validation},
        "groups": {r.get("group_id", r.get("family_id", r.get("metadata", {}).get("group_id"))) for r in validation},
        "texts": {training_text_key(r["text"]) for r in validation}}
    overlap = {name: len(candidate[name] & (values - {None})) for name, values in keys.items()}
    if any(overlap.values()) or any(assessment.values()) or any(safety.values()):
        raise ValueError("New benign source or any allowed variant overlaps excluded membership.")
    proof = {"schema": 1, "strategy": benign.STRATEGY, "status": "passed", "pool_sha256": pool.sha256,
        "dataset_sha256": dataset.sha256, "label_review_sha256": hashlib.sha256(label_review_bytes).hexdigest(),
        "all_transform_variants": True, "transform_commitment_sha256": benign.transform_commitment(pool),
        "source_overlap_counts": {"ids": 0, "groups": 0, "texts": 0},
        "exclusion_validation": expected, "fit_release": False}
    proof_bytes = legacy.canonical_bytes(proof)
    # This also independently rejects overlap with every accepted legacy source/guard transform.
    manifest = benign.prepare_manifest(pool, dataset, proof_bytes)
    benign.load_snapshot(manifest, pool, dataset, proof_bytes)
    return proof_bytes, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("pool", "dataset", "label-review", "label-rationales", "exclusion-index", "context-opaque-keys",
                 "fixture-opaque-keys", "development-validation", "block-protocol", "output", "proof-output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--pool-sha256", required=True)
    parser.add_argument("--label-review-sha256", required=True)
    args = parser.parse_args()
    pool = benign.load_pool_snapshot(read_pinned(args.pool, args.pool_sha256))
    review = read_pinned(args.label_review, args.label_review_sha256)
    dataset = legacy.load_dataset(args.dataset)
    proof, manifest = prepare(pool, dataset, review, args.label_rationales.read_bytes(), args.exclusion_index.read_bytes(),
        args.context_opaque_keys.read_bytes(), args.fixture_opaque_keys.read_bytes(), args.development_validation.read_bytes(),
        args.block_protocol.read_bytes())
    for path, payload in ((args.proof_output, proof), (args.output, manifest)):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(payload)
    print(json.dumps({"fit_release": False, "pool_sha256": pool.sha256,
        "proof_sha256": hashlib.sha256(proof).hexdigest(), "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "pool_rows": len(pool.rows), "all_transform_variants": True, "protected_payload_opens": 0,
        "assessment_payload_opens": 0, "safety_payload_opens": 0, "endpoint_keys_regenerated": 0,
        "validation_access": "authorized_frozen64_membership_only"}))


if __name__ == "__main__":
    main()
