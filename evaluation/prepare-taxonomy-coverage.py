"""Prepare a separately accepted taxonomy release from byte-pinned historical TRAIN.

Endpoint inputs are used only for exclusion membership, never example selection.
This command neither fits models nor grants permission to fit the new release.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services/privoke-fuzzer/src"))
sys.path.insert(0, str(ROOT / "services/privoke-fuzzer/generated"))
from host_environment import configure_imports
configure_imports()
from privoke_model.training_data import training_text_key
from privoke_eval.synthetic_curriculum import opaque_key, verify_exclusions
from prompt_generation.taxonomy_coverage import canonical_bytes, prepare_release, transform_variants


CONTEXT_KEYS_SHA256 = "d689660b0cf49d9fe0fbeea08ce5a569b4c8721a2b006f30294e1b975b00aeb1"
FIXTURE_KEYS_SHA256 = "1bf69f43f1f00f107281fc1cfe2130a8f25e2f170df151381913ef7f14a1d062"
ASSESSMENT_SHA256 = "47abc757af20bde769aff04405c8706ee054b999a4339c0c1fec0199bd82e629"
VALIDATION_SHA256 = "67e7dfddc3a136b5c9178a22198937758564473da9d46ef0b666e6ea70d5069c"
FIXTURE_SHA256 = "d6c7d5d87235cd6b0f9d24eac43b30c3ace9f0bf4f421ef5d5d812de79827a17"
SAFETY_SHA256 = "ad01ada4d2841b22b529ff872c5b2ef3802e4e4ec703e1a0700849017cd88bac"


def pinned_json(path, expected):
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != expected:
        raise ValueError("Pinned opaque exclusion artifact or development input changed.")
    return json.loads(payload)


def opaque_overlap(rows, keys, expected_counts):
    import re
    if set(keys) != {"ids", "groups", "texts"}:
        raise ValueError("Opaque endpoint keys are incomplete.")
    for kind, values in keys.items():
        if (not isinstance(values, list) or len(values) != expected_counts[kind]
                or len(set(values)) != len(values) or any(type(v) is not str or not re.fullmatch(r"[0-9a-f]{64}", v) for v in values)):
            raise ValueError("Opaque endpoint key inventory changed.")
    candidate = {"ids": {opaque_key("id", r["id"]) for r in rows},
                 "groups": {opaque_key("group", r["metadata"]["group_id"]) for r in rows},
                 "texts": {opaque_key("text_key", training_text_key(r["text"])) for r in rows}}
    overlap = {kind: len(candidate[kind] & set(values)) for kind, values in keys.items()}
    if any(overlap.values()):
        raise ValueError("Taxonomy TRAIN or augmentation overlaps a pinned excluded endpoint.")
    return overlap


def prepare(source, renderer, exclusion_index, context_keys, fixture_keys, development_validation, block_protocol):
    source_bytes, renderer_bytes, exclusion_bytes = source.read_bytes(), renderer.read_bytes(), exclusion_index.read_bytes()
    rows = [json.loads(line) for line in source_bytes.decode("utf-8").splitlines() if line.strip()]
    variants = [{**row, "text": text} for row in rows for text in transform_variants(row["text"])]
    index = json.loads(exclusion_bytes)
    verify_exclusions({"train": variants}, index)
    memberships = {
        "ids": {r["id"] for r in rows}, "groups": {r["metadata"]["group_id"] for r in rows},
        "texts": {training_text_key(r["text"]) for r in variants},
    }
    context = pinned_json(context_keys, CONTEXT_KEYS_SHA256)
    fixture = pinned_json(fixture_keys, FIXTURE_KEYS_SHA256)
    protocol_bytes = block_protocol.read_bytes()
    protocol = json.loads(protocol_bytes)
    if (context["endpoints"]["context"]["sha256"] != ASSESSMENT_SHA256
            or fixture["role_refs"]["fixed_context_fixture"]["sha256"] != FIXTURE_SHA256
            or protocol["endpoints"]["assessment"]["sha256"] != ASSESSMENT_SHA256
            or protocol["endpoints"]["safety"]["sha256"] != SAFETY_SHA256
            or protocol["safety_source"]["sha256"] != FIXTURE_SHA256
            or protocol["endpoints"]["validation"]["sha256"] != VALIDATION_SHA256):
        raise ValueError("Opaque endpoint commitments do not match the frozen block endpoints.")
    # Never dereference endpoint paths from these artifacts. Only opaque sets are consumed.
    assessment_overlap = opaque_overlap(variants, context["canonical_endpoint_key_sets"]["context"],
                                        {"texts": 320, "groups": 40, "ids": 360})
    safety_overlap = opaque_overlap(variants, fixture["role_key_sets"]["fixed_context_fixture"],
                                    {"texts": 48, "groups": 12, "ids": 60})
    # This explicitly named development file is authorized for membership-only checks.
    validation_bytes = development_validation.read_bytes()
    if hashlib.sha256(validation_bytes).hexdigest() != VALIDATION_SHA256:
        raise ValueError("Pinned development validation input changed.")
    endpoint = [json.loads(line) for line in validation_bytes.decode("utf-8").splitlines() if line.strip()]
    if len(endpoint) != 64:
        raise ValueError("Expected the frozen 64-row development validation input.")
    keys = {"ids": {r.get("id", r.get("case_id")) for r in endpoint},
            "groups": {r.get("group_id", r.get("family_id", r.get("metadata", {}).get("group_id"))) for r in endpoint},
            "texts": {training_text_key(r["text"]) for r in endpoint}}
    validation_overlap = {name: len(memberships[name] & (values - {None})) for name, values in keys.items()}
    if any(validation_overlap.values()):
        raise ValueError("Taxonomy TRAIN or augmentation overlaps development validation.")
    endpoint_records = [
        {"role": "assessment", "sha256": ASSESSMENT_SHA256, "rows": 320,
         "opaque_artifact_sha256": CONTEXT_KEYS_SHA256, "overlap_counts": assessment_overlap},
        {"role": "safety", "sha256": SAFETY_SHA256, "rows": 48, "source_sha256": FIXTURE_SHA256,
         "opaque_artifact_sha256": FIXTURE_KEYS_SHA256, "overlap_counts": safety_overlap},
        {"role": "development_validation", "sha256": VALIDATION_SHA256, "rows": 64, "overlap_counts": validation_overlap}]
    validation = {"status": "passed", "all_transform_variants": True,
                  "exclusion_index_sha256": hashlib.sha256(exclusion_bytes).hexdigest(),
                  "protected_union_digest": index["all_exclusion_key_sets_sha256"],
                  "endpoints": endpoint_records, "membership_only": True, "protected_final_opened": False}
    validation.update(assessment_records_opened=False, safety_records_opened=False,
                      block_protocol_sha256=hashlib.sha256(protocol_bytes).hexdigest())
    return prepare_release(source_bytes, renderer_bytes, validation)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--renderer", type=Path, required=True)
    parser.add_argument("--exclusion-index", type=Path, required=True)
    parser.add_argument("--context-opaque-keys", type=Path, required=True)
    parser.add_argument("--fixture-opaque-keys", type=Path, required=True)
    parser.add_argument("--development-validation", type=Path, required=True)
    parser.add_argument("--block-protocol", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = prepare(args.source, args.renderer, args.exclusion_index, args.context_opaque_keys,
                      args.fixture_opaque_keys, args.development_validation, args.block_protocol)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Never replace a release or its provenance, including a partial prior attempt.
    with args.output.open("xb") as stream:
        stream.write(payload)
    provenance = {"dataset_sha256": hashlib.sha256(payload).hexdigest(),
                  "dataset": args.output.name, **json.loads(payload)["provenance"]}
    with args.output.with_suffix(".provenance.json").open("xb") as stream:
        stream.write(canonical_bytes(provenance))
    print(json.dumps({"dataset_sha256": provenance["dataset_sha256"], "fit_release": False, "rows": 640}))


if __name__ == "__main__":
    main()
