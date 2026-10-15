"""Host-only PH3 data preparation; authoring audit never invokes model inference."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

from host_environment import ROOT, configure_imports

configure_imports()
sys.path[:0] = [str(ROOT / "services/privoke-fuzzer/src"), str(ROOT / "extension/client-runtime")]
from prompt_generation.privacy_heads_curriculum import (
    COUNTS, RUBRIC_PATHS, SPLITS, audit, build, canonical,
    audit_components, component_records, digest, fuzzer_training_examples, skeleton,
)
from privoke_model.training_data import training_text_key
from training.transforms import synthetic_common_name

RESOURCE = "evaluation/datasets/privacy-heads-v3-scenarios-v1.json"
OPAQUE = "evaluation/results/external_pii_20261004_prepared_v3/exclusion-index.json"
OPAQUE_SHA = "c0700613a965e26b85a2511c8a721b2f808536f215b8fe6f18f0d3890634fc2d"
# Explicit authorized TRAIN/guard/development inventory. No discovered path is dereferenced.
HISTORICAL = (
    "evaluation/results/iterative_fuzzer_20261011/taxonomy-coverage/release/taxonomy-coverage-v1.json",
    "evaluation/results/iterative_fuzzer_20261011/train-benign-coverage/pool-authored.json",
    "evaluation/results/contextual_fuzzer_20261006_prepared/prompts.jsonl",
    "evaluation/results/accelerated_all_surfaces_20261010/input-preparation/assessment-renditions/context-integrated-1.jsonl",
    "evaluation/results/iterative_fuzzer_20261011/block01/validation.jsonl",
    "evaluation/results/locked-public/development.jsonl",
    "evaluation/results/contextual_fixtures_20261004_v1/support/fixture.jsonl",
    "evaluation/results/representation_20261004_v3/prepared/validation.jsonl",
    "evaluation/datasets/contextual-head-study-20261010.json",
    "evaluation/datasets/contextual-assessment-20261009.json",
    "evaluation/datasets/synthetic-teacher-templates.json",
    "evaluation/datasets/synthetic-teacher-templates-v2.json",
    "evaluation/results/accelerated_all_surfaces_20261010/input-preparation/curriculum/train.jsonl",
    "models/experiments/pretrained_v3_20261012/study/schedules/42.json",
    "models/experiments/pretrained_v3_20261012/study/schedules/43.json",
    "models/experiments/pretrained_v3_20261012/study/schedules/44.json",
)
SOURCE_FILES = (
    RESOURCE, "services/privoke-fuzzer/src/prompt_generation/privacy_heads_curriculum.py",
    "services/privoke-fuzzer/src/prompt_generation/loader.py",
    "services/privoke-fuzzer/src/prompt_generation/types.py",
    "services/privoke-fuzzer/src/training/classifications.py",
    "services/privoke-fuzzer/src/training/transforms.py",
    "shared/python/privoke_model/training_data.py", "evaluation/prepare-privacy-heads-v3.py",
    "extension/client-runtime/src/detection/preprocessing.py",
    "extension/client-runtime/src/transformer_encoder.py", *RUBRIC_PATHS,
)


def records(payload):
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return [json.loads(line) for line in payload.decode("utf-8").splitlines() if line.strip()]


def historical_keys(value):
    """Read text/identity fields only from the explicit authorized captures."""
    keys = {"texts": set(), "ids": set(), "groups": set()}
    if isinstance(value, list):
        for row in value:
            child = historical_keys(row)
            for name in keys:
                keys[name].update(child[name])
    elif isinstance(value, dict):
        for field, item in value.items():
            if field in ("text", "template", "fact", "private", "clean", "teacher_private", "teacher_clean",
                         "evolved_private", "evolved_clean") and isinstance(item, str):
                keys["texts"].add(training_text_key(item))
            elif field in ("id", "case_id", "example_id") and isinstance(item, str):
                keys["ids"].add(item)
            elif field in ("group_id", "family_id") and isinstance(item, str):
                keys["groups"].add(item)
            elif isinstance(item, (dict, list)):
                child = historical_keys(item)
                for name in keys:
                    keys[name].update(child[name])
    return keys


def opaque_key(kind, value):
    return digest(f"privoke-external-exclusion-v1\0{kind}\0{value}".encode("utf-8"))


def exclusion_audit(pools, resource):
    payload = (ROOT / OPAQUE).read_bytes()
    if digest(payload) != OPAQUE_SHA:
        raise ValueError("Historical opaque protection commitment changed.")
    index = json.loads(payload)
    union = index["all_exclusion_key_sets"]
    if set(union) != {"ids", "groups", "texts"}:
        raise ValueError("Incomplete historical opaque protection inventory.")
    encoded = json.dumps(union, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    if digest(encoded) != index["all_exclusion_key_sets_sha256"]:
        raise ValueError("Opaque historical protected union digest differs.")
    protected = {name: set(items) for name, items in union.items()}
    if any(len(values) != len(union[name]) or any(not re.fullmatch(r"[0-9a-f]{64}", x) for x in values)
           for name, values in protected.items()):
        raise ValueError("Invalid opaque exclusion keys.")
    history = {"texts": set(), "ids": set(), "groups": set()}
    inputs = {OPAQUE: digest(payload)}
    for relative in HISTORICAL:
        raw = (ROOT / relative).read_bytes()
        inputs[relative] = digest(raw)
        value = records(raw)
        found = historical_keys(value)
        # Expand both historical teacher grammars without opening external/final records.
        if relative in ("evaluation/datasets/synthetic-teacher-templates.json",
                        "evaluation/datasets/synthetic-teacher-templates-v2.json"):
            from privoke_eval.synthetic_curriculum import build_curriculum
            rendered = historical_keys(list(build_curriculum(value).values()))
            for name in found:
                found[name].update(rendered[name])
        for name in history:
            history[name].update(found[name])
    shaped_history = {re.sub(r"\b\d+\b", "NUMBER", value) for value in history["texts"]}
    components = component_records(resource)
    component_failures = []
    for component in components:
        key = training_text_key(component["text"])
        shape = component["skeleton"]
        if opaque_key("text_key", key) in protected["texts"] or any(key in text for text in history["texts"]):
            component_failures.append(component["id"])
        elif any(shape in text for text in shaped_history):
            component_failures.append(component["id"])
    if component_failures:
        raise ValueError("Assertion components overlap historical exact/normalized/skeleton substrings: "
                         + ",".join(component_failures))
    variants, shaped, identities = {}, {}, {}
    for split, rows in pools.items():
        for row in rows:
            key = training_text_key(row["text"])
            if row["id"] in history["ids"] or row["group_id"] in history["groups"]:
                raise ValueError("New source identity overlaps historical data.")
            for kind, value, field in (("id", row["id"], "ids"), ("group", row["group_id"], "groups")):
                if opaque_key(kind, value) in protected[field]:
                    raise ValueError("New source overlaps historical protected identity.")
            # All maintained invariant alternatives are checked, even though fit uses originals.
            for text in (row["text"], "Please review this prompt: " + row["text"], synthetic_common_name(row["text"])):
                transformed = training_text_key(text)
                if transformed in history["texts"] or opaque_key("text_key", transformed) in protected["texts"]:
                    raise ValueError("New source overlaps historical/protected text.")
                if transformed in variants and variants[transformed] != split:
                    raise ValueError("Invariant transform leaks across splits.")
                variants[transformed] = split
                shape = skeleton(text, row["metadata"]["entity_value"])
                if shape in shaped_history:
                    raise ValueError("New source is only a historical entity/number substitution.")
                if shape in shaped and shaped[shape] != split:
                    raise ValueError("Transformed skeleton leaks across splits.")
                shaped[shape] = split
            identities[row["id"]] = split
    return {"status": "passed", "inputs": inputs, "historical_unique_text_keys": len(history["texts"]),
            "historical_unique_groups": len(history["groups"]), "new_unique_transformed_keys": len(variants),
            "protected_union_sha256": index["all_exclusion_key_sets_sha256"],
            "exact_normalized_identity_transform_overlaps": 0, "historical_final_payload_opened": False,
            "assertion_components": audit_components(resource), "historical_component_substring_overlaps": 0,
            "limitation": "Exact/skeleton checks do not establish semantic novelty; independent family review is required."}


def native_lengths(pools):
    """Use actual native preprocessing and tokenizers; never truncate labeled text."""
    from src.detection.preprocessing import normalize_with_offsets
    from src.transformer_encoder import TOKEN_PATTERN
    from transformers import BertTokenizerFast
    tokenizers = {}
    commitments = {}
    for tier in ("efficient", "balanced", "quality"):
        relative = f"models/experiments/pretrained_v3_20261012/initials/{tier}/vocab.txt"
        path = ROOT / relative
        commitments[relative] = digest(path.read_bytes())
        tokenizers[tier] = BertTokenizerFast(vocab_file=str(path), do_lower_case=True)
    result = {}
    for split, rows in pools.items():
        normalized = [normalize_with_offsets(row["text"]).text for row in rows]
        tiny = [len(TOKEN_PATTERN.findall(text)) + 1 for text in normalized]
        if max(tiny) > 64:
            raise ValueError("Primary data exceed native v1 efficient capacity; no truncation allowed.")
        lengths = {"v1_efficient": {"maximum": max(tiny), "cap": 64, "special_tokens": 1}}
        for tier, tokenizer in tokenizers.items():
            values = [len(ids) for ids in tokenizer(normalized, truncation=False,
                                                   add_special_tokens=True)["input_ids"]]
            if max(values) > 512:
                raise ValueError("Primary data exceed native v3 capacity.")
            lengths["v3_" + tier] = {"maximum": max(values), "cap": 512, "special_tokens": 2}
        result[split] = lengths
    return {"status": "passed", "splits": result, "tokenizer_files": commitments, "inference_executed": False}


def author_review(resource, pools):
    """Retain family rules and representative IDs for independent pre-fit adjudication."""
    families = resource["families"] + [f for rows in resource["auxiliary"].values() for f in rows]
    result = []
    for family in families:
        rows = [r for split in pools.values() for r in split if r["family_id"] == family["family_id"]]
        result.append({"family_id": family["family_id"], "rows": len(rows),
                       "predicate_sha256": digest(family["fact"].encode()),
                       "label_rationale": family["label_rationale"],
                       "coarse_situation_id": family["coarse_situation_id"],
                       "coarse_situation_description": family["coarse_situation_description"],
                       "secondary": family.get("secondary"),
                       "sample_case_ids": [r["id"] for r in rows if r["metadata"]["variant"] in ("0", "3")],
                       "visibility_values": sorted({r["classification"]["visibility"] for r in rows}),
                       "category_sets": sorted({tuple(r["classification"]["categories"]) for r in rows}),
                       "status": "author_rules_recorded_independent_review_pending"})
    return {"status": "authoring_only_not_independent_admission", "families": result,
            "excluded_ambiguous_concepts": resource["ambiguous_exclusions"],
            "included_ambiguous_rows": 0, "model_predictions_consulted": False}


def prepare(output):
    """Create one immutable release, retaining partial failed attempts for diagnosis."""
    if output.exists():
        raise ValueError("Refusing to overwrite any existing data release or failed attempt.")
    resource_bytes = (ROOT / RESOURCE).read_bytes()
    resource = json.loads(resource_bytes)
    pools = build(resource)
    # Rebuilding before I/O verifies byte determinism without permitting mutation of the release.
    repeat = build(json.loads(resource_bytes))
    if canonical(pools) != canonical(repeat):
        raise ValueError("Frozen resource does not regenerate deterministically.")
    exclusion = exclusion_audit(pools, resource)
    lengths = native_lengths(pools)
    structural = audit(pools, resource)
    review = author_review(resource, pools)
    output.mkdir(parents=True)
    names = {"train": "train", "validation": "validation", "eval": "fresh_eval"}
    files = {}
    for split in SPLITS:
        filename = "fresh-eval.jsonl" if split == "eval" else split + ".jsonl"
        payload = b"".join(canonical(r) for r in pools[split])
        with (output / filename).open("xb") as handle:
            handle.write(payload)
        files[names[split]] = {"path": filename, "sha256": digest(payload), "rows": len(pools[split]),
                               "groups": len({r["group_id"] for r in pools[split]})}
    # The adapter is the actual maintained-loader path into the fitting stream.
    generated = fuzzer_training_examples(output / "train.jsonl", COUNTS["train"], 13102026)
    if (len(generated) != COUNTS["train"] or {training_text_key(r.text) for r in generated}
            != {training_text_key(r["text"]) for r in pools["train"]}):
        raise ValueError("Maintained fuzzer adapter loses TRAIN rows.")
    source_files = {name: digest((ROOT / name).read_bytes()) for name in sorted(set(SOURCE_FILES))}
    proof = {"schema": 1, "structural": structural, "exclusions": exclusion, "native_lengths": lengths,
             "regeneration_byte_equal": True, "fuzzer_adapter_unique_train_rows": len(generated),
             "source_files": source_files, "no_model_inference": True,
             "independent_review_required_before_fit": True}
    for filename, value in (("audit.json", proof), ("author-review.json", review)):
        with (output / filename).open("xb") as handle:
            handle.write(canonical(value))
    manifest = {"schema": 1, "study_id": "privacy_heads_v3_20261013", "resource_id": resource["resource_id"],
                "files": files, "source_files": source_files,
                "audit": {"status": "passed", "proof_path": "audit.json", "sha256": digest(canonical(proof)),
                          "independent_admission": "pending"},
                "author_review": {"path": "author-review.json", "sha256": digest(canonical(review))},
                "label_status": "assistant_provisional", "semantic_layers": [4], "visibility_hints": "empty",
                "training_boundary": "train_only; validation_for_predeclared_selection; fresh_eval_after_all_three_exports_frozen",
                "fresh_eval_feature_cache_before_exports": False, "historical_final_payload_opened": False,
                "fit_data": "unique_originals_only; no stochastic replacement or hidden augmentation",
                "scoring_subgroups": ["category_bearing_disclosures", "all_sensitive_including_mild_S1", "clean_S0"],
                "limitations": ["Assistant-provisional synthetic truth, not independently adjudicated human labels.",
                                "New sealed synthetic short disclosure/control workload; general privacy concepts are shared.",
                                "Scenario/component lineage and split predicates/entities/framing are audited; no universal semantic novelty or indirect/adversarial robustness claim.",
                                "V1 has a different historical training stream; native comparison is not a causal generation experiment."]}
    with (output / "manifest.json").open("xb") as handle:
        handle.write(canonical(manifest))
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = prepare(args.output)
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(1, f"PH3 preparation failed: {type(error).__name__}: {error}\n")
    print(json.dumps({"study_id": manifest["study_id"], "files": manifest["files"],
                      "audit": manifest["audit"], "fit_admission": "pending independent review"}))


if __name__ == "__main__":
    main()
