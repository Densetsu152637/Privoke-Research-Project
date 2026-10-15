"""Prospective, family-separated privacy-head fuzzer data; no model access."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import re

from privoke_contracts.classification import Category, Sensitivity, Visibility, initialise_unpacked
from privoke_model.training_data import training_text_key
from training.types import BatchTrainingExample
from .loader import load_prompt_dataset

VERSION = "privacy_heads_fact_contrast_v2"
SPLITS = ("train", "validation", "eval")
COUNTS = {"train": 6240, "validation": 1560, "eval": 1560}
CATEGORIES = tuple(Category.__members__)
AUDIENCES = tuple(Visibility.__members__)
RUBRIC_PATHS = (
    "paper/research/contextual-cascade-rubric.md",
    "evaluation/datasets/synthetic-teacher-templates-v2.json",
    "shared/python/privoke_contracts/classification.py",
    "extension/client-runtime/src/classification/classification_policy.py",
)


def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                       allow_nan=False) + "\n").encode("utf-8")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def target(sensitivity, visibility, categories):
    """Require explicit complete targets; never infer missing labels as clean."""
    if sensitivity not in Sensitivity.__members__ or visibility not in Visibility.__members__:
        raise ValueError("Unknown privacy classification component.")
    if (not isinstance(categories, list) or len(set(categories)) != len(categories)
            or any(c not in CATEGORIES for c in categories)):
        raise ValueError("Categories must be an explicit unique supported list.")
    return initialise_unpacked(Sensitivity[sensitivity], Visibility[visibility],
                              [Category[c] for c in CATEGORIES if c in categories])


def component_skeleton(text, entity_values=()):
    """Canonical asserted facts without personal entity/amount substitutions."""
    value = training_text_key(text)
    for entity in entity_values:
        value = re.sub(rf"\b{re.escape(training_text_key(entity))}\b", "ENTITY", value)
    return re.sub(r"\b\d+\b", "NUMBER", value)


def component_records(resource):
    """Enumerate actual assertion lineage independently of whole narrative rows."""
    result = []
    for family in resource["families"]:
        for component in (family, family["secondary"]):
            result.append({"id": component["component_id"], "split": family["split"],
                           "text": component["fact"], "skeleton": component_skeleton(
                               component["fact"], component.get("entity_values", [])),
                           "coarse_situation_id": component["coarse_situation_id"],
                           "coarse_situation_description": component["coarse_situation_description"]})
    for split, families in resource["auxiliary"].items():
        for family in families:
            result.append({"id": family["component_id"], "split": split, "text": family["fact"],
                           "skeleton": component_skeleton(family["fact"]),
                           "coarse_situation_id": family["coarse_situation_id"],
                           "coarse_situation_description": family["coarse_situation_description"]})
    return result


def audit_components(resource):
    """All shared assertion components and coarser scenario mechanisms stay in one split."""
    ids, literals, normalized, shapes, coarse = set(), {}, {}, {}, {}
    records = component_records(resource)
    for row in records:
        if row["id"] in ids or not row["coarse_situation_description"]:
            raise ValueError("Missing/duplicate assertion component lineage.")
        ids.add(row["id"])
        for value, inventory in ((row["text"], literals), (training_text_key(row["text"]), normalized),
                                 (row["skeleton"], shapes), (row["coarse_situation_id"], coarse)):
            if value in inventory and inventory[value] != row["split"]:
                raise ValueError("Assertion component or coarse situation crosses permanent splits.")
            inventory[value] = row["split"]
    return {"components": len(records), "unique_normalized_components": len(normalized),
            "unique_component_skeletons": len(shapes), "coarse_situation_groups": len(coarse),
            "cross_split_component_or_situation_overlaps": 0}


def validate_resource(resource):
    """Validate permanent allocation and explicit facts before any descendants exist."""
    if (resource.get("schema_version") != 1 or resource.get("generator_version") != VERSION
            or resource.get("label_status") != "assistant_provisional"
            or resource.get("rubric_sources") != list(RUBRIC_PATHS)):
        raise ValueError("Unsupported resource/provenance contract.")
    if set(resource["splits"]) != set(SPLITS) or set(resource["auxiliary"]) != set(SPLITS):
        raise ValueError("All permanent splits are required.")
    seen_ids, predicates, templates, entities = set(), set(), {}, {}
    counts = Counter()
    for split in SPLITS:
        config = resource["splits"][split]
        if (len(config["variants"]) != 4 or len(config["controls"]) != 4
                or set(config["audience"]) != set(AUDIENCES)
                or len(config["entities"]) != 24 or len(set(config["entities"])) != 24):
            raise ValueError("Incomplete split framing/entity allocation.")
        for text in (*config["variants"], *config["controls"], *config["audience"].values()):
            key = training_text_key(text)
            if key in templates and templates[key] != split:
                raise ValueError("Narrative template crosses permanent splits.")
            templates[key] = split
        for value in config["entities"]:
            key = training_text_key(value)
            if key in entities:
                raise ValueError("Entity vocabulary crosses permanent splits.")
            entities[key] = split
        if len(resource["auxiliary"][split]) != (20 if split == "train" else 5):
            raise ValueError("Auxiliary family denominator differs.")
    for family in resource["families"]:
        split, primary = family["split"], family["primary_category"]
        if split not in SPLITS or primary not in CATEGORIES:
            raise ValueError("Unsupported permanent family allocation.")
        target(family["sensitivity"], "PU", family["categories"])
        if primary not in family["categories"] or not family.get("label_rationale"):
            raise ValueError("Family lacks explicit target closure/rationale.")
        if family.get("subject_relationship") == "other_child" and "THIRD_PARTY" not in family["categories"]:
            raise ValueError("Minor disclosure must retain third-party closure.")
        if family.get("asserted_other_health") is True and "HEALTH" not in family["categories"]:
            raise ValueError("Third-party health predicate loses its health category.")
        secondary = family["secondary"]
        target(secondary["sensitivity"], "PU", secondary["categories"])
        if secondary["split"] != split or not secondary.get("label_rationale"):
            raise ValueError("Secondary assertion loses split/target rationale.")
        if secondary.get("subject_relationship") in ("other_child", "other_adult"):
            if "THIRD_PARTY" not in secondary["categories"]:
                raise ValueError("Secondary assertion loses its explicit third-party category.")
        counts[(split, primary)] += 1
    for split in SPLITS:
        for family in [r for r in resource["families"] if r["split"] == split] + resource["auxiliary"][split]:
            identifier = family["family_id"]
            predicate = training_text_key(family["fact"])
            if (not identifier.startswith(f"PH3/{split}/") or identifier in seen_ids
                    or not predicate or predicate in predicates or not family.get("topic")):
                raise ValueError("Duplicate or inconsistent scenario family.")
            if "{" in family["fact"] or "}" in family["fact"]:
                raise ValueError("Fact predicates must be rendered literal assertions.")
            seen_ids.add(identifier)
            predicates.add(predicate)
        if any(counts[(split, c)] != (12 if split == "train" else 3) for c in CATEGORIES):
            raise ValueError("Per-category family quotas differ.")
    exclusions = resource.get("ambiguous_exclusions")
    if not isinstance(exclusions, list) or not exclusions or any(not r.get("reason") for r in exclusions):
        raise ValueError("Predeclared ambiguity exclusions are required.")
    audit_components(resource)


def _row(resource, family, split, visibility, variant, actual, auxiliary=False):
    config = resource["splits"][split]
    entity = config["entities"][AUDIENCES.index(visibility) * 4 + variant]
    categories = list(family.get("categories", [])) if actual else []
    severity = ("S1" if auxiliary else family["sensitivity"]) if actual else "S0"
    fact = family["fact"]
    additional_rationale = ""
    family_slot = int(family["family_id"].rsplit("/", 1)[1])
    multilabel_slot = (variant + AUDIENCES.index(visibility) + family_slot) % 4 >= 2
    if actual and not auxiliary and multilabel_slot:
        secondary = family["secondary"]
        fact += "; " + secondary["fact"]
        categories = list(set(categories) | set(secondary["categories"]))
        severity = max((severity, secondary["sensitivity"]), key=lambda s: Sensitivity[s].value)
        additional_rationale = secondary["label_rationale"]
    classification = target(severity, visibility, categories)
    template = config["variants"][variant] if actual else config["controls"][variant]
    body = template.format(fact=fact, topic=family["topic"])
    audience = config["audience"][visibility].format(entity=entity)
    text = f"{body} {audience}"
    identifier = f"{family['family_id']}/{visibility}/{variant}/{int(actual)}"
    control = "mild_personal" if actual and auxiliary else "actual_disclosure" if actual else (
        "generic_instruction", "unfilled_form", "invented_scene", "absent_record")[variant]
    # Labels operationalize the existing disclosure rubric, not topic annotation presence.
    allowed = ["ALLOW"] if severity in ("S0", "S1") else ["WARN", "BLOCK"]
    return {
        "id": identifier, "case_id": identifier, "group_id": family["family_id"],
        "family_id": family["family_id"], "text": text,
        "partition": "fresh_eval" if split == "eval" else split,
        "classification": classification.to_dict(), "packed_classification": classification.pack(),
        "packed": classification.pack(),
        "required_sensitive": classification.is_sensitive(), "allowed_actions": allowed,
        "expected_action": allowed[0] if len(allowed) == 1 else None,
        "minimum_action": allowed[0], "ambiguous": False, "context_truth_eligible": True,
        "action_accuracy_eligible": True, "label_status": resource["label_status"],
        "metadata": {
            "example_id": identifier, "group_id": family["family_id"],
            "family_id": family["family_id"], "parent_id": family["family_id"],
            "split": split, "primary_category": family.get("primary_category", "NONE"),
            "training_role": "authored_privacy_fact_contrast", "control": control,
            "generator": VERSION, "generation_seed": "13102026", "variant": str(variant),
            "label_status": resource["label_status"], "entity_pool_id": f"PH3/{split}/audience_titles",
            "entity_value": entity, "template_id": f"PH3/{split}/variant/{variant}/{int(actual)}",
            "sensitivity_rationale": resource["rubric"][severity],
            "visibility_evidence": audience,
            "visibility_rationale": resource["rubric"]["visibility"],
            "category_rationale": (family["label_rationale"] + " " + additional_rationale).strip()
                if actual else "No actual personal disclosure is asserted; domain mention alone is not disclosure.",
            "control_rationale": "Explicitly asserted actual personal fact." if actual
                else "The text explicitly removes actual personal records, persons or completed details.",
            "scenario_predicate": family["fact"], "auxiliary": str(auxiliary).lower(),
            "subject_relationship": family.get("subject_relationship", "self"),
            "component_ids": json.dumps([family["component_id"]] +
                ([family["secondary"]["component_id"]] if actual and not auxiliary and multilabel_slot else [])),
            "asserted_component_ids": json.dumps(([family["component_id"]] +
                ([family["secondary"]["component_id"]] if not auxiliary and multilabel_slot else [])) if actual else []),
            "coarse_situation_id": family["coarse_situation_id"],
            "coarse_situation_description": family["coarse_situation_description"],
            "template_group_id": family["template_group_id"],
            "source_resource": resource["resource_id"],
        },
    }


def build(resource):
    """Generate unique original rows in fixed source order, with no replacement."""
    validate_resource(resource)
    pools = {split: [] for split in SPLITS}
    for family in resource["families"]:
        split = family["split"]
        for visibility in AUDIENCES:
            for variant in range(4):
                pools[split].extend(_row(resource, family, split, visibility, variant, actual)
                                    for actual in (False, True))
    for split in SPLITS:
        for family in resource["auxiliary"][split]:
            for visibility in AUDIENCES:
                for variant in range(4):
                    pools[split].append(_row(resource, family, split, visibility, variant,
                                             variant < 3, auxiliary=True))
    audit(pools, resource)
    return pools


def skeleton(text, entity):
    """Remove split entity values and numbers; retaining facts prevents entity-only novelty."""
    value = re.sub(rf"\b{re.escape(entity.lower())}\b", "ENTITY", training_text_key(text))
    return re.sub(r"\b\d+\b", "NUMBER", value)


def audit(pools, resource):
    """Fail closed on conflicting targets, duplicate rows, and family leakage."""
    validate_resource(resource)
    ids, texts, skeletons, groups, parent_splits = set(), set(), {}, {}, {}
    summary = {}
    family_map = {f["family_id"]: f for f in resource["families"]}
    family_map.update({f["family_id"]: f for families in resource["auxiliary"].values() for f in families})
    for split in SPLITS:
        rows = pools[split]
        if len(rows) != COUNTS[split]:
            raise ValueError("Unique original row budget differs.")
        counts = {name: Counter() for name in ("sensitivity", "visibility", "categories", "control", "cardinality")}
        for row in rows:
            value = row.get("classification")
            if not isinstance(value, dict) or set(value) != {"sensitivity", "visibility", "categories"}:
                raise ValueError("Every row needs an explicit complete target.")
            expected = target(**value)
            if expected.to_dict() != value or row.get("packed_classification") != expected.pack():
                raise ValueError("Named and packed target differ.")
            meta = row["metadata"]
            if meta["split"] != split or row["group_id"] != meta["group_id"]:
                raise ValueError("Row partition/group disagrees with lineage.")
            family = family_map.get(row["family_id"])
            if family is None:
                raise ValueError("Row has no admitted scenario parent.")
            auxiliary = meta["auxiliary"] == "true"
            variant = int(meta["variant"])
            actual = meta["control"] in ("mild_personal", "actual_disclosure")
            if row != _row(resource, family, split, value["visibility"], variant, actual, auxiliary):
                raise ValueError("Actual row differs from declared fact-preserving rendering.")
            if row.get("visibility_hint") or not row.get("context_truth_eligible") or row.get("ambiguous"):
                raise ValueError("Primary admission cannot add hints or ambiguous truth.")
            key = training_text_key(row["text"])
            if not key or key in texts or row["id"] in ids or "{" in row["text"] or "}" in row["text"]:
                raise ValueError("Empty, duplicate or unrendered row.")
            for identity, inventory in ((row["family_id"], groups), (meta["parent_id"], parent_splits)):
                if identity in inventory and inventory[identity] != split:
                    raise ValueError("Scenario lineage crosses permanent splits.")
                inventory[identity] = split
            shaped = skeleton(row["text"], meta["entity_value"])
            if shaped in skeletons and skeletons[shaped] != split:
                raise ValueError("Entity/number-only template crosses splits.")
            skeletons[shaped] = split
            ids.add(row["id"])
            texts.add(key)
            counts["sensitivity"][value["sensitivity"]] += 1
            counts["visibility"][value["visibility"]] += 1
            counts["categories"].update(value["categories"])
            counts["cardinality"][str(len(value["categories"]))] += 1
            counts["control"][meta["control"]] += 1
        expected_auxiliary = 360 if split == "train" else 90
        if counts["sensitivity"]["S1"] != expected_auxiliary:
            raise ValueError("Mild-personal supervision quota differs.")
        if any(counts["visibility"][v] != COUNTS[split] // 6 for v in AUDIENCES):
            raise ValueError("Meaningful visibility strata must remain balanced.")
        if any(counts["categories"][c] == 0 for c in CATEGORIES):
            raise ValueError("Every category requires positive examples.")
        combinations = {tuple(r["classification"]["categories"]) for r in rows if r["classification"]["categories"]}
        if len(combinations) < 15:
            raise ValueError("Insufficient valid full category-set combinations.")
        summary[split] = {"rows": len(rows), "families": len({r["family_id"] for r in rows}),
                          "category_set_combinations": len(combinations),
                          **{k: dict(v) for k, v in counts.items()}}
    return summary


def fuzzer_training_examples(dataset_path, count, seed):
    """Read only the released TRAIN JSONL via maintained PromptSeed loader."""
    payload = Path(dataset_path).read_bytes()
    rows = [json.loads(line) for line in payload.decode("utf-8").splitlines() if line.strip()]
    for row in rows:
        value = row.get("classification")
        if not isinstance(value, dict) or set(value) != {"sensitivity", "visibility", "categories"}:
            raise ValueError("TRAIN fitting requires explicit complete named targets before PromptSeed loading.")
        expected = target(**value)
        if (expected.to_dict() != value or row.get("packed") != expected.pack()
                or row.get("packed_classification") != expected.pack()):
            raise ValueError("TRAIN fitting named/packed classification mismatch.")
    seeds = load_prompt_dataset(Path(dataset_path))
    if any(r.metadata.get("split") != "train" for r in seeds):
        raise ValueError("Fuzzer fitting accepts only the permanent TRAIN release.")
    if type(count) is not int or count <= 0 or count > len(seeds):
        raise ValueError("Requested unique rows exhaust the admitted TRAIN pool.")
    keys = [training_text_key(r.template) for r in seeds]
    if len(keys) != len(set(keys)):
        raise ValueError("TRAIN release contains duplicate texts.")
    rng = random.Random(seed)  # nosec B311 -- reproducible research order
    rng.shuffle(seeds)
    return [BatchTrainingExample(r.template, r.classification, metadata=dict(r.metadata))
            for r in seeds[:count]]
