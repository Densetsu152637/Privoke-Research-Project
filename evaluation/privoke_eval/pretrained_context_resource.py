"""Fixed provisional disclosure families and deterministic, split-aware rendering."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re

from host_environment import configure_imports

configure_imports()
from privoke_contracts.classification import Category
from privoke_model.training_data import training_text_key
from .synthetic_curriculum import classification, canonical_json, sha256, verify_exclusions

CONVENTION = "asserted_personal_disclosure_v1"
SPLITS = ("train", "validation", "assessment")
VISIBILITIES = ("P0", "P1", "P2", "P3", "P4", "PU")


def span(text, evidence):
    start = text.find(evidence)
    if not evidence or start < 0 or text.find(evidence, start + 1) >= 0:
        raise ValueError("Evidence must occur exactly once in rendered text.")
    return [start, start + len(evidence)]


def validate_resource(resource):
    if (resource.get("schema_version") != 1 or resource.get("target_convention") != CONVENTION
            or resource.get("label_status") != "assistant_provisional"
            or resource.get("origin") != "offline assistant authored synthetic scenarios"):
        raise ValueError("Unsupported resource provenance or target convention.")
    families = resource.get("families", [])
    if len(families) != 60 or len({f["family_id"] for f in families}) != 60:
        raise ValueError("Exactly sixty distinct authored families required.")
    counts = Counter((f["primary_category"], f["split"]) for f in families)
    if counts != Counter({(category, split): count for category in Category.__members__
                          for split, count in zip(SPLITS, (4, 1, 1))}):
        raise ValueError("Each sampling stratum needs four/one/one families.")
    banks = resource["frames"]
    for split in SPLITS:
        if set(banks[split]) != {*VISIBILITIES, "fiction", "mixed", "hypothetical"}:
            raise ValueError("Incomplete split-specific framing bank.")
        for template in banks[split].values():
            if template.count("{fact}") != 1:
                raise ValueError("Frames require exactly one fact slot.")
    all_frames = [frame for bank in banks.values() for frame in bank.values()]
    if len(all_frames) != len(set(all_frames)):
        raise ValueError("Framing templates must be split-specific.")
    inventories = {}
    for family in families:
        categories = family["categories"]
        validated = classification(family["sensitivity"], "PU", categories)
        if categories != validated["categories"] or family["primary_category"] not in categories:
            raise ValueError("Full reviewed categories must be canonical and include their sampling stratum.")
        if family["sensitivity"] != ("S2" if family["primary_category"] in
                                       {"FINANCIAL", "LOCATION", "THIRD_PARTY"} else "S3"):
            raise ValueError("Unexpected authored severity convention.")
        if set(family["category_rationales"]) != set(categories):
            raise ValueError("Every included category needs an explicit rationale.")
        for key in ("fact", "mild_fact", "sensitivity_rationale", "mild_rationale"):
            if not isinstance(family.get(key), str) or not family[key].strip():
                raise ValueError("Missing authored fact or rationale.")
        for term in family["entity_inventory"]:
            if not term or term not in family["fact"]:
                raise ValueError("Entity inventory must cite an authored value.")
            if term in inventories and inventories[term] != family["split"]:
                raise ValueError("Entity value inventory crosses splits.")
            inventories[term] = family["split"]


def render(resource):
    validate_resource(resource)
    pools = {split: [] for split in SPLITS}
    for family in resource["families"]:
        bank = resource["frames"][family["split"]]
        for slot in range(16):
            visibility = VISIBILITIES[slot % 6] if slot < 12 else ("P4" if slot == 13 else "P1" if slot == 15 else "PU")
            mild, fictional = slot >= 14, 6 <= slot < 12
            fact = family["mild_fact"] if mild else family["fact"]
            inner = bank["fiction"].format(fact=fact) if fictional else fact
            if slot == 12:
                inner = bank["mixed"].format(fact=fact)
            elif slot == 13:
                inner = bank["hypothetical"].format(fact=fact)
            text = bank[visibility].format(fact=inner)
            target = classification("S1" if mild else "S0" if fictional else family["sensitivity"],
                                    visibility, [] if mild or fictional else family["categories"])
            fact_span = span(text, fact)
            # Frames put audience information before the fact, preserving exact spans.
            prefix = bank[visibility].split("{fact}")[0].strip()
            visibility_evidence = prefix if prefix else fact
            categories = {category: {"rationale": rationale, "span": fact_span}
                          for category, rationale in family["category_rationales"].items()
                          if category in target["categories"]}
            rationale = (family["mild_rationale"] if mild else
                         "The entire attributed fact is explicitly invented; no actual personal disclosure is asserted."
                         if fictional else family["sensitivity_rationale"])
            sensitivity_span = span(text, inner) if fictional or slot in (12, 13) else fact_span
            group = "contextual-head-20261010/" + family["family_id"]
            pools[family["split"]].append({"id": f"{group}/{slot:02d}", "text": text,
                "classification": target, "allowed_actions": ["BLOCK" if target["sensitivity"] == "S3" else
                    "WARN" if target["sensitivity"] == "S2" else "ALLOW"],
                "metadata": {"group_id": group, "family_id": family["family_id"],
                    "split": family["split"], "slot": slot, "primary_category": family["primary_category"],
                    "label_status": resource["label_status"], "target_convention": CONVENTION,
                    "control": "mild" if mild else "fiction" if fictional else "mixed" if slot == 12 else
                        "hypothetical_real_premise" if slot == 13 else "actual",
                    "annotations": {"sensitivity": {"rationale": rationale, "span": sensitivity_span},
                        "visibility": {"rationale": resource["visibility_rationales"][visibility],
                                       "span": span(text, visibility_evidence)},
                        "categories": categories,
                        "category_set_rationale": "Only asserted personal facts receive category labels; fiction and mild context have no supported category."}}})
    validate_rows(pools)
    return pools


def validate_rows(pools):
    if {split: len(rows) for split, rows in pools.items()} != {"train": 640, "validation": 160, "assessment": 160}:
        raise ValueError("Unexpected split sizes.")
    seen_ids, seen_texts, families = set(), set(), {}
    for split, rows in pools.items():
        for row in rows:
            meta, target = row["metadata"], row["classification"]
            key = training_text_key(row["text"])
            if row["id"] in seen_ids or key in seen_texts:
                raise ValueError("Duplicate ID or normalized text.")
            group = meta["group_id"]
            if group in families and families[group] != split:
                raise ValueError("Family crosses splits.")
            if target != classification(target["sensitivity"], target["visibility"], target["categories"]):
                raise ValueError("Noncanonical target.")
            if set(meta["annotations"]["categories"]) != set(target["categories"]):
                raise ValueError("Incomplete category evidence.")
            for annotation in [meta["annotations"]["sensitivity"], meta["annotations"]["visibility"],
                               *meta["annotations"]["categories"].values()]:
                lo, hi = annotation["span"]
                if not 0 <= lo < hi <= len(row["text"]) or not annotation["rationale"]:
                    raise ValueError("Invalid evidence span or rationale.")
            if re.search(r"\{[^}]+\}", row["text"]):
                raise ValueError("Unrendered slot.")
            seen_ids.add(row["id"]); seen_texts.add(key); families[group] = split


def inventory(pools):
    result = {}
    for split, rows in pools.items():
        targets = [row["classification"] for row in rows]
        result[split] = {"rows": len(rows), "families": len({r["metadata"]["family_id"] for r in rows}),
            "sensitivity": dict(Counter(t["sensitivity"] for t in targets)),
            "visibility": dict(Counter(t["visibility"] for t in targets)),
            "category_support": dict(Counter(c for t in targets for c in t["categories"])),
            "category_cardinality": dict(Counter(str(len(t["categories"])) for t in targets)),
            "keys_sha256": sha256(canonical_json(sorted(training_text_key(r["text"]) for r in rows)).encode())}
    return result


def check_exclusions(pools, index, prior_rows):
    verify_exclusions(pools, index, prior_rows)
    ids = {r["id"] for r in prior_rows if "id" in r}
    groups = {r.get("group_id", r.get("metadata", {}).get("group_id")) for r in prior_rows}
    for rows in pools.values():
        if any(r["id"] in ids or r["metadata"]["group_id"] in groups for r in rows):
            raise ValueError("Prior public ID/group overlap.")
