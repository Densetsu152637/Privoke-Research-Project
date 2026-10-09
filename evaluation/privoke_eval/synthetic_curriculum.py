"""Prepare immutable provisional contextual curricula without reading final data."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import re
from string import Formatter
from typing import Mapping, Sequence

from privoke_contracts.classification import Category, Sensitivity, Visibility
from privoke_model.training_data import training_text_key

VERSION = "contextual_fact_grammar_v1"
LABEL_STATUS = "assistant_provisional"
# Efficient profile: models/generate_baseline.py uses 64 tokens including CLS.
MAX_CONTENT_TOKENS = 63
MAX_WORDS = 45
TOKEN_PATTERN = re.compile(r"[A-Za-z]+(?:'[A-Za-z]+)?|\d+|[^\w\s]", re.UNICODE)
ROLES = ("grammar", "teacher", "evolved")


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def opaque_key(kind: str, value: str) -> str:
    return sha256(f"privoke-external-exclusion-v1\0{kind}\0{value}".encode())


def classification(sensitivity: str, visibility: str, categories: Sequence[str]) -> dict:
    """Validate contextual targets strictly; categories are never inferred from words."""
    if (not isinstance(sensitivity, str) or not isinstance(visibility, str)
            or sensitivity not in Sensitivity.__members__ or visibility not in Visibility.__members__):
        raise ValueError("Unknown sensitivity or visibility.")
    if (not isinstance(categories, (list, tuple))
            or any(not isinstance(name, str) for name in categories)
            or len(set(categories)) != len(categories)):
        raise ValueError("Categories must be a unique list.")
    if any(name not in Category.__members__ for name in categories):
        raise ValueError("Unknown category.")
    return {"sensitivity": sensitivity, "visibility": visibility,
            "categories": [name for name in Category.__members__ if name in categories]}


def validate_resource(resource: Mapping) -> None:
    """Accept only explicit fact templates with preserved provisional provenance."""
    if not isinstance(resource, Mapping):
        raise ValueError("Teacher resource must be an object.")
    if resource.get("schema_version") != 1 or resource.get("label_status") != LABEL_STATUS:
        raise ValueError("Teacher resource requires schema 1 and assistant_provisional labels.")
    if not resource.get("origin") or not resource.get("teacher_model"):
        raise ValueError("Teacher resource needs origin and teacher_model provenance.")
    families = resource.get("families")
    if not isinstance(families, list) or len(families) < 22:
        raise ValueError("At least 22 authored semantic families are required.")
    identifiers = set()
    for family in families:
        if not isinstance(family, dict) or not isinstance(family.get("family_id"), str):
            raise ValueError("Invalid family.")
        if family["family_id"] in identifiers:
            raise ValueError("Duplicate family ID.")
        identifiers.add(family["family_id"])
        classification(family["sensitivity"], family["visibility"], family["categories"])
        classification("S0", family["clean_visibility"], [])
        slots = family.get("values")
        if not isinstance(slots, list) or len(slots) < 4 or any(not isinstance(v, str) or not v for v in slots):
            raise ValueError("Families require four explicit fact values.")
        for field in ("private", "clean", "teacher_private", "teacher_clean"):
            template = family.get(field)
            if not isinstance(template, str) or not template.strip():
                raise ValueError("Missing teacher/fact rendering.")
            fields = [name for _, name, spec, conversion in Formatter().parse(template) if name is not None]
            if fields != ["value"] or any(spec or conversion for _, name, spec, conversion in Formatter().parse(template) if name is not None):
                raise ValueError("Each rendering must preserve exactly one plain value slot.")
            if field.endswith("clean") and "fiction" not in template.lower() and "blank" not in template.lower() and "public" not in template.lower():
                raise ValueError("Clean renderings must state the control's decisive fact.")
    heldout = resource.get("heldout")
    replay = resource.get("replay")
    if not isinstance(heldout, list) or len(heldout) != 16 or not isinstance(replay, list) or len(replay) != 16:
        raise ValueError("Resource requires exactly 16 independent guard and 16 replay anchors.")
    for row in heldout + replay:
        classification(row["sensitivity"], row["visibility"], row["categories"])
        if not isinstance(row.get("text"), str) or not row["text"].strip():
            raise ValueError("Guard and replay texts must be explicit.")


def _row(text: str, target: dict, group: str, role: str, parent: str,
         facts: dict, provenance: Mapping, seed: int, variant: int) -> dict:
    return {"id": f"{group}/{role}/{variant}", "text": text, "classification": target,
            "metadata": {"group_id": group, "family_id": group, "parent_id": parent,
                         "generator": VERSION, "label_status": LABEL_STATUS,
                         "curriculum_role": role, "seed": str(seed),
                         "scenario_facts": canonical_json(facts),
                         "teacher_origin": provenance["origin"],
                         "teacher_model": provenance["teacher_model"],
                         "rubric": "contextual-cascade-rubric_assistant_provisional",
                         "mutation": "fact_preserving"}}


def build_curriculum(resource: Mapping, seed: int = 9102026) -> dict[str, list[dict]]:
    """Assign every authored family to a permanent split before rendering descendants.

    Slots are siblings, not independent semantic families. Seed changes order only,
    never split assignment or targets. No annotation-presence corpus is imported.
    """
    validate_resource(resource)
    pools = {"train": [], "heldout": [], "replay": []}
    for family in resource["families"]:
        group = f"synthetic/train/{family['family_id']}"
        for value_index, value in enumerate(family["values"][:4]):
            for is_private in (False, True):
                key = "private" if is_private else "clean"
                target = classification(family["sensitivity"] if is_private else "S0",
                                        family["visibility"] if is_private else family["clean_visibility"],
                                        family["categories"] if is_private else [])
                facts = {"domain": family["domain"], "disclosure": is_private,
                         "real_subject_asserted": is_private, "fact_value": value,
                         "mentioned_categories": family["categories"],
                         "subject_relationship": family.get("subject_relationship", "self"),
                         "control": "none" if is_private else "fictional_or_generic"}
                variant = value_index * 2 + int(is_private)
                parent = f"{group}/grammar/{variant}"
                for role in ROLES:
                    template = family[key] if role == "grammar" else family[f"teacher_{key}"]
                    text = template.format(value=value)
                    if role == "evolved":
                        # Negation refers to hypothetical status, never negates a diagnosis.
                        prefixes = ("Chat note: ", "Document excerpt: ", "Email summary: ", "Message: ")
                        suffix = " This is not hypothetical." if is_private else " No real person is described."
                        text = prefixes[value_index] + text + suffix
                    pools["train"].append(_row(text, target, group, role,
                                              "" if role == "grammar" else parent,
                                              facts, resource, seed, variant))
    for index, item in enumerate(resource["heldout"]):
        group = f"synthetic/heldout/guard_{index:02d}"
        target = classification(item["sensitivity"], item["visibility"], item["categories"])
        pools["heldout"].append(_row(item["text"], target, group, "grammar", "",
                                    {"domain": item["domain"], "guard_family": True}, resource, seed, 0))
    for index, item in enumerate(resource["replay"]):
        group = f"synthetic/replay/anchor_{index:02d}"
        target = classification(item["sensitivity"], item["visibility"], item["categories"])
        for variant, prefix in enumerate(("", "Note: ", "Please summarize: ", "For reference: ")):
            pools["replay"].append(_row(prefix + item["text"], target, group, "replay",
                                       "" if variant == 0 else f"{group}/replay/0",
                                       {"domain": item["domain"], "historical_anchor": True,
                                        "source": "assistant_review_of_existing_bootstrap_semantics"},
                                       resource, seed, variant))
    rng = random.Random(seed)
    for rows in pools.values():
        rng.shuffle(rows)
    validate_pools(pools)
    return pools


def validate_pools(pools: Mapping[str, Sequence[Mapping]]) -> None:
    """Fail closed on conflicting labels, duplicates, leakage, or hidden fact truncation."""
    seen_ids, seen_texts, group_splits = set(), {}, {}
    for split in ("train", "heldout", "replay"):
        rows = pools[split]
        counts = Counter()
        for row in rows:
            text, metadata, target = row["text"], row["metadata"], row["classification"]
            allowed_roles = ROLES if split == "train" else ("replay",) if split == "replay" else ("grammar",)
            if metadata["curriculum_role"] not in allowed_roles:
                raise ValueError("Unexpected curriculum role for split.")
            validated = classification(target["sensitivity"], target["visibility"], target["categories"])
            if target != validated or metadata["label_status"] != LABEL_STATUS:
                raise ValueError("Invalid target or label provenance.")
            if len(text.split()) > MAX_WORDS or len(TOKEN_PATTERN.findall(training_text_key(text))) > MAX_CONTENT_TOKENS:
                raise ValueError("Prompt exceeds smallest serving token capacity or word limit.")
            if "{" in text or "}" in text:
                raise ValueError("Unrendered template or unsafe direct-text brace.")
            key = training_text_key(text)
            if key in seen_texts:
                if seen_texts[key] != target:
                    raise ValueError("Conflicting labels for normalized duplicate.")
                raise ValueError("Normalized duplicate across or within splits.")
            if row["id"] in seen_ids:
                raise ValueError("Duplicate row ID.")
            group = metadata["group_id"]
            if group in group_splits and group_splits[group] != split:
                raise ValueError("Family crosses permanent split.")
            seen_ids.add(row["id"])
            seen_texts[key] = target
            group_splits[group] = split
            label = "clean" if target["sensitivity"] == "S0" and not target["categories"] else "sensitive"
            counts[(metadata["curriculum_role"], label)] += 1
        roles = ROLES if split == "train" else ("replay",) if split == "replay" else ("grammar",)
        for role in roles:
            if counts[(role, "clean")] == 0 or counts[(role, "clean")] != counts[(role, "sensitive")]:
                raise ValueError("Each role pool must balance both contextual classes.")
    if len(pools["train"]) < 512 or len(pools["heldout"]) != 16 or len(pools["replay"]) < 64:
        raise ValueError("Curriculum pools do not meet training/guard/replay sizes.")
    if len({row["metadata"]["group_id"] for row in pools["heldout"]}) != 16:
        raise ValueError("Guard rows require sixteen distinct families.")


def verify_exclusions(pools: Mapping, index: Mapping, development_rows: Sequence[Mapping] = ()) -> None:
    sets = index.get("all_exclusion_key_sets")
    if index.get("schema_version") != 1 or not isinstance(sets, dict) or set(sets) != {"ids", "groups", "texts"}:
        raise ValueError("Opaque exclusion index lacks protected union key sets.")
    for values in sets.values():
        if not isinstance(values, list) or len(values) != len(set(values)) or any(not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{64}", v) for v in values):
            raise ValueError("Opaque protected keys must be unique SHA256 strings.")
    if index.get("all_exclusion_key_sets_sha256") != sha256(canonical_json(sets).encode()):
        raise ValueError("Opaque protected union digest mismatch.")
    protected = {name: set(values) for name, values in sets.items()}
    dev_texts = {training_text_key(row["text"]) for row in development_rows}
    for rows in pools.values():
        for row in rows:
            key = training_text_key(row["text"])
            if (opaque_key("id", row["id"]) in protected["ids"]
                    or opaque_key("group", row["metadata"]["group_id"]) in protected["groups"]
                    or opaque_key("text_key", key) in protected["texts"] or key in dev_texts):
                raise ValueError("Synthetic row overlaps protected keys or pinned development.")


def reject_final_path(path: Path) -> None:
    """Reject final-named inputs before opening files; never discover corpus paths."""
    if any(re.search(r"(^|[^a-z])final([^a-z]|$)", part.lower()) for part in path.resolve().parts):
        raise ValueError("Final evaluation paths are prohibited.")


def prepare(output: Path, teacher_templates: Path, exclusion_index: Path,
            evaluation_file: Path | None = None, evaluation_sha256: str | None = None,
            seed: int = 9102026) -> dict:
    """Write a fresh immutable pool package after provenance and overlap verification."""
    for path in (output, teacher_templates, exclusion_index):
        reject_final_path(path)
    if output.exists():
        raise ValueError("Output must be a fresh directory.")
    teacher_raw, exclusion_raw = teacher_templates.read_bytes(), exclusion_index.read_bytes()
    resource = json.loads(teacher_raw)
    pools = build_curriculum(resource, seed)
    development_rows = []
    development_hash = None
    if evaluation_file is not None:
        reject_final_path(evaluation_file)
        if "development" not in evaluation_file.name.lower():
            raise ValueError("Evaluation input must be explicitly named development JSONL.")
        if not evaluation_sha256 or not re.fullmatch(r"[0-9a-f]{64}", evaluation_sha256):
            raise ValueError("Pinned development input needs --evaluation-sha256.")
        raw = evaluation_file.read_bytes()
        development_hash = sha256(raw)
        if development_hash != evaluation_sha256:
            raise ValueError("Development digest mismatch.")
        development_rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    elif evaluation_sha256:
        raise ValueError("Development digest requires its evaluation file.")
    verify_exclusions(pools, json.loads(exclusion_raw), development_rows)
    payloads = {name: ("\n".join(canonical_json(row) for row in rows) + "\n").encode()
                for name, rows in pools.items()}
    curriculum_id = sha256(canonical_json({"generator": VERSION, "teacher": sha256(teacher_raw),
                                           "exclusion": sha256(exclusion_raw), "seed": seed,
                                           "pools": {name: sha256(raw) for name, raw in payloads.items()}}).encode())
    splits = {}
    for name, rows in pools.items():
        counts = Counter((row["metadata"]["curriculum_role"], "clean" if row["classification"]["sensitivity"] == "S0" and not row["classification"]["categories"] else "sensitive") for row in rows)
        splits[name] = {"path": f"{name}.jsonl", "sha256": sha256(payloads[name]), "count": len(rows),
                        "family_ids": sorted({r["metadata"]["group_id"] for r in rows}),
                        "counts_by_role_class": {f"{role}/{label}": count for (role, label), count in sorted(counts.items())}}
    manifest = {"schema_version": 1, "curriculum_id": curriculum_id, "generator": VERSION,
                "seed": seed, "splits": splits, "label_status": LABEL_STATUS,
                "teacher_origin": resource["origin"], "teacher_model": resource["teacher_model"],
                "teacher_templates_sha256": sha256(teacher_raw), "exclusion_index_sha256": sha256(exclusion_raw),
                "development_sha256": development_hash, "protected_final_opened": False,
                "max_content_tokens": MAX_CONTENT_TOKENS, "max_words": MAX_WORDS,
                "observed_max_content_tokens": max(len(TOKEN_PATTERN.findall(training_text_key(r["text"]))) for rows in pools.values() for r in rows),
                "normalizer": "shared/python/privoke_model/training_data.py:training_text_key",
                "limitations": ["Assistant provisional labels; no independent human adjudication.",
                                "Offline authored teacher templates; no live external teacher API or invented model identity.",
                                "Lexical descendants are correlated siblings; family counts are distinct from row counts.",
                                "Fixed guard is a publication check, not generalization ground truth."]}
    output.mkdir(parents=True, exist_ok=False)
    for name, payload in payloads.items():
        (output / f"{name}.jsonl").write_bytes(payload)
    (output / "manifest.json").write_text(canonical_json(manifest) + "\n", encoding="utf-8")
    return manifest
