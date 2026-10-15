"""Versioned TRAIN-only taxonomy exposure; no model-quality claim is implied."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import random

from privoke_contracts.classification import Category, Sensitivity, Visibility, initialise_unpacked
from privoke_model.training_data import training_text_key
from training.types import BatchTrainingExample
from training.transforms import synthetic_common_name

STRATEGY = "taxonomy_coverage_v1"
SOURCE_SHA256 = "ceeb394020f6c5de6e1d6d4737c7c7c6d3b6eae8122391660b9986325a3f7ece"
RENDERER_SHA256 = "ee2c6310a759ea5162bd2cd8a46518f883b3bf2cf8dc825071411d9deed2d62e"
PARTITION_RECIPE = "sort_four_family_ids_per_primary_category_first_two_train_last_two_guard_v1"
AUDIENCES = {
    "HEALTH": ("P0", "P3"), "POLITICS": ("P0", "P4"),
    "RELIGION": ("P1", "P3"), "CRIMINAL": ("P2", "P4"),
    "FINANCIAL": ("P0", "P3"), "SEXUAL": ("P0", "P4"),
    "CHILD": ("P1", "P3"), "LOCATION": ("P2", "P4"),
    "IDENTITY": ("P2", "PU"), "THIRD_PARTY": ("P2", "PU"),
}
CLEAN_AUDIENCES = ("P0", "P1", "P2", "P3", "P4", "PU", "P0", "PU")
MILD_AUDIENCES = ("P1", "P1", "PU", "PU")
SENSITIVITY_COUNTS = {"S0": 8, "S1": 4, "S2": 6, "S3": 14}
CATEGORY_MINIMUMS = {name: 2 for name in AUDIENCES}
# These distinct category/family slots also preserve the eight-clean/eight-sensitive alternation.
GUARD_POSITIVE_SLOTS = (
    ("POLITICS", "mild", "P1"), ("RELIGION", "mild", "PU"),
    ("FINANCIAL", "actual", "P0"), ("LOCATION", "actual", "P2"),
    ("HEALTH", "actual", "P3"), ("SEXUAL", "actual", "P4"),
    ("CHILD", "actual", "P0"), ("IDENTITY", "actual", "PU"),
)


def canonical_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                       allow_nan=False) + "\n").encode("utf-8")


def policy_contract():
    """Everything changing selection or execution participates in replay identity."""
    return {"strategy": STRATEGY, "partition_recipe": PARTITION_RECIPE,
            "audiences": AUDIENCES, "clean_audiences": CLEAN_AUDIENCES,
            "mild_audiences": MILD_AUDIENCES, "sensitivity_counts": SENSITIVITY_COUNTS,
            "category_minimums": CATEGORY_MINIMUMS, "guard_positive_slots": GUARD_POSITIVE_SLOTS,
            "category_closure": "preserve_actual_source_full_sets_third_party_4_or_6_v1",
            "originals": 32, "guard": 16, "transforms": 1,
            "semantic_execution_contract": "explicit_semantic_only_success_training_base_candidate_v1"}


@dataclass(frozen=True)
class TaxonomyDataset:
    sha256: str
    rows: tuple[BatchTrainingExample, ...]
    partitions: dict[str, str]
    exclusion_validation: dict = field(default_factory=dict)


def transform_variants(text):
    return (text, f"Please review this prompt: {text}", synthetic_common_name(text))


def prepare_release(source_bytes, renderer_bytes, exclusion_validation):
    """Export only the already rendered, byte-pinned historical TRAIN split."""
    if hashlib.sha256(source_bytes).hexdigest() != SOURCE_SHA256:
        raise ValueError("Taxonomy preparation requires the pinned historical TRAIN bytes.")
    if hashlib.sha256(renderer_bytes).hexdigest() != RENDERER_SHA256:
        raise ValueError("Taxonomy preparation requires the reviewed renderer bytes.")
    rows = [json.loads(line) for line in source_bytes.decode("utf-8").splitlines() if line.strip()]
    families = {}
    for row in rows:
        meta = row["metadata"]
        if meta.get("split") != "train":
            raise ValueError("Taxonomy preparation accepts TRAIN membership only.")
        families.setdefault(meta["primary_category"], set()).add(meta["group_id"])
    if set(families) != set(AUDIENCES) or any(len(groups) != 4 for groups in families.values()):
        raise ValueError("Taxonomy release requires four families per primary category.")
    partitions = {group: "train" if index < 2 else "guard"
                  for groups in families.values() for index, group in enumerate(sorted(groups))}
    for row in rows:
        row["packed_classification"] = int(_target(row["classification"]).pack())
        row["metadata"]["taxonomy_partition"] = partitions[row["metadata"]["group_id"]]
    release = {"schema_version": 1, "strategy": STRATEGY,
               "policy": json.loads(canonical_bytes(policy_contract())), "rows": rows,
               "provenance": {"source_sha256": SOURCE_SHA256, "renderer_sha256": RENDERER_SHA256,
                   "source_split": "historical_train", "label_status": "assistant_provisional",
                   "partition_recipe": PARTITION_RECIPE, "fit_release": False,
                   "exclusion_validation": exclusion_validation}}
    payload = canonical_bytes(release)
    load_snapshot(payload)
    return payload


def _target(value):
    if not isinstance(value, dict) or set(value) != {"sensitivity", "visibility", "categories"}:
        raise ValueError("Taxonomy rows require explicit canonical classification components.")
    sensitivity, visibility, categories = value["sensitivity"], value["visibility"], value["categories"]
    if (type(sensitivity) is not str or sensitivity not in Sensitivity.__members__
            or type(visibility) is not str or visibility not in Visibility.__members__
            or not isinstance(categories, list) or any(type(c) is not str or c not in Category.__members__ for c in categories)
            or len(categories) != len(set(categories))):
        raise ValueError("Taxonomy rows contain unsupported or duplicate classification labels.")
    result = initialise_unpacked(Sensitivity[sensitivity], Visibility[visibility], [Category[c] for c in categories])
    if result.to_dict() != value:
        raise ValueError("Taxonomy classification categories must use canonical enum order.")
    return result


def load_dataset(path):
    if not path:
        raise ValueError("Taxonomy coverage requires an explicit prepared dataset path.")
    return load_snapshot(Path(path).read_bytes())


def load_snapshot(payload):
    """Parse exactly the bytes whose digest is used before durable lookup."""
    release = json.loads(payload)
    if (not isinstance(release, dict) or release.get("schema_version") != 1 or release.get("strategy") != STRATEGY
            or release.get("policy") != json.loads(canonical_bytes(policy_contract()))):
        raise ValueError("Unsupported taxonomy release or policy plan.")
    provenance = release.get("provenance", {})
    if (provenance.get("source_sha256") != SOURCE_SHA256 or provenance.get("renderer_sha256") != RENDERER_SHA256
            or provenance.get("source_split") != "historical_train"
            or provenance.get("label_status") != "assistant_provisional"
            or provenance.get("partition_recipe") != PARTITION_RECIPE):
        raise ValueError("Unsupported taxonomy TRAIN provenance.")
    validation = provenance.get("exclusion_validation", {})
    if validation.get("status") != "passed" or validation.get("all_transform_variants") is not True:
        raise ValueError("Taxonomy release requires completed exclusion validation.")
    rows, ids, texts, families = [], set(), set(), {}
    for raw in release.get("rows", []):
        if not isinstance(raw, dict):
            raise ValueError("Taxonomy rows must be objects.")
        target = _target(raw.get("classification"))
        if type(raw.get("packed_classification")) is not int or raw["packed_classification"] != int(target.pack()):
            raise ValueError("Taxonomy named and packed targets disagree.")
        meta = raw.get("metadata", {})
        if not isinstance(meta, dict):
            raise ValueError("Taxonomy rows require metadata objects.")
        group, category, partition = meta.get("group_id"), meta.get("primary_category"), meta.get("taxonomy_partition")
        if (type(group) is not str or not group.strip() or category not in AUDIENCES
                or partition not in ("train", "guard") or meta.get("split") != "train"
                or meta.get("label_status") != "assistant_provisional"
                or meta.get("target_convention") != "asserted_personal_disclosure_v1"):
            raise ValueError("Taxonomy rows require declared TRAIN source groups and partitions.")
        if group in families and families[group] != (category, partition):
            raise ValueError("Taxonomy family crosses category or permanent partition.")
        families[group] = category, partition
        text, identity = raw.get("text"), raw.get("id")
        if type(text) is not str or not training_text_key(text) or type(identity) is not str or not identity:
            raise ValueError("Taxonomy rows require explicit nonempty text and IDs.")
        if identity in ids or training_text_key(text) in texts:
            raise ValueError("Taxonomy release contains duplicate IDs or normalized texts.")
        ids.add(identity); texts.add(training_text_key(text))
        control = meta.get("control")
        annotations = meta.get("annotations", {})
        if (control not in ("actual", "fiction", "mild", "mixed", "hypothetical_real_premise")
                or not isinstance(annotations, dict) or not isinstance(annotations.get("categories"), dict)
                or set(annotations["categories"]) != set(raw["classification"]["categories"])):
            raise ValueError("Taxonomy rows require complete source category evidence and supported controls.")
        severity = "S2" if category in ("FINANCIAL", "LOCATION", "THIRD_PARTY") else "S3"
        if (target.sensitivity().name != ("S0" if control == "fiction" else "S1" if control == "mild" else severity)
                or (control in ("fiction", "mild") and target.categories())
                or (control not in ("fiction", "mild") and category not in raw["classification"]["categories"])):
            raise ValueError("Taxonomy source targets violate the reviewed disclosure convention.")
        metadata = {str(k): v if isinstance(v, str) else json.dumps(v, sort_keys=True) for k, v in meta.items()}
        metadata.update(taxonomy_strategy=STRATEGY, taxonomy_row_id=identity)
        rows.append(BatchTrainingExample(text, target, metadata=metadata))
    if len(rows) != 640 or len(families) != 40:
        raise ValueError("Taxonomy release requires 640 rows from forty complete TRAIN families.")
    for category in AUDIENCES:
        groups = sorted(group for group, (c, _) in families.items() if c == category)
        if len(groups) != 4 or [families[g][1] for g in groups] != ["train", "train", "guard", "guard"]:
            raise ValueError("Taxonomy family partition differs from the permanent recipe.")
    dataset = TaxonomyDataset(hashlib.sha256(payload).hexdigest(), tuple(rows), {g: p for g, (_, p) in families.items()}, validation)
    # Every family must support each required control/audience before any reservation.
    for group in families:
        if len([r for r in rows if r.metadata["group_id"] == group]) != 16:
            raise ValueError("Taxonomy release requires sixteen rows per complete family.")
        for control, audiences in (("actual", Visibility.__members__), ("fiction", Visibility.__members__),
                                   ("mild", ("P1", "PU"))):
            for audience in audiences:
                _row(dataset, group, control, audience)
    return dataset


def _row(dataset, group, control, audience):
    matches = [r for r in dataset.rows if r.metadata["group_id"] == group and r.metadata.get("control") == control
               and r.expected_classification.visibility().name == audience]
    if len(matches) != 1:
        raise ValueError("Taxonomy family cannot supply a unique required control/audience slot.")
    return matches[0]


def generate_partition(dataset, seed):
    rng = random.Random(seed)  # nosec B311
    selected, heldout = [], []
    chosen = {}
    for category, audiences in AUDIENCES.items():
        groups = sorted({r.metadata["group_id"] for r in dataset.rows
                         if r.metadata["primary_category"] == category and r.metadata["taxonomy_partition"] == "train"})
        group = rng.choice(groups)
        chosen[category] = group
        selected.extend(_row(dataset, group, "actual", audience) for audience in audiences)
    selected.extend(_row(dataset, chosen[c], "fiction", v) for c, v in zip(AUDIENCES, CLEAN_AUDIENCES))
    selected.extend(_row(dataset, chosen[c], "mild", v) for c, v in zip(AUDIENCES, MILD_AUDIENCES))
    guard_groups = {c: sorted({r.metadata["group_id"] for r in dataset.rows
                              if r.metadata["primary_category"] == c and r.metadata["taxonomy_partition"] == "guard"})
                    for c in AUDIENCES}
    for groups in guard_groups.values():
        rng.shuffle(groups)
    used = set()
    for (clean_category, clean_audience), (category, control, audience) in zip(
            zip(AUDIENCES, CLEAN_AUDIENCES), GUARD_POSITIVE_SLOTS):
        group = guard_groups[clean_category][0]
        used.add(group)
        heldout.append(_row(dataset, group, "fiction", clean_audience))
        # Prefer the second family, so later clean slots cannot collide.
        group = guard_groups[category][1]
        if group in used:
            raise ValueError("Taxonomy guard source groups collide.")
        used.add(group)
        heldout.append(_row(dataset, group, control, audience))
    rng.shuffle(selected)
    training = [BatchTrainingExample(r.text, r.expected_classification, r.weight,
                {**r.metadata, "generation_seed": str(seed), "generation_index": str(i)}) for i, r in enumerate(selected)]
    audit_originals(dataset, training, heldout)
    return training, heldout


def _counts(rows):
    return (Counter(r.expected_classification.sensitivity().name for r in rows),
            Counter(r.expected_classification.visibility().name for r in rows if r.expected_classification.is_sensitive()),
            Counter(c.name for r in rows for c in r.expected_classification.categories()))


def _digest(values):
    return hashlib.sha256(canonical_bytes(sorted(values))).hexdigest()


def audit_originals(dataset, training, heldout):
    sensitivity, visibility, categories = _counts(training)
    groups = {r.metadata.get("group_id") for r in training}
    guard_groups = {r.metadata.get("group_id") for r in heldout}
    if (len(training) != 32 or len({training_text_key(r.text) for r in training}) != 32 or len(groups) != 10
            or sensitivity != SENSITIVITY_COUNTS or visibility != {v: 4 for v in Visibility.__members__}
            or any(categories[c] < n for c, n in CATEGORY_MINIMUMS.items())):
        raise ValueError("Actual taxonomy training selection does not satisfy the fixed quotas.")
    if (len(heldout) != 16 or len(guard_groups) != 16 or groups & guard_groups
            or any(dataset.partitions.get(g) != "train" for g in groups)
            or any(dataset.partitions.get(g) != "guard" for g in guard_groups)
            or _counts(heldout)[0] != {"S0": 8, "S1": 2, "S2": 2, "S3": 4}
            or set(_counts(heldout)[1]) != set(Visibility.__members__)
            or [r.expected_classification.is_sensitive() for r in heldout] != [False, True] * 8):
        raise ValueError("Actual taxonomy guard violates its fixed quotas or permanent source partition.")
    guard_texts = {training_text_key(r.text) for r in heldout}
    if len(guard_texts) != 16 or guard_texts & {training_text_key(v) for r in training for v in transform_variants(r.text)}:
        raise ValueError("Taxonomy guard overlaps a possible transformed training text.")
    source = {r.metadata["taxonomy_row_id"]: r for r in dataset.rows}
    for row in (*training, *heldout):
        original = source.get(row.metadata.get("taxonomy_row_id"))
        if (original is None or row.text != original.text or row.expected_packed_classification != original.expected_packed_classification
                or row.weight != 1.0 or any(row.metadata.get(k) != original.metadata.get(k)
                                          for k in ("group_id", "taxonomy_partition", "primary_category", "control"))):
            raise ValueError("Taxonomy row differs from its snapshotted source target or provenance.")
    selected_groups = {}
    for row in training:
        category = row.metadata["primary_category"]
        if selected_groups.setdefault(category, row.metadata["group_id"]) != row.metadata["group_id"]:
            raise ValueError("Taxonomy selection must use one TRAIN family per primary category.")
    if set(selected_groups) != set(AUDIENCES):
        raise ValueError("Taxonomy selection omits a primary category family.")
    expected = [_row(dataset, selected_groups[c], "actual", v) for c, vs in AUDIENCES.items() for v in vs]
    expected.extend(_row(dataset, selected_groups[c], "fiction", v) for c, v in zip(AUDIENCES, CLEAN_AUDIENCES))
    expected.extend(_row(dataset, selected_groups[c], "mild", v) for c, v in zip(AUDIENCES, MILD_AUDIENCES))
    if Counter(r.metadata["taxonomy_row_id"] for r in training) != Counter(r.metadata["taxonomy_row_id"] for r in expected):
        raise ValueError("Actual taxonomy selection differs from the fixed source/audience slot plan.")
    return {"contextual_sampling_strategy": STRATEGY, "taxonomy_dataset_sha256": dataset.sha256,
            "sampling_training_rows": "32", "sampling_training_unique_texts": "32", "sampling_training_groups": "10",
            "sampling_guard_rows": "16", "sampling_guard_groups": "16",
            "sampling_sensitivity_counts": json.dumps(dict(sensitivity), sort_keys=True),
            "sampling_sensitive_visibility_counts": json.dumps(dict(visibility), sort_keys=True),
            "sampling_category_counts": json.dumps(dict(categories), sort_keys=True),
            "sampling_training_ids_sha256": _digest(r.metadata["taxonomy_row_id"] for r in training),
            "sampling_training_groups_sha256": _digest(groups), "sampling_guard_groups_sha256": _digest(guard_groups)}


def audit_expanded(dataset, originals, expanded, heldout, config):
    audit = audit_originals(dataset, originals, heldout)
    if config.transformations_per_example != 1 or len(expanded) != 64:
        raise ValueError("Taxonomy coverage requires exactly one transformation and 64 actual training rows.")
    for index, original in enumerate(originals):
        for offset, actual in enumerate(expanded[index * 2:index * 2 + 2]):
            allowed = transform_variants(original.text) if offset else (original.text,)
            if (actual.text not in allowed or actual.expected_packed_classification != original.expected_packed_classification
                    or actual.metadata != original.metadata or actual.weight != original.weight * config.new_example_weight):
                raise ValueError("Actual taxonomy augmentation changed a target, weight or source provenance.")
    sensitivity, visibility, categories = _counts(expanded)
    original_categories = _counts(originals)[2]
    if (sensitivity != {k: v * 2 for k, v in SENSITIVITY_COUNTS.items()}
            or visibility != {v: 8 for v in Visibility.__members__}
            or categories != {k: v * 2 for k, v in original_categories.items()}):
        raise ValueError("Actual expanded taxonomy batch lost declared positive exposure.")
    audit.update(sampling_expanded_rows="64", sampling_expanded_unique_texts=str(len({training_text_key(r.text) for r in expanded})),
                 sampling_expanded_ids_sha256=_digest(r.metadata["taxonomy_row_id"] for r in expanded))
    return audit
