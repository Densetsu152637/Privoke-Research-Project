"""Pinned TRAIN-only audience coverage for the normal automatic requester.

The shipped catalog contains no validation/test authoring templates. Guards are
explicit separate rows. Rendering and quota selection are prediction-free.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import random

from privoke_model.training_data import training_text_key
from training.types import BatchTrainingExample
from .privacy_heads_curriculum import _row as legacy_row, target, canonical

STRATEGY = "audience_coverage_v1"
LEGACY = "legacy_random_v1"
VERSION = "audience_contrast_v3_v1"
DATA = Path(__file__).resolve().parents[2] / "data"
DEFAULT_MANIFEST = DATA / "audience-v3-manifest-v1.json"
BUNDLED_MANIFEST_SHA256 = "7f17f43473deb4235ed189508008576abd19cf5eba0e9912d4c4ba4c58d7c010"
AUDIENCES = ("P0", "P1", "P2", "P3", "P4", "PU")
CATEGORIES = ("HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL", "SEXUAL", "CHILD", "LOCATION", "IDENTITY", "THIRD_PARTY")


def digest(payload):
    return hashlib.sha256(payload).hexdigest()


def implementation_closure():
    """Bind sampler/rendering/augmentation bytes before durable receipt lookup."""
    root = Path(__file__).resolve().parents[4]
    names = ("services/privoke-fuzzer/src/prompt_generation/audience_coverage.py",
             "services/privoke-fuzzer/src/prompt_generation/privacy_heads_curriculum.py",
             "services/privoke-fuzzer/src/prompt_generation/generator.py",
             "services/privoke-fuzzer/src/training/transforms.py", "services/privoke-fuzzer/src/training/types.py",
             "services/privoke-fuzzer/src/training/trainer.py", "services/privoke-fuzzer/src/fuzzer_service.py",
             "services/privoke-fuzzer/src/config.py", "shared/python/privoke_model/training_data.py",
             "shared/python/privoke_contracts/classification.py")
    files = {name: digest((root/name).read_bytes()) for name in names}
    return {"sha256": digest(canonical(files)), "files": files}


def render_catalog(catalog):
    """Render one permanent split, with complete named and packed targets."""
    split = catalog["split"]
    if split not in ("train", "validation", "fresh_eval") or catalog["label_status"] != "assistant_provisional":
        raise ValueError("Unknown audience catalog partition/label status.")
    families = catalog["families"]
    catalog_sha256 = digest(canonical(catalog))
    if set(catalog["audience"]) != set(AUDIENCES):
        raise ValueError("Audience catalog must cover all six classes.")
    expected_expressions = 8 if split == "train" else 4
    if any(len(v) != expected_expressions for v in catalog["audience"].values()):
        raise ValueError("Audience expression diversity budget differs.")
    rows = []
    for family_index, family in enumerate(families):
        mild = family["primary_category"] == "NONE"
        for visibility_index, visibility in enumerate(AUDIENCES):
            for variant in range(4):
                for actual in ((variant < 3,) if mild else (False, True)):
                    expression_index = (family_index * 3 + variant) % expected_expressions
                    expression = catalog["audience"][visibility][expression_index]
                    entity = catalog["entities"][(family_index + variant * 5 + visibility_index * 7) % len(catalog["entities"])]
                    evidence = expression.format(entity=entity)
                    fact = family["fact"]
                    components = [family["component_id"]]
                    categories = list(family["categories"])
                    sensitivity = family["sensitivity"]
                    if actual and not mild and variant >= 2:
                        secondary = families[(family_index + 7) % (len(families) - catalog["mild_families"])]
                        fact += "; " + secondary["fact"]
                        categories = list(set(categories) | set(secondary["categories"]))
                        sensitivity = max(sensitivity, secondary["sensitivity"])
                        components.append(secondary["component_id"])
                    control = "mild_personal" if actual and mild else "actual_disclosure" if actual else catalog["control_names"][variant]
                    body = (catalog["actual_framings"][variant] if actual else catalog["clean_framings"][variant]).format(fact=fact, topic=family["topic"])
                    text = f"{body} {evidence}" if variant % 2 == 0 else f"{evidence} {body}"
                    classification = target(sensitivity if actual else "S0", visibility, categories if actual else [])
                    identifier = f"{family['family_id']}/{visibility}/{variant}/{int(actual)}"
                    allowed = ["ALLOW"] if classification.sensitivity().name in ("S0", "S1") else ["WARN", "BLOCK"]
                    metadata = {
                        "example_id": identifier, "family_id": family["family_id"], "group_id": family["family_id"],
                        "parent_id": family["family_id"], "split": split, "source_resource": catalog["resource_id"],
                        "source_resource_sha256": catalog_sha256,
                        "generator": VERSION, "training_role": "authored_audience_contrast", "primary_category": family["primary_category"],
                        "control": control, "subject_relationship": family["subject_relationship"],
                        "component_ids": json.dumps(components), "asserted_component_ids": json.dumps(components if actual else []),
                        "coarse_situation_id": family["coarse_situation_id"], "body_framing_group_id": f"AU3/{split}/body/{variant}/{int(actual)}",
                        "audience_expression_id": f"AU3/{split}/{visibility}/expression/{expression_index}",
                        "audience_expression_group_id": f"AU3/{split}/{visibility}/expression/{expression_index}",
                        "audience_class": visibility, "audience_evidence": evidence,
                        "visibility_rationale": catalog["audience_rationales"][visibility],
                        "category_rationale": "All explicitly asserted actual domains, including named secondary facts." if actual else "No actual person's completed record is supplied; domain words alone are not disclosure.",
                        "sensitivity_rationale": "Actual mild preference/routine." if actual and mild else "Explicit actual personal fact with all asserted domains retained." if actual else "Explicitly absent, unfilled or wholly invented record; no real referent.",
                        "entity_pool_id": f"AU3/{split}/neutral_titles", "entity_value": entity,
                        "label_status": "assistant_provisional", "variant": str(variant),
                    }
                    rows.append({"id": identifier, "case_id": identifier, "family_id": family["family_id"], "group_id": family["family_id"],
                                 "partition": split, "text": text, "classification": classification.to_dict(), "packed": classification.pack(),
                                 "packed_classification": classification.pack(), "weight": 1.0, "required_sensitive": classification.is_sensitive(),
                                 "allowed_actions": allowed, "ambiguous": False, "context_truth_eligible": True,
                                 "action_accuracy_eligible": True, "label_status": "assistant_provisional", "metadata": metadata})
    validate_rows(rows, split)
    return rows


def legacy_train_rows(resource):
    """Reproduce unchanged PH3 TRAIN rows from a TRAIN-only restricted catalog."""
    if set(resource["splits"]) != {"train"} or set(resource["auxiliary"]) != {"train"} or any(f["split"] != "train" for f in resource["families"]):
        raise ValueError("Runtime rehearsal catalog must contain TRAIN only.")
    rows = []
    for family in resource["families"]:
        for audience in AUDIENCES:
            for variant in range(4):
                rows.extend(legacy_row(resource, family, "train", audience, variant, actual) for actual in (False, True))
    for family in resource["auxiliary"]["train"]:
        for audience in AUDIENCES:
            for variant in range(4):
                rows.append(legacy_row(resource, family, "train", audience, variant, variant < 3, auxiliary=True))
    if len(rows) != 6240:
        raise ValueError("PH3 TRAIN rehearsal row budget changed.")
    validate_rows(rows, "train")
    return rows


def validate_rows(rows, partition):
    ids, keys = set(), set()
    for row in rows:
        value = row.get("classification")
        if not isinstance(value, dict) or set(value) != {"sensitivity", "visibility", "categories"}:
            raise ValueError("Audience rows need complete named truth.")
        classification = target(**value)
        if (classification.to_dict() != value or row.get("packed") != classification.pack()
                or row.get("packed_classification") != classification.pack() or row.get("partition") != partition
                or row.get("metadata", {}).get("split") != partition or row.get("ambiguous") is not False
                or row.get("weight", 1.0) != 1.0 or not row.get("context_truth_eligible") or row.get("visibility_hint")):
            raise ValueError("Audience row target/partition/weight/eligibility mismatch.")
        key = training_text_key(row["text"])
        if not key or key in keys or row["id"] in ids or "{" in row["text"] or "}" in row["text"]:
            raise ValueError("Empty, duplicate or unrendered audience row.")
        if row["group_id"] != row["family_id"] or row["metadata"]["group_id"] != row["group_id"]:
            raise ValueError("Audience row group provenance mismatch.")
        allowed = ["ALLOW"] if classification.sensitivity().name in ("S0", "S1") else ["WARN", "BLOCK"]
        if row.get("allowed_actions") != allowed:
            raise ValueError("Audience allowed actions disagree with disclosed severity.")
        if row["id"].startswith("AU3/"):
            required = {"example_id", "parent_id", "source_resource", "source_resource_sha256", "generator", "training_role",
                        "primary_category", "control", "subject_relationship", "component_ids", "asserted_component_ids",
                        "coarse_situation_id", "body_framing_group_id", "audience_expression_id", "audience_expression_group_id",
                        "audience_class", "audience_evidence", "visibility_rationale", "category_rationale", "sensitivity_rationale",
                        "entity_pool_id", "entity_value", "label_status"}
            if (not required <= row["metadata"].keys() or any(not isinstance(v, str) or not v for v in row["metadata"].values())
                    or row["metadata"]["audience_class"] != classification.visibility().name
                    or row["metadata"]["label_status"] != "assistant_provisional"):
                raise ValueError("Audience row lacks complete explicit source/label provenance.")
        ids.add(row["id"]); keys.add(key)


def example(row, seed=None, index=None):
    metadata = dict(row["metadata"])
    if seed is not None:
        metadata.update(generation_seed=str(seed), generation_index=str(index), sampler=STRATEGY)
    return BatchTrainingExample(row["text"], target(**row["classification"]), metadata=metadata)


@dataclass(frozen=True)
class Release:
    train: tuple
    rehearsal: tuple
    guard: tuple
    manifest: dict
    sha256: str


def load_release(manifest_path=None, expected_sha256=None):
    path = Path(manifest_path or DEFAULT_MANIFEST)
    raw = path.read_bytes(); sha = digest(raw)
    if manifest_path is None and expected_sha256 is None:
        expected_sha256 = BUNDLED_MANIFEST_SHA256
    if manifest_path is not None and expected_sha256 is None:
        raise ValueError("Custom audience manifest requires an explicit trusted SHA256 pin.")
    if expected_sha256 is not None and sha != expected_sha256:
        raise ValueError("Audience manifest hash differs from trusted pin.")
    manifest = json.loads(raw)
    if manifest.get("schema") != 1 or manifest.get("strategy") != STRATEGY or set(manifest["files"]) != {"train_catalog", "rehearsal_catalog", "guard"}:
        raise ValueError("Wrong audience runtime manifest.")
    values = {}
    for key, descriptor in manifest["files"].items():
        relative = Path(descriptor["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Audience runtime inputs must remain inside release directory.")
        payload = (path.parent / relative).read_bytes()
        if digest(payload) != descriptor["sha256"]:
            raise ValueError("Audience runtime source bytes changed: " + key)
        values[key] = json.loads(payload)
    if values["train_catalog"].get("split") != "train":
        raise ValueError("Automatic audience generation accepts TRAIN catalog only.")
    train = render_catalog(values["train_catalog"])
    rehearsal = legacy_train_rows(values["rehearsal_catalog"])
    guard = values["guard"]
    validate_rows(guard, "validation")
    if len(train) != 3120 or len(guard) != 16 or digest(b"".join(canonical(r) for r in rehearsal)) != manifest["ph3_train_sha256"]:
        raise ValueError("Audience release row budget or immutable PH3 ancestry differs.")
    all_train = train + rehearsal
    validate_rows(all_train, "train")
    if ({training_text_key(r["text"]) for r in all_train} & {training_text_key(r["text"]) for r in guard}
            or {r["group_id"] for r in all_train} & {r["group_id"] for r in guard}):
        raise ValueError("Audience TRAIN/guard overlap.")
    return Release(tuple(train), tuple(rehearsal), tuple(guard), manifest, sha)


def validate_count(count, heldout_count=16):
    if type(count) is not int or count < 32 or count % 32 or heldout_count != 16:
        raise ValueError("Audience coverage requires multiples of 32 originals and 16 guard rows.")


def generate_partition(release, seed, count=32):
    validate_count(count)
    rng = random.Random(seed)  # nosec B311 -- reproducible experiment sampling
    chosen, used = [], set()
    sensitive = {category: [r for r in release.train if r["metadata"]["primary_category"] == category and r["metadata"]["control"] == "actual_disclosure"] for category in CATEGORIES}
    def choose(candidates):
        eligible = [r for r in candidates if r["id"] not in used]
        if not eligible:
            raise ValueError("Audience TRAIN pool cannot satisfy quota without replacement.")
        # Prefer an unseen expression/family before taking a sibling in this cycle.
        seen_groups = {r["group_id"] for r in chosen}
        seen_expressions = {r["metadata"].get("audience_expression_id") for r in chosen}
        preferred = [r for r in eligible if r["group_id"] not in seen_groups and r["metadata"].get("audience_expression_id") not in seen_expressions]
        row = rng.choice(preferred or eligible)
        chosen.append(row); used.add(row["id"])
    for block in range(count // 32):
        categories = list(CATEGORIES); rng.shuffle(categories)
        categories += categories[:2]
        for i, audience in enumerate(AUDIENCES):
            for category in categories[i*2:i*2+2]:
                choose([r for r in sensitive[category] if r["classification"]["visibility"] == audience])
            choose([r for r in release.train if r["classification"]["visibility"] == audience and r["classification"]["sensitivity"] == "S0" and r["metadata"]["primary_category"] != "NONE"])
            choose([r for r in release.train if r["classification"]["visibility"] == audience and r["metadata"]["primary_category"] == "NONE"])
        replay = list(release.rehearsal); rng.shuffle(replay)
        for index in range(8):
            audience = AUDIENCES[(index + seed + block) % 6]
            choose([r for r in replay if r["classification"]["visibility"] == audience and r["required_sensitive"] == bool(index % 2)])
    rng.shuffle(chosen)
    training = [example(r, seed, index) for index, r in enumerate(chosen)]
    guard = [example(r) for r in release.guard]
    audit_originals(release, training, guard, seed)
    return training, guard


def audit_originals(release, training, guard, seed=None):
    validate_count(len(training), len(guard))
    source = {r["id"]: r for r in (*release.train, *release.rehearsal)}
    keys, counts, categories, roles, replay_labels = set(), Counter(), set(), Counter(), Counter()
    for index, row in enumerate(training):
        identifier = row.metadata.get("example_id")
        expected = source.get(identifier)
        if expected is None or row.text != expected["text"] or row.expected_packed_classification != expected["packed"] or row.weight != 1:
            raise ValueError("Actual audience selection differs from pinned TRAIN source.")
        allowed_metadata = dict(expected["metadata"])
        for key in ("generation_seed", "generation_index", "sampler"):
            allowed_metadata[key] = row.metadata.get(key)
        if row.metadata != allowed_metadata or row.metadata.get("sampler") != STRATEGY:
            raise ValueError("Actual audience metadata differs from pinned TRAIN provenance.")
        if row.metadata.get("generation_index") != str(index) or (seed is not None and row.metadata.get("generation_seed") != str(seed)):
            raise ValueError("Actual audience generation seed/order differs.")
        if identifier in keys:
            raise ValueError("Audience selection repeats a source row within cycle.")
        keys.add(identifier)
        if row.metadata.get("generator") == VERSION:
            visibility = row.expected_classification.visibility().name
            counts[visibility] += 1
            role = ("mild_source" if row.metadata["primary_category"] == "NONE" else
                    "actual" if row.metadata["control"] == "actual_disclosure" else "hard_clean")
            roles[visibility, role] += 1
            if row.metadata["control"] == "actual_disclosure":
                categories.add(row.metadata["primary_category"])
        else:
            replay_labels[row.expected_classification.is_sensitive()] += 1
    if set(categories) != set(CATEGORIES) or any(counts[v] != len(training)//8 for v in AUDIENCES):
        raise ValueError("Actual audience/category quotas differ.")
    blocks = len(training)//32
    if (any(roles[v,role] != multiplier*blocks for v in AUDIENCES for role,multiplier in (("actual",2),("hard_clean",1),("mild_source",1)))
            or replay_labels != Counter({False:4*blocks,True:4*blocks})):
        raise ValueError("Actual audience role/rehearsal clean-sensitive quotas differ.")
    if [(r.text, r.expected_packed_classification, r.weight) for r in guard] != [(r["text"], r["packed"], 1.0) for r in release.guard]:
        raise ValueError("Actual audience guard differs from permanent release.")
    return {"contextual_sampling_strategy": STRATEGY, "audience_manifest_sha256": release.sha256,
            "audience_implementation_sha256": implementation_closure()["sha256"],
            "sampling_training_rows": str(len(training)), "sampling_au3_rows": str(sum(counts.values())),
            "sampling_rehearsal_rows": str(len(training)-sum(counts.values())), "sampling_primary_categories": str(len(categories)),
            "sampling_audience_counts": json.dumps(dict(counts), sort_keys=True),
            "sampling_role_counts": json.dumps({v:{role:roles[v,role] for role in ("actual","hard_clean","mild_source")} for v in AUDIENCES},sort_keys=True),
            "sampling_rehearsal_sensitive_rows": str(replay_labels[True]), "sampling_rehearsal_clean_rows": str(replay_labels[False]),
            "sampling_selected_ids_sha256": digest(canonical([r.metadata["example_id"] for r in training])),
            "sampling_audience_expression_groups": str(len({r.metadata.get("audience_expression_group_id") for r in training if r.metadata.get("generator") == VERSION}))}


def audit_expanded(release, originals, expanded, guard, config):
    from training.trainer import iter_training_examples
    result = audit_originals(release, originals, guard, config.seed)
    expected = list(iter_training_examples(originals, (), config))
    if expanded != expected or any(r.weight != 1.0 for r in expanded):
        raise ValueError("Actual audience transformed stream/weights differ from admitted invariants.")
    result["sampling_expanded_exposures"] = str(len(expanded))
    result["sampling_expanded_unique_texts"] = str(len({training_text_key(r.text) for r in expanded}))
    return result
