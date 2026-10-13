"""Prediction-free AU3 release preparation and strict host data admission."""
from __future__ import annotations

from collections import Counter
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "services/privoke-fuzzer/src"), str(ROOT / "shared/python")]
from prompt_generation import audience_coverage as audience
from prompt_generation.privacy_heads_curriculum import canonical
from privoke_model.training_data import training_text_key
from training.transforms import synthetic_common_name

STUDY_ID = "audience_v3_20261013"
COUNTS = {"train": 9360, "validation": 1560, "fresh_eval": 1560}
CATALOGS = {"train": "services/privoke-fuzzer/data/audience-v3-train-v1.json",
            "validation": "evaluation/datasets/audience-v3-validation-v1.json",
            "fresh_eval": "evaluation/datasets/audience-v3-fresh_eval-v1.json"}
REHEARSAL = "services/privoke-fuzzer/data/privacy-heads-v3-train-replay-v1.json"
OLD_TRAIN = "evaluation/results/privacy_heads_v3_20261013/data/release-03/train.jsonl"
SOURCES = ("evaluation/privoke_eval/audience_v3_data.py", "evaluation/prepare-audience-v3.py",
           "services/privoke-fuzzer/src/prompt_generation/audience_coverage.py",
           "services/privoke-fuzzer/src/prompt_generation/privacy_heads_curriculum.py", REHEARSAL, *CATALOGS.values(),
           "services/privoke-fuzzer/data/audience-v3-guard-v1.json", "services/privoke-fuzzer/data/audience-v3-manifest-v1.json")


def read(path):
    return json.loads(Path(path).read_bytes())


def relative_file(parent, value):
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("AU3 release paths must stay inside their declared directory.")
    return Path(parent) / path


def load_partition(manifest_path, role, *, evaluation_authorized=False):
    # The authorization boundary precedes every file/catalog read.
    if role not in ("train", "validation") and not (role == "fresh_eval" and evaluation_authorized):
        raise ValueError("Fresh AU3 data cannot be opened before all-model sealing.")
    manifest_path = Path(manifest_path)
    manifest = read(manifest_path)
    if manifest.get("schema") != 1 or manifest.get("study_id") != STUDY_ID:
        raise ValueError("Wrong AU3 data manifest.")
    item = manifest["files"][role]
    payload = relative_file(manifest_path.parent, item["path"]).read_bytes()
    if audience.digest(payload) != item["sha256"]:
        raise ValueError("AU3 partition bytes changed: " + role)
    rows = [json.loads(line) for line in payload.decode("utf8").splitlines() if line.strip()]
    audience.validate_rows(rows, role)
    if len(rows) != item["rows"] or len({r["group_id"] for r in rows}) != item["groups"]:
        raise ValueError("AU3 partition denominator changed.")
    return rows


def validate_training_data(manifest_path, root=ROOT):
    manifest_path, root = Path(manifest_path), Path(root)
    manifest = read(manifest_path)
    if (manifest.get("schema") != 1 or manifest.get("study_id") != STUDY_ID
            or set(manifest["files"]) != set(COUNTS) or manifest["audit"]["status"] != "passed"):
        raise ValueError("AU3 release audit/roles missing.")
    proof = relative_file(manifest_path.parent, manifest["audit"]["proof_path"])
    if audience.digest(proof.read_bytes()) != manifest["audit"]["sha256"]:
        raise ValueError("AU3 exclusion proof changed.")
    for name, sha in manifest["source_files"].items():
        # Holdout catalogs were audited by data authors; fit admission checks
        # their commitment in retained proof without opening their payloads.
        if name == CATALOGS["fresh_eval"]:
            continue
        if audience.digest((root / name).read_bytes()) != sha:
            raise ValueError("AU3 data source drift: " + name)
    train, validation = load_partition(manifest_path, "train"), load_partition(manifest_path, "validation")
    for role, rows in (("train", train), ("validation", validation)):
        if len(rows) != COUNTS[role] or {r["classification"]["visibility"] for r in rows} != set(audience.AUDIENCES):
            raise ValueError("AU3 fit partition class/count mismatch.")
        for category in audience.CATEGORIES:
            support = sum(category in r["classification"]["categories"] for r in rows)
            if not 0 < support < len(rows):
                raise ValueError("AU3 missing category positive/negative supervision.")
    if manifest["files"]["fresh_eval"]["rows"] != COUNTS["fresh_eval"]:
        raise ValueError("AU3 sealed fresh denominator changed.")
    if ({r["group_id"] for r in train} & {r["group_id"] for r in validation}
            or {training_text_key(r["text"]) for r in train} & {training_text_key(r["text"]) for r in validation}):
        raise ValueError("AU3 TRAIN/validation overlap.")
    legacy = [r for r in train if r["id"].startswith("PH3/")]
    if len(legacy) != 6240 or audience.digest(b"".join(canonical(r) for r in legacy)) != manifest["ph3_rehearsal"]["sha256"]:
        raise ValueError("AU3 PH3 rehearsal ancestry/row bytes differ.")
    return manifest, train, validation


def skeleton(text, entities=()):
    value = training_text_key(text)
    for entity in sorted(entities, key=len, reverse=True):
        if entity:
            value = re.sub(rf"\b{re.escape(training_text_key(entity))}\b", "ENTITY", value)
    return re.sub(r"\b\d+\b", "NUMBER", value)


def audit(pools, catalogs):
    identities, text_partitions, shaped_partitions = {}, {}, {}
    component_keys, expression_keys, framing_keys, entity_keys, mechanisms = {}, {}, {}, {}, {}
    summary = {}
    for split, catalog in catalogs.items():
        for family in catalog["families"]:
            mechanism = family["coarse_situation_id"]
            if mechanism in mechanisms and mechanisms[mechanism] != split:
                raise ValueError("AU3 declared scenario mechanism crosses splits.")
            mechanisms[mechanism] = split
            key = skeleton(family["fact"])
            if key in component_keys and component_keys[key] != split:
                raise ValueError("AU3 assertion component crosses splits.")
            component_keys[key] = split
        for expression in (v for group in catalog["audience"].values() for v in group):
            key = training_text_key(expression)
            if key in expression_keys and expression_keys[key] != split:
                raise ValueError("AU3 audience expression crosses splits.")
            expression_keys[key] = split
        for framing in catalog["actual_framings"] + catalog["clean_framings"]:
            key = training_text_key(framing)
            if key in framing_keys and framing_keys[key] != split:
                raise ValueError("AU3 body framing crosses splits.")
            framing_keys[key] = split
        for entity in catalog["entities"]:
            if entity in entity_keys:
                raise ValueError("AU3 entity vocabulary crosses splits.")
            entity_keys[entity] = split
    for split, rows in pools.items():
        audience.validate_rows(rows, split)
        if len(rows) != COUNTS[split]:
            raise ValueError("AU3 row budget differs.")
        counts = {name: Counter() for name in ("visibility", "sensitivity", "categories", "control")}
        for row in rows:
            for kind, value in (("id", row["id"]), ("group", row["group_id"])):
                if (kind, value) in identities and identities[kind, value] != split:
                    raise ValueError("AU3 source identity crosses partitions.")
                identities[kind, value] = split
            for text in (row["text"], "Please review this prompt: " + row["text"], synthetic_common_name(row["text"])):
                key = training_text_key(text)
                shape = skeleton(text, (*catalogs[split]["entities"], row["metadata"].get("entity_value", "")))
                for value, inventory in ((key, text_partitions), (shape, shaped_partitions)):
                    if value in inventory and inventory[value] != split:
                        raise ValueError("AU3 invariant text/skeleton crosses partitions.")
                    inventory[value] = split
            for field in ("visibility", "sensitivity"):
                counts[field][row["classification"][field]] += 1
            counts["categories"].update(row["classification"]["categories"])
            counts["control"][row["metadata"]["control"]] += 1
        if any(counts["visibility"][v] != COUNTS[split] // 6 for v in audience.AUDIENCES):
            raise ValueError("AU3 audience balance differs.")
        combinations = {tuple(r["classification"]["categories"]) for r in rows if r["classification"]["categories"]}
        if len(combinations) < 15:
            raise ValueError("AU3 category-set coverage insufficient.")
        summary[split] = {"rows": len(rows), "groups": len({r["group_id"] for r in rows}),
                          "category_set_combinations": len(combinations), **{k: dict(v) for k, v in counts.items()},
                          "new_audience_expression_groups": len({r["metadata"].get("audience_expression_group_id") for r in rows if r["id"].startswith("AU3/")})}
    return summary


def historical_audit(pools, catalogs, root=ROOT):
    """Check declared old sources and opaque final commitments without final access."""
    spec = importlib.util.spec_from_file_location("au3_ph3_preparer", Path(root) / "evaluation/prepare-privacy-heads-v3.py")
    old = importlib.util.module_from_spec(spec); spec.loader.exec_module(old)
    historical = {"texts": set(), "ids": set(), "groups": set()}
    paths = (*old.HISTORICAL, "evaluation/datasets/privacy-heads-v3-scenarios-v1.json",
             "evaluation/results/privacy_heads_v3_20261013/data/release-03/train.jsonl",
             "evaluation/results/privacy_heads_v3_20261013/data/release-03/validation.jsonl",
             "evaluation/results/privacy_heads_v3_20261013/data/release-03/fresh-eval.jsonl")
    inputs = {}
    for name in paths:
        payload = (Path(root) / name).read_bytes(); inputs[name] = audience.digest(payload)
        found = old.historical_keys(old.records(payload))
        if name in ("evaluation/datasets/synthetic-teacher-templates.json", "evaluation/datasets/synthetic-teacher-templates-v2.json"):
            from privoke_eval.synthetic_curriculum import build_curriculum
            extra = old.historical_keys(list(build_curriculum(old.records(payload)).values()))
            for field in found: found[field].update(extra[field])
        for field in historical: historical[field].update(found[field])
    payload = (Path(root) / old.OPAQUE).read_bytes()
    if audience.digest(payload) != old.OPAQUE_SHA:
        raise ValueError("Historical opaque exclusion index changed.")
    opaque = json.loads(payload); protected = {k: set(v) for k, v in opaque["all_exclusion_key_sets"].items()}
    if audience.digest(json.dumps(opaque["all_exclusion_key_sets"], sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()) != opaque["all_exclusion_key_sets_sha256"]:
        raise ValueError("Historical opaque union commitment changed.")
    old_catalog = read(Path(root) / "evaluation/datasets/privacy-heads-v3-scenarios-v1.json")
    historical_entities = [entity for split in old_catalog["splits"].values() for entity in split["entities"]]
    historical_shapes = {skeleton(text, historical_entities) for text in historical["texts"]}
    historical_components = [f for family in old_catalog["families"] for f in (family, family["secondary"])]
    historical_mechanisms = {f["coarse_situation_id"] for f in historical_components}
    for split, rows in pools.items():
        for row in rows:
            if row["id"].startswith("PH3/"):
                if split != "train": raise ValueError("Historical rehearsal outside TRAIN.")
                continue
            if row["id"] in historical["ids"] or row["group_id"] in historical["groups"]:
                raise ValueError("AU3 source identity overlaps history.")
            for kind, value, field in (("id", row["id"], "ids"), ("group", row["group_id"], "groups")):
                if old.opaque_key(kind, value) in protected[field]:
                    raise ValueError("AU3 identity overlaps protected final.")
            for text in (row["text"], "Please review this prompt: " + row["text"], synthetic_common_name(row["text"])):
                key = training_text_key(text)
                if key in historical["texts"] or old.opaque_key("text_key", key) in protected["texts"]:
                    raise ValueError("AU3 normalized/transformed text overlaps history.")
                if skeleton(text, catalogs[split]["entities"]) in historical_shapes:
                    raise ValueError("AU3 full-text entity/number skeleton overlaps history.")
    facts = [(split, f) for split, catalog in catalogs.items() for f in catalog["families"]]
    component_overlaps = []
    for split, family in facts:
        key = training_text_key(family["fact"])
        shape = skeleton(family["fact"])
        if (any(key in text for text in historical["texts"])
                or any(shape in text for text in historical_shapes)
                or family["coarse_situation_id"] in historical_mechanisms):
            component_overlaps.append(family["component_id"])
    if component_overlaps:
        raise ValueError("AU3 actual assertion component overlaps history: " + ",".join(component_overlaps))
    return {"status": "passed", "inputs": inputs, "opaque_index_sha256": old.OPAQUE_SHA,
            "protected_union_sha256": opaque["all_exclusion_key_sets_sha256"],
            "historical_unique_texts": len(historical["texts"]), "historical_final_payload_opened": False,
            "intentional_ph3_train_rehearsal_rows": 6240, "new_exact_normalized_transformed_identity_overlaps": 0,
            "new_assertion_substring_overlaps": 0,
            "new_historical_full_skeleton_or_declared_mechanism_overlaps": 0,
            "limitation": "Exact/component/skeleton exclusion cannot prove semantic novelty. Independent assistant review of coarse scenario and wording families is required."}


def native_lengths(pools, root=ROOT):
    """Tokenizer-only checks: all v3 rows512; automatic Tiny TRAIN/transforms64."""
    sys.path.insert(0, str(Path(root) / "extension/client-runtime"))
    from src.detection.preprocessing import normalize_with_offsets
    from src.transformer_encoder import TOKEN_PATTERN
    from transformers import BertTokenizerFast
    result, assets = {}, {}
    for tier in ("efficient", "balanced", "quality"):
        directory = Path(root) / "models/experiments/pretrained_v3_20261012/initials" / tier
        config = read(directory / "config.json")
        cap = config["max_position_embeddings"]
        tokenizer = BertTokenizerFast(vocab_file=str(directory / "vocab.txt"), do_lower_case=True)
        assets[tier] = {name: audience.digest((directory/name).read_bytes()) for name in ("config.json", "vocab.txt")}
        result[tier] = {}
        for split, rows in pools.items():
            normalized = [normalize_with_offsets(r["text"]).text for r in rows]
            counts = [len(ids) for ids in tokenizer(normalized, truncation=False, add_special_tokens=True)["input_ids"]]
            if max(counts) > cap:
                raise ValueError("AU3 data exceed actual native v3 positional capacity.")
            result[tier][split] = {"maximum": max(counts), "cap": cap, "truncation": False}
    tiny = {}
    for split, rows in pools.items():
        counts = [len(TOKEN_PATTERN.findall(normalize_with_offsets(r["text"]).text))+1 for r in rows]
        tiny[split] = {"maximum": max(counts), "comparison_scope": "descriptive_only_v3_test" if split=="fresh_eval" else "automatic_train_or_guard"}
    transformed_max = max(len(TOKEN_PATTERN.findall(normalize_with_offsets("Please review this prompt: " + r["text"]).text))+1 for r in pools["train"])
    guard = audience.load_release().guard
    guard_max = max(len(TOKEN_PATTERN.findall(normalize_with_offsets(r["text"]).text))+1 for r in guard)
    if transformed_max > 64 or guard_max > 64:
        raise ValueError("Automatic AU3 TRAIN/guard would truncate at Tiny64.")
    return {"status": "passed", "v3": result, "tokenizer_assets": assets, "tiny": tiny,
            "automatic_tiny_train_transformed_max": transformed_max, "automatic_tiny_guard_max": guard_max,
            "automatic_tiny_cap_checked": 64, "fresh_tiny_scoring_authorized": False, "inference_executed": False}


def prepare(output, root=ROOT):
    output, root = Path(output), Path(root)
    if output.exists():
        raise ValueError("Refusing to overwrite an AU3 release or failed attempt.")
    catalogs = {k: read(root / v) for k, v in CATALOGS.items()}
    new = {k: audience.render_catalog(v) for k, v in catalogs.items()}
    legacy = audience.legacy_train_rows(read(root / REHEARSAL))
    old_payload = (root / OLD_TRAIN).read_bytes()
    if b"".join(canonical(r) for r in legacy) != old_payload:
        raise ValueError("Restricted runtime catalog does not reproduce PH3 TRAIN bytes exactly.")
    pools = dict(new, train=legacy + new["train"])
    summary = audit(pools, catalogs)
    exclusions = historical_audit(pools, catalogs, root)
    # Tokenizer-only checks use no weights or predictions. Native v3 never truncates.
    lengths = native_lengths(pools, root)
    runtime_release = audience.load_release()
    validation_by_id = {r["id"]: r for r in pools["validation"]}
    if any(validation_by_id.get(r["id"]) != r for r in runtime_release.guard):
        raise ValueError("Shipped runtime guard must be an exact declared new-validation subset.")
    sources = {name: audience.digest((root / name).read_bytes()) for name in SOURCES}
    proof = {"schema": 1, "structural": summary, "exclusions": exclusions, "native_lengths": lengths,
             "ph3_train_byte_identical": True, "no_model_inference": True, "source_files": sources,
             "independent_review_required_before_fit": True}
    output.mkdir(parents=True)
    files = {}
    for role, rows in pools.items():
        filename = role + ".jsonl"; payload = b"".join(canonical(r) for r in rows)
        (output / filename).write_bytes(payload)
        files[role] = {"path": filename, "sha256": audience.digest(payload), "rows": len(rows), "groups": len({r["group_id"] for r in rows})}
    (output / "audit.json").write_bytes(canonical(proof))
    guard_payload = b"".join(canonical(r) for r in runtime_release.guard)
    (output / "runtime-guard.jsonl").write_bytes(guard_payload)
    manifest = {"schema": 1, "study_id": STUDY_ID, "release_id": "AU3-R1", "files": files,
                "source_files": sources, "source_closure": audience.digest(canonical(sources)),
                "audit": {"status": "passed", "proof_path": "audit.json", "sha256": audience.digest(canonical(proof)), "independent_admission": "pending"},
                "ph3_rehearsal": {"rows": 6240, "sha256": audience.digest(old_payload), "source": OLD_TRAIN},
                "runtime_guard": {"path": "runtime-guard.jsonl", "sha256": audience.digest(guard_payload), "rows": 16,
                                  "groups": len({r["group_id"] for r in runtime_release.guard}), "role": "validation_subset_not_fresh_test",
                                  "runtime_manifest_sha256": runtime_release.sha256},
                "label_status": "assistant_provisional", "semantic_layers": [4], "visibility_hints": "empty",
                "fresh_eval_opening": "all_three_fits_selected_terminal_exports_native_audits_and_root_seal_first",
                "limitations": ["Synthetic assistant-provisional labels, not human annotation.", "Rows within scenario families are dependent; lexical/component exclusion is not proof of semantic novelty."]}
    (output / "manifest.json").write_bytes(canonical(manifest))
    return manifest
