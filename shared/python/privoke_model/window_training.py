"""Opt-in frozen TRAIN window, component retention and checkpoint contracts.

This module has no model execution. Canonical immutable releases and explicit
trusted pins are checked before compute; legacy Adam/retention IDs keep v1 semantics.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path

from .full_adam import CONFIG as ADAM_CONFIG, OBJECTIVE, canonical
from .sensitive_retention import canonical_bytes, sha256, is_sha256, EPSILON

POLICY = "full_projected_adam64_window_checkpoint_v1"
ELIGIBILITY = "candidate_window_exact_component_retention_v1"
SAMPLER = "taxonomy_benign_train_window_v1"
SELECTOR = "transported_train_component_rank_v1"
CONFIG_KEY = "train_window_config_v1"
WINDOW_KEY = "train_window_manifest_sha256"
REFERENCE_KEY = "original_train_component_manifest_sha256"
TRACE_KEY = "train_window_trace_v1"
SUMMARY_KEY = "train_window_summary_v1"
COMPONENTS = ("sensitivity", "severity", "category", "visibility", "action")
CONFIG = {"adam": ADAM_CONFIG, "blocks": 8, "block_rows": 64, "epochs": 8,
          "candidate_seeds": 64, "checkpoints": list(range(8, 65, 8)),
          "epsilon": EPSILON, "margin_cap": 1.0, "auxiliary_coefficient": 1,
          "normalization": "category_bits_then_components_then_rows_v1",
          "main_normalization": "eight_times_block_over_frozen_window_weight_v1",
          "selector": SELECTOR, "component_order": list(COMPONENTS)}


def derived_seed(seed, purpose, index):
    return int.from_bytes(hashlib.sha256(canonical([SAMPLER, seed, purpose, index]).encode()).digest()[:8], "big")


def schedule(seed):
    """Eight permutations; hashing avoids dependence on a runtime RNG implementation."""
    return tuple(block for epoch in range(8) for block in sorted(range(8),
        key=lambda block: (derived_seed(seed, "epoch", epoch * 8 + block), block)))


def wire_rows(rows):
    result = []
    for row in rows:
        target = getattr(row, "expected_classification", getattr(row, "target", None))
        if target is None or not math.isfinite(row.weight) or row.weight <= 0:
            raise ValueError("Window requires explicit targets and finite positive weights.")
        result.append({"text": row.text, "packed": target.pack(), "weight": float(row.weight)})
    return result


def read_pinned(path, pin):
    if not path or not is_sha256(pin) or Path(path).is_symlink():
        raise ValueError("Window/reference requires explicit non-symlink path and independently configured SHA256.")
    payload = Path(path).read_bytes()
    value = json.loads(payload)
    if len(payload) > 4 * 1024 * 1024 or canonical_bytes(value) != payload or sha256(payload) != pin:
        raise ValueError("Canonical immutable release differs from trusted pin.")
    return value


def validate_window(value):
    from privoke_contracts.classification import Classification
    from .training_data import training_text_key
    keys = {"schema", "sampler", "seed", "config", "sources", "blocks", "guard", "provenance"}
    if (type(value) is not dict or set(value) != keys or value["schema"] != 1
            or value["sampler"] != SAMPLER or type(value["seed"]) is not int or value["config"] != CONFIG
            or len(value["blocks"]) != 8 or len(value["guard"]) != 16
            or set(value["sources"]) != {"taxonomy", "benign", "pool", "proof"}
            or not all(is_sha256(v) for v in value["sources"].values())):
        raise ValueError("Invalid frozen TRAIN window contract.")
    groups, guard_groups, ids, texts = set(), set(), [], []
    for block in value["blocks"]:
        if set(block) != {"seed", "rows"} or type(block["seed"]) is not int or len(block["rows"]) != 64:
            raise ValueError("Invalid frozen TRAIN block.")
        for row in block["rows"]:
            _validate_row(row)
            if row["partition"] != "train":
                raise ValueError("Window may access permanent TRAIN only.")
            Classification(row["packed"]).visibility()
            if row["family_kind"] == "taxonomy":
                groups.add(row["group"])
            ids.append(row["id"]); texts.append(training_text_key(row["text"]))
    for row in value["guard"]:
        _validate_row(row)
        if row["partition"] != "guard":
            raise ValueError("Guard must retain permanent guard membership.")
        guard_groups.add(row["group"])
    if (len(groups) != 20 or groups & guard_groups
            or set(texts) & {training_text_key(r["text"]) for r in value["guard"]}):
        raise ValueError("Window requires all20 TRAIN families and separate guard groups/texts.")
    actual = {"wire_rows": 512, "unique_source_ids": len(set(ids)), "unique_texts": len(set(texts)),
              "taxonomy_families": 20, "repeated_source_presentations": 512 - len(set(ids)), "fit_release": False}
    if value["provenance"] != actual:
        raise ValueError("Window source multiplicity accounting differs.")
    return value


def _validate_row(row):
    from privoke_contracts.classification import Classification
    if (type(row) is not dict or set(row) != {"text", "packed", "weight", "id", "group", "partition", "family_kind"}
            or type(row["packed"]) is not int or not 0 <= row["packed"] <= 65535
            or type(row["weight"]) not in (int, float) or not math.isfinite(row["weight"]) or row["weight"] <= 0
            or any(type(row[k]) is not str or not row[k] for k in ("text", "id", "group"))
            or row["family_kind"] not in ("taxonomy", "benign")):
        raise ValueError("Malformed frozen source row.")
    Classification(row["packed"]).visibility()


def flat_rows(window):
    return [row for block in window["blocks"] for row in block["rows"]]


def row_wire(rows):
    return [{k: row[k] for k in ("text", "packed", "weight")} for row in rows]


def validate_request(window, examples, guard):
    validate_window(window)
    if wire_rows(examples) != row_wire(flat_rows(window)) or wire_rows(guard) != row_wire(window["guard"]):
        raise ValueError("Actual ordered request texts/targets/raw weights differ from frozen window.")


@dataclass(frozen=True)
class ComponentRelease:
    bank_payload: bytes
    reference_payload: bytes
    manifest_payload: bytes
    teacher_path: str
    teacher_sha256: str

    @property
    def sha256(self):
        return sha256(self.manifest_payload)

    @property
    def manifest(self):
        return json.loads(self.manifest_payload)

    @property
    def rows(self):
        return tuple(zip(json.loads(self.bank_payload), json.loads(self.reference_payload)["rows"]))


def component_specs(gold_packed, original_packed, logits, config):
    """Frozen positive capped teacher margins, grouped to prevent label-count weighting."""
    from privoke_contracts.classification import Classification
    gold, original = Classification(gold_packed), Classification(original_packed)
    if not original.is_sensitive():
        return {}
    sensitivity = config["sensitivity_labels"]
    s0 = sensitivity.index("S0")
    specs = {}
    def save(name, entries):
        kept = [{**{k: v for k, v in entry.items() if k != "margin"}, "target": min(1.0, entry["margin"])}
                for entry in entries if entry["margin"] > EPSILON]
        if kept:
            specs[name] = kept
    alternatives = [i for i, label in enumerate(sensitivity) if label != "S0"]
    s = logits["sensitivity"]
    save("sensitivity", [{"task": "sensitivity", "positive": alternatives, "negative": [s0],
        "margin": max(s[i] for i in alternatives) - s[s0]}])
    floor = min(gold.sensitivity().value, original.sensitivity().value)
    if floor > 0:
        allowed = [i for i, label in enumerate(sensitivity) if int(label[1:]) >= floor]
        disallowed = [i for i, label in enumerate(sensitivity) if int(label[1:]) < floor]
        save("severity", [{"task": "sensitivity", "positive": allowed, "negative": disallowed,
            "margin": max(s[i] for i in allowed) - max(s[i] for i in disallowed)}])
    threshold = config.get("category_threshold", .5)
    offset = math.log(threshold) - math.log1p(-threshold)
    gold_categories = {c.name for c in gold.categories()}
    original_categories = {c.name for c in original.categories()}
    categories = []
    for i, label in enumerate(config["category_labels"]):
        if (label in gold_categories) == (label in original_categories):
            sign = 1 if label in gold_categories else -1
            categories.append({"task": "category", "index": i, "sign": sign, "offset": offset,
                               "margin": sign * (logits["category"][i] - offset)})
    save("category", categories)
    if original.visibility() == gold.visibility():
        positive = config["visibility_labels"].index(gold.visibility().name)
        negative = [i for i in range(len(config["visibility_labels"])) if i != positive]
        save("visibility", [{"task": "visibility", "positive": [positive], "negative": negative,
            "margin": logits["visibility"][positive] - max(logits["visibility"][i] for i in negative)}])
    return specs


def validate_component_release(release, *, model_id=None, trusted_sha256=None):
    from . import sensitive_retention as old
    if type(release) is not ComponentRelease or (trusted_sha256 is not None and
            (not is_sha256(trusted_sha256) or trusted_sha256 != release.sha256)):
        raise ValueError("Component release differs from distinct trusted configured pin.")
    bank = old.validate_bank(release.bank_payload)
    refs = old.parse_canonical(release.reference_payload)
    manifest = old.parse_canonical(release.manifest_payload)
    teacher = teacher_identity(release.teacher_path, manifest["teacher"]["profile"], release.teacher_sha256)
    if (set(refs) != {"schema", "teacher", "bank_sha256", "rows"} or refs["schema"] != 2
            or refs["teacher"] != teacher or refs["bank_sha256"] != old.BANK_SHA256 or len(refs["rows"]) != len(bank)
            or (model_id is not None and teacher["model_id"] != model_id)):
        raise ValueError("Component reference teacher/bank/profile differs.")
    config = teacher["config"]
    eligible_groups = set()
    for source, row in zip(bank, refs["rows"]):
        if (set(row) != {"id", "gold", "original", "confidence", "logits", "components"}
                or row["id"] != source["id"] or row["gold"] != source["packed_classification"]
                or type(row["original"]) is not int or not 0 <= row["original"] <= 65535
                or type(row["confidence"]) not in (int, float) or not 0 <= row["confidence"] <= .999
                or row["confidence"] != round(row["confidence"], 3)
                or set(row["logits"]) != {"sensitivity", "category", "visibility"}):
            raise ValueError("Malformed authenticated task-logit reference.")
        from privoke_contracts.classification import Classification
        original = Classification(row["original"]); original.visibility()
        for task, values in row["logits"].items():
            if len(values) != len(config[task + "_labels"]) or any(type(v) not in (int, float) or not math.isfinite(v) for v in values):
                raise ValueError("Reference logits require complete finite task arrays.")
        if decoded_logits(row["logits"], config) != [row["original"], row["confidence"]]:
            raise ValueError("Reference packed output/confidence differs from exact float32 task-logit decoding.")
        if row["components"] != component_specs(row["gold"], row["original"], row["logits"], config):
            raise ValueError("Reference eligible components/capped margins differ.")
        if row["components"]:
            eligible_groups.add(source["metadata"]["group_id"])
    expected = {"schema": 2, "kind": "original_train_component_retention_v2", "teacher": teacher,
        "bank_sha256": old.BANK_SHA256, "references_sha256": sha256(release.reference_payload),
        "epsilon": EPSILON, "margin_cap": 1.0, "normalization": CONFIG["normalization"],
        "coefficient": 1, "fit_release": False}
    if manifest != expected or len(eligible_groups) != 20:
        raise ValueError("Component manifest/eligible20-family coverage differs.")
    return release


def load_components(bank_path, reference_path, manifest_path, teacher_path, *, model_id, trusted_sha256, teacher_sha256):
    paths = [Path(p) for p in (bank_path, reference_path, manifest_path, teacher_path) if p]
    if len(paths) != 4 or any(p.is_symlink() for p in paths):
        raise ValueError("Component retention requires four non-symlink sidecar paths.")
    return validate_component_release(ComponentRelease(*(p.read_bytes() for p in paths[:3]), str(paths[3]), teacher_sha256),
                                      model_id=model_id, trusted_sha256=trusted_sha256)


def teacher_identity(path, profile, trusted_sha256):
    """v2 teachers require a separately configured accepted raw-file pin; legacy pins stay unchanged."""
    from .artifact import MAX_ARTIFACT_BYTES,validate_artifact
    from .sensitive_retention import original_effective_parameters
    from .fingerprint import parameter_fingerprint
    teacher_path=Path(path)
    if not is_sha256(trusted_sha256) or teacher_path.is_symlink():
        raise ValueError("Component ORIGINAL teacher differs from independently configured accepted raw-file SHA.")
    with teacher_path.open("rb") as stream:
        raw=stream.read(MAX_ARTIFACT_BYTES+1)
    if len(raw)>MAX_ARTIFACT_BYTES or sha256(raw)!=trusted_sha256:
        raise ValueError("Component ORIGINAL teacher differs from independently configured accepted raw-file SHA.")
    artifact=json.loads(raw.decode("utf-8",errors="strict"))
    validate_artifact(artifact)
    if artifact["model_id"] != "privoke-" + profile:
        raise ValueError("Component ORIGINAL teacher profile differs.")
    shapes = {n: tuple(t["shape"]) for n,t in artifact["parameters"].items()}
    return {"profile":profile,"file_sha256":trusted_sha256,"checksum":artifact["checksum"],
        "model_id":artifact["model_id"],"version":artifact["version"],"config":artifact["config"],
        "parameter_fingerprint":parameter_fingerprint(original_effective_parameters(artifact),shapes),
        "inventory_fingerprint":parameter_fingerprint({n:() for n in shapes},shapes)}


def validate_policy(metadata):
    active = metadata.get("contextual_training_optimizer") == POLICY
    if not active:
        if any(k in metadata for k in (CONFIG_KEY, WINDOW_KEY, REFERENCE_KEY)):
            raise ValueError("Orphan window/checkpoint artifact policy.")
        return False
    if (metadata.get("contextual_training_strategy") != "contextual_full_encoder_sgd_v1"
            or metadata.get("contextual_training_objective") != OBJECTIVE
            or metadata.get("contextual_candidate_eligibility") != ELIGIBILITY
            or metadata.get(CONFIG_KEY) != canonical(CONFIG)
            or not all(is_sha256(metadata.get(k)) for k in (WINDOW_KEY, REFERENCE_KEY))
            or any(k in metadata for k in ("contextual_training_backtracking_policy", "contextual_training_diagnostics_policy", "full_projected_adam_config_v1", "original_train_retention_manifest_sha256"))):
        raise ValueError("Window policy requires exact exclusive FULL optimizer/objective/config/pins.")
    return True


def expectations(metadata):
    if metadata.get("expected_contextual_training_optimizer") != POLICY:
        if any("expected_" + k in metadata for k in (WINDOW_KEY, REFERENCE_KEY, CONFIG_KEY)):
            raise ValueError("Orphan window/checkpoint request pin.")
        return None
    if (metadata.get("expected_contextual_training_objective") != OBJECTIVE
            or metadata.get("expected_contextual_candidate_eligibility") != ELIGIBILITY
            or metadata.get("expected_contextual_training_scope") != "full_encoder"
            or metadata.get("expected_" + CONFIG_KEY) != canonical(CONFIG)
            or not all(is_sha256(metadata.get("expected_" + k)) for k in (WINDOW_KEY, REFERENCE_KEY))):
        raise ValueError("Window admission requires exact FULL policy/config and independent release pins.")
    return {"expected_objective": OBJECTIVE, "expected_diagnostics_policy": None,
        "expected_optimizer": POLICY, "expected_candidate_eligibility": ELIGIBILITY,
        "expected_optimizer_config": canonical(CONFIG), "expected_training_scope": "full_encoder",
        "expected_window_manifest_sha256": metadata["expected_" + WINDOW_KEY],
        "expected_component_manifest_sha256": metadata["expected_" + REFERENCE_KEY]}


def validate_admission(admission, metadata):
    if not validate_policy(metadata) or admission is None:
        raise ValueError("Window artifact requires explicit matching pre-gradient admission.")
    expected = expectations({"expected_contextual_training_optimizer": POLICY,
        "expected_contextual_training_objective": OBJECTIVE, "expected_contextual_candidate_eligibility": ELIGIBILITY,
        "expected_contextual_training_scope": "full_encoder", "expected_" + CONFIG_KEY: metadata[CONFIG_KEY],
        "expected_" + WINDOW_KEY: metadata[WINDOW_KEY], "expected_" + REFERENCE_KEY: metadata[REFERENCE_KEY]})
    if admission != expected:
        raise ValueError("Window artifact differs from admitted effective settings.")


def prepare_artifact(artifact, window_sha256, reference_sha256):
    from .artifact import validate_artifact, artifact_checksum
    validate_artifact(artifact)
    result = copy.deepcopy(artifact)
    meta = result["metadata"]
    if "contextual_training_optimizer" in meta:
        raise ValueError("Window preparation requires an optimizer-free FULL SUM-margin artifact.")
    meta.update(contextual_training_optimizer=POLICY, contextual_candidate_eligibility=ELIGIBILITY)
    meta.update({CONFIG_KEY: canonical(CONFIG), WINDOW_KEY: window_sha256, REFERENCE_KEY: reference_sha256})
    validate_policy(meta)
    result["checksum"] = artifact_checksum({k: v for k, v in result.items() if k != "checksum"})
    validate_artifact(result)
    return result


def eligible(checkpoint, baseline):
    """No cross-component compensation; ORIGINAL and BASE predicates are separate."""
    return checkpoint["violations"] == 0 and all(checkpoint["counts"][k] >= baseline["counts"][k]
        for k in baseline["counts"])


def progress(checkpoint, baseline):
    keys = ("sensitive_joint", *("sensitive_" + c for c in COMPONENTS))
    return any(checkpoint["counts"][k] > baseline["counts"][k] for k in keys)


def rank(checkpoint):
    c = checkpoint["counts"]
    return (c["sensitive_joint"], *(c["sensitive_" + name] for name in COMPONENTS),
            c["all_joint"], -checkpoint["loss"], -checkpoint["step"])


def select(checkpoints):
    baseline = checkpoints[0]
    candidates = [row for row in checkpoints[1:] if eligible(row, baseline) and progress(row, baseline)]
    return max([baseline, *candidates], key=rank)


def decoded_logits(logits, config):
    """The NumPy float32 serving decoder, including first-index ties and confidence."""
    import numpy as np
    from privoke_contracts.classification import Sensitivity, Visibility, Category, initialise_unpacked
    arrays = {k: np.asarray(v, dtype=np.float32) for k, v in logits.items()}
    s = np.exp(arrays["sensitivity"] - arrays["sensitivity"].max())
    s = s / s.sum()
    v = np.exp(arrays["visibility"] - arrays["visibility"].max())
    v = v / v.sum()
    c = 1.0 / (1.0 + np.exp(-np.clip(arrays["category"], -30.0, 30.0)))
    packed = initialise_unpacked(Sensitivity[config["sensitivity_labels"][int(np.argmax(s))]],
        Visibility[config["visibility_labels"][int(np.argmax(v))]],
        [Category[label] for label, p in zip(config["category_labels"], c) if p >= config.get("category_threshold", .5)]).pack()
    return [packed, round(min(max(float(max(*s, *c)), 0.0), .999), 3)]


def action_value(packed, confidence=None):
    """Versioned exact production action predicate; parity tested against runtime policy."""
    from privoke_contracts.classification import Classification, Category, Visibility
    c = Classification(packed)
    severity = c.sensitivity().value
    identifiers = set(c.categories()) & {Category.IDENTITY, Category.LOCATION}
    if confidence is not None and confidence < .5:
        return 1 if severity == 3 or (severity == 2 and identifiers) else 0
    if severity >= 2:
        return severity - 1
    private = c.visibility() != Visibility.PU and c.visibility().value >= Visibility.P2.value
    return int(bool(identifiers) and (len(identifiers) > 1 or private))


def component_predicates(gold, original, original_confidence, candidate, candidate_confidence):
    from privoke_contracts.classification import Classification, Category
    g, o, c = map(Classification, (gold, original, candidate))
    return {"sensitivity": c.is_sensitive(),
        "severity": c.sensitivity().value >= min(g.sensitivity().value, o.sensitivity().value),
        "category": all(c.has_category(bit) == g.has_category(bit) for bit in Category
                        if o.has_category(bit) == g.has_category(bit)),
        "visibility": o.visibility() != g.visibility() or c.visibility() == g.visibility(),
        "action": action_value(candidate, candidate_confidence) >= min(action_value(gold), action_value(original, original_confidence))}


def checkpoint_counts(targets, predictions):
    from privoke_contracts.classification import Classification
    counts = {key: 0 for key in ("all_joint", "clean_joint", "sensitive_joint", "clean_specificity", "sensitive_recall",
              *(prefix + component for prefix in ("clean_", "sensitive_") for component in COMPONENTS))}
    if len(targets) != len(predictions):
        raise ValueError("Checkpoint row membership differs.")
    for packed, (candidate, confidence) in zip(targets, predictions):
        g, c = Classification(packed), Classification(candidate)
        prefix = "sensitive_" if g.is_sensitive() else "clean_"
        correct = {"sensitivity": c.is_sensitive() == g.is_sensitive(),
            "severity": c.sensitivity() == g.sensitivity(), "category": c.categories() == g.categories(),
            "visibility": c.visibility() == g.visibility(), "action": action_value(candidate, confidence) == action_value(packed)}
        for component, ok in correct.items():
            counts[prefix + component] += int(ok)
        joint = all(correct.values())
        counts[prefix + "joint"] += int(joint)
        counts["all_joint"] += int(joint)
        counts["sensitive_recall" if g.is_sensitive() else "clean_specificity"] += int(correct["sensitivity"])
    return counts


def packed_exact_rate(rows, checkpoint):
    """Preserve the configured legacy packed-classification exact floor."""
    if len(rows)!=len(checkpoint["predictions"]) or not rows:
        raise ValueError("Exact TRAIN metric membership differs.")
    return sum(row["packed"]==prediction[0] for row,prediction in zip(rows,checkpoint["predictions"]))/len(rows)


def execution_phases(trace):
    phases = [("training", trace["main"]["rows_completed"]),
              ("original_train_component_backward", trace["auxiliary"]["rows_completed"])]
    ordered = [f"checkpoint_{step}_{part}" for step in (0,*CONFIG["checkpoints"])
               for part in ("window","original_train")]
    if trace["guard"] is not None:
        ordered.extend(("base_heldout","candidate_heldout"))
    phases.extend((name,trace["work"]["phases"][name]["rows_completed"]) for name in ordered)
    return phases


def summary(trace, raw):
    selected = next(row for row in trace["checkpoints"] if row["step"] == trace["selected_step"])
    return {"schema": 1, "policy": POLICY, "trace_sha256": sha256(raw.encode()), "window": trace["window_sha256"],
        "references": trace["references_sha256"], "base": trace["base"], "terminal": trace["terminal"],
        "selected": trace["selected"], "selected_step": trace["selected_step"], "delta": trace["selected_delta"],
        "published": trace["published"], "status": trace["status"], "reason": trace["reason"],
        "main_rows": trace["main"]["rows_completed"], "auxiliary_rows": trace["auxiliary"]["rows_completed"],
        "checkpoint_rows": sum(v["rows_completed"] for k,v in trace["work"]["phases"].items() if k.startswith("checkpoint_")),
        "violations": selected["violations"], "guard_passed": trace["guard"] is not None and trace["guard"]["passed"],
        "sensitive_progress": progress(selected, trace["checkpoints"][0])}


def validate_trace(metadata, *, window, release, gradients, shapes):
    """Independently derive checkpoint decisions and work from retained immutable inputs."""
    from .fingerprint import parameter_fingerprint
    validate_policy(metadata)
    validate_window(window)
    validate_component_release(release, trusted_sha256=metadata[REFERENCE_KEY])
    raw = metadata.get(TRACE_KEY)
    if type(raw) is not str or len(raw.encode()) > 4 * 1024 * 1024:
        raise ValueError("Missing or excessive window trace.")
    trace = json.loads(raw)
    if (raw != canonical(trace) or trace["schema"] != 1 or trace["policy"] != POLICY or trace["config"] != CONFIG
            or trace["window_sha256"] != sha256(canonical_bytes(window)) or trace["window_sha256"] != metadata[WINDOW_KEY]
            or trace["references_sha256"] != metadata[REFERENCE_KEY] or trace["base"] != metadata["base_parameter_fingerprint"]
            or len(trace["steps"]) != 64 or [c["step"] for c in trace["checkpoints"]] != [0, *CONFIG["checkpoints"]]):
        raise ValueError("Window trace source/config/identity differs.")
    previous = trace["base"]
    for step, block, row in zip(range(1,65), schedule(window["seed"]), trace["steps"]):
        if (row["step"] != step or row["block"] != block or row["before"] != previous
                or not all(is_sha256(row[k]) for k in ("before", "after", "gradient", "moments", "delta"))
                or any(type(row[k]) not in (int,float) or not math.isfinite(row[k]) or row[k] < 0 for k in ("main_loss", "auxiliary_loss"))
                or type(row["clipped"]) is not int or row["clipped"] < 0):
            raise ValueError("Window Adam recurrence/schedule evidence differs.")
        previous = row["after"]
    if previous != trace["terminal"]:
        raise ValueError("Terminal fingerprint differs from step64.")
    references = [(s,r) for s,r in release.rows if r["components"]]
    targets = [r["packed"] for r in flat_rows(window)]
    expected_phases = {}
    layers = json.loads(metadata["model_config"]).get("num_layers", 1)
    for checkpoint in trace["checkpoints"]:
        step = checkpoint["step"]
        fingerprint = trace["base"] if step == 0 else trace["steps"][step-1]["after"]
        if checkpoint["fingerprint"] != fingerprint or checkpoint["counts"] != checkpoint_counts(targets, checkpoint["predictions"]):
            raise ValueError("Checkpoint state/independently recomputed counts differ.")
        for packed, confidence in checkpoint["predictions"] + checkpoint["original_predictions"]:
            if type(packed) is not int or not 0 <= packed <= 65535 or type(confidence) not in (int,float) or not 0 <= confidence <= .999 or round(confidence,3) != confidence:
                raise ValueError("Malformed checkpoint output.")
        if len(checkpoint["original_predictions"]) != len(references):
            raise ValueError("ORIGINAL TRAIN checkpoint membership differs.")
        predicates = [component_predicates(r["gold"], r["original"], r["confidence"], *prediction)
                      for (_,r), prediction in zip(references, checkpoint["original_predictions"])]
        if (checkpoint["violations"] != sum(not all(p.values()) for p in predicates)
                or checkpoint["component_violations"] != {c: sum(not p[c] for p in predicates) for c in COMPONENTS}
                or type(checkpoint["loss"]) not in (int,float) or not math.isfinite(checkpoint["loss"]) or checkpoint["loss"] < 0):
            raise ValueError("Checkpoint ORIGINAL component predicates/loss differ.")
        expected_phases[f"checkpoint_{step}_window"] = 512
        expected_phases[f"checkpoint_{step}_original_train"] = len(references)
    selected = select(trace["checkpoints"])
    if trace["selected_step"] != selected["step"] or trace["selected"] != selected["fingerprint"]:
        raise ValueError("Selected checkpoint differs from fixed TRAIN-only eligibility/rank.")
    if trace["guard"] is not None:
        if not selected["step"]:
            raise ValueError("BASE fallback must not execute a guard.")
        expected_phases.update(base_heldout=16, candidate_heldout=16)
        validate_guard(trace["guard"], window["guard"])
    if trace["status"] not in ("selected", "no_update"):
        raise ValueError("Successful trace requires known terminal outcome.")
    expected_outcome=("no_update","base_selected") if not selected["step"] else (
        ("no_update","no_transported_encoder_change") if trace["guard"] is None else
        (("selected","guard_passed") if trace["guard"]["passed"] else ("no_update","guard_failed")))
    if (trace["status"],trace["reason"])!=expected_outcome or (not selected["step"] and trace["selected_delta"] is not None):
        raise ValueError("Window terminal status/reason/BASE delta is contradictory.")
    if trace["status"] == "selected":
        if not selected["step"] or trace["guard"] is None or not trace["guard"]["passed"] or not gradients:
            raise ValueError("Publication requires sensitive progress and selected candidate guard.")
        if trace["published"] != selected["fingerprint"] or trace["selected_delta"] != parameter_fingerprint(gradients, shapes):
            raise ValueError("Selected delta/published state differs from winner.")
    elif gradients or trace["published"] != trace["base"]:
        raise ValueError("Known no_update must retain immutable BASE without deltas.")
    if selected["step"] and trace["selected_delta"] != trace["steps"][selected["step"]-1]["delta"]:
        raise ValueError("Selected delta differs from exact transported step.")
    if set(trace["work"]["phases"]) != set(expected_phases):
        raise ValueError("Unexpected/fabricated NumPy execution phase.")
    for name, count in expected_phases.items():
        if trace["work"]["phases"][name] != {"rows_attempted": count, "rows_completed": count,
                                               "blocks_attempted": count*layers, "blocks_completed": count*layers}:
            raise ValueError("Observed NumPy row/block accounting differs.")
    for work, rows, batches in ((trace["main"],4096,128),(trace["auxiliary"],64*len(references),64*math.ceil(len(references)/32))):
        expected = {"directions_attempted":64,"directions_completed":64,"rows_attempted":rows,"rows_completed":rows,
            "microbatch_forward_attempted":batches,"microbatch_forward_completed":batches,
            "microbatch_backward_started":batches,"microbatch_backward_completed":batches,
            "torch_block_forwards_attempted":batches*layers,"torch_block_forwards_completed":batches*layers}
        if work != expected:
            raise ValueError("Observed main/auxiliary backward accounting differs.")
    if trace["work"]["objective_attempted"] != 9 or trace["work"]["objective_completed"] != 9:
        raise ValueError("Checkpoint objective accounting differs.")
    if metadata.get(SUMMARY_KEY) != canonical(summary(trace, raw)) or len(metadata[SUMMARY_KEY].encode()) > 2048:
        raise ValueError("Compact winner/terminal summary differs from full retained trace.")
    if metadata.get("updated_parameter_fingerprint") != trace["published"] or metadata.get("window_outcome") != trace["status"]:
        raise ValueError("Response outcome/state differs from trace.")
    return trace


def validate_guard(guard, rows):
    from privoke_contracts.classification import Classification
    targets = [Classification(r["packed"]) for r in rows]
    if len(guard["before"]) != 16 or len(guard["after"]) != 16:
        raise ValueError("Selected guard execution membership differs.")
    def counts(predictions):
        return {"exact": sum(t.pack()==p[0] for t,p in zip(targets,predictions)),
            "recall": sum(Classification(p[0]).is_sensitive() for t,p in zip(targets,predictions) if t.is_sensitive()),
            "specificity": sum(not Classification(p[0]).is_sensitive() for t,p in zip(targets,predictions) if not t.is_sensitive())}
    before, after = counts(guard["before"]), counts(guard["after"])
    regressions = sum(Classification(a[0]).sensitivity().value < min(t.sensitivity().value, Classification(b[0]).sensitivity().value)
        or action_value(a[0],a[1]) < min(action_value(t.pack()),action_value(b[0],b[1]))
        for t,b,a in zip(targets,guard["before"],guard["after"])) / 16
    passed = all(after[k]>=before[k] for k in before) and regressions==0
    if guard != {"before":guard["before"],"after":guard["after"],"base_counts":before,"candidate_counts":after,
                 "regression_rate":regressions,"passed":passed}:
        raise ValueError("Selected guard predicates differ.")


def validate_publication(request, artifact):
    """Updater boundary: full inventory and exact selected delta/state, never terminal substitution."""
    from .artifact import float32, updated_parameter_values
    from .fingerprint import parameter_fingerprint
    if not validate_policy(artifact.get("metadata",{})):
        if request.metadata.get("contextual_training_optimizer")==POLICY:
            raise ValueError("Window publication requires its actual prepared artifact policy.")
        return
    validate_policy(request.metadata)
    for key in (CONFIG_KEY,WINDOW_KEY,REFERENCE_KEY):
        if request.metadata[key]!=artifact["metadata"][key]:
            raise ValueError("Selected publication differs from prepared artifact source/config pins.")
    raw=request.metadata.get(SUMMARY_KEY)
    if type(raw) is not str or len(raw.encode())>2048:
        raise ValueError("Missing compact selected checkpoint publication summary.")
    summary_value=json.loads(raw)
    keys={"schema","policy","trace_sha256","window","references","base","terminal","selected","selected_step","delta","published",
        "status","reason","main_rows","auxiliary_rows","checkpoint_rows","violations","guard_passed","sensitive_progress"}
    if (raw!=canonical(summary_value) or set(summary_value)!=keys or summary_value["schema"]!=1 or summary_value["policy"]!=POLICY
            or summary_value["status"]!="selected" or summary_value["reason"]!="guard_passed"
            or summary_value["guard_passed"] is not True or summary_value["sensitive_progress"] is not True or summary_value["violations"]!=0
            or summary_value["window"]!=artifact["metadata"][WINDOW_KEY] or summary_value["references"]!=artifact["metadata"][REFERENCE_KEY]
            or type(summary_value["selected_step"]) is not int or summary_value["selected_step"] not in CONFIG["checkpoints"]
            or summary_value["main_rows"]!=4096 or type(summary_value["auxiliary_rows"]) is not int
            or summary_value["auxiliary_rows"]%64 or not 20*64<=summary_value["auxiliary_rows"]<=200*64
            or summary_value["checkpoint_rows"]!=9*(512+summary_value["auxiliary_rows"]//64)
            or summary_value["published"]!=summary_value["selected"]
            or any(not is_sha256(summary_value[k]) for k in ("trace_sha256","base","terminal","selected","delta","published"))
            or not is_sha256(request.metadata.get("training_evidence_sha256"))):
        raise ValueError("Invalid selected-versus-terminal checkpoint publication evidence.")
    parameters=artifact["parameters"]
    shapes={n:tuple(t["shape"]) for n,t in parameters.items()}
    gradients={p.name:tuple(p.values) for p in request.gradients}
    if len(gradients)!=len(request.gradients) or set(gradients)!=set(parameters):
        raise ValueError("Window publication requires exact complete FULL tensor inventory.")
    if parameter_fingerprint(gradients,shapes)!=summary_value["delta"]:
        raise ValueError("Published delta differs from selected transported checkpoint.")
    if request.metadata.get("updated_parameter_fingerprint")!=summary_value["selected"] or request.metadata.get("base_parameter_fingerprint")!=summary_value["base"]:
        raise ValueError("Publication state identity differs from selected summary.")
    # An identical committed payload is checked by the updater's receipt path;
    # stale uncommitted requests still fail apply_parameter_update's version check.
    if artifact["version"]==request.base_version:
        base={n:tuple(float32(v) for v in t["values"]) for n,t in parameters.items()}
        updated={n:tuple(float32(v) for v in updated_parameter_values(base[n],gradients[n])) for n in base}
        if (parameter_fingerprint(base,shapes)!=summary_value["base"]
                or parameter_fingerprint(updated,shapes)!=summary_value["selected"]
                or request.metadata.get("artifact_checksum")!=artifact["checksum"]):
            raise ValueError("Actual updater BASE/transported selected state differs from admitted runtime identity.")
