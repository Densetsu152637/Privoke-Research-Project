"""Opt-in fixed ORIGINAL TRAIN retention contracts; no model execution here."""
from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path

from .full_adam import CONFIG, CONFIG_KEY, OPTIMIZER_KEY, ELIGIBILITY_KEY, STRATEGY, canonical

GATE_POLICY = "full_projected_adam64_original_train_gate_v1"
HINGE_POLICY = "full_projected_adam64_original_train_hinge_v1"
POLICIES = frozenset((GATE_POLICY, HINGE_POLICY))
GATE_OBJECTIVE = "class_balanced_contextual_sum_margin_original_gate_v1"
HINGE_OBJECTIVE = "class_balanced_contextual_sum_margin_original_hinge_v1"
OBJECTIVES = {GATE_POLICY: GATE_OBJECTIVE, HINGE_POLICY: HINGE_OBJECTIVE}
ELIGIBILITY = "candidate_train_exact_original_target_capped_v1"
MANIFEST_KEY = "original_train_retention_manifest_sha256"
TRACE_KEY = "original_train_retention_trace_v1"
SUMMARY_KEY = "original_train_retention_summary_v1"
EPSILON = 1e-6
DATASET_SHA256 = "3b777f328a8e08140ee964facbd559c694673336b4c5655320befdd84aef66e0"
LEGACY_SHA256 = "04db8a469aa5c430f9333829da015f01b4377eb5268c58c1451c63b0a51dcced"
BANK_SHA256 = "c9b0b64133e6474487c1d3fe2ac9410c720b19a1f1571469dc8c3483f4e4a41a"
LABEL_REVIEW_SHA256 = "7ddca38130b65c167945f8c0f822caee3012b25787000edfbf311f6d89a0a7fe"
TEACHER_SHA256 = {
    "quality": "50657f82e52bb2df56e0ce57c3124a7d7b97a9d9ea338e5eac3c42552fb40733",
    "balanced": "4e991e8f1c3e6211e824613fa8eee2fdc6f0cec6ec9a5e817dbf1c17802cf8a1",
    "efficient": "a23e986915225373663ed7a017d13fa82aac8c3a266ff5a3f4943b129d92e4ef",
}
BOUNDARY = {"version": "original_sensitive_strict_margin_gap_v1", "epsilon": EPSILON,
            "gold_non_s0": True, "decoded_sensitive": True, "packed_exact": False,
            "teacher_at_least_gold": False, "required_groups": 20}
NORMALIZATION = {"main": "unchanged_class_balanced_weight_mean", "auxiliary": "unweighted_eligible_mean",
                 "coefficient": 1, "gradient_denominator": 1, "microbatch_size": 32}


def canonical_bytes(value):
    """Commit canonical Unicode JSON followed by one actual LF byte."""
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                       allow_nan=False) + "\n").encode("utf-8")


def sha256(payload):
    return hashlib.sha256(payload).hexdigest()


def is_sha256(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def parse_canonical(payload, limit=4 * 1024 * 1024):
    if type(payload) is not bytes or len(payload) > limit:
        raise ValueError("Retention sidecar exceeds its byte budget.")
    value = json.loads(payload)
    if canonical_bytes(value) != payload:
        raise ValueError("Retention sidecar must be canonical JSON with one LF.")
    return value


def validate_bank(payload):
    """An independent accepted full-row commitment prevents caller relabeling."""
    from privoke_contracts.classification import Classification
    rows = parse_canonical(payload)
    if (sha256(payload) != BANK_SHA256 or type(rows) is not list or len(rows) != 200
            or rows != sorted(rows, key=lambda r: r["id"])):
        raise ValueError("Retention bank differs from the independently approved200 TRAIN rows.")
    if any(r["metadata"].get("taxonomy_partition") != "train" or r["metadata"].get("split") != "train"
           or Classification(r["packed_classification"]).sensitivity().value == 0 for r in rows):
        raise ValueError("Retention bank requires approved positive permanent TRAIN only.")
    if len({r["metadata"]["group_id"] for r in rows}) != 20:
        raise ValueError("Retention bank must cover exactly20 approved groups.")
    return rows


def load_original_artifact(path, profile):
    """Bind load_artifact's validated value to the same independently pinned bytes."""
    from .artifact import load_artifact
    path = Path(path)
    raw = path.read_bytes()
    if profile not in TEACHER_SHA256 or path.is_symlink() or sha256(raw) != TEACHER_SHA256[profile]:
        raise ValueError("Retention teacher differs from the fixed ORIGINAL artifact bytes.")
    artifact = load_artifact(path)
    if artifact != json.loads(raw):
        raise ValueError("Retention ORIGINAL artifact changed across authentication/loading.")
    return artifact


def original_effective_parameters(artifact):
    """SR01 evaluation identity uses float32, without changing authenticated bytes.

    Callers authenticate the ORIGINAL artifact separately. Tiny evaluation and
    protobuf repeated float values both use these effective tensor values; the
    general fingerprint function and raw artifact checksum stay unchanged.
    """
    from .artifact import float32
    return {name: tuple(float32(value) for value in tensor["values"])
            for name, tensor in artifact["parameters"].items()}


def teacher_identity(path, profile):
    """Authenticate raw ORIGINAL bytes; fingerprint their effective float32 values."""
    from .fingerprint import parameter_fingerprint
    artifact = load_original_artifact(path, profile)
    parameters = original_effective_parameters(artifact)
    shapes = {n: tuple(t["shape"]) for n, t in artifact["parameters"].items()}
    if artifact["model_id"] != "privoke-" + profile:
        raise ValueError("Retention teacher profile differs.")
    return {"profile": profile, "file_sha256": TEACHER_SHA256[profile], "checksum": artifact["checksum"],
            "model_id": artifact["model_id"], "version": artifact["version"], "config": artifact["config"],
            "parameter_fingerprint": parameter_fingerprint(parameters, shapes),
            "inventory_fingerprint": parameter_fingerprint({n: () for n in parameters}, shapes)}


def validate_references(payload, bank, teacher):
    from privoke_contracts.classification import Classification
    value = parse_canonical(payload)
    if (type(value) is not dict or set(value) != {"schema", "teacher", "bank_sha256", "boundary", "rows"}
            or value["schema"] != 1 or value["teacher"] != teacher or value["bank_sha256"] != BANK_SHA256
            or value["boundary"] != BOUNDARY or len(value["rows"]) != len(bank)):
        raise ValueError("Retention references differ from original teacher/bank/boundary policy.")
    groups = set()
    for row, source in zip(value["rows"], bank):
        if (set(row) != {"id", "packed", "confidence", "margin", "sensitivity_gap", "eligible"}
                or row["id"] != source["id"] or type(row["packed"]) is not int
                or not 0 <= row["packed"] <= 65535
                or any(type(row[k]) not in (int, float) or not math.isfinite(row[k]) for k in
                       ("confidence", "margin", "sensitivity_gap"))
                or not 0 <= row["confidence"] <= .999
                or row["confidence"] != round(row["confidence"], 3)
                or row["sensitivity_gap"] < 0 or type(row["eligible"]) is not bool):
            raise ValueError("Malformed ordered ORIGINAL TRAIN reference.")
        decoded = Classification(row["packed"])
        # Validate visibility encoding too; invalid packed labels fail before compute.
        decoded.visibility()
        eligible = decoded.is_sensitive() and row["margin"] > EPSILON and row["sensitivity_gap"] > EPSILON
        if row["eligible"] != eligible:
            raise ValueError("Retention eligibility mask differs from the fixed strict policy.")
        if eligible:
            groups.add(source["metadata"]["group_id"])
    if len(groups) != 20:
        raise ValueError("Retention requires eligible ORIGINAL coverage in every20 TRAIN group; no backfill.")
    return value


def manifest_value(bank_payload, reference_payload, teacher):
    bank = validate_bank(bank_payload)
    refs = validate_references(reference_payload, bank, teacher)
    return {"schema": 1, "kind": "original_train_retention_v1", "dataset_sha256": DATASET_SHA256,
            "legacy_snapshot_sha256": LEGACY_SHA256, "bank_sha256": BANK_SHA256,
            "label_review_sha256": LABEL_REVIEW_SHA256, "references_sha256": sha256(reference_payload),
            "teacher": teacher, "boundary": BOUNDARY, "normalization": NORMALIZATION,
            "eligible_ids": [r["id"] for r in refs["rows"] if r["eligible"]], "fit_release": False}


@dataclass(frozen=True)
class RetentionRelease:
    """Only immutable bytes cross service/trainer boundaries; parsed maps are fresh."""
    bank_payload: bytes
    reference_payload: bytes
    manifest_payload: bytes
    teacher_path: str

    @property
    def sha256(self):
        return sha256(self.manifest_payload)

    @property
    def manifest(self):
        return parse_canonical(self.manifest_payload)

    @property
    def eligible(self):
        bank = validate_bank(self.bank_payload)
        refs = parse_canonical(self.reference_payload)["rows"]
        return tuple((s, r) for s, r in zip(bank, refs) if r["eligible"])


def validate_release(release, *, model_id=None, expected_sha256=None):
    """Validate structure; an optional hash here is not a server trust anchor.

    Preparation may construct a new manifest. Training boundaries additionally
    call validate_trusted_release with a separately configured accepted pin.
    """
    if type(release) is not RetentionRelease:
        raise ValueError("Retention requires its immutable authenticated release snapshot.")
    manifest = release.manifest
    teacher = teacher_identity(release.teacher_path, manifest["teacher"]["profile"])
    if release.manifest_payload != canonical_bytes(manifest_value(release.bank_payload, release.reference_payload, teacher)):
        raise ValueError("Retention manifest/reference/bank/teacher snapshot differs.")
    if (model_id is not None and teacher["model_id"] != model_id) or (expected_sha256 is not None and release.sha256 != expected_sha256):
        raise ValueError("Retention profile or requested immutable manifest pin differs.")
    return release


def validate_trusted_release(release, *, model_id, request_sha256, trusted_sha256):
    if (not is_sha256(trusted_sha256) or request_sha256 != trusted_sha256):
        raise ValueError("Retention requires a distinct trusted configured accepted manifest SHA, matching the request.")
    return validate_release(release, model_id=model_id, expected_sha256=trusted_sha256)


def load_release(bank_path, reference_path, manifest_path, teacher_path, **expected):
    paths = [Path(p) for p in (bank_path, reference_path, manifest_path, teacher_path) if p]
    if len(paths) != 4 or any(p.is_symlink() for p in paths):
        raise ValueError("Retention requires four explicit non-symlink read-only sidecar paths.")
    return validate_release(RetentionRelease(*(p.read_bytes() for p in paths[:3]), str(paths[3])), **expected)


def validate_policy(metadata):
    policy = metadata.get(OPTIMIZER_KEY)
    if policy not in POLICIES:
        if MANIFEST_KEY in metadata:
            raise ValueError("Orphan ORIGINAL retention artifact pin.")
        return False
    if (metadata.get("contextual_training_strategy") != STRATEGY
            or metadata.get("contextual_training_objective") != OBJECTIVES[policy]
            or metadata.get(ELIGIBILITY_KEY) != ELIGIBILITY or metadata.get(CONFIG_KEY) != canonical(CONFIG)
            or not is_sha256(metadata.get(MANIFEST_KEY))
            or any(k in metadata for k in ("contextual_training_backtracking_policy",
                   "contextual_training_backtracking_preparation", "contextual_training_diagnostics_policy"))):
        raise ValueError("Retention requires its exact versioned optimizer/objective/config/admission/manifest.")
    return True


def expectations(metadata):
    policy = metadata.get("expected_contextual_training_optimizer")
    if policy not in POLICIES:
        if "expected_" + MANIFEST_KEY in metadata:
            raise ValueError("Orphan ORIGINAL retention request pin.")
        return None
    pin = metadata.get("expected_" + MANIFEST_KEY)
    if (metadata.get("expected_contextual_training_objective") != OBJECTIVES[policy]
            or metadata.get("expected_contextual_candidate_eligibility") != ELIGIBILITY
            or metadata.get("expected_full_projected_adam_config_v1") != canonical(CONFIG)
            or metadata.get("expected_contextual_training_scope") != "full_encoder"
            or not is_sha256(pin) or metadata.get("expected_contextual_training_diagnostics_policy") is not None
            or metadata.get("expected_contextual_training_backtracking_policy") is not None):
        raise ValueError("Retention admission requires exact FULL policy/config/objective and immutable manifest pin.")
    return {"expected_optimizer": policy, "expected_candidate_eligibility": ELIGIBILITY,
            "expected_optimizer_config": canonical(CONFIG), "expected_training_scope": "full_encoder",
            "expected_retention_manifest_sha256": pin}


def validate_admission(admission, metadata):
    if not validate_policy(metadata):
        raise ValueError("Retention admission requires its actual artifact policy.")
    policy = metadata[OPTIMIZER_KEY]
    if (admission is None or admission.get("expected_optimizer") != policy
            or admission.get("expected_objective") != OBJECTIVES[policy]
            or admission.get("expected_candidate_eligibility") != ELIGIBILITY
            or admission.get("expected_optimizer_config") != canonical(CONFIG)
            or admission.get("expected_training_scope") != "full_encoder"
            or admission.get("expected_retention_manifest_sha256") != metadata[MANIFEST_KEY]):
        raise ValueError("Retention artifact differs from pre-gradient admission.")


def prepare_artifact(artifact, policy, release):
    from .artifact import validate_artifact, artifact_checksum
    validate_artifact(artifact)
    validate_release(release, model_id=artifact["model_id"])
    if policy not in POLICIES:
        raise ValueError("Unsupported retention optimizer.")
    result = copy.deepcopy(artifact)
    meta = result["metadata"]
    if meta.get(OPTIMIZER_KEY) not in (None, "full_projected_adam64_v1"):
        raise ValueError("Retention preparation rejects policy mixtures.")
    meta.update({OPTIMIZER_KEY: policy, "contextual_training_objective": OBJECTIVES[policy],
                 ELIGIBILITY_KEY: ELIGIBILITY, CONFIG_KEY: canonical(CONFIG), MANIFEST_KEY: release.sha256})
    validate_policy(meta)
    result["checksum"] = artifact_checksum({k: v for k, v in result.items() if k != "checksum"})
    validate_artifact(result)
    return result


def execution_phases(metadata):
    """Only a validated bounded summary may extend the old three-phase contract."""
    summary = json.loads(metadata[SUMMARY_KEY])
    count = summary["eligible"]
    if type(count) is not int or not 20 <= count <= 200:
        raise ValueError("Retention auxiliary execution count differs.")
    phases = [("base_original_train_safety", count), ("original_train_safety", count)]
    if metadata.get(OPTIMIZER_KEY) == HINGE_POLICY:
        phases.insert(0, ("original_train_hinge", 64 * count))
    return phases


def validate_trace(metadata, *, scope, examples, candidate_fingerprint, delta_fingerprint):
    from . import full_adam
    validate_policy(metadata)
    policy = metadata[OPTIMIZER_KEY]
    if scope != "full_encoder" or metadata.get(full_adam.EXECUTED_KEY) != policy:
        raise ValueError("Retention requires actual FULL execution; HEAD is not admitted.")
    raw = metadata.get(TRACE_KEY)
    if type(raw) is not str or len(raw.encode()) > 524288:
        raise ValueError("Missing or excessive ORIGINAL retention raw trace.")
    trace = json.loads(raw)
    if (raw != canonical(trace) or set(trace) != {"schema", "policy", "manifest_sha256", "adam", "auxiliary", "base_safety", "safety"}
            or trace["schema"] != 1 or trace["policy"] != policy
            or trace["manifest_sha256"] != metadata[MANIFEST_KEY]):
        raise ValueError("Retention trace identity differs from immutable admission.")
    adam = trace["adam"]
    base_meta = {**metadata, OPTIMIZER_KEY: full_adam.POLICY, ELIGIBILITY_KEY: full_adam.ELIGIBILITY,
                 full_adam.EXECUTED_KEY: full_adam.POLICY, full_adam.TRACE_KEY: canonical(adam)}
    base_meta.pop(MANIFEST_KEY, None)
    base_meta[full_adam.SUMMARY_KEY] = canonical({"schema": 1, "policy": full_adam.POLICY,
        "trace_sha256": sha256(canonical(adam).encode()), "base": adam["base"], "final": adam["final"],
        "delta": adam["delta"], "counts": adam["counts"], "eligibility": full_adam.ELIGIBILITY,
        "metric": "candidate_train_exact_match_rate"})
    full_adam.validate_trace(base_meta, scope=scope, examples=examples,
        candidate_fingerprint=candidate_fingerprint, delta_fingerprint=delta_fingerprint)
    safety = trace["safety"]
    if (type(safety) is not list or not 20 <= len(safety) <= 200
            or len({r["id"] for r in safety}) != len(safety)):
        raise ValueError("Retention safety trace requires distinct eligible rows.")
    if (type(trace["base_safety"]) is not list or len(trace["base_safety"]) != len(safety)
            or [r["id"] for r in trace["base_safety"]] != [r["id"] for r in safety]):
        raise ValueError("Retention base/final auxiliary membership differs.")
    for row in trace["base_safety"] + safety:
        if (set(row) != {"id", "gold", "original", "candidate", "original_confidence", "candidate_confidence",
                         "gold_action", "original_action", "candidate_action", "violation",
                         "original_margin", "candidate_margin", "hinge"}
                or any(type(row[k]) is not int or not 0 <= row[k] <= 65535 for k in ("gold", "original", "candidate"))
                or any(type(row[k]) is not int or not 0 <= row[k] <= 2 for k in ("gold_action", "original_action", "candidate_action"))
                or any(type(row[k]) not in (int, float) or not math.isfinite(row[k]) or not 0 <= row[k] <= .999
                       or round(row[k], 3) != row[k] for k in ("original_confidence", "candidate_confidence"))
                or type(row["violation"]) is not bool):
            raise ValueError("Malformed target-capped per-row safety trace.")
        if (any(type(row[k]) not in (int, float) or not math.isfinite(row[k]) for k in
                ("original_margin", "candidate_margin", "hinge"))
                or row["hinge"] != max(0.0, row["original_margin"] - row["candidate_margin"])):
            raise ValueError("Retention raw per-row margin/exact hinge differs.")
        from privoke_contracts.classification import Classification
        target, original, candidate = (Classification(row[k]) for k in ("gold", "original", "candidate"))
        violation = (not candidate.is_sensitive() or candidate.sensitivity().value < min(target.sensitivity().value, original.sensitivity().value)
                     or row["candidate_action"] < min(row["gold_action"], row["original_action"]))
        if row["violation"] != violation:
            raise ValueError("Per-row target-capped safety predicate differs.")
    auxiliary = trace["auxiliary"]
    if set(auxiliary) != {"counts", "steps"}:
        raise ValueError("Retention auxiliary work schema differs.")
    if policy == GATE_POLICY:
        if auxiliary != {"counts": {}, "steps": []}:
            raise ValueError("Gate-only control must not perform padded auxiliary gradients.")
    else:
        count, batches = len(safety), math.ceil(len(safety) / 32)
        expected = {"directions_attempted": 64, "directions_completed": 64,
                    "rows_attempted": 64 * count, "rows_completed": 64 * count,
                    "microbatch_forward_attempted": 64 * batches, "microbatch_forward_completed": 64 * batches,
                    "microbatch_backward_started": 64 * batches, "microbatch_backward_completed": 64 * batches}
        if any(auxiliary["counts"].get(k) != v for k, v in expected.items()) or len(auxiliary["steps"]) != 64:
            raise ValueError("Retention actual auxiliary work count differs.")
        for index, step in enumerate(auxiliary["steps"], 1):
            if (set(step) != {"step", "main_loss", "auxiliary_loss", "main_gradient_norm", "auxiliary_gradient_norm", "gradient_dot",
                             "active_rows", "maximum_hinge", "original_state_parity_scaled_error"}
                    or step["step"] != index or any(type(step[k]) not in (int, float) or not math.isfinite(step[k])
                        or (k != "gradient_dot" and step[k] < 0) for k in step.keys() - {"step", "original_state_parity_scaled_error"})
                    or type(step["active_rows"]) is not int or not 0 <= step["active_rows"] <= count
                    or (step["original_state_parity_scaled_error"] is not None and
                        (type(step["original_state_parity_scaled_error"]) not in (int, float)
                         or not math.isfinite(step["original_state_parity_scaled_error"]) or step["original_state_parity_scaled_error"] < 0))):
                raise ValueError("Malformed independently normalized main/auxiliary diagnostics.")
    summary = {"schema": 1, "policy": policy, "manifest_sha256": metadata[MANIFEST_KEY],
               "trace_sha256": sha256(raw.encode()), "base": adam["base"], "final": adam["final"],
               "delta": adam["delta"], "eligible": len(safety), "violations": sum(r["violation"] for r in safety),
               "auxiliary": auxiliary["counts"]}
    if metadata.get(SUMMARY_KEY) != canonical(summary) or len(canonical(summary).encode()) > 2048:
        raise ValueError("Retention bounded summary differs from complete retained raw trace.")
    return trace
