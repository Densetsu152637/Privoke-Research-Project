"""Fixed opt-in FULL Adam contract; no default training policy is changed."""
from __future__ import annotations

import copy
import hashlib
import json
import math

POLICY = "full_projected_adam64_v1"
ELIGIBILITY = "candidate_train_exact_eligibility_v1"
ELIGIBILITY_KEY = "contextual_candidate_eligibility"
EXECUTED_KEY = "executed_contextual_training_optimizer"
TRACE_KEY = "full_projected_adam_trace_v1"
SUMMARY_KEY = "full_projected_adam_summary_v1"
CONFIG_KEY = "full_projected_adam_config_v1"
CONFIG = {"steps": 64, "eta": .003, "beta1": .9, "beta2": .999, "epsilon": 1e-8,
          "delta_cap": .05, "margin_coefficient": 1, "device": "cpu", "moment_dtype": "float64",
          "gradient_denominator": 1, "microbatch_size": 32, "cpu_threads": 1}
OBJECTIVE = "class_balanced_contextual_sum_category_decision_margin_v1"
STRATEGY = "contextual_full_encoder_sgd_v1"
OPTIMIZER_KEY = "contextual_training_optimizer"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def validate_policy(metadata):
    """Validate artifact policy including dormant HEAD capability, before any fit."""
    from . import window_training as window
    if metadata.get(OPTIMIZER_KEY) == window.POLICY:
        return window.validate_policy(metadata)
    window.validate_policy(metadata)
    from . import sensitive_retention as retention
    if metadata.get(OPTIMIZER_KEY) in retention.POLICIES:
        return retention.validate_policy(metadata)
    retention.validate_policy(metadata)
    active = metadata.get(OPTIMIZER_KEY) == POLICY
    if not active:
        if ELIGIBILITY_KEY in metadata or CONFIG_KEY in metadata:
            raise ValueError("FULL Adam configuration/eligibility requires its optimizer.")
        return False
    if (metadata.get("contextual_training_strategy") != STRATEGY
            or metadata.get("contextual_training_objective") != OBJECTIVE
            or metadata.get(ELIGIBILITY_KEY) != ELIGIBILITY
            or metadata.get(CONFIG_KEY) != canonical(CONFIG)
            or any(k in metadata for k in ("contextual_training_backtracking_policy",
                "contextual_training_backtracking_preparation", "contextual_training_diagnostics_policy"))):
        raise ValueError("FULL Adam requires its exact FULL, SUM-margin, fixed config and eligibility contract.")
    return True


def expectations(metadata):
    from .window_training import expectations as window_expectations
    window = window_expectations(metadata)
    if window is not None:
        return window
    from .sensitive_retention import expectations as retention_expectations
    retention = retention_expectations(metadata)
    if retention is not None:
        return retention
    optimizer = metadata.get("expected_contextual_training_optimizer")
    eligibility = metadata.get("expected_contextual_candidate_eligibility")
    config = metadata.get("expected_full_projected_adam_config_v1")
    scope = metadata.get("expected_contextual_training_scope")
    if optimizer is None and eligibility is None and config is None and scope is None:
        return {}
    if (optimizer != POLICY or eligibility != ELIGIBILITY or config != canonical(CONFIG) or scope not in ("heads", "full_encoder")
            or metadata.get("expected_contextual_training_objective") != OBJECTIVE
            or metadata.get("expected_contextual_training_diagnostics_policy") is not None
            or metadata.get("expected_contextual_training_backtracking_policy") is not None):
        raise ValueError("FULL Adam admission requires exact optimizer, eligibility, config and objective.")
    return {"expected_optimizer": POLICY, "expected_candidate_eligibility": ELIGIBILITY,
            "expected_optimizer_config": canonical(CONFIG), "expected_training_scope": scope}


def validate_admission(admission, metadata):
    from . import window_training as window
    if metadata.get(OPTIMIZER_KEY) == window.POLICY:
        window.validate_admission(admission, metadata)
        return True
    from . import sensitive_retention as retention
    if metadata.get(OPTIMIZER_KEY) in retention.POLICIES:
        retention.validate_admission(admission, metadata)
        return True
    active = validate_policy(metadata)
    expected = {"expected_optimizer": POLICY, "expected_candidate_eligibility": ELIGIBILITY,
                "expected_optimizer_config": canonical(CONFIG)}
    if active:
        if admission is None or any(admission.get(k) != v for k, v in expected.items()):
            raise ValueError("FULL Adam artifact requires matching explicit pre-gradient admission.")
    elif admission is not None and any(k in admission for k in expected):
        raise ValueError("FULL Adam admission differs from actual artifact.")
    return active


def prepare_artifact(artifact):
    from .artifact import validate_artifact, artifact_checksum
    validate_artifact(artifact)
    result = copy.deepcopy(artifact)
    meta = result["metadata"]
    if OPTIMIZER_KEY in meta or "contextual_training_backtracking_policy" in meta:
        raise ValueError("FULL Adam preparation rejects existing optimizer/backtracking mixtures.")
    meta.update({OPTIMIZER_KEY: POLICY, ELIGIBILITY_KEY: ELIGIBILITY,
                 CONFIG_KEY: canonical(CONFIG)})
    validate_policy(meta)
    result["checksum"] = artifact_checksum({k: v for k, v in result.items() if k != "checksum"})
    validate_artifact(result)
    return result


def validate_trace(metadata, *, scope, examples, candidate_fingerprint, delta_fingerprint):
    """Validate prompt-free detailed evidence and its independently bound summary."""
    from . import sensitive_retention as retention
    if metadata.get(OPTIMIZER_KEY) in retention.POLICIES:
        return retention.validate_trace(metadata, scope=scope, examples=examples,
            candidate_fingerprint=candidate_fingerprint, delta_fingerprint=delta_fingerprint)
    if metadata.get(OPTIMIZER_KEY) != POLICY or metadata.get(CONFIG_KEY) != canonical(CONFIG):
        raise ValueError("Missing FULL Adam artifact policy/config identity.")
    executed = metadata.get(EXECUTED_KEY)
    if scope == "heads":
        if executed != "dormant_head_v1" or TRACE_KEY in metadata or SUMMARY_KEY in metadata or ELIGIBILITY_KEY in metadata:
            raise ValueError("HEAD must report dormant Adam without candidate eligibility.")
        return None
    if scope != "full_encoder" or executed != POLICY or metadata.get(ELIGIBILITY_KEY) != ELIGIBILITY:
        raise ValueError("Candidate eligibility requires actual FULL Adam execution.")
    raw = metadata.get(TRACE_KEY)
    if type(raw) is not str or len(raw.encode()) > 131072:
        raise ValueError("Missing or excessive FULL Adam detailed trace.")
    trace = json.loads(raw)
    summary = json.loads(metadata[SUMMARY_KEY])
    if raw != canonical(trace) or metadata[SUMMARY_KEY] != canonical(summary):
        raise ValueError("FULL Adam evidence must use canonical JSON.")
    if (set(trace) != {"schema", "policy", "config", "base", "final", "delta", "steps", "counts", "train"}
            or trace["schema"] != 1 or trace["policy"] != POLICY or trace["config"] != CONFIG
            or trace["base"] != metadata.get("base_parameter_fingerprint")
            or trace["final"] != candidate_fingerprint or trace["delta"] != delta_fingerprint
            or trace["train"] != examples or len(trace["steps"]) != 64
            or summary != {"schema": 1, "policy": POLICY, "trace_sha256": hashlib.sha256(raw.encode()).hexdigest(),
                "base": trace["base"], "final": trace["final"], "delta": trace["delta"], "counts": trace["counts"],
                "eligibility": ELIGIBILITY, "metric": "candidate_train_exact_match_rate"}):
        raise ValueError("FULL Adam trace/summary identity differs.")
    previous = trace["base"]
    for step, row in enumerate(trace["steps"], 1):
        if (set(row) != {"step", "before", "after", "loss", "gradient", "moments", "delta", "clipped"}
                or row["step"] != step or row["before"] != previous
                or type(row["loss"]) not in (int, float) or not math.isfinite(row["loss"]) or row["loss"] < 0
                or type(row["clipped"]) is not int or row["clipped"] < 0
                or any(type(row[k]) is not str or len(row[k]) != 64
                       or any(c not in "0123456789abcdef" for c in row[k])
                       for k in ("before", "after", "gradient", "moments", "delta"))):
            raise ValueError("Malformed FULL Adam step recurrence evidence.")
        previous = row["after"]
    if previous != trace["final"] or trace["steps"][-1]["delta"] != trace["delta"]:
        raise ValueError("FULL Adam final state differs from recurrence.")
    batches = math.ceil(examples / 32)
    counts = trace["counts"]
    if (counts.get("directions_attempted") != 64 or counts.get("directions_completed") != 64
            or counts.get("microbatch_forward_attempted") != 64 * batches
            or counts.get("microbatch_forward_completed") != 64 * batches
            or counts.get("microbatch_backward_started") != 64 * batches
            or counts.get("microbatch_backward_completed") != 64 * batches
            or counts.get("train_parameter_states") != 65):
        raise ValueError("FULL Adam actual direction/microbatch/state accounting differs.")
    return trace
