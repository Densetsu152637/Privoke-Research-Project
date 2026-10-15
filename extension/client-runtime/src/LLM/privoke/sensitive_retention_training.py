"""Runtime-only ORIGINAL reference authentication and production safety semantics."""
from __future__ import annotations

import json
import math
import os

from privoke_model import sensitive_retention as contract
from privoke_model.full_adam import canonical, TRACE_KEY as ADAM_TRACE, SUMMARY_KEY as ADAM_SUMMARY


def validate_current_config(current_config, teacher_config):
    """Compare JSON configuration content without treating artifact whitespace as identity."""
    error = "Retention CURRENT config/main64/guard16 differs from fixed reference contract."

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate configuration key.")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError("Non-finite configuration value.")

    try:
        if not isinstance(current_config, str) or not isinstance(teacher_config, dict):
            raise ValueError(error)
        current = json.loads(current_config, object_pairs_hook=unique_object, parse_constant=reject_constant)
        if not isinstance(current, dict):
            raise ValueError(error)
        # Canonical strings retain JSON type distinctions (including bool/int and int/float).
        if json.dumps(current, sort_keys=True, separators=(",", ":"), allow_nan=False) != json.dumps(
                teacher_config, sort_keys=True, separators=(",", ":"), allow_nan=False):
            raise ValueError(error)
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise ValueError(error) from None


def load_runtime_release(admission, model_id):
    """No model access precedes sidecar/profile/header authentication."""
    trusted_pin = os.getenv("PRIVOKE_RETENTION_MANIFEST_SHA256")
    request_pin = admission["expected_retention_manifest_sha256"]
    if not contract.is_sha256(trusted_pin) or trusted_pin != request_pin:
        raise ValueError("Runtime retention requires a distinct trusted configured accepted manifest SHA before model access.")
    release = contract.load_release(os.getenv("PRIVOKE_RETENTION_BANK_PATH"),
        os.getenv("PRIVOKE_RETENTION_REFERENCE_PATH"), os.getenv("PRIVOKE_RETENTION_MANIFEST_PATH"),
        os.getenv("PRIVOKE_RETENTION_TEACHER_PATH"), model_id=model_id,
        expected_sha256=trusted_pin)
    return contract.validate_trusted_release(release, model_id=model_id, request_sha256=request_pin, trusted_sha256=trusted_pin)


def auxiliary_examples(release):
    from .training import SemanticTrainingExample
    from ...classification import Classification
    from ...detection.preprocessing import normalize_text
    return tuple(SemanticTrainingExample(normalize_text(source["text"]), Classification(source["packed_classification"]), 1.0)
                 for source, _ in release.eligible)


def margin_and_gap(model, prediction):
    """Use the exact production float32 heads, offset and ordered max branch."""
    import numpy as np
    from privoke_model.contextual_training import validate_decision_margin_config
    validate_decision_margin_config(model.config.__dict__)
    sensitivity = model.prediction_logits(prediction, "sensitivity")
    category = model.prediction_logits(prediction, "category")
    s0 = model.config.sensitivity_labels.index("S0")
    alternatives = [i for i, label in enumerate(model.config.sensitivity_labels) if label != "S0"]
    threshold = model.config.category_threshold
    offset = np.float32(math.log(threshold) - math.log1p(-threshold))
    margins = np.concatenate((sensitivity[alternatives] - sensitivity[s0], category - offset))
    if not np.isfinite(margins).all() or not np.isfinite(sensitivity).all():
        raise ValueError("ORIGINAL retention logits/margins must be finite.")
    ordered = np.sort(sensitivity)
    return float(margins[int(np.argmax(margins))]), float(ordered[-1] - ordered[-2])


def safety_rows(release, predictions, model):
    from .training import _classification_from_prediction, _safety_regression_rate
    from ...classification import Classification, ClassificationResult
    eligible = release.eligible
    if len(predictions) != len(eligible):
        raise ValueError("Retention safety execution returned incomplete rows.")
    rows = []
    for (source, reference), prediction in zip(eligible, predictions):
        gold = Classification(source["packed_classification"])
        original = Classification(reference["packed"])
        candidate = _classification_from_prediction(prediction)
        confidence = round(min(max(prediction.confidence, 0.0), .999), 3)
        actions = [ClassificationResult(c, "", "", confidence=conf).action().value for c, conf in
                   ((gold, None), (original, reference["confidence"]), (candidate, confidence))]
        violation = not candidate.is_sensitive() or bool(_safety_regression_rate([gold], [original], [candidate],
            before_confidence=[reference["confidence"]], after_confidence=[confidence]))
        margin, _ = margin_and_gap(model, prediction)
        rows.append({"id": source["id"], "gold": gold.pack(), "original": original.pack(), "candidate": candidate.pack(),
            "original_confidence": reference["confidence"], "candidate_confidence": confidence,
            "gold_action": actions[0], "original_action": actions[1], "candidate_action": actions[2], "violation": violation,
            "original_margin": reference["margin"], "candidate_margin": margin, "hinge": max(0.0, reference["margin"] - margin)})
    return rows


def finish_audit(audit, release, policy, base_safety, safety):
    from privoke_model.full_adam import EXECUTED_KEY, ELIGIBILITY_KEY, OPTIMIZER_KEY
    adam = json.loads(audit.pop(ADAM_TRACE))
    audit.pop(ADAM_SUMMARY)
    auxiliary = json.loads(audit.pop("original_train_retention_work_v1")) if policy == contract.HINGE_POLICY else {"counts": {}, "steps": []}
    trace = {"schema": 1, "policy": policy, "manifest_sha256": release.sha256,
             "adam": adam, "auxiliary": auxiliary, "base_safety": base_safety, "safety": safety}
    raw = canonical(trace)
    summary = {"schema": 1, "policy": policy, "manifest_sha256": release.sha256,
        "trace_sha256": contract.sha256(raw.encode()), "base": adam["base"], "final": adam["final"], "delta": adam["delta"],
        "eligible": len(safety), "violations": sum(r["violation"] for r in safety), "auxiliary": auxiliary["counts"]}
    audit.update({contract.TRACE_KEY: raw, contract.SUMMARY_KEY: canonical(summary), contract.MANIFEST_KEY: release.sha256,
                  EXECUTED_KEY: policy, ELIGIBILITY_KEY: contract.ELIGIBILITY, OPTIMIZER_KEY: policy})
    return audit
