"""Pure joint validation selection and paired endpoint analysis.

This module consumes only structured, preauthenticated claims. It does not read
artifacts, prompts, RPC receipts or datasets, and it does not authenticate those
claims, grant test access, authorize fitting, or promote a model. A separate
evidence consumer must bind every supplied identity and summary to raw evidence.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence

import numpy as np

from .in_house_study_contract import ARM_KEYS, ARMS, PAIRS


SCHEMA_VERSION = 1
VALIDATION_ROWS = 2000
VALIDATION_POSITIVES = 1000
VALIDATION_NEGATIVES = 1000
TEST_ROWS = 2000
TEST_POSITIVES = 1000
TEST_NEGATIVES = 1000
RECALL_FLOOR = 0.90
BOOTSTRAP_ITERATIONS = 2000
BOOTSTRAP_SEED = 14102026
MIN_CONFIRMATORY_VALID = 1900
CONFIRMATORY_PAIRS = frozenset(("S1", "B-F"))
REGEX_BLOCK_REASON = "Skipped after regex returned BLOCK."
NOT_REQUESTED_REASON = "Layer was not requested."

_HEX = re.compile(r"^[0-9a-f]{64}$")
_ACTIONS = frozenset(("ALLOW", "WARN", "BLOCK"))
_SENSITIVITIES = frozenset(("S0", "S1", "S2", "S3"))
_VISIBILITIES = frozenset(("P0", "P1", "P2", "P3", "P4", "PU"))
_CATEGORIES = frozenset((
    "HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL",
    "SEXUAL", "CHILD", "LOCATION", "IDENTITY", "THIRD_PARTY",
))
_OUTCOME_KEYS = frozenset((
    "status", "error_count", "classification", "action", "allowed",
    "masked_text_sha256", "evidence_sha256", "layers",
))
_LAYER_NAMES = ("regex", "ner", "semantic")
_LAYER_KEYS = frozenset(("status", "results_sha256", "skip_reason"))
_CLASSIFICATION_KEYS = frozenset(("sensitivity", "visibility", "categories"))
_IDENTITY_KEYS = frozenset((
    "model_id", "version", "artifact_sha256", "artifact_checksum",
    "parameter_fingerprint",
))
_TRACE_IDENTITY_KEYS = frozenset((
    "model_id", "model_version", "artifact_checksum", "parameter_fingerprint",
))


class StudyAnalysisError(ValueError):
    """Sanitized structural failure; never includes an input value."""


def _fail() -> None:
    raise StudyAnalysisError("Joint study analysis input is invalid or incomplete.")


def _closed(value: object, keys: frozenset[str] | set[str]) -> Mapping:
    if not isinstance(value, Mapping) or set(value) != set(keys):
        _fail()
    return value


def _sha(value: object) -> str:
    if type(value) is not str or _HEX.fullmatch(value) is None:
        _fail()
    return value


def _count(value: object, expected: int | None = None) -> int:
    if type(value) is not int or value < 0 or (expected is not None and value != expected):
        _fail()
    return value


def _digest(value: object) -> str:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError):
        _fail()
    return hashlib.sha256(raw).hexdigest()


def _identity(value: object, arm: str, epoch: int) -> dict[str, str]:
    value = _closed(value, _IDENTITY_KEYS)
    definition = ARMS[ARM_KEYS.index(arm)]
    expected_version = "v1.0.0" if epoch == 0 else f"v1.0.0+epoch.{epoch}"
    if value["model_id"] != definition.model_id or value["version"] != expected_version:
        _fail()
    result = dict(value)
    for field in ("artifact_sha256", "artifact_checksum", "parameter_fingerprint"):
        _sha(result[field])
    if type(result["version"]) is not str:
        _fail()
    return result


def _trace_identity(value: object, identity: Mapping[str, str]) -> None:
    value = _closed(value, _TRACE_IDENTITY_KEYS)
    expected = {
        "model_id": identity["model_id"],
        "model_version": identity["version"],
        "artifact_checksum": identity["artifact_checksum"],
        "parameter_fingerprint": identity["parameter_fingerprint"],
    }
    if dict(value) != expected:
        _fail()


def _validate_outcome(value: object, *, purpose: str = "requested") -> dict:
    value = _closed(value, _OUTCOME_KEYS)
    if type(value["status"]) is not str or value["status"] != "complete" or _count(value["error_count"]) != 0:
        _fail()
    classification = _closed(value["classification"], _CLASSIFICATION_KEYS)
    if (type(classification["sensitivity"]) is not str
            or classification["sensitivity"] not in _SENSITIVITIES
            or type(classification["visibility"]) is not str
            or classification["visibility"] not in _VISIBILITIES):
        _fail()
    categories = classification["categories"]
    if (type(categories) is not list or len(categories) > len(_CATEGORIES)
            or any(type(item) is not str or item not in _CATEGORIES for item in categories)
            or len(set(categories)) != len(categories)):
        _fail()
    if type(value["action"]) is not str or value["action"] not in _ACTIONS or type(value["allowed"]) is not bool:
        _fail()
    if value["allowed"] is not (value["action"] != "BLOCK"):
        _fail()
    _sha(value["masked_text_sha256"])
    if value["evidence_sha256"] is not None:
        _sha(value["evidence_sha256"])
    layers = _closed(value["layers"], frozenset(_LAYER_NAMES))
    for name in _LAYER_NAMES:
        layer = _closed(layers[name], _LAYER_KEYS)
        status = layer["status"]
        if type(status) is not str:
            _fail()
        if status == "ok":
            _sha(layer["results_sha256"])
            if layer["skip_reason"] is not None:
                _fail()
        elif status in ("skipped", "not_requested"):
            if layer["results_sha256"] is not None or type(layer["skip_reason"]) is not str:
                _fail()
            if not layer["skip_reason"]:
                _fail()
            if status == "not_requested" and (name != "semantic" or layer["skip_reason"] != NOT_REQUESTED_REASON):
                _fail()
        else:
            _fail()
    if layers["regex"]["status"] != "ok":
        _fail()
    regex_shortcut = (
        value["action"] == "BLOCK"
        and layers["ner"]["status"] == "skipped"
        and layers["ner"]["skip_reason"] == REGEX_BLOCK_REASON
        and layers["semantic"]["status"] == "skipped"
        and layers["semantic"]["skip_reason"] == REGEX_BLOCK_REASON
    )
    if purpose == "requested":
        if not regex_shortcut and any(layers[name]["status"] != "ok" for name in _LAYER_NAMES):
            _fail()
        if layers["ner"]["status"] == "skipped" and not regex_shortcut:
            _fail()
    elif purpose == "nonsemantic":
        if (layers["ner"]["status"] == "skipped"
                and not (value["action"] == "BLOCK"
                         and layers["ner"]["skip_reason"] == REGEX_BLOCK_REASON)):
            _fail()
        if layers["ner"]["status"] not in ("ok", "skipped"):
            _fail()
        semantic = layers["semantic"]
        if (semantic["status"] != "not_requested"
                or semantic["skip_reason"] != NOT_REQUESTED_REASON
                or semantic["results_sha256"] is not None):
            _fail()
    else:
        _fail()
    return {
        "status": "complete", "error_count": 0,
        "classification": dict(classification),
        "action": value["action"], "allowed": value["allowed"],
        "masked_text_sha256": value["masked_text_sha256"],
        "evidence_sha256": value["evidence_sha256"],
        "layers": {key: dict(layers[key]) for key in _LAYER_NAMES},
    }


def _summary(value: Mapping) -> tuple:
    classification = value["classification"]
    return (
        classification["sensitivity"], classification["visibility"],
        tuple(classification["categories"]), value["action"], value["allowed"],
        value["masked_text_sha256"], value["evidence_sha256"],
    )


def _detected(value: Mapping) -> bool:
    classification = value["classification"]
    return classification["sensitivity"] != "S0" or bool(classification["categories"])


def _is_regex_block_shortcut(ordinary: Mapping) -> bool:
    layers = ordinary["layers"]
    return (
        ordinary["action"] == "BLOCK"
        and layers["regex"]["status"] == "ok"
        and layers["ner"]["status"] == "skipped"
        and layers["ner"]["skip_reason"] == REGEX_BLOCK_REASON
        and layers["semantic"]["status"] == "skipped"
        and layers["semantic"]["skip_reason"] == REGEX_BLOCK_REASON
    )


def _validate_trace(value: object, expected_identity: Mapping[str, str], ordinary: Mapping,
                    gate_zero: Mapping, *, expected_decision_threshold: float = 0.0) -> dict:
    value = _closed(value, frozenset((
        "status", "model_id", "identity", "probability", "model_threshold",
        "decision_threshold", "predicted_label", "semantic_results_sha256",
    )))
    status = value["status"]
    if type(status) is not str:
        _fail()
    if (type(value["model_id"]) is not str or not value["model_id"]
            or type(value["decision_threshold"]) is not float
            or not math.isfinite(value["decision_threshold"])
            or not 0.0 <= value["decision_threshold"] <= 1.0
            or value["decision_threshold"] != expected_decision_threshold):
        _fail()
    if status == "NOT_RUN":
        if (value["model_id"] != expected_identity["model_id"]
                or value["identity"] is not None or value["probability"] is not None
                or value["model_threshold"] is not None
                or value["predicted_label"] is not None
                or value["semantic_results_sha256"] is not None
                or not _is_regex_block_shortcut(ordinary)
                or _summary(ordinary) != _summary(gate_zero)):
            _fail()
        return {"status": status, "model_id": value["model_id"], "identity": None,
                "decision_threshold": value["decision_threshold"], "model_threshold": None,
                "probability": None, "predicted_label": None,
                "semantic_results_sha256": None}
    if status != "APPLIED" or _is_regex_block_shortcut(ordinary):
        _fail()
    if value["model_id"] != expected_identity["model_id"]:
        _fail()
    _trace_identity(value["identity"], expected_identity)
    probability = value["probability"]
    model_threshold = value["model_threshold"]
    if (type(probability) is not float or not math.isfinite(probability)
            or not 0.0 <= probability <= 1.0
            or type(model_threshold) is not float or not math.isfinite(model_threshold)
            or not 0.0 <= model_threshold <= 1.0
            or type(value["predicted_label"]) is not str
            or value["predicted_label"] not in ("PRESENT", "ABSENT")
            or value["predicted_label"] != ("PRESENT" if probability >= expected_decision_threshold else "ABSENT")):
        _fail()
    raw_semantic = _sha(value["semantic_results_sha256"])
    ordinary_semantic = ordinary["layers"]["semantic"]
    gate_semantic = gate_zero["layers"]["semantic"]
    if (ordinary_semantic["status"] != "ok" or gate_semantic["status"] != "ok"
            or raw_semantic != ordinary_semantic["results_sha256"]
            or raw_semantic != gate_semantic["results_sha256"]):
        _fail()
    return {"status": status, "model_id": value["model_id"],
            "identity": dict(value["identity"]),
            "decision_threshold": value["decision_threshold"],
            "model_threshold": model_threshold, "probability": probability,
            "predicted_label": value["predicted_label"],
            "semantic_results_sha256": raw_semantic}


def _validate_row(value: object, identity: Mapping[str, str]) -> dict:
    value = _closed(value, frozenset((
        "row_id_sha256", "group_id_sha256", "truth", "ordinary", "gate_zero",
        "nonsemantic", "gate",
    )))
    row_id = _sha(value["row_id_sha256"])
    group_id = _sha(value["group_id_sha256"])
    if type(value["truth"]) is not bool:
        _fail()
    ordinary = _validate_outcome(value["ordinary"])
    gate_zero = _validate_outcome(value["gate_zero"])
    nonsemantic = _validate_outcome(value["nonsemantic"], purpose="nonsemantic")
    if (_summary(ordinary) != _summary(gate_zero)
            or ordinary["layers"] != gate_zero["layers"]):
        _fail()
    for layer_name in ("regex", "ner"):
        if ordinary["layers"][layer_name] != nonsemantic["layers"][layer_name]:
            _fail()
    trace = _validate_trace(value["gate"], identity, ordinary, gate_zero)
    return {
        "row_id_sha256": row_id, "group_id_sha256": group_id,
        "truth": value["truth"], "ordinary": ordinary,
        "gate_zero": gate_zero, "nonsemantic": nonsemantic, "trace": trace,
    }


def _binary_metrics(truth: Sequence[bool], predicted: Sequence[bool]) -> dict:
    if len(truth) != len(predicted) or not truth:
        _fail()
    tp = tn = fp = fn = 0
    for actual, guess in zip(truth, predicted):
        if actual and guess:
            tp += 1
        elif actual:
            fn += 1
        elif guess:
            fp += 1
        else:
            tn += 1
    positives, negatives = tp + fn, tn + fp
    recall = tp / positives if positives else None
    specificity = tn / negatives if negatives else None
    balanced = ((recall + specificity) / 2 if recall is not None and specificity is not None else None)
    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "positive_examples": positives, "absent_examples": negatives,
        "recall": recall, "specificity": specificity,
        "balanced_accuracy": balanced,
    }


def _thresholds(rows: Sequence[Mapping]) -> tuple[float, ...]:
    candidates = {0.0, 1.0}
    for row in rows:
        trace = row["trace"]
        if trace["status"] == "APPLIED":
            probability = trace["probability"]
            candidates.add(probability)
            above = math.nextafter(probability, math.inf)
            if above <= 1.0:
                candidates.add(above)
    return tuple(sorted(candidates))


def _project(row: Mapping, threshold: float) -> Mapping:
    trace = row["trace"]
    if trace["status"] == "NOT_RUN" or trace["probability"] >= threshold:
        return row["ordinary"]
    return row["nonsemantic"]


def _validate_live_trace(value: object, expected_identity: Mapping[str, str],
                         expected_threshold: float, source_row: Mapping) -> dict:
    value = _closed(value, frozenset((
        "status", "model_id", "identity", "probability", "model_threshold",
        "decision_threshold", "predicted_label", "semantic_results_sha256",
    )))
    if (type(value["model_id"]) is not str
            or value["model_id"] != expected_identity["model_id"]
            or type(value["decision_threshold"]) is not float
            or not math.isfinite(value["decision_threshold"])
            or value["decision_threshold"] != expected_threshold):
        _fail()
    ordinary = source_row["ordinary"]
    gate_zero = source_row["gate_zero"]
    if value["status"] == "NOT_RUN":
        if (not _is_regex_block_shortcut(ordinary)
                or value["identity"] is not None
                or value["probability"] is not None
                or value["model_threshold"] is not None
                or value["predicted_label"] is not None
                or value["semantic_results_sha256"] is not None):
            _fail()
        return {"status": "NOT_RUN", "model_id": value["model_id"],
                "identity": None, "decision_threshold": expected_threshold,
                "model_threshold": None, "probability": None,
                "predicted_label": None, "semantic_results_sha256": None}
    if value["status"] != "APPLIED" or _is_regex_block_shortcut(ordinary):
        _fail()
    _trace_identity(value["identity"], expected_identity)
    probability, model_threshold = value["probability"], value["model_threshold"]
    label = value["predicted_label"]
    if (type(probability) is not float or not math.isfinite(probability)
            or not 0.0 <= probability <= 1.0
            or type(model_threshold) is not float or not math.isfinite(model_threshold)
            or not 0.0 <= model_threshold <= 1.0
            or type(label) is not str or label not in ("PRESENT", "ABSENT")
            or label != ("PRESENT" if probability >= expected_threshold else "ABSENT")):
        _fail()
    semantic_hash = _sha(value["semantic_results_sha256"])
    if (source_row["trace"]["status"] != "APPLIED"
            or probability != source_row["trace"]["probability"]
            or model_threshold != source_row["trace"]["model_threshold"]
            or semantic_hash != source_row["trace"]["semantic_results_sha256"]):
        _fail()
    return {"status": "APPLIED", "model_id": value["model_id"],
            "identity": dict(value["identity"]), "decision_threshold": expected_threshold,
            "model_threshold": model_threshold, "probability": probability,
            "predicted_label": label, "semantic_results_sha256": semantic_hash}


def _verify_selected_live_validation(original_collection: object, frozen_selection: object,
                                     live_collection: object, *, expected_rows: int,
                                     positive_rows: int, recall_floor: float,
                                     min_components_per_class: int) -> dict:
    recomputed = _select_joint_validation(
        original_collection, expected_rows=expected_rows, positive_rows=positive_rows,
        recall_floor=recall_floor, min_components_per_class=min_components_per_class,
    )
    if (recomputed["status"] != "eligible" or not isinstance(frozen_selection, Mapping)
            or _digest(frozen_selection) != _digest(recomputed)):
        _fail()
    live = _closed(live_collection, frozenset(("schema_version", "control_binding_sha256", "arms")))
    if (type(live["schema_version"]) is not int or live["schema_version"] != SCHEMA_VERSION
            or _sha(live["control_binding_sha256"]) != recomputed["control_binding_sha256"]
            or type(live["arms"]) not in (list, tuple)
            or len(live["arms"]) != len(ARM_KEYS)):
        _fail()
    original_arms = original_collection["arms"]
    for expected_arm, original_record, live_record in zip(ARM_KEYS, original_arms, live["arms"]):
        selection = recomputed["selections"][expected_arm]
        live_record = _closed(live_record, frozenset((
            "arm", "status", "error_count", "epoch", "threshold", "identity", "rows",
        )))
        if (live_record["arm"] != expected_arm
                or live_record["status"] != "complete"
                or _count(live_record["error_count"]) != 0
                or type(live_record["epoch"]) is not int
                or live_record["epoch"] != selection["epoch"]
                or type(live_record["threshold"]) is not float
                or live_record["threshold"] != selection["threshold"]):
            _fail()
        identity = _identity(live_record["identity"], expected_arm, selection["epoch"])
        if identity != selection["identity"]:
            _fail()
        source_checkpoint = next(
            checkpoint for checkpoint in original_record["checkpoints"]
            if checkpoint["epoch"] == selection["epoch"]
        )
        source_identity = _identity(source_checkpoint["identity"], expected_arm, selection["epoch"])
        source_rows = [
            _validate_row(row, source_identity) for row in source_checkpoint["rows"]
        ]
        rows = live_record["rows"]
        if type(rows) not in (list, tuple) or len(rows) != expected_rows:
            _fail()
        for live_row_value, source_row in zip(rows, source_rows):
            live_row = _closed(live_row_value, frozenset((
                "row_id_sha256", "group_id_sha256", "truth", "gate", "outcome",
            )))
            row_id = _sha(live_row["row_id_sha256"])
            group_id = _sha(live_row["group_id_sha256"])
            if (row_id != source_row["row_id_sha256"]
                    or group_id != source_row["group_id_sha256"]
                    or type(live_row["truth"]) is not bool
                    or live_row["truth"] is not source_row["truth"]):
                _fail()
            trace = _validate_live_trace(
                live_row["gate"], identity, selection["threshold"], source_row,
            )
            observed = _validate_outcome(live_row["outcome"])
            projected = _project(source_row, selection["threshold"])
            if _summary(observed) != _summary(projected):
                _fail()
            if observed["layers"]["regex"] != source_row["ordinary"]["layers"]["regex"]:
                _fail()
            if observed["layers"]["ner"] != source_row["ordinary"]["layers"]["ner"]:
                _fail()
            if trace["status"] == "APPLIED":
                if observed["layers"]["semantic"]["status"] != "ok":
                    _fail()
                if trace["predicted_label"] == "PRESENT":
                    if observed["layers"]["semantic"]["results_sha256"] != trace["semantic_results_sha256"]:
                        _fail()
            elif observed["layers"] != source_row["ordinary"]["layers"]:
                _fail()
    return {
        "schema_version": SCHEMA_VERSION, "status": "complete",
        "selection_sha256": recomputed["selection_sha256"],
        "control_binding_sha256": recomputed["control_binding_sha256"],
        "validation_rows": expected_rows, "verified_arms": list(ARM_KEYS),
        "live_validation_sha256": _digest(live_collection),
        "projection_live_parity": True, "test_authorized": False,
        "retention_decision": None,
    }
    return row["nonsemantic"]


def _select_one_arm(checkpoints: Sequence[Mapping], *, recall_floor: float) -> tuple[list[dict], dict | None]:
    candidates = []
    for checkpoint in checkpoints:
        epoch = checkpoint["epoch"]
        rows = checkpoint["rows"]
        truth = [row["truth"] for row in rows]
        for threshold in _thresholds(rows):
            projected = [_project(row, threshold) for row in rows]
            metrics = _binary_metrics(truth, [_detected(value) for value in projected])
            eligible = (metrics["specificity"] is not None and metrics["recall"] is not None
                        and metrics["recall"] >= recall_floor)
            entry = {
                "epoch": epoch, "threshold": threshold,
                "identity": dict(checkpoint["identity"]),
                "metrics": metrics, "eligible": eligible,
                "reason": "meets_recall_floor" if eligible else "recall_below_floor_or_undefined",
            }
            entry["candidate_sha256"] = _digest({
                "epoch": epoch, "threshold": threshold,
                "identity": checkpoint["identity"], "metrics": metrics,
            })
            candidates.append(entry)
    eligible = [entry for entry in candidates if entry["eligible"]]
    if not eligible:
        return candidates, None
    selected = max(eligible, key=lambda item: (
        item["metrics"]["specificity"], item["metrics"]["recall"],
        -item["epoch"], item["threshold"],
    ))
    selected = dict(selected)
    selected["reason"] = "max_specificity_then_recall_then_earlier_epoch_then_higher_threshold"
    return candidates, selected


def _select_joint_validation(value: object, *, expected_rows: int,
                             positive_rows: int, recall_floor: float,
                             min_components_per_class: int) -> dict:
    value = _closed(value, frozenset(("schema_version", "control_binding_sha256", "arms")))
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        _fail()
    control_binding = _sha(value["control_binding_sha256"])
    arms = value["arms"]
    if type(arms) not in (list, tuple) or len(arms) != len(ARM_KEYS):
        _fail()
    if not math.isfinite(recall_floor) or not 0.0 < recall_floor <= 1.0:
        _fail()

    expected_by_arm = {
        "S0": (0,), "S1": (0,),
        **{arm.key: tuple(range(1, 6)) for arm in ARMS[2:]},
    }
    seen_arms = set()
    candidate_tables: dict[str, list[dict]] = {}
    selected: dict[str, dict] = {}
    reference_keys = None
    common_ordinary = {}
    common_nonsemantic = {}

    for arm_record, expected_arm in zip(arms, ARM_KEYS):
        arm_record = _closed(arm_record, frozenset(("arm", "control_binding_sha256", "checkpoints")))
        arm = arm_record["arm"]
        if arm != expected_arm or arm in seen_arms or _sha(arm_record["control_binding_sha256"]) != control_binding:
            _fail()
        seen_arms.add(arm)
        checkpoints = arm_record["checkpoints"]
        epochs = expected_by_arm[arm]
        if type(checkpoints) not in (list, tuple) or len(checkpoints) != len(epochs):
            _fail()
        validated_checkpoints = []
        for checkpoint, expected_epoch in zip(checkpoints, epochs):
            checkpoint = _closed(checkpoint, frozenset(("epoch", "identity", "rows")))
            epoch = checkpoint["epoch"]
            if type(epoch) is not int or epoch != expected_epoch:
                _fail()
            identity = _identity(checkpoint["identity"], arm, epoch)
            rows = checkpoint["rows"]
            if type(rows) not in (list, tuple) or len(rows) != expected_rows:
                _fail()
            validated_rows = []
            seen_ids = set()
            positives = 0
            model_thresholds = set()
            for raw_row in rows:
                row = _validate_row(raw_row, identity)
                if row["row_id_sha256"] in seen_ids:
                    _fail()
                seen_ids.add(row["row_id_sha256"])
                positives += int(row["truth"])
                if row["trace"]["status"] == "APPLIED":
                    model_thresholds.add(row["trace"]["model_threshold"])
                    if len(model_thresholds) > 1:
                        _fail()
                key = (row["row_id_sha256"], row["group_id_sha256"], row["truth"])
                if reference_keys is None:
                    reference_keys = []
                if len(reference_keys) < expected_rows and not validated_checkpoints and expected_epoch == epochs[0]:
                    reference_keys.append(key)
                elif key != reference_keys[len(validated_rows)]:
                    _fail()

                row_id = row["row_id_sha256"]
                ordinary, nonsemantic = row["ordinary"], row["nonsemantic"]
                if row_id in common_ordinary:
                    if common_ordinary[row_id] != ordinary or common_nonsemantic[row_id] != nonsemantic:
                        _fail()
                else:
                    common_ordinary[row_id] = ordinary
                    common_nonsemantic[row_id] = nonsemantic
                validated_rows.append(row)
            if positives != positive_rows or len(seen_ids) != expected_rows:
                _fail()
            # The first complete checkpoint establishes the ordered join. Later
            # checkpoints and arms must match it byte-for-byte in opaque keys.
            if not reference_keys or len(reference_keys) != expected_rows:
                _fail()
            validated_checkpoints.append({"epoch": epoch, "identity": identity, "rows": validated_rows})

        table, choice = _select_one_arm(validated_checkpoints, recall_floor=recall_floor)
        candidate_tables[arm] = table
        if choice is not None:
            selected[arm] = choice

    if seen_arms != set(ARM_KEYS) or set(candidate_tables) != set(ARM_KEYS):
        _fail()
    positive_groups, negative_groups = set(), set()
    for _, group_id, truth_value in reference_keys:
        (positive_groups if truth_value else negative_groups).add(group_id)
    if (len(positive_groups) < min_components_per_class
            or len(negative_groups) < min_components_per_class):
        _fail()
    all_eligible = set(selected) == set(ARM_KEYS)
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "eligible" if all_eligible else "ineligible",
        "control_binding_sha256": control_binding,
        "validation_rows": expected_rows,
        "validation_positive_examples": positive_rows,
        "validation_absent_examples": expected_rows - positive_rows,
        "validation_components": len({group_id for _, group_id, _ in reference_keys}),
        "validation_positive_components": len(positive_groups),
        "validation_negative_components": len(negative_groups),
        "validation_mixed_label_components": len(positive_groups & negative_groups),
        "recall_floor": recall_floor,
        "candidate_tables": candidate_tables,
        # No surviving-arm selection is exposed unless the entire fixed program
        # has at least one eligible candidate for every arm.
        "selections": selected if all_eligible else None,
        "selection_sha256": _digest(selected) if all_eligible else None,
        "test_authorized": False,
    }


def select_joint_validation(value: object) -> dict:
    """Select every fixed arm jointly from its completed validation checkpoints.

    Input rows contain opaque hashes and bounded structured outcome summaries,
    never prompt text. Any missing/failed/misaligned checkpoint raises; if any
    arm has no threshold at the recall floor, all selections are withheld.
    """
    return _select_joint_validation(
        value, expected_rows=VALIDATION_ROWS,
        positive_rows=VALIDATION_POSITIVES, recall_floor=RECALL_FLOOR,
        min_components_per_class=200,
    )


def _confusion(truth: np.ndarray, predicted: np.ndarray, weights: np.ndarray) -> dict:
    positives = int(weights[truth].sum())
    negatives = int(weights[~truth].sum())
    tp = int(weights[truth & predicted].sum())
    fn = positives - tp
    tn = int(weights[(~truth) & (~predicted)].sum())
    fp = negatives - tn
    recall = tp / positives if positives else None
    specificity = tn / negatives if negatives else None
    balanced = ((recall + specificity) / 2 if recall is not None and specificity is not None else None)
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "positive_examples": positives, "absent_examples": negatives,
            "recall": recall, "specificity": specificity, "balanced_accuracy": balanced}


def _resampled_confusions(truth: np.ndarray, predictions: np.ndarray,
                          group_indexes: np.ndarray, draw: np.ndarray) -> list[dict] | None:
    group_multiplicity = np.bincount(draw, minlength=int(group_indexes.max()) + 1)
    row_weights = group_multiplicity[group_indexes]
    if int(row_weights[truth].sum()) == 0 or int(row_weights[~truth].sum()) == 0:
        return None
    return [_confusion(truth, predictions[index], row_weights) for index in range(len(ARM_KEYS))]


def _percentile_interval(values: Sequence[float]) -> dict:
    array = np.asarray(values, dtype=np.float64)
    bounds = np.quantile(array, (0.025, 0.975), method="linear")
    return {"lower": float(bounds[0]), "upper": float(bounds[1]), "valid_replicates": len(values)}


def _paired_bootstrap(truth_values: Sequence[bool], group_values: Sequence[str],
                      prediction_rows: Sequence[Sequence[bool]], *,
                      iterations: int, seed: int) -> dict:
    truth = np.asarray(truth_values, dtype=np.bool_)
    predictions = np.asarray(prediction_rows, dtype=np.bool_)
    group_names = sorted(set(group_values))
    group_to_index = {name: index for index, name in enumerate(group_names)}
    group_indexes = np.asarray([group_to_index[name] for name in group_values], dtype=np.int64)
    point_confusions = [_confusion(truth, predictions[index], np.ones(len(truth), dtype=np.int64))
                        for index in range(len(ARM_KEYS))]
    contrasts = {}
    delta_values = {
        f"{treatment}-{control}": {metric: [] for metric in ("specificity", "recall", "balanced_accuracy")}
        for treatment, control in PAIRS
    }
    rng = np.random.default_rng(seed)
    draw_sha = hashlib.sha256()
    undefined = 0
    for _ in range(iterations):
        draw = rng.integers(0, len(group_names), size=len(group_names))
        draw_sha.update(np.asarray(draw, dtype="<i8").tobytes())
        resampled = _resampled_confusions(truth, predictions, group_indexes, draw)
        if resampled is None:
            undefined += 1
            continue
        for treatment, control in PAIRS:
            key = f"{treatment}-{control}"
            t_metrics = resampled[ARM_KEYS.index(treatment)]
            c_metrics = resampled[ARM_KEYS.index(control)]
            for metric, values in delta_values[key].items():
                t_value, c_value = t_metrics[metric], c_metrics[metric]
                if t_value is not None and c_value is not None:
                    values.append(t_value - c_value)

    for treatment, control in PAIRS:
        key = f"{treatment}-{control}"
        t_point = point_confusions[ARM_KEYS.index(treatment)]
        c_point = point_confusions[ARM_KEYS.index(control)]
        point_delta = {
            metric: (t_point[metric] - c_point[metric]
                     if t_point[metric] is not None and c_point[metric] is not None else None)
            for metric in ("specificity", "recall", "balanced_accuracy")
        }
        confirmatory = treatment in CONFIRMATORY_PAIRS
        valid = len(delta_values[key]["specificity"])
        enough = valid >= MIN_CONFIRMATORY_VALID if confirmatory else valid > 0
        intervals = {
            metric: (_percentile_interval(values) if enough and len(values) == valid else None)
            for metric, values in delta_values[key].items()
        }
        lower = intervals["specificity"]["lower"] if intervals["specificity"] is not None else None
        contrasts[key] = {
            "treatment": treatment, "control": control,
            "confirmatory_directional_contrast": confirmatory,
            "point_delta": point_delta,
            "confidence_intervals_95": intervals,
            "valid_specificity_replicates": valid,
            "specificity_interval_status": "complete" if intervals["specificity"] is not None else "insufficient_valid_replicates",
            "directional_specificity_improvement_supported": (lower is not None and lower > 0.0) if confirmatory else None,
        }
    return {
        "method": "paired_connected_component_bootstrap",
        "numpy_version": np.__version__, "iterations": iterations, "seed": seed,
        "component_count": len(group_names), "undefined_class_replicates": undefined,
        "valid_class_replicates": iterations - undefined,
        "shared_component_draws_sha256": draw_sha.hexdigest(),
        "resampling_unit": "full connected components, sorted opaque IDs; all eight arms share each draw",
        "weighting": "row-weighted confusion rates including component multiplicity",
        "quantile_method": "numpy.quantile(method='linear')",
        "confirmatory_alpha_one_sided": 0.025,
        "confirmatory_family_alpha": 0.05,
        "confirmatory_inference_eligible": all(
            contrasts[f"{treatment}-{control}"]["valid_specificity_replicates"]
            >= MIN_CONFIRMATORY_VALID
            for treatment, control in (pair for pair in PAIRS if pair[0] in CONFIRMATORY_PAIRS)
        ),
        "confirmatory_adjustment": "Bonferroni over H-A and H-B",
        "contrasts": contrasts,
    }


def _analyze_paired_endpoint(value: object, *, expected_rows: int,
                             positive_rows: int, iterations: int, seed: int) -> dict:
    value = _closed(value, frozenset(("schema_version", "arms")))
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        _fail()
    arms = value["arms"]
    if type(arms) not in (list, tuple) or len(arms) != len(ARM_KEYS):
        _fail()
    if type(iterations) is not int or iterations < 1 or type(seed) is not int or seed < 0:
        _fail()
    truth_reference = None
    key_reference = None
    groups: list[str] = []
    predictions_by_arm = []
    seen_arms = set()
    arm_metrics = {}
    for record, expected_arm in zip(arms, ARM_KEYS):
        record = _closed(record, frozenset(("arm", "status", "error_count", "rows")))
        arm = record["arm"]
        if arm != expected_arm or arm in seen_arms or record["status"] != "complete" or _count(record["error_count"]) != 0:
            _fail()
        seen_arms.add(arm)
        rows = record["rows"]
        if type(rows) not in (list, tuple) or len(rows) != expected_rows:
            _fail()
        arm_keys, truth, predictions = [], [], []
        seen_ids = set()
        for row_value in rows:
            row = _closed(row_value, frozenset(("row_id_sha256", "group_id_sha256", "truth", "outcome")))
            row_id, group_id = _sha(row["row_id_sha256"]), _sha(row["group_id_sha256"])
            if row_id in seen_ids or type(row["truth"]) is not bool:
                _fail()
            outcome = _validate_outcome(row["outcome"])
            seen_ids.add(row_id)
            arm_keys.append((row_id, group_id, row["truth"]))
            truth.append(row["truth"])
            # Detection is a property of canonical classification, never the
            # enforcement action: an ALLOW result may still be sensitive.
            predictions.append(_detected(outcome))
        if sum(truth) != positive_rows:
            _fail()
        if key_reference is None:
            key_reference = arm_keys
            truth_reference = truth
            groups = [key[1] for key in arm_keys]
        elif arm_keys != key_reference:
            _fail()
        predictions_by_arm.append(predictions)
        arm_metrics[arm] = _binary_metrics(truth, predictions)
    if seen_arms != set(ARM_KEYS) or key_reference is None or truth_reference is None:
        _fail()
    positive_groups, negative_groups = set(), set()
    for (_, group_id, truth_value) in key_reference:
        (positive_groups if truth_value else negative_groups).add(group_id)
    if len(positive_groups) < 200 or len(negative_groups) < 200:
        _fail()
    paired = _paired_bootstrap(
        truth_reference, groups, predictions_by_arm, iterations=iterations, seed=seed,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "complete",
        "rows": expected_rows,
        "positive_examples": positive_rows,
        "absent_examples": expected_rows - positive_rows,
        "component_count": len(set(groups)),
        "positive_components": len(positive_groups),
        "negative_components": len(negative_groups),
        "mixed_label_components": len(positive_groups & negative_groups),
        "arm_metrics": arm_metrics,
        "paired_component_bootstrap": paired,
        "test_authorized": False,
        "retention_decision": None,
    }


def analyze_paired_endpoint(value: object) -> dict:
    """Summarize one preauthenticated, complete, shared 2,000-row endpoint.

    This function has no selection or authorization behavior. It reports all
    eight arms and the four predefined paired contrasts; it never reads files
    or accepts a partial/survivor denominator.
    """
    return _analyze_paired_endpoint(
        value, expected_rows=TEST_ROWS, positive_rows=TEST_POSITIVES,
        iterations=BOOTSTRAP_ITERATIONS, seed=BOOTSTRAP_SEED,
    )


def verify_selected_live_validation(original_collection: object,
                                    frozen_selection: object,
                                    live_collection: object) -> dict:
    """Check all-arm selected rerun parity using preauthenticated claims.

    This recomputes selection from the original validation collection, rejects
    any difference in the frozen selection, then verifies every selected live
    identity, threshold, ordered row join, gate trace, and projected outcome.
    It is a structural parity barrier, not raw-evidence authentication or test
    authorization.
    """
    return _verify_selected_live_validation(
        original_collection, frozen_selection, live_collection,
        expected_rows=VALIDATION_ROWS, positive_rows=VALIDATION_POSITIVES,
        recall_floor=RECALL_FLOOR, min_components_per_class=200,
    )


__all__ = [
    "BOOTSTRAP_ITERATIONS", "BOOTSTRAP_SEED", "StudyAnalysisError",
    "analyze_paired_endpoint", "select_joint_validation",
    "verify_selected_live_validation",
]
