"""Versioned, bounded contextual Tiny training contracts."""
from __future__ import annotations

import copy
import math
from collections.abc import Mapping

from .artifact import ARCHITECTURE_NAME, ModelArtifactError, artifact_checksum
from .readout import TASK_QUERY_ARCHITECTURE, TASK_QUERY_READOUT, QUERY_NAMES, query_readout, validate_query_config
from .sensitive_retention import (GATE_OBJECTIVE as RETENTION_GATE_OBJECTIVE,
    HINGE_OBJECTIVE as RETENTION_HINGE_OBJECTIVE, POLICIES as RETENTION_POLICIES)

STRATEGY_KEY = "contextual_training_strategy"
LAST_BLOCK_STRATEGY = "contextual_last_block_sgd_v1"
FULL_ENCODER_STRATEGY = "contextual_full_encoder_sgd_v1"
FULL_ENCODER_MAX_TENSOR_VALUES = 24_576
OPTIMIZER_KEY = "contextual_training_optimizer"
LOCAL_SGD_1 = "local_sgd_1_v1"
LOCAL_SGD_4 = "local_sgd_4_v1"
LOCAL_SGD_STEPS = {LOCAL_SGD_1: 1, LOCAL_SGD_4: 4}
OBJECTIVE_KEY = "contextual_training_objective"
LEGACY_OBJECTIVE = "legacy_sum_category"
DIAGNOSTICS_POLICY_KEY = "contextual_training_diagnostics_policy"
TRAIN_DIAGNOSTICS_POLICY = "train_before_candidate_v1"
DIAGNOSTICS_KEY = "contextual_training_diagnostics"
EXECUTED_OBJECTIVE_KEY = "executed_contextual_training_objective"
BACKTRACKING_KEY = "contextual_training_backtracking_policy"
BACKTRACKING_POLICY = "full_train_backtracking_v1"
BACKTRACKING_PREPARATION_KEY = "contextual_training_backtracking_preparation"
BACKTRACKING_TRACE_KEY = "contextual_training_backtracking_trace"
BACKTRACKING_TRIALS_KEY = "contextual_training_backtracking_trials"
BACKTRACKING_HEADER = "x-privoke-training-admission-v1"
BACKTRACKING_REJECTION = "TRAIN_BACKTRACKING_NO_IMPROVEMENT_V1"
BACKTRACKING_SCALES = (1.0, .25, .0625, .015625, .00390625)
BACKTRACKING_DECREASE = .00002
DIAGNOSTIC_LOSS_COLUMNS = ("sensitivity_ce", "visibility_ce", "category_sum_bce", "objective")
DIAGNOSTIC_ACCURACY_COLUMNS = ("exact", "sensitivity_exact", "visibility_exact", "category_set_exact",
                               "clean_specificity", "sensitive_recall")
DIAGNOSTIC_UPDATE_COLUMNS = ("coordinates", "strictly_clipped", "raw_abs_max", "transported_abs_max")
CLASS_BALANCED_OBJECTIVE = "class_balanced_contextual_v1"
CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE = "class_balanced_contextual_mean_category_v1"
CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE = "class_balanced_contextual_decision_margin_v1"
CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE = "class_balanced_contextual_sum_category_decision_margin_v1"
MEAN_CATEGORY_OBJECTIVES = frozenset((CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE, CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE))
DECISION_MARGIN_OBJECTIVES = frozenset((CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE, CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE, RETENTION_GATE_OBJECTIVE, RETENTION_HINGE_OBJECTIVE))
CLASS_BALANCED_OBJECTIVES = frozenset((CLASS_BALANCED_OBJECTIVE, *MEAN_CATEGORY_OBJECTIVES, CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE, RETENTION_GATE_OBJECTIVE, RETENTION_HINGE_OBJECTIVE))
PROCESS_OBJECTIVES = (LEGACY_OBJECTIVE, CLASS_BALANCED_OBJECTIVE, CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE, RETENTION_GATE_OBJECTIVE, RETENTION_HINGE_OBJECTIVE)
SUM_MARGIN_LOSS_COLUMNS = ("sensitivity_ce", "visibility_ce", "category_sum_bce", "decision_margin_bce", "objective")


def training_loss_contract(objective):
    """Keep old four-column evidence strict; the summed-margin policy uses schema two."""
    if objective not in PROCESS_OBJECTIVES:
        raise ValueError("Unsupported TRAIN process objective.")
    return ((2, SUM_MARGIN_LOSS_COLUMNS) if objective in (CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE, RETENTION_GATE_OBJECTIVE, RETENTION_HINGE_OBJECTIVE)
            else (1, DIAGNOSTIC_LOSS_COLUMNS))
HEAD_NAMES = frozenset(f"head.{head}.{part}" for head in
                       ("sensitivity", "visibility", "category") for part in ("weight", "bias"))
BLOCK_NAMES = ("attention.query.weight", "attention.key.weight", "attention.value.weight",
               "attention.output.weight", "attention.output.bias", "ffn.input.weight",
               "ffn.input.bias", "ffn.output.weight", "ffn.output.bias")


def contextual_output_trainable_names(config: Mapping) -> frozenset[str]:
    return HEAD_NAMES | QUERY_NAMES if query_readout(config) else HEAD_NAMES


def contextual_trainable_names(config: Mapping, strategy: str | None = None) -> frozenset[str]:
    if strategy is None:
        return HEAD_NAMES
    if strategy not in (LAST_BLOCK_STRATEGY, FULL_ENCODER_STRATEGY):
        raise ModelArtifactError("Unsupported contextual training strategy.")
    layers = config.get("num_layers", 1)
    if type(layers) is not int or not 1 <= layers <= 512:
        raise ModelArtifactError("Contextual encoder layer count is invalid.")
    if strategy == FULL_ENCODER_STRATEGY:
        return HEAD_NAMES | {"token_embedding", "position_embedding"} | frozenset(
            ("" if layers == 1 else f"layers.{i}.") + name
            for i in range(layers) for name in BLOCK_NAMES)
    prefix = "" if layers == 1 else f"layers.{layers - 1}."
    return HEAD_NAMES | frozenset(prefix + name for name in BLOCK_NAMES)


def validate_contextual_training_objective(metadata) -> str | None:
    if not isinstance(metadata, Mapping):
        raise ModelArtifactError("Contextual metadata must be a mapping.")
    objective = metadata.get(OBJECTIVE_KEY)
    if OBJECTIVE_KEY in metadata and (type(objective) is not str or objective not in CLASS_BALANCED_OBJECTIVES):
        raise ModelArtifactError("Unsupported contextual training objective.")
    return objective


def validate_training_diagnostics_policy(metadata):
    policy = metadata.get(DIAGNOSTICS_POLICY_KEY)
    if DIAGNOSTICS_POLICY_KEY in metadata and policy != TRAIN_DIAGNOSTICS_POLICY:
        raise ModelArtifactError("Unsupported contextual training diagnostics policy.")
    return policy


def training_policy_expectations(metadata):
    """Resolve optional local caller admission; this does not override artifact policy."""
    objective = metadata.get("expected_contextual_training_objective")
    diagnostics = metadata.get("expected_contextual_training_diagnostics_policy")
    if "expected_contextual_training_objective" in metadata and objective not in PROCESS_OBJECTIVES:
        raise ValueError("Unsupported expected contextual training objective.")
    if ("expected_contextual_training_diagnostics_policy" in metadata and diagnostics != TRAIN_DIAGNOSTICS_POLICY
            and not (objective == CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE and diagnostics is None)):
        raise ValueError("Unsupported expected contextual training diagnostics policy.")
    result = {key: value for key, value in (("expected_objective", objective), ("expected_diagnostics_policy", diagnostics)) if value is not None}
    if objective in (CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE, RETENTION_GATE_OBJECTIVE, RETENTION_HINGE_OBJECTIVE):
        result["expected_diagnostics_policy"] = diagnostics
    policy = metadata.get("expected_contextual_training_backtracking_policy")
    preparation = metadata.get("expected_contextual_training_backtracking_preparation_sha256")
    if policy is not None or preparation is not None:
        if (policy != BACKTRACKING_POLICY or not _sha256_string(preparation)
                or objective not in PROCESS_OBJECTIVES
                or diagnostics != TRAIN_DIAGNOSTICS_POLICY):
            raise ValueError("Backtracking admission requires its policy, preparation hash, objective and diagnostics.")
        result.update(expected_backtracking_policy=policy, expected_backtracking_preparation_sha256=preparation)
    from .full_adam import expectations
    result.update(expectations(metadata))
    return result


def _sha256_string(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _bounded_training_json(raw):
    import json
    if type(raw) is not str or len(raw.encode("utf-8")) > 2048:
        raise ValueError("Training policy JSON exceeds its byte budget.")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate training policy field.")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def training_admission_metadata(expectations):
    import json
    from .window_training import POLICY as WINDOW_POLICY
    if expectations.get("expected_optimizer") == WINDOW_POLICY:
        record = {"schema": 5, **expectations}
    elif "expected_optimizer" in expectations:
        record = {"schema": 4 if expectations["expected_optimizer"] in RETENTION_POLICIES else 3, **expectations}
    elif "expected_backtracking_policy" not in expectations:
        if expectations.get("expected_objective") != CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE:
            return ()
        record = {"schema": 2, "expected_objective": expectations["expected_objective"],
                  "expected_diagnostics_policy": expectations.get("expected_diagnostics_policy")}
    else:
        record = {"schema": 1, **expectations}
    raw = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)
    parse_training_admission_metadata(((BACKTRACKING_HEADER, raw),))
    return ((BACKTRACKING_HEADER, raw),)


def parse_training_admission_metadata(metadata):
    values = [value for key, value in metadata if key == BACKTRACKING_HEADER]
    if not values:
        return None
    if len(values) != 1:
        raise ValueError("Duplicate backtracking admission header.")
    record = _bounded_training_json(values[0])
    if type(record) is dict and type(record.get("schema")) is int and record["schema"] == 5:
        from . import window_training as window
        keys = {"schema", "expected_objective", "expected_diagnostics_policy", "expected_optimizer",
                "expected_candidate_eligibility", "expected_optimizer_config", "expected_training_scope",
                "expected_window_manifest_sha256", "expected_component_manifest_sha256"}
        if set(record) != keys or record["expected_diagnostics_policy"] is not None:
            raise ValueError("Unsupported frozen-window schema5 admission.")
        checked = window.expectations({"expected_contextual_training_optimizer": record["expected_optimizer"],
            "expected_contextual_training_objective": record["expected_objective"],
            "expected_contextual_candidate_eligibility": record["expected_candidate_eligibility"],
            "expected_contextual_training_scope": record["expected_training_scope"],
            "expected_" + window.CONFIG_KEY: record["expected_optimizer_config"],
            "expected_" + window.WINDOW_KEY: record["expected_window_manifest_sha256"],
            "expected_" + window.REFERENCE_KEY: record["expected_component_manifest_sha256"]})
        if checked is None:
            raise ValueError("Schema5 requires window optimizer.")
        return checked
    if type(record) is dict and type(record.get("schema")) is int and record["schema"] == 4:
        from .sensitive_retention import expectations
        keys = {"schema", "expected_objective", "expected_diagnostics_policy", "expected_optimizer",
                "expected_candidate_eligibility", "expected_optimizer_config", "expected_training_scope",
                "expected_retention_manifest_sha256"}
        if set(record) != keys or record["expected_diagnostics_policy"] is not None:
            raise ValueError("Unsupported ORIGINAL TRAIN retention admission contract.")
        checked = expectations({"expected_contextual_training_optimizer": record["expected_optimizer"],
            "expected_contextual_candidate_eligibility": record["expected_candidate_eligibility"],
            "expected_full_projected_adam_config_v1": record["expected_optimizer_config"],
            "expected_contextual_training_scope": record["expected_training_scope"],
            "expected_contextual_training_objective": record["expected_objective"],
            "expected_original_train_retention_manifest_sha256": record["expected_retention_manifest_sha256"]})
        if checked is None:
            raise ValueError("Retention schema4 requires a retention optimizer.")
        return {"expected_objective": record["expected_objective"], "expected_diagnostics_policy": None, **checked}
    if type(record) is dict and record.get("schema") == 3:
        from .full_adam import expectations
        keys = {"schema", "expected_objective", "expected_diagnostics_policy", "expected_optimizer",
                "expected_candidate_eligibility", "expected_optimizer_config", "expected_training_scope"}
        if set(record) != keys or type(record["schema"]) is not int:
            raise ValueError("Unsupported FULL Adam admission contract.")
        checked = expectations({"expected_contextual_training_optimizer": record["expected_optimizer"],
            "expected_contextual_candidate_eligibility": record["expected_candidate_eligibility"],
            "expected_full_projected_adam_config_v1": record["expected_optimizer_config"],
            "expected_contextual_training_scope": record["expected_training_scope"],
            "expected_contextual_training_objective": record["expected_objective"],
            "expected_contextual_training_diagnostics_policy": record["expected_diagnostics_policy"]})
        return {"expected_objective": record["expected_objective"],
                "expected_diagnostics_policy": None, **checked}
    if type(record) is dict and type(record.get("schema")) is int and record["schema"] == 2:
        if (set(record) != {"schema", "expected_objective", "expected_diagnostics_policy"}
                or record["expected_objective"] != CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE
                or record["expected_diagnostics_policy"] not in (None, TRAIN_DIAGNOSTICS_POLICY)):
            raise ValueError("Unsupported objective-only admission contract.")
        return {key: value for key, value in record.items() if key != "schema"}
    keys = {"schema", "expected_objective", "expected_diagnostics_policy",
            "expected_backtracking_policy", "expected_backtracking_preparation_sha256"}
    if (type(record) is not dict or set(record) != keys or type(record["schema"]) is not int
            or record["schema"] != 1 or record["expected_backtracking_policy"] != BACKTRACKING_POLICY
            or record["expected_objective"] not in PROCESS_OBJECTIVES
            or record["expected_diagnostics_policy"] != TRAIN_DIAGNOSTICS_POLICY
            or not _sha256_string(record["expected_backtracking_preparation_sha256"])):
        raise ValueError("Unsupported backtracking admission contract.")
    return {key: record[key] for key in keys if key != "schema"}


def validate_backtracking_policy(metadata):
    import hashlib
    if BACKTRACKING_KEY not in metadata:
        if BACKTRACKING_PREPARATION_KEY in metadata:
            raise ModelArtifactError("Backtracking preparation requires its policy.")
        return None
    if (metadata[BACKTRACKING_KEY] != BACKTRACKING_POLICY
            or metadata.get(STRATEGY_KEY) != FULL_ENCODER_STRATEGY
            or metadata.get(OBJECTIVE_KEY) not in (None, CLASS_BALANCED_OBJECTIVE, CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE)
            or metadata.get(DIAGNOSTICS_POLICY_KEY) != TRAIN_DIAGNOSTICS_POLICY
            or OPTIMIZER_KEY in metadata):
        raise ModelArtifactError("Backtracking requires FULL summed BCE, diagnostics and absent optimizer.")
    try:
        record = _bounded_training_json(metadata.get(BACKTRACKING_PREPARATION_KEY))
        if (type(record) is not dict or set(record) != {"schema", "baseline_checksum", "baseline_fingerprint", "protocol_sha256", "source_sha256"}
                or type(record["schema"]) is not int or record["schema"] != 1
                or any(not _sha256_string(value) for key, value in record.items() if key != "schema")):
            raise ValueError("Invalid backtracking preparation identity.")
    except (ValueError, TypeError) as exc:
        raise ModelArtifactError("Backtracking preparation is invalid.") from exc
    return hashlib.sha256(metadata[BACKTRACKING_PREPARATION_KEY].encode()).hexdigest()


def prepare_training_backtracking_artifact(artifact, *, preparation):
    import json
    from .artifact import validate_artifact
    validate_artifact(artifact)
    result = copy.deepcopy(artifact)
    result["metadata"][BACKTRACKING_KEY] = BACKTRACKING_POLICY
    result["metadata"][BACKTRACKING_PREPARATION_KEY] = json.dumps(preparation, sort_keys=True, separators=(",", ":"), allow_nan=False)
    validate_backtracking_policy(result["metadata"])
    result["checksum"] = artifact_checksum({k: v for k, v in result.items() if k != "checksum"})
    validate_artifact(result)
    return result


def validate_backtracking_trace(metadata, *, examples, requested_rate, rejected=False):
    """Validate compact bounded trials without accepting nonfinite JSON arithmetic."""
    try:
        header = _bounded_training_json(metadata.get(BACKTRACKING_TRACE_KEY))
        trials = _bounded_training_json(metadata.get(BACKTRACKING_TRIALS_KEY))
        schema, columns = training_loss_contract(metadata.get(EXECUTED_OBJECTIVE_KEY))
        keys = {"schema", "policy", "objective", "base", "raw", "selected", "gradient_fits"}
        if schema == 2:
            keys.add("loss_columns")
        if (type(header) is not dict or set(header) != keys or type(header["schema"]) is not int or header["schema"] != schema
                or (schema == 2 and header["loss_columns"] != list(columns))
                or header["policy"] != BACKTRACKING_POLICY or type(header["gradient_fits"]) is not int or header["gradient_fits"] != 1
                or header["objective"] != metadata.get(EXECUTED_OBJECTIVE_KEY)
                or type(trials) is not list or not 1 <= len(trials) <= 5):
            raise ValueError("Invalid backtracking trace schema.")
        def finite(value):
            return type(value) in (int, float) and math.isfinite(value) and value >= 0
        base, raw = header["base"], header["raw"]
        if (type(base) is not list or len(base) != 2 or not _sha256_string(base[0]) or base[0] != metadata.get("base_parameter_fingerprint")
                or type(base[1]) is not list or len(base[1]) != len(columns) or not all(finite(v) for v in base[1])
                or not math.isclose(math.fsum(base[1][:-1]), base[1][-1], rel_tol=1e-10, abs_tol=1e-10)
                or type(raw) is not list or len(raw) != 5 or not _sha256_string(raw[0])
                or not _sha256_string(raw[1]) or raw[1] != metadata.get("trained_parameter_inventory_fingerprint")
                or type(raw[2]) is not int or raw[2] <= 0 or not all(finite(v) for v in raw[3:])):
            raise ValueError("Invalid backtracking base/raw-gradient audit.")
        improving = []
        for i, row in enumerate(trials):
            # rate, losses, clipping, rawmax, transportmax, deltaSHA, candidateSHA, status, completed rows, encoder changed, attempted rows
            if (type(row) is not list or len(row) != 11 or not finite(row[0]) or row[0] <= 0
                    or row[0] != requested_rate * BACKTRACKING_SCALES[i]):
                raise ValueError("Invalid backtracking trial rate/shape.")
            if (row[7] not in ("ok", "invalid_numeric") or type(row[8]) is not int or row[8] not in (0, examples) or type(row[9]) is not bool
                    or type(row[10]) is not int or row[10] not in (0, examples) or row[8] > row[10]):
                raise ValueError("Invalid backtracking trial execution.")
            if row[7] == "invalid_numeric":
                if (row[1] is not None
                        or (row[2] is not None and (type(row[2]) is not int or not 0 <= row[2] <= raw[2]))
                        or any(v is not None and not finite(v) for v in row[3:5])
                        or any(v is not None and not _sha256_string(v) for v in row[5:7])):
                    raise ValueError("Invalid numeric trial must have null loss.")
                continue
            if (type(row[1]) is not list or len(row[1]) != len(columns) or not all(finite(v) for v in row[1])
                    or not math.isclose(math.fsum(row[1][:-1]), row[1][-1], rel_tol=1e-10, abs_tol=1e-10)
                    or type(row[2]) is not int or not 0 <= row[2] <= raw[2]
                    or not all(finite(v) for v in row[3:5]) or not all(_sha256_string(v) for v in row[5:7])
                    or row[8] != examples):
                raise ValueError("Invalid backtracking trial values.")
            if base[1][-1] - row[1][-1] > BACKTRACKING_DECREASE and row[9]:
                improving.append(i)
        selected = header["selected"]
        if rejected:
            if selected is not None or improving or len(trials) != 5:
                raise ValueError("No-improvement rejection contradicts trial evidence.")
        elif (type(selected) is not int or improving != [selected] or selected != len(trials) - 1
                or metadata.get("effective_learning_rate") != str(trials[selected][0])
                or metadata.get("updated_parameter_fingerprint") != trials[selected][6]):
            raise ValueError("Selected backtracking trial differs from first improvement.")
        return header, trials
    except (OverflowError, TypeError, KeyError, IndexError) as exc:
        raise ValueError("Malformed backtracking numeric admission.") from exc


def prepare_training_policy_artifact(artifact, *, objective=LEGACY_OBJECTIVE, diagnostics=None):
    """Prepare the controlled legacy/class-balanced policy without changing model weights."""
    if objective not in PROCESS_OBJECTIVES:
        raise ModelArtifactError("Training process policy requires legacy or class-balanced summed BCE.")
    result = prepare_training_objective_artifact(artifact, None if objective == LEGACY_OBJECTIVE else objective)
    if diagnostics is None:
        result["metadata"].pop(DIAGNOSTICS_POLICY_KEY, None)
    else:
        result["metadata"][DIAGNOSTICS_POLICY_KEY] = diagnostics
    validate_training_diagnostics_policy(result["metadata"])
    result["checksum"] = artifact_checksum({k: v for k, v in result.items() if k != "checksum"})
    from .artifact import validate_artifact
    validate_artifact(result)
    return result


def validate_training_diagnostics(raw, *, objective, examples, base_fingerprint, candidate_fingerprint):
    """Admit a bounded prompt-free semantic TRAIN record for the exact transported state."""
    import json
    def finite_nonnegative(value):
        try:
            return type(value) in (int, float) and math.isfinite(value) and value >= 0
        except OverflowError:
            return False
    if type(raw) is not str or len(raw.encode("utf-8")) > 2048:
        raise ValueError("TRAIN diagnostics exceed their byte budget or are missing.")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate TRAIN diagnostic field.")
            result[key] = value
        return result
    record = json.loads(raw, object_pairs_hook=unique)
    schema, loss_columns = training_loss_contract(objective)
    keys = {"schema", "objective", "fingerprints", "phases", "counts", "loss_columns", "loss",
            "accuracy_columns", "accuracy", "update_columns", "update"}
    if not isinstance(record, dict) or set(record) != keys or type(record["schema"]) is not int or record["schema"] != schema:
        raise ValueError("Unknown TRAIN diagnostics schema.")
    if (record["objective"] != objective or record["fingerprints"] != [base_fingerprint, candidate_fingerprint]
            or record["phases"] != [["base_training", "semantic", "ok", examples],
                                     ["candidate_training", "semantic", "ok", examples]]):
        raise ValueError("TRAIN diagnostic policy, identity or semantic execution differs.")
    counts = record["counts"]
    if (not isinstance(counts, list) or len(counts) != 3 or any(type(v) is not int or v <= 0 for v in counts)
            or counts[0] != examples or counts[1] + counts[2] != examples):
        raise ValueError("TRAIN diagnostic strata counts are invalid.")
    for key, columns in (("loss", loss_columns), ("accuracy", DIAGNOSTIC_ACCURACY_COLUMNS)):
        if record[key + "_columns"] != list(columns) or not isinstance(record[key], list) or len(record[key]) != 2:
            raise ValueError("TRAIN diagnostic columns are invalid.")
        for row in record[key]:
            if (not isinstance(row, list) or len(row) != len(columns)
                    or any(not finite_nonnegative(v) for v in row)
                    or (key == "accuracy" and any(v > 1 for v in row))):
                raise ValueError("TRAIN diagnostic values are invalid.")
            if key == "loss":
                try:
                    reconciled = math.fsum(row[:-1])
                except OverflowError as exc:
                    raise ValueError("TRAIN diagnostic objective must remain finite.") from exc
                if not math.isclose(reconciled, row[-1], rel_tol=1e-10, abs_tol=1e-10):
                    raise ValueError("TRAIN diagnostic objective does not reconcile.")
    update = record["update"]
    if (record["update_columns"] != list(DIAGNOSTIC_UPDATE_COLUMNS) or not isinstance(update, list) or len(update) != 4
            or any(type(v) is not int or v < 0 for v in update[:2]) or update[0] <= 0 or update[1] > update[0]
            or any(not finite_nonnegative(v) for v in update[2:])):
        raise ValueError("TRAIN diagnostic update summary is invalid.")
    return record


def validate_decision_margin_config(config):
    """The union margin needs an S0 reference and at least one severity alternative."""
    labels = config.get("sensitivity_labels", ())
    if (not isinstance(labels, (list, tuple)) or any(type(label) is not str for label in labels)
            or labels.count("S0") != 1 or not any(label != "S0" for label in labels)):
        raise ModelArtifactError("Decision-margin training requires S0 and non-S0 sensitivity labels.")
    threshold = config.get("category_threshold", 0.5)
    if (type(threshold) not in (int, float) or not math.isfinite(threshold)
            or not 0 < threshold < 1):
        raise ModelArtifactError("Decision-margin category threshold must be finite and between zero and one.")


def validate_contextual_training_optimizer(metadata) -> int | None:
    """Return the explicit local step budget; absent metadata retains legacy SGD."""
    if not isinstance(metadata, Mapping):
        raise ModelArtifactError("Contextual metadata must be a mapping.")
    if OPTIMIZER_KEY not in metadata:
        return None
    optimizer = metadata[OPTIMIZER_KEY]
    if type(optimizer) is not str:
        raise ModelArtifactError("Contextual training optimizer must be a string.")
    from .full_adam import POLICY, validate_policy
    from .window_training import POLICY as WINDOW_POLICY
    if optimizer in (POLICY, WINDOW_POLICY) or optimizer in RETENTION_POLICIES:
        validate_policy(metadata)
        return None  # Distinct dispatch; never route Adam through local SGD.
    if type(optimizer) is not str or optimizer not in LOCAL_SGD_STEPS:
        raise ModelArtifactError("Unsupported contextual training optimizer.")
    return LOCAL_SGD_STEPS[optimizer]


def validate_contextual_training_contract(config, parameters, shapes, flags, metadata) -> frozenset[str]:
    """Validate exact trainability; inference configuration validates full tensor shapes."""
    if not isinstance(metadata, Mapping):
        raise ModelArtifactError("Contextual metadata must be a mapping.")
    if OPTIMIZER_KEY in metadata and type(metadata[OPTIMIZER_KEY]) is not str:
        raise ModelArtifactError("Contextual training optimizer must be a string.")
    objective = validate_contextual_training_objective(metadata)
    validate_training_diagnostics_policy(metadata)
    if objective in DECISION_MARGIN_OBJECTIVES:
        validate_decision_margin_config(config)
    from .full_adam import POLICY, validate_policy
    validate_policy(metadata)
    from .window_training import POLICY as WINDOW_POLICY
    if objective in (RETENTION_GATE_OBJECTIVE, RETENTION_HINGE_OBJECTIVE) and metadata.get(OPTIMIZER_KEY) not in RETENTION_POLICIES:
        raise ModelArtifactError("ORIGINAL retention objectives require their explicit optimizer contract.")
    if (objective == CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE and OPTIMIZER_KEY in metadata
            and metadata[OPTIMIZER_KEY] not in (POLICY, WINDOW_POLICY)):
        raise ModelArtifactError("Summed-category decision-margin training requires absent optimizer metadata.")
    validate_contextual_training_optimizer(metadata)
    validate_backtracking_policy(metadata)
    strategy = metadata.get(STRATEGY_KEY)
    if STRATEGY_KEY in metadata and (type(strategy) is not str or not strategy):
        raise ModelArtifactError("Contextual training strategy must be a nonempty string.")
    expected = contextual_trainable_names(config, strategy)
    if strategy == FULL_ENCODER_STRATEGY:
        exact_shapes = full_encoder_tensor_shapes(config)
        if set(shapes) != set(exact_shapes) or any(tuple(shapes[name]) != shape for name, shape in exact_shapes.items()):
            raise ModelArtifactError("Full encoder tensor shapes do not match the configuration.")
    if not isinstance(flags, Mapping) or set(flags) != set(parameters) or set(shapes) != set(parameters):
        raise ModelArtifactError("Contextual trainable manifest is incomplete.")
    if not expected.issubset(parameters):
        raise ModelArtifactError("Contextual training tensor manifest is incomplete.")
    for name, flag in flags.items():
        if type(flag) is not bool or flag != (name in expected):
            raise ModelArtifactError("Contextual trainable flags do not match its strategy.")
    if strategy is not None:
        # All model tensors must be supported, even when marked frozen.
        layers = config.get("num_layers", 1)
        allowed = HEAD_NAMES | {"token_embedding", "position_embedding"} | {
            ("" if layers == 1 else f"layers.{i}.") + name
            for i in range(layers) for name in BLOCK_NAMES}
        if set(parameters) != allowed:
            raise ModelArtifactError("Contextual adapted tensor manifest is not exact.")
        for name in expected:
            shape = shapes[name]
            if (not isinstance(shape, (list, tuple)) or not shape
                    or any(type(v) is not int or v <= 0 for v in shape)
                    or math.prod(shape) != len(parameters[name])
                    or len(parameters[name]) > (FULL_ENCODER_MAX_TENSOR_VALUES if strategy == FULL_ENCODER_STRATEGY else 4096)):
                raise ModelArtifactError("Contextual training tensor exceeds its update contract.")
        if sum(len(values) for values in parameters.values()) > 65_536:
            raise ModelArtifactError("Contextual training exceeds its total update contract.")
    return expected


def full_encoder_tensor_shapes(config):
    """Exact Tiny full-training inventory; bound allocations before construction."""
    dimensions = [config.get(name) for name in ("vocab_size", "hidden_size", "intermediate_size", "max_tokens")]
    if any(type(value) is not int or not 1 <= value <= 65_536 for value in dimensions):
        raise ModelArtifactError("Full encoder configuration dimensions are invalid.")
    vocab, hidden, intermediate, context = dimensions
    if context > 512 or vocab < 2:
        raise ModelArtifactError("Full encoder context/vocabulary exceeds its contract.")
    result = {"token_embedding": (vocab, hidden), "position_embedding": (context, hidden)}
    for task in ("sensitivity", "visibility", "category"):
        labels = config.get(task + "_labels")
        if not isinstance(labels, (list, tuple)) or not labels:
            raise ModelArtifactError("Full encoder requires explicit label inventories.")
        result[f"head.{task}.weight"] = (hidden, len(labels))
        result[f"head.{task}.bias"] = (len(labels),)
    for layer in range(config.get("num_layers", 1)):
        prefix = "" if config.get("num_layers", 1) == 1 else f"layers.{layer}."
        result.update({prefix + name: shape for name, shape in {
            "attention.query.weight": (hidden, hidden), "attention.key.weight": (hidden, hidden),
            "attention.value.weight": (hidden, hidden), "attention.output.weight": (hidden, hidden),
            "attention.output.bias": (hidden,), "ffn.input.weight": (hidden, intermediate),
            "ffn.input.bias": (intermediate,), "ffn.output.weight": (intermediate, hidden),
            "ffn.output.bias": (hidden,)}.items()})
    if sum(math.prod(shape) for shape in result.values()) > 65_536:
        raise ModelArtifactError("Full encoder configuration exceeds the total parameter budget.")
    return result


def prepare_contextual_training_artifact(artifact, strategy=LAST_BLOCK_STRATEGY, *, objective=None):
    """Return independent opt-in release bytes; do not install or change weights/version."""
    from .artifact import validate_artifact
    validate_artifact(artifact)
    if artifact["architecture"] != ARCHITECTURE_NAME:
        raise ModelArtifactError("Contextual adaptation requires a contextual transformer.")
    result = copy.deepcopy(artifact)
    names = contextual_trainable_names(result["config"], strategy)
    for name, tensor in result["parameters"].items():
        tensor["trainable"] = name in names
    metadata = result.setdefault("metadata", {})
    if strategy is None:
        metadata.pop(STRATEGY_KEY, None)
    else:
        metadata[STRATEGY_KEY] = strategy
    if objective is not None:
        metadata[OBJECTIVE_KEY] = objective
    validate_contextual_training_objective(metadata)
    result["checksum"] = artifact_checksum({k: v for k, v in result.items() if k != "checksum"})
    validate_artifact(result)
    return result


def prepare_full_encoder_artifact(artifact, *, version, generated_at_unix, source_revision, max_tokens=None):
    """Create an opt-in release preserving every existing weight coordinate.

    The caller persists the result separately; shipped artifacts are never updated.
    Optional context extension appends versioned position rows; shapes and full
    fingerprints then change. Provenance binds the source checksum and commit.
    """
    import re
    if "last_update_receipt" in artifact.get("metadata", {}):
        raise ModelArtifactError("Checkpoint and clear the recovery receipt before preparing a new release.")
    if (not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}", version)
            or version == artifact.get("version")):
        raise ModelArtifactError("Full encoder preparation requires a distinct valid release version.")
    if type(generated_at_unix) is not int or generated_at_unix <= 0:
        raise ModelArtifactError("Full encoder preparation requires a positive timestamp.")
    if not isinstance(source_revision, str) or not re.fullmatch(r"[0-9a-f]{40}", source_revision):
        raise ModelArtifactError("Full encoder preparation requires an exact source commit.")
    result = prepare_contextual_training_artifact(artifact, FULL_ENCODER_STRATEGY)
    previous_context = result["config"]["max_tokens"]
    selected_context = previous_context if max_tokens is None else max_tokens
    if type(selected_context) is not int or not previous_context <= selected_context <= 512:
        raise ModelArtifactError("Context extension must be an integer between the source context and 512.")
    if selected_context != previous_context:
        import hashlib
        from .artifact import float32
        hidden = result["config"]["hidden_size"]
        position = result["parameters"]["position_embedding"]
        # Independent hash draws avoid a framework RNG/version dependency. Each
        # new coordinate maps a 32-bit integer to [-.03, .03], then float32.
        for row in range(previous_context, selected_context):
            for column in range(hidden):
                key = f"privoke_position_sha256_v1:{row}:{column}".encode("ascii")
                number = int.from_bytes(hashlib.sha256(key).digest()[:4], "big")
                position["values"].append(float32((number / (2**32 - 1) * 2 - 1) * .03))
        position["shape"] = [selected_context, hidden]
        result["config"]["max_tokens"] = selected_context
    result["version"] = version
    result["generated_at_unix"] = generated_at_unix
    result["metadata"].update(release_version=version, training_revision="0",
        preparation_source_revision=source_revision, preparation_base_version=artifact["version"],
        preparation_base_checksum=artifact["checksum"],
        preparation_old_max_tokens=str(previous_context), preparation_max_tokens=str(selected_context),
        preparation_position_initialization="sha256_coordinate_uniform_float32_v1" if selected_context != previous_context else "unchanged",
        preparation_purpose="explicit_full_tiny_encoder_training_no_quality_promotion")
    result["checksum"] = artifact_checksum({key: value for key, value in result.items() if key != "checksum"})
    from .artifact import validate_artifact
    validate_artifact(result)
    return result


def prepare_training_objective_artifact(artifact, objective=None):
    """Set or remove the objective without changing weights, version or trainable flags."""
    from .artifact import validate_artifact
    validate_artifact(artifact)
    if artifact["architecture"] != ARCHITECTURE_NAME:
        raise ModelArtifactError("Contextual objectives require a contextual transformer.")
    result = copy.deepcopy(artifact)
    metadata = result.setdefault("metadata", {})
    if objective is None:
        metadata.pop(OBJECTIVE_KEY, None)
    else:
        metadata[OBJECTIVE_KEY] = objective
    validate_contextual_training_objective(metadata)
    result["checksum"] = artifact_checksum({k: v for k, v in result.items() if k != "checksum"})
    validate_artifact(result)
    return result


def prepare_training_optimizer_artifact(artifact, optimizer=None):
    """Set/remove local SGD independently; preserve weights, release and trainability."""
    from .artifact import validate_artifact
    validate_artifact(artifact)
    if artifact["architecture"] != ARCHITECTURE_NAME:
        raise ModelArtifactError("Contextual optimizers require a contextual transformer.")
    result = copy.deepcopy(artifact)
    metadata = result.setdefault("metadata", {})
    if optimizer is None:
        metadata.pop(OPTIMIZER_KEY, None)
    else:
        metadata[OPTIMIZER_KEY] = optimizer
    validate_contextual_training_optimizer(metadata)
    result["checksum"] = artifact_checksum({k: v for k, v in result.items() if k != "checksum"})
    validate_artifact(result)
    return result
