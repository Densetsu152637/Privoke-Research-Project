"""Versioned, bounded contextual last-block training contract."""
from __future__ import annotations

import copy
import math
from collections.abc import Mapping

from .artifact import ARCHITECTURE_NAME, ModelArtifactError, artifact_checksum

STRATEGY_KEY = "contextual_training_strategy"
LAST_BLOCK_STRATEGY = "contextual_last_block_sgd_v1"
OPTIMIZER_KEY = "contextual_training_optimizer"
LOCAL_SGD_1 = "local_sgd_1_v1"
LOCAL_SGD_4 = "local_sgd_4_v1"
LOCAL_SGD_STEPS = {LOCAL_SGD_1: 1, LOCAL_SGD_4: 4}
OBJECTIVE_KEY = "contextual_training_objective"
CLASS_BALANCED_OBJECTIVE = "class_balanced_contextual_v1"
CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE = "class_balanced_contextual_mean_category_v1"
CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE = "class_balanced_contextual_decision_margin_v1"
MEAN_CATEGORY_OBJECTIVES = frozenset((CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE, CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE))
CLASS_BALANCED_OBJECTIVES = frozenset((CLASS_BALANCED_OBJECTIVE, *MEAN_CATEGORY_OBJECTIVES))
HEAD_NAMES = frozenset(f"head.{head}.{part}" for head in
                       ("sensitivity", "visibility", "category") for part in ("weight", "bias"))
BLOCK_NAMES = ("attention.query.weight", "attention.key.weight", "attention.value.weight",
               "attention.output.weight", "attention.output.bias", "ffn.input.weight",
               "ffn.input.bias", "ffn.output.weight", "ffn.output.bias")


def contextual_trainable_names(config: Mapping, strategy: str | None = None) -> frozenset[str]:
    if strategy is None:
        return HEAD_NAMES
    if strategy != LAST_BLOCK_STRATEGY:
        raise ModelArtifactError("Unsupported contextual training strategy.")
    layers = config.get("num_layers", 1)
    if type(layers) is not int or not 1 <= layers <= 512:
        raise ModelArtifactError("Contextual encoder layer count is invalid.")
    prefix = "" if layers == 1 else f"layers.{layers - 1}."
    return HEAD_NAMES | frozenset(prefix + name for name in BLOCK_NAMES)


def validate_contextual_training_objective(metadata) -> str | None:
    if not isinstance(metadata, Mapping):
        raise ModelArtifactError("Contextual metadata must be a mapping.")
    objective = metadata.get(OBJECTIVE_KEY)
    if OBJECTIVE_KEY in metadata and (type(objective) is not str or objective not in CLASS_BALANCED_OBJECTIVES):
        raise ModelArtifactError("Unsupported contextual training objective.")
    return objective


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
    if type(optimizer) is not str or optimizer not in LOCAL_SGD_STEPS:
        raise ModelArtifactError("Unsupported contextual training optimizer.")
    return LOCAL_SGD_STEPS[optimizer]


def validate_contextual_training_contract(config, parameters, shapes, flags, metadata) -> frozenset[str]:
    """Validate exact trainability; inference configuration validates full tensor shapes."""
    if not isinstance(metadata, Mapping):
        raise ModelArtifactError("Contextual metadata must be a mapping.")
    objective = validate_contextual_training_objective(metadata)
    if objective == CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE:
        validate_decision_margin_config(config)
    validate_contextual_training_optimizer(metadata)
    strategy = metadata.get(STRATEGY_KEY)
    if STRATEGY_KEY in metadata and (type(strategy) is not str or not strategy):
        raise ModelArtifactError("Contextual training strategy must be a nonempty string.")
    expected = contextual_trainable_names(config, strategy)
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
                    or math.prod(shape) != len(parameters[name]) or len(parameters[name]) > 4096):
                raise ModelArtifactError("Contextual training tensor exceeds its update contract.")
    return expected


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
