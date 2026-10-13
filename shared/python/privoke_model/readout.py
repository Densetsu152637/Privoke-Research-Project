"""Versioned Tiny task readout identity and exact tensor inventory."""
from __future__ import annotations

LEGACY_ARCHITECTURE = "privoke_tiny_transformer_v1"
TASK_QUERY_ARCHITECTURE = "privoke_tiny_transformer_v2"
TASK_QUERY_READOUT = "residual_task_query_v1"
TASKS = ("sensitivity", "visibility", "category")
QUERY_NAMES = frozenset(f"readout.{task}.query" for task in TASKS)


def query_readout(config):
    from .artifact import ModelArtifactError
    readout = config.get("readout")
    if readout is not None and readout not in ("legacy_pool_v1", TASK_QUERY_READOUT):
        raise ModelArtifactError("Unsupported Tiny readout.")
    if "readout" in config and readout is None:
        raise ModelArtifactError("Tiny readout must be explicit when declared.")
    return readout == TASK_QUERY_READOUT


def validate_readout_identity(architecture, config):
    from .artifact import ModelArtifactError
    enabled = query_readout(config)
    if architecture != (TASK_QUERY_ARCHITECTURE if enabled else LEGACY_ARCHITECTURE):
        raise ModelArtifactError("Tiny architecture and readout configuration disagree.")
    if enabled:
        validate_query_config(config)
    return enabled


def validate_query_config(config):
    import math
    from .artifact import ModelArtifactError
    from privoke_contracts.classification import Category, Sensitivity, Visibility
    for name in ("vocab_size", "hidden_size", "intermediate_size", "max_tokens", "num_layers", "num_attention_heads"):
        value = config.get(name, 1 if name in ("num_layers", "num_attention_heads") else None)
        if type(value) is not int or not 1 <= value <= 65_536:
            raise ModelArtifactError("Invalid task-query Tiny dimensions.")
    if (config["vocab_size"] < 2 or config["max_tokens"] > 512 or config.get("num_layers", 1) > 512
            or config["hidden_size"] % config.get("num_attention_heads", 1)):
        raise ModelArtifactError("Invalid task-query Tiny capacity or attention heads.")
    for task, enum in (("sensitivity", Sensitivity), ("visibility", Visibility), ("category", Category)):
        labels = config.get(f"{task}_labels")
        if (not isinstance(labels, (list, tuple)) or any(type(v) is not str for v in labels)
                or len(labels) != len(enum) or set(labels) != set(enum.__members__)):
            raise ModelArtifactError("Task-query Tiny requires exact label inventories.")
    threshold = config.get("category_threshold", .5)
    if type(threshold) not in (int, float) or not math.isfinite(threshold) or not 0 < threshold < 1:
        raise ModelArtifactError("Invalid task-query category threshold.")
