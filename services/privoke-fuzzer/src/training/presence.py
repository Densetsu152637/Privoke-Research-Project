"""Presence-specific runtime gradient orchestration."""

from __future__ import annotations

from collections.abc import Sequence

from privoke_model.training_data import training_text_key
from runtime_client import PrivokeRuntimeClient

from .trainer import _default_runtime_client, _validate_config
from .types import BatchTrainingConfig, BatchTrainingUpdate


def train_presence_batch(
    model_id: str,
    examples: Sequence,
    heldout_examples: Sequence = (),
    config: BatchTrainingConfig | None = None,
    runtime_client: PrivokeRuntimeClient | None = None,
    request_id: str = "",
) -> BatchTrainingUpdate:
    """Send explicit presence labels to runtime; no augmentation or local model access."""
    config = config or BatchTrainingConfig(transformations_per_example=0)
    _validate_config(config)
    if not examples:
        raise ValueError("At least one presence training example is required.")
    if len(examples) + len(heldout_examples) > 1024:
        raise ValueError("Presence training plus held-out examples must not exceed 1024.")
    for example in (*examples, *heldout_examples):
        if type(example.sensitive) is not bool:
            raise ValueError("Presence targets must be strict booleans.")
        if not example.group_id:
            raise ValueError("Presence examples need source group IDs.")
    train_groups = {example.group_id for example in examples}
    heldout_groups = {example.group_id for example in heldout_examples}
    if train_groups & heldout_groups:
        raise ValueError("Presence training and held-out source groups overlap.")
    train_texts = {training_text_key(example.text) for example in examples}
    heldout_texts = {training_text_key(example.text) for example in heldout_examples}
    if train_texts & heldout_texts:
        raise ValueError("Presence training and held-out normalized texts overlap.")
    client = runtime_client or _default_runtime_client()
    batch = client.compute_presence_gradients(
        examples,
        heldout_examples=heldout_examples,
        model_id=model_id,
        learning_rate=config.learning_rate,
        max_gradient=config.max_gradient,
        request_id=request_id,
    )
    metadata = dict(batch["metadata"])
    metadata["training_pipeline"] = "client_runtime_presence_gradients"
    metadata["task"] = "annotation_presence"
    return BatchTrainingUpdate(
        model_id=batch["model_id"],
        base_version=batch["base_version"],
        gradients=batch["gradients"],
        parameter_shapes=batch["shapes"],
        metrics=dict(batch["metrics"]),
        metadata=metadata,
    )
