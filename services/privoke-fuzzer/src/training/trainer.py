from __future__ import annotations

import math
import random
from collections.abc import Iterable, Sequence
from pathlib import Path

from privoke_service import env_float, env_string
from runtime_client import PrivokeRuntimeClient

from .io import load_training_examples
from .transforms import random_pii_transform
from .types import BatchTrainingConfig, BatchTrainingExample, BatchTrainingUpdate


def train_parameter_batch_from_files(
    model_id: str,
    batch_path: str | Path,
    golden_batch_path: str | Path | None = None,
    config: BatchTrainingConfig | None = None,
    runtime_client: PrivokeRuntimeClient | None = None,
) -> BatchTrainingUpdate:
    golden_examples = (
        load_training_examples(golden_batch_path)
        if golden_batch_path is not None
        else []
    )
    return train_parameter_batch(
        model_id=model_id,
        new_examples=load_training_examples(batch_path),
        golden_examples=golden_examples,
        config=config,
        runtime_client=runtime_client,
    )


def train_parameter_batch(
    model_id: str,
    new_examples: Sequence[BatchTrainingExample],
    golden_examples: Sequence[BatchTrainingExample] = (),
    config: BatchTrainingConfig | None = None,
    runtime_client: PrivokeRuntimeClient | None = None,
) -> BatchTrainingUpdate:
    """Prepare examples and delegate model execution and descent to client-runtime."""
    config = config or BatchTrainingConfig()
    _validate_config(config)
    trainer_examples = list(
        iter_training_examples(new_examples, golden_examples, config)
    )
    _validate_examples(trainer_examples)
    runtime_client = runtime_client or _default_runtime_client()
    batch = runtime_client.compute_semantic_gradients(
        trainer_examples,
        model_id=model_id,
        learning_rate=config.learning_rate,
        max_gradient=config.max_gradient,
    )
    metrics = dict(batch["metrics"])
    metrics.update(
        {
            "new_examples": float(len(new_examples)),
            "golden_examples": float(len(golden_examples)),
        }
    )
    metadata = dict(batch["metadata"])
    metadata["transformations_per_example"] = str(config.transformations_per_example)
    return BatchTrainingUpdate(
        model_id=batch["model_id"],
        base_version=batch["base_version"],
        gradients=batch["gradients"],
        parameter_shapes=batch["shapes"],
        metrics=metrics,
        metadata=metadata,
    )


def _default_runtime_client() -> PrivokeRuntimeClient:
    return PrivokeRuntimeClient(
        env_string("PRIVOKE_RUNTIME_TARGET", "client-runtime:50054"),
        timeout_seconds=env_float("FUZZ_TIMEOUT_SECONDS", 10.0),
    )


def _validate_examples(examples: Sequence[BatchTrainingExample]) -> None:
    if not examples:
        raise ValueError("At least one training example is required.")
    if any(
        not math.isfinite(example.weight) or example.weight <= 0 for example in examples
    ):
        raise ValueError("Training example weights must be finite and positive.")


def iter_training_examples(
    new_examples: Sequence[BatchTrainingExample],
    golden_examples: Sequence[BatchTrainingExample],
    config: BatchTrainingConfig,
) -> Iterable[BatchTrainingExample]:
    rng = random.Random(config.seed)  # nosec B311
    for example in new_examples:
        yield example.with_text_and_weight(
            example.text,
            example.weight * config.new_example_weight,
        )
        for _ in range(max(0, config.transformations_per_example)):
            yield example.with_text_and_weight(
                random_pii_transform(example.text, rng),
                example.weight * config.new_example_weight,
            )
    for example in golden_examples:
        yield example.with_text_and_weight(
            example.text,
            example.weight * config.golden_example_weight,
        )


def _validate_config(config: BatchTrainingConfig) -> None:
    if not math.isfinite(config.learning_rate) or config.learning_rate <= 0:
        raise ValueError("learning_rate must be finite and greater than zero.")
    if not math.isfinite(config.max_gradient) or config.max_gradient <= 0:
        raise ValueError("max_gradient must be finite and greater than zero.")
