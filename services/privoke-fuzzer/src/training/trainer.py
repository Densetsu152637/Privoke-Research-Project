from __future__ import annotations

import random
import os
from pathlib import Path
from typing import Iterable, Sequence

from .evaluation import (
    accumulate_gradient,
    classification_loss,
)
from .io import load_training_examples
from .parameters import (
    add_parameter_delta,
    clamp,
    parameter_fingerprint,
    snapshot_with_trainable_parameters,
)
from .protocols import StreamedParameterSnapshot
from .transforms import random_pii_transform
from .types import BatchTrainingConfig, BatchTrainingExample, BatchTrainingUpdate
from runtime_client import PrivokeRuntimeClient


def train_parameter_batch_from_files(
    snapshot: StreamedParameterSnapshot,
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
        snapshot=snapshot,
        new_examples=load_training_examples(batch_path),
        golden_examples=golden_examples,
        config=config,
        runtime_client=runtime_client,
    )


def train_parameter_batch(
    snapshot: StreamedParameterSnapshot,
    new_examples: Sequence[BatchTrainingExample],
    golden_examples: Sequence[BatchTrainingExample] = (),
    config: BatchTrainingConfig | None = None,
    runtime_client: PrivokeRuntimeClient | None = None,
) -> BatchTrainingUpdate:
    config = config or BatchTrainingConfig()
    _validate_config(config)

    client_snapshot = snapshot_with_trainable_parameters(snapshot)
    parameters = dict(client_snapshot.parameters)
    trainer_examples = list(iter_training_examples(new_examples, golden_examples, config))
    if not trainer_examples:
        raise ValueError("At least one training example is required.")

    runtime_client = runtime_client or PrivokeRuntimeClient(
        os.getenv("PRIVOKE_RUNTIME_TARGET", "client-runtime:50054"),
        timeout_seconds=float(os.getenv("FUZZ_TIMEOUT_SECONDS", "10")),
    )
    gradients = {name: [0.0 for _ in values] for name, values in parameters.items()}
    total_weight = 0.0
    total_loss = 0.0
    exact_matches = 0

    for example in trainer_examples:
        predicted = runtime_client.classify(
            example.text,
            layer="semantic",
            model_id=client_snapshot.model_id,
        )
        target = target_classification_for_example(example, predicted)
        loss = classification_loss(target, predicted)

        if target.pack() == predicted.pack():
            exact_matches += 1

        accumulate_gradient(
            gradients=gradients,
            parameters=parameters,
            target=target,
            predicted=predicted,
            weight=example.weight,
        )
        total_loss += loss * example.weight
        total_weight += example.weight

    gradient_parameters = {
        name: tuple(
            clamp(
                (value / total_weight) * config.learning_rate,
                -config.max_gradient,
                config.max_gradient,
            )
            for value in values
        )
        for name, values in gradients.items()
    }
    updated_parameters = add_parameter_delta(parameters, gradient_parameters)

    return BatchTrainingUpdate(
        model_id=client_snapshot.model_id,
        base_version=client_snapshot.version,
        gradients=gradient_parameters,
        updated_parameters=updated_parameters,
        metrics={
            "examples": float(len(trainer_examples)),
            "new_examples": float(len(new_examples)),
            "golden_examples": float(len(golden_examples)),
            "average_loss": total_loss / total_weight,
            "exact_match_rate": exact_matches / len(trainer_examples),
            "total_weight": total_weight,
        },
        metadata={
            "strategy": "grpc_runtime_semantic_batch_training",
            "base_parameter_fingerprint": parameter_fingerprint(parameters),
            "updated_parameter_fingerprint": parameter_fingerprint(updated_parameters),
            "learning_rate": str(config.learning_rate),
            "max_gradient": str(config.max_gradient),
            "transformations_per_example": str(config.transformations_per_example),
        },
    )


def target_classification_for_example(
    example: BatchTrainingExample,
    predicted,
):
    if example.has_explicit_target:
        return example.expected_classification
    # Unlabelled examples are useful as stability/golden samples: the runtime's
    # current classification is their target, so they do not invent labels in
    # the fuzzer process.
    return predicted


def iter_training_examples(
    new_examples: Sequence[BatchTrainingExample],
    golden_examples: Sequence[BatchTrainingExample],
    config: BatchTrainingConfig,
) -> Iterable[BatchTrainingExample]:
    rng = random.Random(config.seed)

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
    if config.learning_rate <= 0:
        raise ValueError("learning_rate must be greater than zero.")
    if config.max_gradient <= 0:
        raise ValueError("max_gradient must be greater than zero.")
