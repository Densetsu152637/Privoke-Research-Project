from __future__ import annotations

import math
import os
import random
from pathlib import Path
from typing import Iterable, Sequence

from privoke_model import ModelConfig, TinyTransformerModel

from .evaluation import classification_loss
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
    model = TinyTransformerModel(
        ModelConfig.from_metadata(client_snapshot.metadata),
        parameters,
        client_snapshot.shapes,
    )
    trainable_names = {
        name
        for name in client_snapshot.metadata.get("trainable_parameters", "").split(",")
        if name
    }
    if not trainable_names:
        raise ValueError("The streamed model declares no trainable parameters.")
    gradients = {
        name: [0.0 for _ in parameters[name]]
        for name in sorted(trainable_names)
        if name in parameters
    }
    if set(gradients) != trainable_names:
        raise ValueError("The model trainable parameter manifest is inconsistent.")
    total_weight = 0.0
    total_loss = 0.0
    exact_matches = 0

    for example in trainer_examples:
        if not math.isfinite(example.weight) or example.weight <= 0:
            raise ValueError("Training example weights must be finite and positive.")
        predicted = runtime_client.classify(
            example.text,
            layer="semantic",
            model_id=client_snapshot.model_id,
        )
        target = target_classification_for_example(example, predicted)
        loss = classification_loss(target, predicted)

        if target.pack() == predicted.pack():
            exact_matches += 1

        example_deltas = model.classification_head_deltas(
            example.text,
            sensitivity=target.sensitivity().name,
            visibility=target.visibility().name,
            categories=[category.name for category in target.categories()],
        )
        for name, values in example_deltas.items():
            if name not in gradients:
                continue
            for index, value in enumerate(values):
                gradients[name][index] += value * example.weight
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
        parameter_shapes={
            name: client_snapshot.shapes[name]
            for name in gradient_parameters
        },
        metrics={
            "examples": float(len(trainer_examples)),
            "new_examples": float(len(new_examples)),
            "golden_examples": float(len(golden_examples)),
            "average_loss": total_loss / total_weight,
            "exact_match_rate": exact_matches / len(trainer_examples),
            "total_weight": total_weight,
        },
        metadata={
            "strategy": "transformer_classification_head_finetune",
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
    # Reproducible training transforms; this value is not security-sensitive.
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
