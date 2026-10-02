from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Sequence

from privoke_model.fingerprint import parameter_fingerprint
from ...classification import Classification
from ...model import ModelConfig, TinyTransformerModel
from .parameter_stream import ModelParameterStreamer
from .streamed_model import GLOBAL_STREAMED_MODEL_CACHE


@dataclass(frozen=True)
class SemanticTrainingExample:
    text: str
    target: Classification | None
    weight: float


@dataclass(frozen=True)
class SemanticGradientBatch:
    model_id: str
    base_version: str
    gradients: dict[str, tuple[float, ...]]
    shapes: dict[str, tuple[int, ...]]
    metrics: dict[str, float]
    metadata: dict[str, str]


def compute_semantic_gradients(
    examples: Sequence[SemanticTrainingExample],
    *,
    model_id: str,
    learning_rate: float,
    max_gradient: float,
    heldout_examples: Sequence[SemanticTrainingExample] = (),
) -> SemanticGradientBatch:
    """Execute one bounded classification-head update using the cached runtime model."""
    if not examples:
        raise ValueError("At least one training example is required.")
    if not math.isfinite(learning_rate) or learning_rate <= 0:
        raise ValueError("learning_rate must be finite and greater than zero.")
    if not math.isfinite(max_gradient) or max_gradient <= 0:
        raise ValueError("max_gradient must be finite and greater than zero.")
    if any(not math.isfinite(item.weight) or item.weight <= 0 for item in examples):
        raise ValueError("Training example weights must be finite and positive.")

    streamer = ModelParameterStreamer(model_id=model_id)
    runtime_model = GLOBAL_STREAMED_MODEL_CACHE.model_for_training(streamer)
    snapshot = runtime_model.snapshot
    trainable_names = {
        name
        for name in snapshot.metadata.get("trainable_parameters", "").split(",")
        if name
    }
    if not trainable_names:
        raise ValueError("The streamed model declares no trainable parameters.")
    if not trainable_names.issubset(snapshot.parameters):
        raise ValueError("The model trainable parameter manifest is inconsistent.")

    gradients = {
        name: [0.0 for _ in snapshot.parameters[name]]
        for name in sorted(trainable_names)
    }
    predictions = runtime_model.model.predict_many(
        tuple(example.text for example in examples)
    )
    total_weight = 0.0
    total_loss = 0.0
    exact_matches = 0

    for example, prediction in zip(examples, predictions):
        predicted = _classification_from_prediction(prediction)
        target = example.target or predicted
        if target.pack() == predicted.pack():
            exact_matches += 1
        deltas = runtime_model.model.classification_head_deltas_from_prediction(
            prediction,
            sensitivity=target.sensitivity().name,
            visibility=target.visibility().name,
            categories=[category.name for category in target.categories()],
        )
        for name, values in deltas.items():
            if name not in gradients:
                continue
            for index, value in enumerate(values):
                gradients[name][index] += value * example.weight
        total_loss += _classification_loss(target, predicted) * example.weight
        total_weight += example.weight

    scaled = {
        name: tuple(
            _clamp(
                (value / total_weight) * learning_rate,
                -max_gradient,
                max_gradient,
            )
            for value in values
        )
        for name, values in gradients.items()
    }
    heldout_metrics = _heldout_metrics(
        runtime_model,
        snapshot.parameters,
        heldout_examples,
    )
    candidate_parameters = {
        name: tuple(
            float(value) + float(scaled.get(name, ())[index])
            if name in scaled
            else float(value)
            for index, value in enumerate(values)
        )
        for name, values in snapshot.parameters.items()
    }
    heldout_metrics.update(
        {
            f"candidate_{key}": value
            for key, value in _heldout_metrics(
                runtime_model,
                candidate_parameters,
                heldout_examples,
            ).items()
        }
    )
    updated = {}
    for name, values in snapshot.parameters.items():
        delta = scaled.get(name)
        updated[name] = (
            tuple(float(value) for value in values)
            if delta is None
            else tuple(
                float(value) + float(delta[index])
                for index, value in enumerate(values)
            )
        )
    return SemanticGradientBatch(
        model_id=snapshot.model_id,
        base_version=snapshot.version,
        gradients=scaled,
        shapes={name: snapshot.shapes[name] for name in scaled},
        metrics={
            "examples": float(len(examples)),
            "average_loss": total_loss / total_weight,
            "exact_match_rate": exact_matches / len(examples),
            "total_weight": total_weight,
            **heldout_metrics,
        },
        metadata={
            "strategy": "transformer_classification_head_finetune",
            "base_parameter_fingerprint": _parameter_fingerprint(snapshot.parameters),
            "updated_parameter_fingerprint": _parameter_fingerprint(updated),
            "learning_rate": str(learning_rate),
            "max_gradient": str(max_gradient),
            "model_cache_key": snapshot.cache_key,
        },
    )


def _classification_from_prediction(prediction) -> Classification:
    from ...classification import Category, Sensitivity, Visibility, initialise_unpacked

    return initialise_unpacked(
        Sensitivity.__members__.get(prediction.sensitivity, Sensitivity.S0),
        Visibility.__members__.get(prediction.visibility, Visibility.PU),
        [
            Category.__members__[name]
            for name in prediction.categories
            if name in Category.__members__
        ],
    )


def _heldout_metrics(runtime_model, parameters, examples):
    if not examples:
        return {}
    model = TinyTransformerModel(
        ModelConfig.from_metadata(runtime_model.snapshot.metadata),
        parameters,
        runtime_model.snapshot.shapes,
    )
    predictions = model.predict_many(tuple(example.text for example in examples))
    exact = 0
    sensitive = 0
    sensitive_correct = 0
    clean = 0
    clean_correct = 0
    for example, prediction in zip(examples, predictions):
        if example.target is None:
            continue
        target = example.target
        predicted = _classification_from_prediction(prediction)
        exact += target.pack() == predicted.pack()
        if target.is_sensitive():
            sensitive += 1
            sensitive_correct += target.is_sensitive() == predicted.is_sensitive()
        else:
            clean += 1
            clean_correct += target.is_sensitive() == predicted.is_sensitive()
    total = sensitive + clean
    return {
        "heldout_examples": float(total),
        "heldout_exact_match_rate": exact / total if total else 0.0,
        "heldout_sensitive_recall": sensitive_correct / sensitive if sensitive else 1.0,
        "heldout_clean_specificity": clean_correct / clean if clean else 1.0,
    }


def _classification_loss(target: Classification, predicted: Classification) -> float:
    from ...classification import Category, Visibility, visibility_rank

    sensitivity_loss = abs(
        target.sensitivity().value - predicted.sensitivity().value
    ) / 3.0
    visibility_loss = abs(
        visibility_rank(target.visibility()) - visibility_rank(predicted.visibility())
    ) / visibility_rank(Visibility.P4)
    category_loss = len(set(target.categories()) ^ set(predicted.categories())) / max(
        1,
        len(list(Category)),
    )
    return sensitivity_loss + 0.5 * visibility_loss + 0.25 * category_loss


def _parameter_fingerprint(parameters) -> str:
    return parameter_fingerprint(parameters)


def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))
