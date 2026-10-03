"""Bounded binary-head updates for annotation-presence artifacts only."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Sequence

from privoke_model.artifact import float32, updated_parameter_values
from privoke_model.fingerprint import parameter_fingerprint
from privoke_model.presence import SparsePresenceModel
from privoke_model.training_data import training_text_key

from .parameter_stream import ModelParameterStreamer
from .streamed_model import GLOBAL_STREAMED_MODEL_CACHE, StreamedPresenceModel


@dataclass(frozen=True)
class PresenceTrainingExample:
    text: str
    target: bool
    weight: float
    group_id: str


@dataclass(frozen=True)
class PresenceGradientBatch:
    model_id: str
    base_version: str
    gradients: dict[str, tuple[float, ...]]
    shapes: dict[str, tuple[int, ...]]
    metrics: dict[str, float]
    metadata: dict[str, str]


def compute_presence_gradients(
    examples: Sequence[PresenceTrainingExample],
    *,
    model_id: str,
    learning_rate: float,
    max_gradient: float,
    heldout_examples: Sequence[PresenceTrainingExample] = (),
) -> PresenceGradientBatch:
    """Compute weighted BCE ascent deltas and evaluate the exact published candidate."""
    examples = tuple(examples)
    heldout_examples = tuple(heldout_examples)
    if not model_id or not model_id.strip():
        raise ValueError("model_id is required.")
    if not examples:
        raise ValueError("At least one training example is required.")
    if isinstance(learning_rate, bool) or not math.isfinite(learning_rate) or learning_rate <= 0:
        raise ValueError("learning_rate must be finite and greater than zero.")
    if isinstance(max_gradient, bool) or not math.isfinite(max_gradient) or max_gradient <= 0:
        raise ValueError("max_gradient must be finite and greater than zero.")
    _validate_examples(examples, "training")
    if heldout_examples:
        _validate_heldout_examples(examples, heldout_examples)

    streamer = ModelParameterStreamer(model_id=model_id)
    runtime_model = GLOBAL_STREAMED_MODEL_CACHE.presence_model_for_training(streamer)
    snapshot = runtime_model.snapshot
    model = runtime_model.model
    trainable = {
        name for name in snapshot.metadata.get("trainable_parameters", "").split(",")
        if name
    }
    expected_trainable = {
        name for name in snapshot.parameters if name.startswith("head.presence.")
    }
    if not expected_trainable or trainable != expected_trainable:
        raise ValueError("Presence snapshot has an invalid trainable parameter manifest.")

    gradient_sums = {name: [0.0] * len(snapshot.parameters[name]) for name in sorted(trainable)}
    try:
        total_weight = math.fsum(item.weight for item in examples)
    except (OverflowError, ValueError) as exc:
        raise ValueError("Training weights must have a finite positive total.") from exc
    if not math.isfinite(total_weight) or total_weight <= 0:
        raise ValueError("Training weights must have a finite positive total.")
    total_loss = 0.0
    exact_matches = 0
    for item in examples:
        probability = model.predict_probability(item.text)
        total_loss += _binary_cross_entropy(item.target, probability) * item.weight
        exact_matches += (probability >= model.threshold) == item.target
        deltas = model.presence_head_deltas(item.text, item.target)
        if set(deltas) != trainable:
            raise ValueError("Presence head returned an unexpected delta manifest.")
        for name, values in deltas.items():
            if len(values) != len(gradient_sums[name]):
                raise ValueError(f"Presence gradient shape mismatch for {name!r}.")
            for index, value in enumerate(values):
                if not math.isfinite(value):
                    raise ValueError("Presence gradient contains a non-finite value.")
                gradient_sums[name][index] += value * item.weight
    if not math.isfinite(total_loss):
        raise ValueError("Training loss must remain finite.")

    gradients = {
        name: tuple(
            float32(max(-max_gradient, min(max_gradient, value / total_weight * learning_rate)))
            for value in values
        )
        for name, values in gradient_sums.items()
    }
    candidate_parameters = {
        name: tuple(float32(value) for value in updated_parameter_values(values, gradients[name]))
        if name in gradients else tuple(float32(value) for value in values)
        for name, values in snapshot.parameters.items()
    }
    candidate = SparsePresenceModel(model.config, candidate_parameters, snapshot.shapes)

    metrics = {
        "examples": float(len(examples)),
        "average_loss": total_loss / total_weight,
        "exact_match_rate": exact_matches / len(examples),
        "total_weight": total_weight,
    }
    metrics.update(_heldout_metrics(model, heldout_examples))
    metrics.update({f"candidate_{key}": value for key, value in _heldout_metrics(candidate, heldout_examples).items()})

    return PresenceGradientBatch(
        model_id=snapshot.model_id,
        base_version=snapshot.version,
        gradients=gradients,
        shapes={name: snapshot.shapes[name] for name in gradients},
        metrics=metrics,
        metadata={
            "strategy": "sparse_annotation_presence_head_finetune",
            "task": "annotation_presence",
            "architecture": "privoke_sparse_presence_v1",
            "artifact_checksum": snapshot.metadata.get("artifact_checksum", ""),
            "base_parameter_fingerprint": parameter_fingerprint(snapshot.parameters, snapshot.shapes),
            "updated_parameter_fingerprint": parameter_fingerprint(candidate_parameters, snapshot.shapes),
            "candidate_parameter_fingerprint": parameter_fingerprint(candidate_parameters, snapshot.shapes),
            "publication_delta_fingerprint": parameter_fingerprint(
                gradients,
                {name: snapshot.shapes[name] for name in gradients},
            ),
            "learning_rate": str(learning_rate),
            "max_gradient": str(max_gradient),
            "model_cache_key": snapshot.cache_key,
            "text_preprocessing": "training_text_key_v1",
            "publication_arithmetic": "float32_parameters_float64_features_fsum_v1",
        },
    )


def _validate_examples(examples: Sequence[PresenceTrainingExample], name: str) -> None:
    keys = []
    for item in examples:
        if type(item.target) is not bool:
            raise ValueError(f"{name.capitalize()} targets must be strict booleans.")
        if not isinstance(item.text, str) or not item.text.strip():
            raise ValueError(f"{name.capitalize()} example text is required.")
        if not isinstance(item.group_id, str) or not item.group_id.strip():
            raise ValueError(f"{name.capitalize()} group_id is required.")
        if isinstance(item.weight, bool) or not math.isfinite(item.weight) or item.weight <= 0:
            raise ValueError(f"{name.capitalize()} weights must be finite and positive.")
        key = training_text_key(item.text)
        if not key:
            raise ValueError(f"{name.capitalize()} text is empty after normalization.")
        keys.append(key)
    if len(keys) != len(set(keys)):
        raise ValueError(f"{name.capitalize()} texts must be distinct after normalization.")
    if {item.target for item in examples} != {False, True}:
        raise ValueError(f"{name.capitalize()} examples require both binary labels.")


def _validate_heldout_examples(training, heldout) -> None:
    _validate_examples(heldout, "held-out")
    training_keys = {training_text_key(item.text) for item in training}
    heldout_keys = {training_text_key(item.text) for item in heldout}
    if training_keys.intersection(heldout_keys):
        raise ValueError("Held-out texts must be separate from training texts.")
    training_groups = {item.group_id for item in training}
    heldout_groups = {item.group_id for item in heldout}
    if training_groups.intersection(heldout_groups):
        raise ValueError("Held-out groups must be separate from training groups.")


def _binary_cross_entropy(target: bool, probability: float) -> float:
    epsilon = 1e-15
    probability = min(1.0 - epsilon, max(epsilon, probability))
    return -math.log(probability if target else 1.0 - probability)


def _heldout_metrics(model, examples) -> dict[str, float]:
    if not examples:
        return {}
    try:
        total_weight = math.fsum(item.weight for item in examples)
    except (OverflowError, ValueError) as exc:
        raise ValueError("Held-out weights must have a finite positive total.") from exc
    total_loss = 0.0
    correct = present = present_correct = absent = absent_correct = 0
    for item in examples:
        probability = model.predict_probability(item.text)
        predicted = probability >= model.threshold
        total_loss += _binary_cross_entropy(item.target, probability) * item.weight
        correct += predicted == item.target
        if item.target:
            present += 1
            present_correct += predicted
        else:
            absent += 1
            absent_correct += not predicted
    if not math.isfinite(total_loss):
        raise ValueError("Held-out loss must remain finite.")
    return {
        "heldout_examples": float(len(examples)),
        "heldout_present_examples": float(present),
        "heldout_absent_examples": float(absent),
        "heldout_average_loss": total_loss / total_weight,
        "heldout_exact_match_rate": correct / len(examples),
        "heldout_present_recall": present_correct / present,
        "heldout_absent_specificity": absent_correct / absent,
    }
