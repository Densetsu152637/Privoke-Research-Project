"""Validation for incoming parameter updates."""

from __future__ import annotations

import math

from privoke_model import ModelArtifactError
from privoke_service import validate_text

MAX_GRADIENTS = 256
MAX_GRADIENT_VALUES = 4_096
MAX_UPDATE_VALUES = 65_536
MAX_METADATA_ENTRIES = 64


def validate_parameter_update(
    request,
    *,
    expected_model_id: str,
    max_abs_gradient: float,
) -> None:
    validate_text(request.source_id, "source_id", required=True)
    validate_text(request.model_id, "model_id", required=True)
    validate_text(request.base_version, "base_version", required=True)
    if request.model_id != expected_model_id:
        raise ValueError(f"model_id must be {expected_model_id!r}.")
    if not request.gradients:
        raise ValueError("At least one gradient is required.")
    if len(request.gradients) > MAX_GRADIENTS:
        raise ValueError(
            f"A parameter update may contain at most {MAX_GRADIENTS} gradients."
        )

    _validate_gradients(request.gradients, max_abs_gradient)
    _validate_metadata(request.metadata)


def _validate_gradients(gradients, max_abs_gradient: float) -> None:
    names: set[str] = set()
    total_values = 0

    for gradient in gradients:
        validate_text(gradient.name, "gradient name", required=True, limit=256)
        if gradient.name in names:
            raise ValueError(f"Duplicate gradient name: {gradient.name!r}.")
        names.add(gradient.name)

        _validate_gradient_shape(gradient)
        _validate_gradient_values(gradient, max_abs_gradient)
        total_values += len(gradient.values)

    if total_values > MAX_UPDATE_VALUES:
        raise ValueError(
            f"A parameter update may contain at most {MAX_UPDATE_VALUES} values."
        )


def _validate_gradient_shape(gradient) -> None:
    if not gradient.values:
        raise ValueError(f"Gradient {gradient.name!r} has no values.")
    if len(gradient.values) > MAX_GRADIENT_VALUES:
        raise ValueError(
            f"Gradient {gradient.name!r} exceeds {MAX_GRADIENT_VALUES} values."
        )
    if not gradient.shape:
        raise ValueError(f"Gradient {gradient.name!r} has no shape.")
    if any(dimension <= 0 for dimension in gradient.shape):
        raise ValueError(f"Gradient {gradient.name!r} has an invalid shape.")

    expected_values = math.prod(int(dimension) for dimension in gradient.shape)
    if expected_values != len(gradient.values):
        raise ValueError(f"Gradient {gradient.name!r} shape does not match its values.")


def _validate_gradient_values(gradient, max_abs_gradient: float) -> None:
    if any(
        not math.isfinite(value) or abs(value) > max_abs_gradient
        for value in gradient.values
    ):
        raise ValueError(
            f"Gradient {gradient.name!r} contains a non-finite or out-of-range value."
        )


def _validate_metadata(metadata) -> None:
    if len(metadata) > MAX_METADATA_ENTRIES:
        raise ValueError(
            f"metadata may contain at most {MAX_METADATA_ENTRIES} entries."
        )
    for key, value in metadata.items():
        validate_text(key, "metadata key", required=True, limit=128)
        validate_text(value, "metadata value", required=False, limit=2_048)


def validate_gradient_shapes_against_artifact(request, artifact) -> None:
    parameters = artifact["parameters"]
    for gradient in request.gradients:
        tensor = parameters.get(gradient.name)
        if tensor is None:
            continue
        if tuple(int(size) for size in gradient.shape) != tuple(tensor["shape"]):
            raise ModelArtifactError(f"Parameter shape mismatch for {gradient.name!r}.")
