from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Mapping, Sequence

import numpy as np

from .artifact import ARCHITECTURE_NAME, ModelArtifactError


TOKEN_PATTERN = re.compile(r"[A-Za-z]+(?:'[A-Za-z]+)?|\d+|[^\w\s]", re.UNICODE)


@dataclass(frozen=True)
class ModelConfig:
    vocab_size: int
    hidden_size: int
    intermediate_size: int
    max_tokens: int
    sensitivity_labels: tuple[str, ...]
    visibility_labels: tuple[str, ...]
    category_labels: tuple[str, ...]
    category_threshold: float = 0.5

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ModelConfig":
        try:
            config = cls(
                vocab_size=int(value["vocab_size"]),
                hidden_size=int(value["hidden_size"]),
                intermediate_size=int(value["intermediate_size"]),
                max_tokens=int(value["max_tokens"]),
                sensitivity_labels=tuple(str(item) for item in value["sensitivity_labels"]),
                visibility_labels=tuple(str(item) for item in value["visibility_labels"]),
                category_labels=tuple(str(item) for item in value["category_labels"]),
                category_threshold=float(value.get("category_threshold", 0.5)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ModelArtifactError(f"Invalid transformer config: {exc}") from exc
        if min(
            config.vocab_size,
            config.hidden_size,
            config.intermediate_size,
            config.max_tokens,
        ) <= 0:
            raise ModelArtifactError("Transformer dimensions must be positive.")
        if not 0.0 < config.category_threshold < 1.0:
            raise ModelArtifactError("category_threshold must be between zero and one.")
        return config

    @classmethod
    def from_metadata(cls, metadata: Mapping[str, str]) -> "ModelConfig":
        if metadata.get("architecture") != ARCHITECTURE_NAME:
            raise ModelArtifactError("Streamed snapshot is not a supported PriVoke transformer.")
        try:
            value = json.loads(metadata["model_config"])
        except (KeyError, json.JSONDecodeError) as exc:
            raise ModelArtifactError("Streamed snapshot has no valid model_config.") from exc
        if not isinstance(value, dict):
            raise ModelArtifactError("model_config must be a JSON object.")
        return cls.from_mapping(value)


@dataclass(frozen=True)
class ModelPrediction:
    sensitivity: str
    visibility: str
    categories: tuple[str, ...]
    sensitivity_probabilities: tuple[float, ...]
    visibility_probabilities: tuple[float, ...]
    category_probabilities: tuple[float, ...]
    pooled: tuple[float, ...]

    @property
    def confidence(self) -> float:
        probabilities = list(self.sensitivity_probabilities) + list(
            self.category_probabilities
        )
        return float(max(probabilities, default=0.0))


class TinyTransformerModel:
    """A compact transformer encoder with trainable classification heads."""

    REQUIRED_TENSORS = (
        "token_embedding",
        "position_embedding",
        "attention.query.weight",
        "attention.key.weight",
        "attention.value.weight",
        "attention.output.weight",
        "attention.output.bias",
        "ffn.input.weight",
        "ffn.input.bias",
        "ffn.output.weight",
        "ffn.output.bias",
        "head.sensitivity.weight",
        "head.sensitivity.bias",
        "head.visibility.weight",
        "head.visibility.bias",
        "head.category.weight",
        "head.category.bias",
    )

    def __init__(
        self,
        config: ModelConfig,
        parameters: Mapping[str, Sequence[float]],
        shapes: Mapping[str, Sequence[int]],
    ):
        self.config = config
        self.parameters = {
            name: np.asarray(values, dtype=np.float32).reshape(tuple(shapes[name]))
            for name, values in parameters.items()
            if name in shapes
        }
        missing = [name for name in self.REQUIRED_TENSORS if name not in self.parameters]
        if missing:
            raise ModelArtifactError(f"Model is missing tensor {missing[0]!r}.")
        self._validate_shapes()

    @classmethod
    def from_artifact(cls, payload: Mapping[str, object]) -> "TinyTransformerModel":
        config_value = payload.get("config")
        parameter_value = payload.get("parameters")
        if not isinstance(config_value, Mapping) or not isinstance(parameter_value, Mapping):
            raise ModelArtifactError("Artifact config and parameters must be objects.")
        parameters = {}
        shapes = {}
        for name, tensor in parameter_value.items():
            if not isinstance(name, str) or not isinstance(tensor, Mapping):
                raise ModelArtifactError("Invalid artifact parameter entry.")
            parameters[name] = tensor["values"]
            shapes[name] = tensor["shape"]
        return cls(ModelConfig.from_mapping(config_value), parameters, shapes)

    def predict(self, text: str) -> ModelPrediction:
        pooled = self.encode(text)
        sensitivity_probs = _softmax(
            pooled @ self.parameters["head.sensitivity.weight"]
            + self.parameters["head.sensitivity.bias"]
        )
        visibility_probs = _softmax(
            pooled @ self.parameters["head.visibility.weight"]
            + self.parameters["head.visibility.bias"]
        )
        category_probs = _sigmoid(
            pooled @ self.parameters["head.category.weight"]
            + self.parameters["head.category.bias"]
        )
        sensitivity_index = int(np.argmax(sensitivity_probs))
        visibility_index = int(np.argmax(visibility_probs))
        categories = tuple(
            label
            for label, probability in zip(self.config.category_labels, category_probs)
            if probability >= self.config.category_threshold
        )
        return ModelPrediction(
            sensitivity=self.config.sensitivity_labels[sensitivity_index],
            visibility=self.config.visibility_labels[visibility_index],
            categories=categories,
            sensitivity_probabilities=tuple(float(value) for value in sensitivity_probs),
            visibility_probabilities=tuple(float(value) for value in visibility_probs),
            category_probabilities=tuple(float(value) for value in category_probs),
            pooled=tuple(float(value) for value in pooled),
        )

    def classification_head_deltas(
        self,
        text: str,
        *,
        sensitivity: str,
        visibility: str,
        categories: Sequence[str],
    ) -> dict[str, tuple[float, ...]]:
        prediction = self.predict(text)
        pooled = np.asarray(prediction.pooled, dtype=np.float32)
        sensitivity_error = np.asarray(
            prediction.sensitivity_probabilities, dtype=np.float32
        )
        sensitivity_error[self.config.sensitivity_labels.index(sensitivity)] -= 1.0
        visibility_error = np.asarray(
            prediction.visibility_probabilities, dtype=np.float32
        )
        visibility_error[self.config.visibility_labels.index(visibility)] -= 1.0
        category_error = np.asarray(
            prediction.category_probabilities, dtype=np.float32
        ) - np.asarray(
            [1.0 if label in categories else 0.0 for label in self.config.category_labels],
            dtype=np.float32,
        )

        # These are update deltas (negative loss gradients), ready to be bounded
        # and applied atomically by param-update-service.
        return {
            "head.sensitivity.weight": tuple(float(value) for value in -np.outer(pooled, sensitivity_error).ravel()),
            "head.sensitivity.bias": tuple(float(value) for value in -sensitivity_error.ravel()),
            "head.visibility.weight": tuple(float(value) for value in -np.outer(pooled, visibility_error).ravel()),
            "head.visibility.bias": tuple(float(value) for value in -visibility_error.ravel()),
            "head.category.weight": tuple(float(value) for value in -np.outer(pooled, category_error).ravel()),
            "head.category.bias": tuple(float(value) for value in -category_error.ravel()),
        }

    def encode(self, text: str) -> np.ndarray:
        token_ids = self.token_ids(text)
        token_embedding = self.parameters["token_embedding"][token_ids]
        positions = self.parameters["position_embedding"][: len(token_ids)]
        hidden = token_embedding + positions

        query = hidden @ self.parameters["attention.query.weight"]
        key = hidden @ self.parameters["attention.key.weight"]
        value = hidden @ self.parameters["attention.value.weight"]
        attention_scores = query @ key.T / math.sqrt(self.config.hidden_size)
        attention = _softmax(attention_scores, axis=-1)
        attended = (
            attention @ value @ self.parameters["attention.output.weight"]
            + self.parameters["attention.output.bias"]
        )
        hidden = _layer_norm(hidden + attended)
        intermediate = _gelu(
            hidden @ self.parameters["ffn.input.weight"]
            + self.parameters["ffn.input.bias"]
        )
        hidden = _layer_norm(
            hidden
            + intermediate @ self.parameters["ffn.output.weight"]
            + self.parameters["ffn.output.bias"]
        )
        return (hidden[0] * 0.5 + hidden.mean(axis=0) * 0.5).astype(np.float32)

    def token_ids(self, text: str) -> np.ndarray:
        tokens = TOKEN_PATTERN.findall(text.lower())[: self.config.max_tokens - 1]
        ids = [0]
        for token in tokens:
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            ids.append(1 + int.from_bytes(digest[:4], "big") % (self.config.vocab_size - 1))
        return np.asarray(ids, dtype=np.int64)

    def _validate_shapes(self) -> None:
        hidden = self.config.hidden_size
        intermediate = self.config.intermediate_size
        expected = {
            "token_embedding": (self.config.vocab_size, hidden),
            "position_embedding": (self.config.max_tokens, hidden),
            "attention.query.weight": (hidden, hidden),
            "attention.key.weight": (hidden, hidden),
            "attention.value.weight": (hidden, hidden),
            "attention.output.weight": (hidden, hidden),
            "attention.output.bias": (hidden,),
            "ffn.input.weight": (hidden, intermediate),
            "ffn.input.bias": (intermediate,),
            "ffn.output.weight": (intermediate, hidden),
            "ffn.output.bias": (hidden,),
            "head.sensitivity.weight": (hidden, len(self.config.sensitivity_labels)),
            "head.sensitivity.bias": (len(self.config.sensitivity_labels),),
            "head.visibility.weight": (hidden, len(self.config.visibility_labels)),
            "head.visibility.bias": (len(self.config.visibility_labels),),
            "head.category.weight": (hidden, len(self.config.category_labels)),
            "head.category.bias": (len(self.config.category_labels),),
        }
        for name, shape in expected.items():
            if self.parameters[name].shape != shape:
                raise ModelArtifactError(
                    f"Tensor {name!r} has shape {self.parameters[name].shape}, expected {shape}."
                )


def _softmax(value: np.ndarray, axis: int = -1) -> np.ndarray:
    shifted = value - np.max(value, axis=axis, keepdims=True)
    exponent = np.exp(shifted)
    return exponent / np.sum(exponent, axis=axis, keepdims=True)


def _sigmoid(value: np.ndarray) -> np.ndarray:
    clipped = np.clip(value, -30.0, 30.0)
    return 1.0 / (1.0 + np.exp(-clipped))


def _gelu(value: np.ndarray) -> np.ndarray:
    return 0.5 * value * (
        1.0 + np.tanh(math.sqrt(2.0 / math.pi) * (value + 0.044715 * value**3))
    )


def _layer_norm(value: np.ndarray) -> np.ndarray:
    mean = value.mean(axis=-1, keepdims=True)
    variance = ((value - mean) ** 2).mean(axis=-1, keepdims=True)
    return (value - mean) / np.sqrt(variance + 1e-5)
