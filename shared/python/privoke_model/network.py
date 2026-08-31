from __future__ import annotations

import hashlib
import json
import math
import os
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

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
    num_layers: int = 1
    num_attention_heads: int = 1

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
                num_layers=int(value.get("num_layers", 1)),
                num_attention_heads=int(value.get("num_attention_heads", 1)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ModelArtifactError(f"Invalid transformer config: {exc}") from exc
        if min(
            config.vocab_size,
            config.hidden_size,
            config.intermediate_size,
            config.max_tokens,
            config.num_layers,
            config.num_attention_heads,
        ) <= 0:
            raise ModelArtifactError("Transformer dimensions must be positive.")
        if config.hidden_size % config.num_attention_heads:
            raise ModelArtifactError(
                "hidden_size must be divisible by num_attention_heads."
            )
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

    SHARED_TENSORS = (
        "token_embedding",
        "position_embedding",
        "head.sensitivity.weight",
        "head.sensitivity.bias",
        "head.visibility.weight",
        "head.visibility.bias",
        "head.category.weight",
        "head.category.bias",
    )
    BLOCK_TENSORS = (
        "attention.query.weight",
        "attention.key.weight",
        "attention.value.weight",
        "attention.output.weight",
        "attention.output.bias",
        "ffn.input.weight",
        "ffn.input.bias",
        "ffn.output.weight",
        "ffn.output.bias",
    )

    def __init__(
        self,
        config: ModelConfig,
        parameters: Mapping[str, Sequence[float]],
        shapes: Mapping[str, Sequence[int]],
        device: str | None = None,
    ):
        self.config = config
        self.parameters = {
            name: np.asarray(values, dtype=np.float32).reshape(tuple(shapes[name]))
            for name, values in parameters.items()
            if name in shapes
        }
        missing = [name for name in self._required_tensors() if name not in self.parameters]
        if missing:
            raise ModelArtifactError(f"Model is missing tensor {missing[0]!r}.")
        self._validate_shapes()
        self.compute_device, self._torch = _resolve_compute_device(device)
        self._torch_parameters = (
            {
                name: self._torch.as_tensor(value, device=self.compute_device)
                for name, value in self.parameters.items()
            }
            if self._torch is not None
            else None
        )

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
        return self.predict_many((text,))[0]

    def predict_many(self, texts: Sequence[str]) -> tuple[ModelPrediction, ...]:
        """Predict a bounded caller-provided batch on the selected compute device."""
        if not texts:
            return ()
        if self._torch is not None:
            return self._predict_many_torch(texts)
        return tuple(self._predict_numpy(text) for text in texts)

    def _predict_numpy(self, text: str) -> ModelPrediction:
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

    def _predict_many_torch(
        self,
        texts: Sequence[str],
    ) -> tuple[ModelPrediction, ...]:
        torch = self._torch
        parameters = self._torch_parameters
        if torch is None or parameters is None:
            raise RuntimeError("Torch compute was not initialised.")

        token_rows = [self.token_ids(text).tolist() for text in texts]
        sequence_length = max(len(row) for row in token_rows)
        token_ids = torch.zeros(
            (len(token_rows), sequence_length),
            dtype=torch.long,
            device=self.compute_device,
        )
        token_mask = torch.zeros(
            (len(token_rows), sequence_length),
            dtype=torch.bool,
            device=self.compute_device,
        )
        for index, row in enumerate(token_rows):
            row_length = len(row)
            token_ids[index, :row_length] = torch.as_tensor(
                row,
                dtype=torch.long,
                device=self.compute_device,
            )
            token_mask[index, :row_length] = True

        with torch.inference_mode():
            hidden = (
                parameters["token_embedding"][token_ids]
                + parameters["position_embedding"][:sequence_length]
            )
            for layer_index in range(self.config.num_layers):
                prefix = self._layer_prefix(layer_index)
                hidden = self._torch_encoder_block(
                    hidden,
                    token_mask,
                    prefix,
                    torch,
                    parameters,
                )
            mask = token_mask.unsqueeze(-1)
            pooled = hidden[:, 0] * 0.5 + (
                (hidden * mask).sum(dim=1)
                / mask.sum(dim=1).clamp_min(1)
            ) * 0.5
            sensitivity = torch.softmax(
                pooled @ parameters["head.sensitivity.weight"]
                + parameters["head.sensitivity.bias"],
                dim=-1,
            )
            visibility = torch.softmax(
                pooled @ parameters["head.visibility.weight"]
                + parameters["head.visibility.bias"],
                dim=-1,
            )
            categories = torch.sigmoid(
                pooled @ parameters["head.category.weight"]
                + parameters["head.category.bias"]
            )

        pooled_rows = pooled.cpu().tolist()
        sensitivity_rows = sensitivity.cpu().tolist()
        visibility_rows = visibility.cpu().tolist()
        category_rows = categories.cpu().tolist()
        predictions = []
        for pooled_row, sensitivity_row, visibility_row, category_row in zip(
            pooled_rows,
            sensitivity_rows,
            visibility_rows,
            category_rows,
        ):
            predictions.append(
                ModelPrediction(
                    sensitivity=self.config.sensitivity_labels[
                        int(np.argmax(sensitivity_row))
                    ],
                    visibility=self.config.visibility_labels[
                        int(np.argmax(visibility_row))
                    ],
                    categories=tuple(
                        label
                        for label, probability in zip(
                            self.config.category_labels,
                            category_row,
                        )
                        if probability >= self.config.category_threshold
                    ),
                    sensitivity_probabilities=tuple(float(value) for value in sensitivity_row),
                    visibility_probabilities=tuple(float(value) for value in visibility_row),
                    category_probabilities=tuple(float(value) for value in category_row),
                    pooled=tuple(float(value) for value in pooled_row),
                )
            )
        return tuple(predictions)

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

        for layer_index in range(self.config.num_layers):
            hidden = self._numpy_encoder_block(
                hidden,
                self._layer_prefix(layer_index),
            )
        return (hidden[0] * 0.5 + hidden.mean(axis=0) * 0.5).astype(np.float32)

    def _numpy_encoder_block(self, hidden: np.ndarray, prefix: str) -> np.ndarray:
        query = hidden @ self.parameters[f"{prefix}attention.query.weight"]
        key = hidden @ self.parameters[f"{prefix}attention.key.weight"]
        value = hidden @ self.parameters[f"{prefix}attention.value.weight"]
        heads = self.config.num_attention_heads
        head_size = self.config.hidden_size // heads
        query = query.reshape(len(hidden), heads, head_size).transpose(1, 0, 2)
        key = key.reshape(len(hidden), heads, head_size).transpose(1, 0, 2)
        value = value.reshape(len(hidden), heads, head_size).transpose(1, 0, 2)
        attention = _softmax(query @ key.transpose(0, 2, 1) / math.sqrt(head_size))
        attended = (attention @ value).transpose(1, 0, 2).reshape(hidden.shape)
        attended = (
            attended @ self.parameters[f"{prefix}attention.output.weight"]
            + self.parameters[f"{prefix}attention.output.bias"]
        )
        hidden = _layer_norm(hidden + attended)
        intermediate = _gelu(
            hidden @ self.parameters[f"{prefix}ffn.input.weight"]
            + self.parameters[f"{prefix}ffn.input.bias"]
        )
        return _layer_norm(
            hidden
            + intermediate @ self.parameters[f"{prefix}ffn.output.weight"]
            + self.parameters[f"{prefix}ffn.output.bias"]
        )

    def _torch_encoder_block(
        self,
        hidden,
        token_mask,
        prefix: str,
        torch,
        parameters,
    ):
        batch_size, sequence_length, _ = hidden.shape
        heads = self.config.num_attention_heads
        head_size = self.config.hidden_size // heads

        def split_heads(value):
            shaped = value.reshape(
                batch_size,
                sequence_length,
                heads,
                head_size,
            )
            return shaped.transpose(1, 2)

        query = split_heads(hidden @ parameters[f"{prefix}attention.query.weight"])
        key = split_heads(hidden @ parameters[f"{prefix}attention.key.weight"])
        value = split_heads(hidden @ parameters[f"{prefix}attention.value.weight"])
        scores = query @ key.transpose(2, 3) / math.sqrt(head_size)
        scores = scores.masked_fill(~token_mask[:, None, None, :], -10_000.0)
        attended = (torch.softmax(scores, dim=-1) @ value).transpose(1, 2)
        attended = attended.reshape(batch_size, sequence_length, self.config.hidden_size)
        attended = (
            attended @ parameters[f"{prefix}attention.output.weight"]
            + parameters[f"{prefix}attention.output.bias"]
        )
        hidden = torch.nn.functional.layer_norm(
            hidden + attended,
            (self.config.hidden_size,),
            eps=1e-5,
        )
        intermediate = torch.nn.functional.gelu(
            hidden @ parameters[f"{prefix}ffn.input.weight"]
            + parameters[f"{prefix}ffn.input.bias"],
            approximate="tanh",
        )
        return torch.nn.functional.layer_norm(
            hidden
            + intermediate @ parameters[f"{prefix}ffn.output.weight"]
            + parameters[f"{prefix}ffn.output.bias"],
            (self.config.hidden_size,),
            eps=1e-5,
        )

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
            "head.sensitivity.weight": (hidden, len(self.config.sensitivity_labels)),
            "head.sensitivity.bias": (len(self.config.sensitivity_labels),),
            "head.visibility.weight": (hidden, len(self.config.visibility_labels)),
            "head.visibility.bias": (len(self.config.visibility_labels),),
            "head.category.weight": (hidden, len(self.config.category_labels)),
            "head.category.bias": (len(self.config.category_labels),),
        }
        block_shapes = {
            "attention.query.weight": (hidden, hidden),
            "attention.key.weight": (hidden, hidden),
            "attention.value.weight": (hidden, hidden),
            "attention.output.weight": (hidden, hidden),
            "attention.output.bias": (hidden,),
            "ffn.input.weight": (hidden, intermediate),
            "ffn.input.bias": (intermediate,),
            "ffn.output.weight": (intermediate, hidden),
            "ffn.output.bias": (hidden,),
        }
        for layer_index in range(self.config.num_layers):
            prefix = self._layer_prefix(layer_index)
            expected.update(
                {
                    f"{prefix}{name}": shape
                    for name, shape in block_shapes.items()
                }
            )
        for name, shape in expected.items():
            if self.parameters[name].shape != shape:
                raise ModelArtifactError(
                    f"Tensor {name!r} has shape {self.parameters[name].shape}, expected {shape}."
                )

    def _required_tensors(self) -> tuple[str, ...]:
        return self.SHARED_TENSORS + tuple(
            f"{self._layer_prefix(layer_index)}{name}"
            for layer_index in range(self.config.num_layers)
            for name in self.BLOCK_TENSORS
        )

    def _layer_prefix(self, layer_index: int) -> str:
        # Schema-v1 artifacts used unprefixed names for their sole encoder block.
        return "" if self.config.num_layers == 1 else f"layers.{layer_index}."


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


def _resolve_compute_device(requested: str | None) -> tuple[str, Any | None]:
    choice = (requested or os.getenv("PRIVOKE_MODEL_DEVICE", "auto")).strip().lower()
    if choice not in {"auto", "cpu", "cuda", "mps"}:
        raise ValueError("PRIVOKE_MODEL_DEVICE must be auto, cpu, cuda, or mps.")
    if choice == "cpu":
        return "cpu", None

    try:
        import torch
    except ImportError:
        return "cpu", None

    if choice in {"auto", "cuda"} and torch.cuda.is_available():
        return "cuda", torch
    mps = getattr(torch.backends, "mps", None)
    if choice in {"auto", "mps"} and mps is not None and mps.is_available():
        return "mps", torch
    return "cpu", None
