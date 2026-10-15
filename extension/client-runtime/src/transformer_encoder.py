"""Label-free CPU encoder shared by contextual and scratch binary models.

Tokenization deliberately does not normalize detector text. Callers own that
boundary. NumPy equations retain the legacy operation order; batch padding is
removed before executing each row so masked positions cannot change pooling.
"""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Sequence

import numpy as np

TOKEN_PATTERN = re.compile(r"[A-Za-z]+(?:'[A-Za-z]+)?|\d+|[^\w\s]", re.UNICODE)
MAX_ENCODER_VALUES = 65_536
MAX_ENCODER_CONTEXT = 512


@dataclass(frozen=True)
class EncoderConfig:
    vocab_size: int
    hidden_size: int
    intermediate_size: int
    max_tokens: int
    num_layers: int = 1
    num_attention_heads: int = 1

    def __post_init__(self) -> None:
        dimensions = (self.vocab_size, self.hidden_size, self.intermediate_size,
                      self.max_tokens, self.num_layers, self.num_attention_heads)
        if any(type(value) is not int or value <= 0 for value in dimensions):
            raise ValueError("Encoder dimensions must be positive integers.")
        if self.vocab_size < 2 or self.hidden_size % self.num_attention_heads:
            raise ValueError("Encoder vocabulary or attention dimensions are invalid.")
        if self.max_tokens > MAX_ENCODER_CONTEXT:
            raise ValueError("Encoder context exceeds the capacity bound.")
        hidden = self.hidden_size
        count = hidden * (self.vocab_size + self.max_tokens) + self.num_layers * (
            4 * hidden * hidden + 2 * hidden * self.intermediate_size
            + 2 * hidden + self.intermediate_size
        )
        if count > MAX_ENCODER_VALUES:
            raise ValueError("Encoder configuration exceeds the parameter budget.")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "EncoderConfig":
        return cls(**{name: value[name] for name in (
            "vocab_size", "hidden_size", "intermediate_size", "max_tokens",
        )}, **{name: value.get(name, 1) for name in ("num_layers", "num_attention_heads")})


def layer_prefix(config, layer_index: int) -> str:
    return "" if config.num_layers == 1 else f"layers.{layer_index}."


def encoder_tensor_shapes(config: EncoderConfig) -> dict[str, tuple[int, ...]]:
    hidden, intermediate = config.hidden_size, config.intermediate_size
    shapes = {"token_embedding": (config.vocab_size, hidden),
              "position_embedding": (config.max_tokens, hidden)}
    block = {
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
    for index in range(config.num_layers):
        shapes.update({layer_prefix(config, index) + name: shape for name, shape in block.items()})
    return shapes


def token_ids(text: str, config) -> np.ndarray:
    tokens = TOKEN_PATTERN.findall(text.lower())[:config.max_tokens - 1]
    ids = [0]
    for token in tokens:
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        ids.append(1 + int.from_bytes(digest[:4], "big") % (config.vocab_size - 1))
    return np.asarray(ids, dtype=np.int64)


def _softmax(value: np.ndarray, axis: int = -1) -> np.ndarray:
    shifted = value - np.max(value, axis=axis, keepdims=True)
    exponent = np.exp(shifted)
    return exponent / np.sum(exponent, axis=axis, keepdims=True)


def _gelu(value: np.ndarray) -> np.ndarray:
    return 0.5 * value * (
        1.0 + np.tanh(math.sqrt(2.0 / math.pi) * (value + 0.044715 * value**3))
    )


def _layer_norm(value: np.ndarray) -> np.ndarray:
    mean = value.mean(axis=-1, keepdims=True)
    variance = ((value - mean) ** 2).mean(axis=-1, keepdims=True)
    return (value - mean) / np.sqrt(variance + 1e-5)


def numpy_encoder_block(config, parameters: Mapping[str, np.ndarray],
                        hidden: np.ndarray, prefix: str) -> np.ndarray:
    query = hidden @ parameters[f"{prefix}attention.query.weight"]
    key = hidden @ parameters[f"{prefix}attention.key.weight"]
    value = hidden @ parameters[f"{prefix}attention.value.weight"]
    heads = config.num_attention_heads
    head_size = config.hidden_size // heads
    query = query.reshape(len(hidden), heads, head_size).transpose(1, 0, 2)
    key = key.reshape(len(hidden), heads, head_size).transpose(1, 0, 2)
    value = value.reshape(len(hidden), heads, head_size).transpose(1, 0, 2)
    attention = _softmax(query @ key.transpose(0, 2, 1) / math.sqrt(head_size))
    attended = (attention @ value).transpose(1, 0, 2).reshape(hidden.shape)
    attended = (attended @ parameters[f"{prefix}attention.output.weight"]
                + parameters[f"{prefix}attention.output.bias"])
    hidden = _layer_norm(hidden + attended)
    intermediate = _gelu(hidden @ parameters[f"{prefix}ffn.input.weight"]
                         + parameters[f"{prefix}ffn.input.bias"])
    return _layer_norm(hidden + intermediate @ parameters[f"{prefix}ffn.output.weight"]
                       + parameters[f"{prefix}ffn.output.bias"])


def encode_token_ids(config, parameters: Mapping[str, np.ndarray], ids: np.ndarray) -> np.ndarray:
    hidden = parameters["token_embedding"][ids] + parameters["position_embedding"][:len(ids)]
    for index in range(config.num_layers):
        hidden = numpy_encoder_block(config, parameters, hidden, layer_prefix(config, index))
    return (hidden[0] * 0.5 + hidden.mean(axis=0) * 0.5).astype(np.float32)


@dataclass(frozen=True, init=False)
class NumpyTransformerEncoder:
    """Own immutable float32 arrays; execute without Torch or classification labels."""

    config: EncoderConfig
    parameters: Mapping[str, np.ndarray]

    def __init__(self, config: EncoderConfig, parameters: Mapping[str, np.ndarray]):
        if not isinstance(config, EncoderConfig):
            raise TypeError("A validated EncoderConfig is required.")
        object.__setattr__(self, "config", config)
        arrays = {}
        for name, shape in encoder_tensor_shapes(config).items():
            value = parameters.get(name)
            if not isinstance(value, np.ndarray) or value.shape != shape:
                raise ValueError("Encoder tensor shape does not match its configuration.")
            if value.dtype != np.float32 or not np.isfinite(value).all():
                raise ValueError("Encoder tensors must contain finite float32 values.")
            # A bytes-backed array cannot have its write flag re-enabled by a caller.
            arrays[name] = np.frombuffer(value.tobytes(order="C"), dtype=np.float32).reshape(shape)
        object.__setattr__(self, "parameters", MappingProxyType(arrays))

    def encode(self, text: str) -> np.ndarray:
        return self._encode_ids(token_ids(text, self.config))

    def encode_many(self, texts: Sequence[str]) -> np.ndarray:
        if not texts:
            return np.empty((0, self.config.hidden_size), dtype=np.float32)
        return np.stack([self.encode(text) for text in texts])

    def encode_tokens(self, ids: np.ndarray, mask: np.ndarray | None = None) -> np.ndarray:
        """Encode one row or a padded batch with a nonempty contiguous true prefix."""
        if not isinstance(ids, np.ndarray) or ids.dtype.kind not in "iu" or ids.ndim not in (1, 2):
            raise ValueError("Token IDs must be a one- or two-dimensional integer array.")
        single = ids.ndim == 1
        rows = ids[None, :] if single else ids
        if not 0 < rows.shape[1] <= self.config.max_tokens:
            raise ValueError("Token context is out of bounds.")
        if mask is None:
            masks = np.ones(rows.shape, dtype=np.bool_)
        else:
            if not isinstance(mask, np.ndarray) or mask.dtype != np.bool_ or mask.shape != ids.shape:
                raise ValueError("Token mask must be a matching bool array.")
            masks = mask[None, :] if single else mask
        outputs = []
        for row, row_mask in zip(rows, masks):
            length = int(row_mask.sum())
            if (length == 0 or not row_mask[:length].all() or row_mask[length:].any()
                    or row[0] != 0 or np.any(row[length:] != 0)
                    or np.any(row[1:length] == 0) or np.any(row[:length] < 0) or np.any(row[:length] >= self.config.vocab_size)):
                raise ValueError("Token IDs/mask violate the real-first-token and padding contract.")
            outputs.append(self._encode_ids(row[:length]))
        if not outputs:
            return np.empty((0, self.config.hidden_size), dtype=np.float32)
        result = np.stack(outputs)
        return result[0] if single else result

    def encoder_block(self, hidden: np.ndarray, prefix: str) -> np.ndarray:
        if prefix not in {layer_prefix(self.config, i) for i in range(self.config.num_layers)}:
            raise ValueError("Unknown encoder block prefix.")
        if (not isinstance(hidden, np.ndarray) or hidden.dtype != np.float32
                or hidden.ndim != 2 or hidden.shape[1] != self.config.hidden_size
                or not 0 < hidden.shape[0] <= self.config.max_tokens
                or not np.isfinite(hidden).all()):
            raise ValueError("Encoder hidden states are invalid.")
        try:
            with np.errstate(over="raise", invalid="raise", divide="raise", under="ignore"):
                output = numpy_encoder_block(self.config, self.parameters, hidden, prefix)
        except FloatingPointError as exc:
            raise ValueError("Encoder block produced non-finite intermediate states.") from exc
        if not np.isfinite(output).all():
            raise ValueError("Encoder block produced non-finite states.")
        return output

    def _encode_ids(self, ids: np.ndarray) -> np.ndarray:
        try:
            with np.errstate(over="raise", invalid="raise", divide="raise", under="ignore"):
                hidden = self.parameters["token_embedding"][ids] + self.parameters["position_embedding"][:len(ids)]
                if not np.isfinite(hidden).all():
                    raise ValueError("Encoder embedding produced non-finite states.")
                for index in range(self.config.num_layers):
                    hidden = self.encoder_block(hidden, layer_prefix(self.config, index))
                pooled = (hidden[0] * 0.5 + hidden.mean(axis=0) * 0.5).astype(np.float32)
        except FloatingPointError as exc:
            raise ValueError("Encoder produced non-finite intermediate states.") from exc
        if not np.isfinite(pooled).all():
            raise ValueError("Encoder pooling produced non-finite states.")
        return pooled
