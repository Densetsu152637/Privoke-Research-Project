"""Bounded lexical annotation-presence inference shared by serving and calibration.

Binary annotation presence supplies no contextual sensitivity, visibility or action.
Vocabulary and IDF are immutable release data; only the logistic head is updated.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Sequence

from .artifact import ModelArtifactError, float32
from .training_data import training_text_key

PRESENCE_ARCHITECTURE = "privoke_sparse_presence_v1"
PRESENCE_TASK = "annotation_presence"
NORMALIZATION = "training_text_key_v1"
ARITHMETIC = "float32_parameters_float64_features_fsum_v1"
PROFILE_MAX_FEATURES = {"efficient": 2000, "balanced": 8000, "quality": 16000}
BLOCK_SIZE = 4096
MAX_CONFIG_BYTES = 2 * 1024 * 1024
TOKEN_PATTERN = r"(?u)\b\w\w+\b"
_WORD_TOKENS = re.compile(TOKEN_PATTERN)
_CONFIG_KEYS = {"task", "profile", "threshold", "normalization", "column_order",
                "coefficient_block_size", "branches"}
_BRANCH_KEYS = {"analyzer", "ngram_range", "max_features", "features",
                "sublinear_tf", "use_idf", "smooth_idf", "norm", "lowercase"}


def validate_presence_config(config: Mapping) -> dict:
    """Return a defensive validated JSON configuration, rejecting unknown keys."""
    if not isinstance(config, Mapping) or set(config) != _CONFIG_KEYS:
        raise ModelArtifactError("Presence config has missing or unknown fields.")
    try:
        raw = json.dumps(_plain(config), ensure_ascii=False, allow_nan=False,
                         separators=(",", ":"))
        copied = json.loads(raw)
        config_bytes = len(raw.encode("utf-8"))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ModelArtifactError("Presence config must contain finite JSON values.") from exc
    if config_bytes > MAX_CONFIG_BYTES:
        raise ModelArtifactError("Presence config exceeds the 2 MiB budget.")
    if copied["task"] != PRESENCE_TASK or copied["normalization"] != NORMALIZATION:
        raise ModelArtifactError("Unsupported presence task or normalization.")
    profile = copied["profile"]
    if not isinstance(profile, str) or profile not in PROFILE_MAX_FEATURES:
        raise ModelArtifactError("Unsupported presence profile.")
    threshold = copied["threshold"]
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not 0 <= threshold <= 1:
        raise ModelArtifactError("Presence threshold must be finite and in [0, 1].")
    if copied["column_order"] != ["word", "char"]:
        raise ModelArtifactError("Presence columns must be word then char.")
    if type(copied["coefficient_block_size"]) is not int or copied["coefficient_block_size"] != BLOCK_SIZE:
        raise ModelArtifactError("Presence coefficient blocks must contain at most 4096 columns.")
    branches = copied["branches"]
    if not isinstance(branches, dict) or set(branches) != {"word", "char"}:
        raise ModelArtifactError("Presence requires exactly word and char branches.")
    for name, branch in branches.items():
        required = _BRANCH_KEYS | ({"token_pattern"} if name == "word" else set())
        if not isinstance(branch, dict) or set(branch) != required:
            raise ModelArtifactError(f"Presence {name} branch has missing or unknown fields.")
        if branch["analyzer"] != name or branch["ngram_range"] != ([1, 2] if name == "word" else [3, 5]):
            raise ModelArtifactError(f"Unsupported {name} analyzer or n-grams.")
        if any(type(value) is not int for value in branch["ngram_range"]):
            raise ModelArtifactError("N-gram bounds must be integers.")
        if name == "word" and branch["token_pattern"] != TOKEN_PATTERN:
            raise ModelArtifactError("Unsupported presence word token rule.")
        if type(branch["max_features"]) is not int or branch["max_features"] != PROFILE_MAX_FEATURES[profile]:
            raise ModelArtifactError("Presence feature bound does not match its profile.")
        features = branch["features"]
        if not isinstance(features, list) or not 0 < len(features) <= branch["max_features"]:
            raise ModelArtifactError("Presence vocabulary is empty or exceeds its profile bound.")
        if any(not isinstance(feature, str) or not feature or any(0xD800 <= ord(c) <= 0xDFFF for c in feature)
               for feature in features) or len(set(features)) != len(features):
            raise ModelArtifactError("Presence vocabulary must contain unique nonempty Unicode strings.")
        if name == "word" and any(
            " ".join(_WORD_TOKENS.findall(feature)) != feature or len(feature.split(" ")) not in (1, 2)
            for feature in features
        ):
            raise ModelArtifactError("Word vocabulary does not match the token and n-gram rules.")
        if name == "char" and any(not 3 <= len(feature) <= 5 for feature in features):
            raise ModelArtifactError("Character vocabulary contains an invalid n-gram.")
        if any(branch[key] is not True for key in ("sublinear_tf", "use_idf", "smooth_idf")):
            raise ModelArtifactError("Presence TF-IDF settings must be enabled.")
        if branch["norm"] != "l2" or branch["lowercase"] is not False:
            raise ModelArtifactError("Presence requires independent L2 normalization and canonical text.")
    return copied


def presence_tensor_shapes(config: Mapping) -> dict[str, tuple[int, ...]]:
    """Return the exact immutable-IDF and trainable-head tensor manifest."""
    config = validate_presence_config(config)
    dimensions = {name: len(config["branches"][name]["features"]) for name in ("word", "char")}
    shapes = {f"features.{name}.idf": (dimension,) for name, dimension in dimensions.items()}
    total = sum(dimensions.values())
    shapes.update({f"head.presence.weight.{index // BLOCK_SIZE:03d}": (min(BLOCK_SIZE, total - index),)
                   for index in range(0, total, BLOCK_SIZE)})
    shapes["head.presence.bias"] = (1,)
    return shapes


def validate_presence_parameters(config: Mapping, parameters: Mapping[str, Sequence[float]],
                                 shapes: Mapping[str, Sequence[int]],
                                 trainable: Mapping[str, bool] | None = None) -> None:
    """Validate exact tensors and finite float32 values; optional flags are strict."""
    expected = presence_tensor_shapes(config)
    if not isinstance(parameters, Mapping) or not isinstance(shapes, Mapping) or set(parameters) != set(expected) or set(shapes) != set(expected):
        raise ModelArtifactError("Presence tensor manifest is incomplete or contains unknown tensors.")
    if trainable is not None and (not isinstance(trainable, Mapping) or set(trainable) != set(expected)):
        raise ModelArtifactError("Presence trainable manifest is incomplete.")
    for name, shape in expected.items():
        actual_shape = shapes[name]
        if not isinstance(actual_shape, (list, tuple)) or any(type(size) is not int for size in actual_shape) or tuple(actual_shape) != shape:
            raise ModelArtifactError(f"Presence tensor {name!r} has the wrong shape.")
        values = parameters[name]
        if not isinstance(values, (list, tuple)) or len(values) != shape[0]:
            raise ModelArtifactError(f"Presence tensor {name!r} has the wrong value count.")
        for value in values:
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ModelArtifactError(f"Presence tensor {name!r} contains an invalid value.")
            converted = float32(value)
            if name.startswith("features.") and converted <= 0:
                raise ModelArtifactError("Presence IDF values must be positive finite float32 values.")
        if trainable is not None and (type(trainable[name]) is not bool or trainable[name] != name.startswith("head.presence.")):
            raise ModelArtifactError("Only presence coefficient and bias tensors may be trainable.")


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _plain(value):
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


@dataclass(frozen=True, init=False)
class SparsePresenceModel:
    """Immutable CPU model using transported parameters and deterministic arithmetic."""

    config: Mapping
    parameters: Mapping[str, tuple[float, ...]]
    shapes: Mapping[str, tuple[int, ...]]
    _vocabularies: Mapping
    _coefficients: tuple[float, ...]

    def __init__(self, config: Mapping, parameters: Mapping, shapes: Mapping):
        validated = validate_presence_config(config)
        validate_presence_parameters(validated, parameters, shapes)
        copied = {name: tuple(float32(value) for value in values) for name, values in parameters.items()}
        object.__setattr__(self, "config", _freeze(validated))
        object.__setattr__(self, "parameters", MappingProxyType(copied))
        object.__setattr__(self, "shapes", MappingProxyType({name: tuple(shape) for name, shape in shapes.items()}))
        object.__setattr__(self, "_vocabularies", MappingProxyType({name: MappingProxyType({feature: index for index, feature in enumerate(validated["branches"][name]["features"])}) for name in ("word", "char")}))
        object.__setattr__(self, "_coefficients", tuple(value for name in sorted(copied) if name.startswith("head.presence.weight.") for value in copied[name]))

    @classmethod
    def from_artifact(cls, artifact: Mapping) -> "SparsePresenceModel":
        from .artifact import validate_artifact
        validate_artifact(artifact)
        if artifact["architecture"] != PRESENCE_ARCHITECTURE:
            raise ModelArtifactError("Artifact is not an annotation-presence model.")
        return cls(artifact["config"], {name: tensor["values"] for name, tensor in artifact["parameters"].items()},
                   {name: tensor["shape"] for name, tensor in artifact["parameters"].items()})

    @property
    def threshold(self) -> float:
        return self.config["threshold"]

    @property
    def profile(self) -> str:
        return self.config["profile"]

    @property
    def feature_dimension(self) -> int:
        return len(self._coefficients)

    def features(self, text: str) -> dict[int, float]:
        if not isinstance(text, str):
            raise ValueError("Presence text must be a string.")
        text = training_text_key(text)
        tokens = _WORD_TOKENS.findall(text)
        counts = {"word": Counter(tokens)}
        counts["word"].update(" ".join(tokens[index:index + 2]) for index in range(len(tokens) - 1))
        counts["char"] = Counter(text[index:index + size] for size in (3, 4, 5) for index in range(len(text) - size + 1))
        result, offset = {}, 0
        for name in ("word", "char"):
            vocabulary = self._vocabularies[name]
            idf = self.parameters[f"features.{name}.idf"]
            values = {vocabulary[feature]: (1.0 + math.log(count)) * idf[vocabulary[feature]]
                      for feature, count in counts[name].items() if feature in vocabulary}
            norm = math.sqrt(math.fsum(values[index] ** 2 for index in sorted(values)))
            if norm:
                result.update({offset + index: values[index] / norm for index in sorted(values)})
            offset += len(vocabulary)
        return result

    def predict_probability(self, text: str) -> float:
        features = self.features(text)
        logit = math.fsum(self._coefficients[index] * features[index] for index in sorted(features)) + self.parameters["head.presence.bias"][0]
        if logit >= 0:
            return 1.0 / (1.0 + math.exp(-logit))
        exponent = math.exp(logit)
        return exponent / (1.0 + exponent)

    def classify(self, text: str) -> bool:
        return self.predict_probability(text) >= self.threshold

    def presence_head_deltas(self, text: str, target: bool) -> dict[str, tuple[float, ...]]:
        """Return unscaled BCE ascent deltas; caller owns averaging and clipping."""
        if type(target) is not bool:
            raise ValueError("Presence target must be a strict boolean.")
        residual = int(target) - self.predict_probability(text)
        features = self.features(text)
        deltas = {}
        offset = 0
        for name in sorted(self.parameters):
            if name.startswith("head.presence.weight."):
                size = len(self.parameters[name])
                deltas[name] = tuple(residual * features.get(offset + index, 0.0) for index in range(size))
                offset += size
        deltas["head.presence.bias"] = (residual,)
        return deltas
