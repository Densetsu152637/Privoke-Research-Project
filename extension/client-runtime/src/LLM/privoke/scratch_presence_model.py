"""Immutable CPU inference for explicitly named offline scratch binary models."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

import numpy as np
from privoke_model.scratch_presence import (
    scratch_presence_trainable_names,
    validate_scratch_presence_parameters,
    validate_scratch_presence_stream_metadata,
)

from ...detection.preprocessing import normalize_text
from ...transformer_encoder import EncoderConfig, NumpyTransformerEncoder
from .parameter_stream import ParameterSnapshot


@dataclass(frozen=True, init=False)
class StreamedScratchPresenceModel:
    """Validate and own one snapshot; provide binary probabilities only."""

    snapshot: ParameterSnapshot
    config: Mapping[str, object]
    encoder: NumpyTransformerEncoder
    _weight: np.ndarray
    _bias: np.ndarray

    def __init__(self, snapshot: ParameterSnapshot):
        config = validate_scratch_presence_stream_metadata(
            snapshot.model_id, snapshot.version, dict(snapshot.metadata),
        )
        if type(snapshot.generated_at_unix) is not int or not 0 < snapshot.generated_at_unix <= 2**63 - 1:
            raise ValueError("Scratch snapshot timestamp is invalid.")
        trainable_names = set(scratch_presence_trainable_names(config))
        trainable = {name: name in trainable_names for name in snapshot.parameters}
        validate_scratch_presence_parameters(
            config, snapshot.parameters, snapshot.shapes, trainable,
        )
        owned = ParameterSnapshot(
            model_id=snapshot.model_id, version=snapshot.version,
            generated_at_unix=snapshot.generated_at_unix,
            parameters=MappingProxyType({name: tuple(values) for name, values in snapshot.parameters.items()}),
            shapes=MappingProxyType({name: tuple(shape) for name, shape in snapshot.shapes.items()}),
            metadata=MappingProxyType(dict(snapshot.metadata)),
        )
        arrays = {name: np.frombuffer(np.asarray(values, dtype=np.float32).tobytes(), dtype=np.float32)
                  .reshape(owned.shapes[name]) for name, values in owned.parameters.items()}
        object.__setattr__(self, "snapshot", owned)
        object.__setattr__(self, "config", MappingProxyType(config))
        object.__setattr__(self, "encoder", NumpyTransformerEncoder(EncoderConfig.from_mapping(config), arrays))
        object.__setattr__(self, "_weight", arrays["head.presence.weight"])
        object.__setattr__(self, "_bias", arrays["head.presence.bias"])

    @property
    def model_id(self) -> str:
        return self.snapshot.model_id

    @property
    def version(self) -> str:
        return self.snapshot.version

    @property
    def threshold(self) -> float:
        return float(self.config["threshold"])

    def predict_probability(self, text: str) -> float:
        """Normalize raw detector text once, then execute the immutable CPU model."""
        return self.predict_normalized_probability(normalize_text(text))

    def predict_normalized_probability(self, text: str) -> float:
        """Execute text already canonicalized by the pipeline's offset normalizer."""
        pooled = self.encoder.encode(text)
        logit = pooled @ self._weight + self._bias
        if logit.shape != (1,) or not np.isfinite(logit).all():
            raise ValueError("Scratch presence model produced a non-finite logit.")
        clipped = np.clip(logit, -30.0, 30.0)
        probability = float((1.0 / (1.0 + np.exp(-clipped)))[0])
        if not np.isfinite(probability) or not 0.0 <= probability <= 1.0:
            raise ValueError("Scratch presence model produced an invalid probability.")
        return probability

    def classify(self, text: str) -> bool:
        return self.predict_probability(text) >= self.threshold
