"""Runtime wrapper for the separate sparse annotation-presence task."""

from __future__ import annotations

import json
import re

from privoke_model.presence import (
    PRESENCE_ARCHITECTURE,
    PRESENCE_TASK,
    SparsePresenceModel,
    validate_presence_config,
    validate_presence_parameters,
)

from .parameter_stream import ParameterSnapshot


class StreamedPresenceModel:
    """Validate and execute one immutable presence-model stream snapshot."""

    def __init__(self, snapshot: ParameterSnapshot):
        self.snapshot = snapshot
        if snapshot.metadata.get("architecture") != PRESENCE_ARCHITECTURE:
            raise ValueError("Streamed model is not an annotation-presence artifact.")
        try:
            raw_config = json.loads(snapshot.metadata["model_config"])
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("Presence snapshot has no valid model_config.") from exc
        config = validate_presence_config(raw_config)
        if config.get("task") != PRESENCE_TASK:
            raise ValueError("Streamed artifact is not the annotation-presence task.")
        if snapshot.model_id != f"privoke-presence-{config['profile']}":
            raise ValueError("Presence model ID does not match its profile.")
        checksum = snapshot.metadata.get("artifact_checksum", "")
        if not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise ValueError("Presence stream is missing a valid artifact checksum.")

        trainable_names = {
            item for item in snapshot.metadata.get("trainable_parameters", "").split(",")
            if item
        }
        expected_trainable = {
            name for name in snapshot.parameters if name.startswith("head.presence.")
        }
        if trainable_names != expected_trainable:
            raise ValueError("Presence snapshot trainable manifest does not match its tensors.")
        trainable = {name: name in trainable_names for name in snapshot.parameters}
        validate_presence_parameters(config, snapshot.parameters, snapshot.shapes, trainable)
        self.model = SparsePresenceModel(config, snapshot.parameters, snapshot.shapes)
        if not re.fullmatch(r"[0-9a-f]{64}", snapshot.fingerprint):
            raise ValueError("Presence stream has no valid parameter fingerprint.")

    @property
    def model_id(self) -> str:
        return self.snapshot.model_id

    @property
    def version(self) -> str:
        return self.snapshot.version

    @property
    def threshold(self) -> float:
        return self.model.threshold

    def predict_probability(self, text: str) -> float:
        return self.model.predict_probability(text)

    def classify(self, text: str) -> bool:
        return self.model.classify(text)
