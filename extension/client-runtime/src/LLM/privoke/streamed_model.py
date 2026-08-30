from __future__ import annotations

import threading
from typing import Dict, List

from privoke_model import ModelConfig, TinyTransformerModel

from ...classification import (
    Category,
    ClassificationResult,
    Sensitivity,
    Visibility,
    initialise_unpacked,
)
from .parameter_stream import ModelParameterStreamer, ParameterSnapshot


class StreamedTransformerPrivacyModel:
    """Executable transformer reconstructed entirely from a streamed snapshot."""

    def __init__(self, snapshot: ParameterSnapshot):
        self.snapshot = snapshot
        self.model = TinyTransformerModel(
            ModelConfig.from_metadata(snapshot.metadata),
            snapshot.parameters,
            snapshot.shapes,
        )

    def classify(self, text: str) -> List[ClassificationResult]:
        prediction = self.model.predict(text)
        sensitivity = Sensitivity.__members__.get(
            prediction.sensitivity,
            Sensitivity.S0,
        )
        visibility = Visibility.__members__.get(
            prediction.visibility,
            Visibility.PU,
        )
        categories = [
            Category.__members__[name]
            for name in prediction.categories
            if name in Category.__members__
        ]

        if sensitivity == Sensitivity.S0 and not categories and visibility == Visibility.PU:
            return []

        category_probabilities = {
            label: round(probability, 4)
            for label, probability in zip(
                self.model.config.category_labels,
                prediction.category_probabilities,
            )
        }
        classification = initialise_unpacked(sensitivity, visibility, categories)
        return [
            ClassificationResult(
                classification=classification,
                section_of_text=text,
                reasoning=(
                    f"Streamed transformer {self.snapshot.model_id} "
                    f"{self.snapshot.version} predicted "
                    f"{sensitivity.name}/{visibility.name}."
                ),
                span=(0, len(text)) if text else None,
                confidence=round(min(max(prediction.confidence, 0.0), 0.999), 3),
                metadata={
                    "classifier": "privoke_streamed_transformer",
                    "architecture": self.snapshot.metadata.get("architecture", "unknown"),
                    "model_id": self.snapshot.model_id,
                    "model_version": self.snapshot.version,
                    "parameter_count": self.snapshot.parameter_count,
                    "parameter_fingerprint": self.snapshot.fingerprint,
                    "artifact_checksum": self.snapshot.metadata.get(
                        "artifact_checksum",
                        "unknown",
                    ),
                    "category_probabilities": category_probabilities,
                },
            )
        ]


class StreamedModelCache:
    """Thread-safe cache that retains only the latest version of each model."""

    def __init__(self):
        self._lock = threading.RLock()
        self._models: Dict[
            str,
            tuple[str, StreamedTransformerPrivacyModel],
        ] = {}

    def classify(
        self,
        text: str,
        streamer: ModelParameterStreamer,
    ) -> List[ClassificationResult]:
        snapshot = streamer.fetch()
        model = self._model_for_snapshot(snapshot)
        return model.classify(text)

    def _model_for_snapshot(
        self,
        snapshot: ParameterSnapshot,
    ) -> StreamedTransformerPrivacyModel:
        with self._lock:
            cached = self._models.get(snapshot.model_id)
            if cached is not None and cached[0] == snapshot.cache_key:
                return cached[1]
            model = StreamedTransformerPrivacyModel(snapshot)
            self._models[snapshot.model_id] = (snapshot.cache_key, model)
            return model

    def clear(self) -> None:
        with self._lock:
            self._models.clear()


GLOBAL_STREAMED_MODEL_CACHE = StreamedModelCache()
