from __future__ import annotations

import math
import os
import threading
import time
from dataclasses import dataclass
from typing import Dict, List

from ...classification import (
    Category,
    ClassificationResult,
    Sensitivity,
    Visibility,
    initialise_unpacked,
)
from ...model import ModelConfig, TinyTransformerModel
from .parameter_stream import ModelParameterStreamer, ParameterSnapshot
from .presence_model import StreamedPresenceModel


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
        sensitivity = Sensitivity[prediction.sensitivity]
        visibility = Visibility[prediction.visibility]
        categories = [
            Category.__members__[name]
            for name in prediction.categories
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
                    "compute_device": self.model.compute_device,
                    "category_probabilities": category_probabilities,
                },
            )
        ]


@dataclass(frozen=True)
class _CachedModel:
    cache_key: str
    model: StreamedTransformerPrivacyModel
    refreshed_at: float


@dataclass(frozen=True)
class _CachedPresenceModel:
    cache_key: str
    model: StreamedPresenceModel
    refreshed_at: float


class StreamedModelCache:
    """Thread-safe cache that retains only the latest version of each model."""

    def __init__(self, refresh_interval_seconds: float | None = None):
        self._lock = threading.RLock()
        self._models: Dict[
            tuple[str, str],
            _CachedModel,
        ] = {}
        # Presence models have a distinct type/task namespace and can never be
        # returned by the semantic transformer cache.
        self._presence_models: Dict[tuple[str, str], _CachedPresenceModel] = {}
        self.refresh_interval_seconds = (
            refresh_interval_seconds
            if refresh_interval_seconds is not None
            else float(os.getenv("MODEL_STREAMING_CACHE_TTL_SECONDS", "1.0"))
        )
        if (
            not math.isfinite(self.refresh_interval_seconds)
            or self.refresh_interval_seconds < 0
        ):
            raise ValueError(
                "MODEL_STREAMING_CACHE_TTL_SECONDS must be finite and non-negative."
            )

    def classify(
        self,
        text: str,
        streamer: ModelParameterStreamer,
    ) -> List[ClassificationResult]:
        model = self._model_for_streamer(streamer)
        return model.classify(text)

    def model_for_training(
        self,
        streamer: ModelParameterStreamer,
    ) -> StreamedTransformerPrivacyModel:
        """Return the cached, versioned model used for one atomic training batch."""
        return self._model_for_streamer(streamer, force_refresh=True)

    def semantic_model_for_streamer(
        self,
        streamer: ModelParameterStreamer,
    ) -> StreamedTransformerPrivacyModel:
        """Return the current immutable semantic snapshot for trace metadata."""
        return self._model_for_streamer(streamer)

    def presence_model_for_streamer(
        self,
        streamer: ModelParameterStreamer,
        *,
        force_refresh: bool = False,
    ) -> StreamedPresenceModel:
        """Fetch/cache only the explicitly requested sparse presence model."""
        identity = (streamer.target, streamer.model_id)
        with self._lock:
            now = time.monotonic()
            cached = self._presence_models.get(identity)
            if (
                not force_refresh
                and cached is not None
                and now - cached.refreshed_at < self.refresh_interval_seconds
            ):
                return cached.model

            snapshot = streamer.fetch()
            if snapshot.model_id != streamer.model_id:
                raise RuntimeError(
                    "Model parameter stream returned a different presence model ID."
                )
            # Presence responses publish the artifact checksum, so provenance-only
            # artifact changes must replace the wrapper even when model math matches.
            same_artifact_identity = (
                cached is not None
                and cached.cache_key == snapshot.cache_key
                and cached.model.snapshot.metadata.get("artifact_checksum")
                == snapshot.metadata.get("artifact_checksum")
            )
            if same_artifact_identity:
                model = cached.model
            else:
                model = StreamedPresenceModel(snapshot)
            self._presence_models[identity] = _CachedPresenceModel(
                cache_key=snapshot.cache_key,
                model=model,
                refreshed_at=time.monotonic(),
            )
            return model

    def presence_model_for_training(
        self,
        streamer: ModelParameterStreamer,
    ) -> StreamedPresenceModel:
        """Use a freshly fetched presence snapshot for one bounded update."""
        return self.presence_model_for_streamer(streamer, force_refresh=True)

    def _model_for_streamer(
        self,
        streamer: ModelParameterStreamer,
        force_refresh: bool = False,
    ) -> StreamedTransformerPrivacyModel:
        identity = (streamer.target, streamer.model_id)
        with self._lock:
            now = time.monotonic()
            cached = self._models.get(identity)
            if (
                not force_refresh
                and cached is not None
                and now - cached.refreshed_at < self.refresh_interval_seconds
            ):
                return cached.model

            snapshot = streamer.fetch()
            if (
                streamer.model_id != ModelParameterStreamer.DEFAULT_MODEL_ID
                and snapshot.model_id != streamer.model_id
            ):
                raise RuntimeError(
                    "Model parameter stream returned a different model ID."
                )
            if cached is not None and cached.cache_key == snapshot.cache_key:
                model = cached.model
            else:
                model = StreamedTransformerPrivacyModel(snapshot)
            self._models[identity] = _CachedModel(
                cache_key=snapshot.cache_key,
                model=model,
                refreshed_at=time.monotonic(),
            )
            return model

    def _model_for_snapshot(
        self,
        snapshot: ParameterSnapshot,
    ) -> StreamedTransformerPrivacyModel:
        with self._lock:
            identity = ("", snapshot.model_id)
            cached = self._models.get(identity)
            if cached is not None and cached.cache_key == snapshot.cache_key:
                return cached.model
            model = StreamedTransformerPrivacyModel(snapshot)
            self._models[identity] = _CachedModel(
                cache_key=snapshot.cache_key,
                model=model,
                refreshed_at=time.monotonic(),
            )
            return model

    def clear(self) -> None:
        with self._lock:
            self._models.clear()
            self._presence_models.clear()


GLOBAL_STREAMED_MODEL_CACHE = StreamedModelCache()
