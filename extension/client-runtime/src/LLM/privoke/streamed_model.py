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
from .scratch_presence_model import StreamedScratchPresenceModel
from privoke_model.scratch_presence import SCRATCH_PRESENCE_MODEL_IDS
from privoke_model.pretrained_context import (
    PRETRAINED_CONTEXT_ARCHITECTURE, PRETRAINED_CONTEXT_MODEL_ID, validate_pretrained_stream,
    validate_pretrained_release_identity,
)


class StreamedTransformerPrivacyModel:
    """Executable transformer reconstructed entirely from a streamed snapshot."""

    def __init__(self, snapshot: ParameterSnapshot):
        self.snapshot = snapshot
        self.model = TinyTransformerModel(
            ModelConfig.from_metadata(snapshot.metadata),
            snapshot.parameters,
            snapshot.shapes,
            reject_overlength=snapshot.metadata.get("contextual_training_strategy") == "contextual_full_encoder_sgd_v1",
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
                (self.model.config["category_labels"] if self.snapshot.metadata.get("architecture") == PRETRAINED_CONTEXT_ARCHITECTURE
                 else self.model.config.category_labels),
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


@dataclass(frozen=True)
class _CachedScratchPresenceModel:
    cache_key: str
    model: StreamedScratchPresenceModel
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
        self._scratch_presence_models: Dict[tuple[str, str], _CachedScratchPresenceModel] = {}
        self._pretrained_encoders = {}
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
        if streamer.model_id == PRETRAINED_CONTEXT_MODEL_ID:
            raise ValueError("Pretrained contextual online training is unsupported; use offline head fitting.")
        model = self._model_for_streamer(streamer, force_refresh=True)
        if model.snapshot.metadata.get("architecture") == PRETRAINED_CONTEXT_ARCHITECTURE:
            raise ValueError("Pretrained contextual online training is unsupported; use offline head fitting.")
        return model

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

    def annotation_presence_model_for_streamer(
        self,
        streamer: ModelParameterStreamer,
        *,
        force_refresh: bool = False,
    ) -> StreamedPresenceModel | StreamedScratchPresenceModel:
        """Dispatch inference only; sparse training keeps its separate entry point."""
        if streamer.model_id not in SCRATCH_PRESENCE_MODEL_IDS:
            if force_refresh:
                return self.presence_model_for_streamer(streamer, force_refresh=True)
            return self.presence_model_for_streamer(streamer)
        identity = (streamer.target, streamer.model_id)
        with self._lock:
            cached = self._scratch_presence_models.get(identity)
            if (not force_refresh and cached is not None
                    and time.monotonic() - cached.refreshed_at < self.refresh_interval_seconds):
                return cached.model
            snapshot = streamer.fetch()
            if snapshot.model_id != streamer.model_id:
                raise RuntimeError("Scratch stream returned a different explicitly requested model ID.")
            # Validate even an unchanged fingerprint: invalid/provenance-only
            # declarations must not reuse an old wrapper before validation.
            candidate = StreamedScratchPresenceModel(snapshot)
            key = candidate.snapshot.cache_key + ":" + candidate.snapshot.metadata["artifact_checksum"]
            model = cached.model if cached is not None and cached.cache_key == key else candidate
            self._scratch_presence_models[identity] = _CachedScratchPresenceModel(
                cache_key=key, model=model, refreshed_at=time.monotonic(),
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
            if snapshot.metadata.get("architecture") == PRETRAINED_CONTEXT_ARCHITECTURE and streamer.model_id != PRETRAINED_CONTEXT_MODEL_ID:
                raise ValueError("Pretrained contextual inference requires its explicit model ID; latest is prohibited.")
            key = self._semantic_cache_key(snapshot)
            if cached is not None and cached.cache_key == key:
                model = cached.model
            else:
                model = self._semantic_model(snapshot)
            self._models[identity] = _CachedModel(
                cache_key=key,
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
            key = self._semantic_cache_key(snapshot)
            if cached is not None and cached.cache_key == key:
                return cached.model
            model = self._semantic_model(snapshot)
            self._models[identity] = _CachedModel(
                cache_key=key,
                model=model,
                refreshed_at=time.monotonic(),
            )
            return model

    def _semantic_cache_key(self, snapshot):
        if (snapshot.metadata.get("architecture") == PRETRAINED_CONTEXT_ARCHITECTURE
                or snapshot.model_id == PRETRAINED_CONTEXT_MODEL_ID):
            config = validate_pretrained_stream(snapshot.model_id, snapshot.metadata)
            validate_pretrained_release_identity(snapshot.version, snapshot.generated_at_unix)
            return snapshot.cache_key + ":" + snapshot.metadata["artifact_checksum"] + ":" + str(config["max_tokens"])
        return snapshot.cache_key

    def _semantic_model(self, snapshot):
        if snapshot.metadata.get("architecture") == PRETRAINED_CONTEXT_ARCHITECTURE:
            from .pretrained_context_model import StreamedPretrainedContextModel
            max_tokens = validate_pretrained_stream(snapshot.model_id, snapshot.metadata)["max_tokens"]
            model = StreamedPretrainedContextModel(snapshot, self._pretrained_encoders.get(max_tokens))
            self._pretrained_encoders[max_tokens] = model.model.encoder
            return model
        return StreamedTransformerPrivacyModel(snapshot)

    def clear(self) -> None:
        with self._lock:
            self._models.clear()
            self._presence_models.clear()
            self._scratch_presence_models.clear()
            self._pretrained_encoders.clear()


GLOBAL_STREAMED_MODEL_CACHE = StreamedModelCache()
