from __future__ import annotations

import math
import threading
from dataclasses import dataclass
from typing import Dict, Iterable, List

from ...classification import (
    Category,
    ClassificationResult,
    Sensitivity,
    Visibility,
    initialise_unpacked,
)
from .parameter_stream import ModelParameterStreamer, ParameterSnapshot
from .semantic_features import (
    SemanticSignal,
    extract_semantic_signals,
    signal_excerpt,
    signal_span,
    strongest_sensitivity,
    strongest_visibility,
    visibility_rank,
)


@dataclass(frozen=True)
class StreamedCalibration:
    bias: float
    strength: float
    s1_threshold: float
    s2_threshold: float
    s3_threshold: float
    category_weights: Dict[Category, float]

    @classmethod
    def from_snapshot(cls, snapshot: ParameterSnapshot) -> "StreamedCalibration":
        values = snapshot.flat_values()
        if not values:
            values = (0.0,)

        mean = sum(values) / len(values)
        mean_abs = sum(abs(value) for value in values) / len(values)
        bias_values = [
            value
            for name, parameter_values in snapshot.parameters.items()
            if "bias" in name.lower()
            for value in parameter_values
        ]
        raw_bias = sum(bias_values) / len(bias_values) if bias_values else mean
        bias = _clamp(math.tanh(raw_bias), -0.35, 0.35)
        strength = _clamp(mean_abs, 0.0, 2.0)

        return cls(
            bias=bias,
            strength=strength,
            s1_threshold=_clamp(0.65 + bias * 0.10 - strength * 0.03, 0.45, 0.85),
            s2_threshold=_clamp(1.05 + bias * 0.12 - strength * 0.04, 0.75, 1.30),
            s3_threshold=_clamp(1.55 + bias * 0.16 - strength * 0.05, 1.10, 1.90),
            category_weights=_category_weights(values),
        )


class ParameterBackedPrivacyModel:
    """
    Executable semantic classifier calibrated by streamed parameter snapshots.

    The current streaming proto carries named float vectors, but not tensor
    shapes or tokenizer/model metadata. Until the service exposes a full model
    artifact contract, this model uses the streamed vectors as calibration for
    the semantic feature space used by the PriVoke runtime.
    """

    def __init__(self, snapshot: ParameterSnapshot):
        self.snapshot = snapshot
        self.calibration = StreamedCalibration.from_snapshot(snapshot)

    def classify(self, text: str) -> List[ClassificationResult]:
        signals = extract_semantic_signals(text)
        if not signals:
            return []

        category_signals = [signal for signal in signals if signal.category is not None]
        visibility = strongest_visibility(signals)

        if not category_signals and visibility == Visibility.PU:
            return []

        categories = _dedupe_categories(
            signal.category for signal in category_signals if signal.category is not None
        )
        sensitivity = self._sensitivity(category_signals, categories, visibility)

        if sensitivity == Sensitivity.S0 and not categories and visibility == Visibility.PU:
            return []

        classification = initialise_unpacked(sensitivity, visibility, categories)
        return [
            ClassificationResult(
                classification=classification,
                section_of_text=signal_excerpt(signals, text),
                reasoning=self._reasoning(signals, sensitivity, visibility),
                span=signal_span(signals, text),
                confidence=self._confidence(category_signals, visibility),
                metadata={
                    "classifier": "privoke_streamed",
                    "model_id": self.snapshot.model_id,
                    "model_version": self.snapshot.version,
                    "parameter_count": self.snapshot.parameter_count,
                    "parameter_fingerprint": self.snapshot.fingerprint,
                    "semantic_signal_count": len(signals),
                    "semantic_signal_reasons": _unique_reasons(signals),
                },
            )
        ]

    def _sensitivity(
        self,
        signals: Iterable[SemanticSignal],
        categories: List[Category],
        visibility: Visibility,
    ) -> Sensitivity:
        category_signals = list(signals)
        if not category_signals:
            return Sensitivity.S0

        score = self._risk_score(category_signals, categories, visibility)
        score_sensitivity = _sensitivity_from_score(score, self.calibration)
        signal_sensitivity = strongest_sensitivity(category_signals)
        return max(
            [score_sensitivity, signal_sensitivity],
            key=lambda item: item.value,
        )

    def _risk_score(
        self,
        signals: Iterable[SemanticSignal],
        categories: List[Category],
        visibility: Visibility,
    ) -> float:
        score_by_category: Dict[Category, float] = {}

        for signal in signals:
            if signal.category is None:
                continue
            weighted_score = (
                signal.weight
                * self.calibration.category_weights.get(signal.category, 1.0)
            )
            score_by_category[signal.category] = max(
                score_by_category.get(signal.category, 0.0),
                weighted_score,
            )

        score = sum(score_by_category.values()) + self.calibration.bias
        category_set = set(categories)

        if Category.THIRD_PARTY in category_set and len(category_set) > 1:
            score += 0.35
        if {Category.IDENTITY, Category.LOCATION}.issubset(category_set):
            score += 0.25
        if visibility_rank(visibility) >= visibility_rank(Visibility.P2):
            score += 0.20
        if visibility == Visibility.P4:
            score += 0.15

        return max(0.0, score)

    def _confidence(
        self,
        signals: Iterable[SemanticSignal],
        visibility: Visibility,
    ) -> float:
        category_signals = list(signals)
        score = self._risk_score(
            category_signals,
            _dedupe_categories(
                signal.category
                for signal in category_signals
                if signal.category is not None
            ),
            visibility,
        )
        confidence = (
            0.50
            + min(score / 4.0, 0.32)
            + min(len(category_signals), 4) * 0.035
            + min(self.calibration.strength, 1.0) * 0.04
        )
        return round(_clamp(confidence, 0.0, 0.99), 3)

    def _reasoning(
        self,
        signals: Iterable[SemanticSignal],
        sensitivity: Sensitivity,
        visibility: Visibility,
    ) -> str:
        reasons = _unique_reasons(signals)
        if not reasons:
            reasons = ["Visibility context was detected."]

        reason_text = "; ".join(reasons[:3])
        return (
            f"{reason_text} Streamed model {self.snapshot.model_id} "
            f"{self.snapshot.version} classified this as "
            f"{sensitivity.name}/{visibility.name}."
        )


class StreamedModelCache:
    """Global streamed-model cache shared across PriVokeClassifier instances."""

    def __init__(self):
        self._lock = threading.RLock()
        self._models: Dict[str, ParameterBackedPrivacyModel] = {}

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
    ) -> ParameterBackedPrivacyModel:
        with self._lock:
            model = self._models.get(snapshot.cache_key)
            if model is None:
                model = ParameterBackedPrivacyModel(snapshot)
                self._models[snapshot.cache_key] = model
            return model

    def clear(self) -> None:
        with self._lock:
            self._models.clear()


def _category_weights(values: Iterable[float]) -> Dict[Category, float]:
    value_list = list(values) or [0.0]
    weights = {}
    for index, category in enumerate(Category):
        value = value_list[index % len(value_list)]
        weights[category] = _clamp(1.0 + math.tanh(value) * 0.18, 0.80, 1.20)
    return weights


def _sensitivity_from_score(
    score: float,
    calibration: StreamedCalibration,
) -> Sensitivity:
    if score >= calibration.s3_threshold:
        return Sensitivity.S3
    if score >= calibration.s2_threshold:
        return Sensitivity.S2
    if score >= calibration.s1_threshold:
        return Sensitivity.S1
    return Sensitivity.S0


def _dedupe_categories(categories: Iterable[Category]) -> List[Category]:
    category_set = set(categories)
    return [category for category in Category if category in category_set]


def _unique_reasons(signals: Iterable[SemanticSignal]) -> List[str]:
    reasons = []
    seen = set()
    for signal in signals:
        if signal.reason in seen:
            continue
        seen.add(signal.reason)
        reasons.append(signal.reason)
    return reasons


def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))


GLOBAL_STREAMED_MODEL_CACHE = StreamedModelCache()
