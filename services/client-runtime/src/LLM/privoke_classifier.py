from typing import List

from .abs_classifier import AbstractClassifier
from ..classification import ClassificationResult
from .privoke import GLOBAL_STREAMED_MODEL_CACHE, ModelParameterStreamer


class PriVokeClassifier(AbstractClassifier):
    """
    Semantic classifier backed by model-streaming-service.

    Parameters are not fetched during initialization. Each classify() call
    streams the latest snapshot, then reuses the globally cached executable
    model unless the streamed version/fingerprint has changed.
    """

    def __init__(
        self,
        target: str | None = None,
        model_id: str | None = None,
        consumer_id: str | None = None,
        timeout_seconds: float | None = None,
    ):
        self.streamer = ModelParameterStreamer(
            target=target,
            model_id=model_id,
            consumer_id=consumer_id,
            timeout_seconds=timeout_seconds,
        )

    def classify(self, text: str) -> List[ClassificationResult]:
        return GLOBAL_STREAMED_MODEL_CACHE.classify(text, self.streamer)
