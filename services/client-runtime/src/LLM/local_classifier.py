

from typing import List, Dict
from .abs_classifier import AbstractClassifier
from ..classification import ClassificationResult

class LocalClassifier(AbstractClassifier):

    def __init__(self):
        pass

    def classify(self, text: str) -> List[ClassificationResult]:
        return []