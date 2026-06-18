
from abc import abstractmethod, ABC
from typing import List
from classification import ClassificationResult

class AbstractClassifier(ABC):

    @abstractmethod
    def classify(self, text: str) -> List[ClassificationResult]:
        """
        returns a classification of text from a LLM
        """

