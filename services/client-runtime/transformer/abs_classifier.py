
from abc import abstractmethod, ABC
from typing import Dict, List
from ..classification import Sensitivity, Visibility, Category, Classification, RiskVector, initialise_unpacked

class LLMResult:

    classification: Classification
    risk_vector: RiskVector
    reasoning: str

    def __init__(self, classification: Classification, risk_vector: RiskVector, reasoning: str):
        self.classification = classification
        self.risk_vector = risk_vector
        self.reasoning = reasoning

class AbstractClassifier(ABC):

    @abstractmethod
    def classify(self, text: str) -> List[LLMResult]:
        """
        returns a classification of text from a LLM
        """

def build_result(content: List[Dict]) -> List[LLMResult]:
    return [map(parse_result, content)]

def parse_result(parsed: Dict) -> LLMResult:
    """
    Convert model JSON into internal enum-backed classification output.
    """

    sensitivity = Sensitivity[parsed.get("sensitivity", "S0")]
    visibility = Visibility[parsed.get("visibility", "PU")]

    categories = []
    raw_categories = parsed.get("categories", [])
    for raw_category in raw_categories:
        categories.append(Category[raw_category])

    risk_vector = RiskVector[parsed.get("risk_vector", "UNKNOWN")]

    return LLMResult(
        initialise_unpacked(sensitivity, visibility, categories),
        risk_vector,
        parsed.get("reasoning", "Unknown Reason")
    )

