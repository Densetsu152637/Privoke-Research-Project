from __future__ import annotations

from collections.abc import Mapping

from json_records import first_value, string_metadata

from .classifications import classification_from_mapping
from .types import BatchTrainingExample

JsonMapping = Mapping[str, object]


def training_example_from_mapping(item: JsonMapping) -> BatchTrainingExample:
    if not isinstance(item, Mapping):
        raise ValueError("Each training example must be a JSON object.")  # noqa: TRY004

    text = first_value(item, "text", "prompt", "input")
    if not isinstance(text, str) or not text:
        raise ValueError(
            "Each training example needs a non-empty text/prompt/input field."
        )

    return BatchTrainingExample(
        text=text,
        expected_classification=classification_from_mapping(item),
        weight=float(item.get("weight", 1.0)),
        metadata=string_metadata(item.get("metadata", {})),
    )
