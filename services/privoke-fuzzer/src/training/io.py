from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from json_records import first_value, load_json_records, string_metadata

from .classifications import classification_from_mapping
from .types import BatchTrainingExample

JsonMapping = Mapping[str, object]


def load_training_examples(path: str | Path) -> list[BatchTrainingExample]:
    items = load_json_records(
        path,
        collection_keys=("examples", "samples", "data"),
        missing_message="Training batch does not exist",
        shape_message="Training batch must be a list or contain examples/samples/data.",
    )
    return [training_example_from_mapping(item) for item in items]


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
