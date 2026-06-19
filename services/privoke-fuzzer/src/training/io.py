from __future__ import annotations

import json
from pathlib import Path
from typing import List, Mapping

from .classifications import classification_from_mapping
from .types import BatchTrainingExample


JsonMapping = Mapping[str, object]


def load_training_examples(path: str | Path) -> List[BatchTrainingExample]:
    batch_path = Path(path)
    if not batch_path.exists():
        raise FileNotFoundError(f"Training batch does not exist: {batch_path}")

    if batch_path.suffix.lower() == ".jsonl":
        items = [
            json.loads(line)
            for line in batch_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    else:
        payload = json.loads(batch_path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            items = (
                payload.get("examples")
                or payload.get("samples")
                or payload.get("data")
                or []
            )
        else:
            items = payload

    if not isinstance(items, list):
        raise ValueError("Training batch must be a list or contain examples/samples/data.")

    return [training_example_from_mapping(item) for item in items]


def training_example_from_mapping(item: JsonMapping) -> BatchTrainingExample:
    if not isinstance(item, Mapping):
        raise ValueError("Each training example must be a JSON object.")

    text = item.get("text") or item.get("prompt") or item.get("input")
    if not isinstance(text, str) or not text:
        raise ValueError("Each training example needs a non-empty text/prompt/input field.")

    return BatchTrainingExample(
        text=text,
        expected_classification=classification_from_mapping(item),
        weight=float(item.get("weight", 1.0)),
        metadata=string_metadata(item.get("metadata", {})),
    )


def string_metadata(raw_metadata: object) -> dict[str, str]:
    if not isinstance(raw_metadata, Mapping):
        return {}
    return {str(key): str(value) for key, value in raw_metadata.items()}
