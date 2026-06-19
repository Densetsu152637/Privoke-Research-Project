from __future__ import annotations

import json
from pathlib import Path
from typing import List, Mapping

from training.classifications import classification_from_mapping

from .defaults import default_prompt_dataset
from .types import PromptSeed


def load_prompt_dataset(
    dataset_path: str | Path | None = None,
) -> List[PromptSeed]:
    if dataset_path is None:
        return list(default_prompt_dataset())

    path = Path(dataset_path)
    if not path.exists():
        raise FileNotFoundError(f"Prompt dataset does not exist: {path}")

    if path.suffix.lower() == ".jsonl":
        items = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    else:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, Mapping):
            items = (
                payload.get("prompts")
                or payload.get("examples")
                or payload.get("data")
                or []
            )
        else:
            items = payload

    if not isinstance(items, list):
        raise ValueError("Prompt dataset must be a JSON array or JSONL file.")

    return [prompt_seed_from_mapping(item) for item in items]


def prompt_seed_from_mapping(item: object) -> PromptSeed:
    if not isinstance(item, Mapping):
        raise ValueError("Prompt dataset entries must be objects.")

    template = item.get("template") or item.get("text") or item.get("prompt")
    if not isinstance(template, str) or not template.strip():
        raise ValueError("Prompt dataset entries need template/text/prompt.")

    classification = classification_from_mapping(item)
    if classification is None:
        raise ValueError(
            "Prompt dataset entries need packed_classification or classification."
        )

    return PromptSeed(
        template=template,
        classification=classification,
        metadata=string_metadata(item.get("metadata", {})),
    )


def string_metadata(raw_metadata: object) -> dict[str, str]:
    if not isinstance(raw_metadata, Mapping):
        return {}
    return {str(key): str(value) for key, value in raw_metadata.items()}
