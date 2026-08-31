from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from json_records import first_value, load_json_records, string_metadata
from training.classifications import classification_from_mapping

from .defaults import default_prompt_dataset
from .types import PromptSeed


def load_prompt_dataset(
    dataset_path: str | Path | None = None,
) -> list[PromptSeed]:
    if dataset_path is None:
        return list(default_prompt_dataset())

    items = load_json_records(
        dataset_path,
        collection_keys=("prompts", "examples", "data"),
        missing_message="Prompt dataset does not exist",
        shape_message="Prompt dataset must be a JSON array or JSONL file.",
    )
    return [prompt_seed_from_mapping(item) for item in items]


def prompt_seed_from_mapping(item: object) -> PromptSeed:
    if not isinstance(item, Mapping):
        raise ValueError("Prompt dataset entries must be objects.")  # noqa: TRY004

    template = first_value(item, "template", "text", "prompt")
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
