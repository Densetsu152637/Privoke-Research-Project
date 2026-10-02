from __future__ import annotations

import random
from pathlib import Path

from privoke_model.training_data import training_text_key
from training import BatchTrainingExample

from .loader import load_prompt_dataset
from .templates import render_template


def generate_training_prompts(
    count: int,
    seed: int,
    dataset_path: str | Path | None = None,
    *,
    excluded_texts: tuple[str, ...] = (),
) -> list[BatchTrainingExample]:
    if count <= 0:
        return []

    # Deterministic experiment sampling; this value is not a security token.
    rng = random.Random(seed)  # nosec B311
    prompt_seeds = load_prompt_dataset(dataset_path)
    generated = []

    excluded = {training_text_key(text) for text in excluded_texts}
    for _ in range(max(256, count * 64)):
        if len(generated) == count:
            break
        index = len(generated)
        prompt_seed = rng.choice(prompt_seeds)
        text = render_template(prompt_seed.template, rng)
        if training_text_key(text) in excluded:
            continue
        metadata = dict(prompt_seed.metadata)
        metadata.update(
            {
                "generator": "prompt_generation",
                "generation_index": str(index),
                "generation_seed": str(seed),
                "packed_classification": str(prompt_seed.packed_classification),
            }
        )
        generated.append(
            BatchTrainingExample(
                text=text,
                expected_classification=prompt_seed.classification,
                metadata=metadata,
            )
        )

    if len(generated) != count:
        raise ValueError("Dataset cannot supply training texts separate from held-out data.")
    return generated


def generate_training_partition(count, heldout_count, seed, dataset_path=None):
    """Reserve distinct labeled clean/sensitive examples before sampling training."""
    if heldout_count < 2:
        raise ValueError("Held-out evaluation needs at least two examples.")
    rng = random.Random(seed + 1)  # nosec B311
    seeds = load_prompt_dataset(dataset_path)
    groups = {
        sensitive: [item for item in seeds if item.classification.is_sensitive() == sensitive]
        for sensitive in (False, True)
    }
    if not all(groups.values()):
        raise ValueError("Held-out evaluation needs both clean and sensitive labels.")
    heldout = []
    seen = set()
    for index in range(heldout_count):
        for _ in range(256):
            item = rng.choice(groups[bool(index % 2)])
            text = render_template(item.template, rng)
            key = training_text_key(text)
            if key not in seen:
                seen.add(key)
                heldout.append(BatchTrainingExample(text, item.classification))
                break
        else:
            raise ValueError("Dataset cannot supply enough distinct held-out examples.")
    training = generate_training_prompts(
        count, seed, dataset_path, excluded_texts=tuple(item.text for item in heldout)
    )
    return training, heldout
