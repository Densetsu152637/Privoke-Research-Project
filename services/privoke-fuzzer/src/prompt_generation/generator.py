from __future__ import annotations

import random
from pathlib import Path
from typing import List

from training import BatchTrainingExample

from .loader import load_prompt_dataset
from .templates import render_template


def generate_training_prompts(
    count: int,
    seed: int,
    dataset_path: str | Path | None = None,
) -> List[BatchTrainingExample]:
    if count <= 0:
        return []

    # Deterministic experiment sampling; this value is not a security token.
    rng = random.Random(seed)  # nosec B311
    prompt_seeds = load_prompt_dataset(dataset_path)
    generated = []

    for index in range(count):
        prompt_seed = rng.choice(prompt_seeds)
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
                text=render_template(prompt_seed.template, rng),
                expected_classification=prompt_seed.classification,
                metadata=metadata,
            )
        )

    return generated
