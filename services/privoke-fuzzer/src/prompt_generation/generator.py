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
    excluded_group_ids: tuple[str, ...] = (),
) -> list[BatchTrainingExample]:
    if count <= 0:
        return []

    # Deterministic experiment sampling; this value is not a security token.
    rng = random.Random(seed)  # nosec B311
    prompt_seeds = load_prompt_dataset(dataset_path)
    if not prompt_seeds:
        raise ValueError("Prompt dataset must contain at least one seed.")
    generated = []

    excluded = {training_text_key(text) for text in excluded_texts}
    excluded_groups = set(excluded_group_ids)
    for prompt_seed in _candidate_seeds(prompt_seeds, rng, max(256, count * 64)):
        if len(generated) == count:
            break
        index = len(generated)
        if _group_id(prompt_seed) in excluded_groups:
            continue
        text = _render_prompt(prompt_seed.template, rng)
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

    if not generated:
        raise ValueError("Dataset cannot supply training texts separate from held-out data.")
    # Training already samples with replacement. Reuse known valid candidates
    # when a nearly exhausted fixed dataset makes stochastic retries unhelpful.
    available = tuple(generated)
    while len(generated) < count:
        item = rng.choice(available)
        metadata = dict(item.metadata)
        metadata["generation_index"] = str(len(generated))
        generated.append(BatchTrainingExample(
            text=item.text, expected_classification=item.expected_classification,
            weight=item.weight, metadata=metadata,
        ))
    return generated


def generate_training_partition(count, heldout_count, seed, dataset_path=None):
    """Reserve labeled examples; exclude their texts and any declared source groups."""
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
    reserved_groups = set()
    for index in range(heldout_count):
        for item in _candidate_seeds(groups[bool(index % 2)], rng, 256):
            group = _group_id(item)
            if group is not None and group in reserved_groups:
                continue
            text = _render_prompt(item.template, rng)
            key = training_text_key(text)
            if key not in seen:
                seen.add(key)
                if group is not None:
                    reserved_groups.add(group)
                heldout.append(BatchTrainingExample(
                    text, item.classification, metadata=dict(item.metadata)
                ))
                break
        else:
            raise ValueError("Dataset cannot supply enough distinct held-out examples or source groups.")
    training = generate_training_prompts(
        count, seed, dataset_path, excluded_texts=tuple(item.text for item in heldout),
        excluded_group_ids=tuple(sorted(reserved_groups)),
    )
    return training, heldout


def _group_id(seed):
    value = seed.metadata.get("group_id")
    return str(value) if value is not None and str(value).strip() else None


def _candidate_seeds(seeds, rng, attempts):
    """Try every seed once before bounded stochastic template variants."""
    candidates = list(seeds)
    rng.shuffle(candidates)
    yield from candidates
    for _ in range(max(0, attempts - len(candidates))):
        yield rng.choice(candidates)


def _render_prompt(template, rng):
    try:
        return render_template(template, rng)
    except (KeyError, ValueError, IndexError, AttributeError) as exc:
        raise ValueError("Prompt dataset contains an invalid template.") from exc
