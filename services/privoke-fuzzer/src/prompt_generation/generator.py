from __future__ import annotations

import random
from collections import Counter, deque
from pathlib import Path

from privoke_model.training_data import training_text_key
from training import BatchTrainingExample

from .loader import load_prompt_dataset
from .templates import render_template


CONTEXTUAL_SAMPLING_STRATEGY_KEY = "contextual_sampling_strategy"
CONTEXTUAL_ROLE_QUOTA_STRATEGY = "contextual_role_quota_v1"
_AUTHORED_ROLE = "authored_contrastive_context"
_PUBLIC_ROLE = "public_annotation_negative"
_BOOTSTRAP_ROLE = "existing_bootstrap_replay"
_CONTEXTUAL_ROLES = frozenset((_AUTHORED_ROLE, _PUBLIC_ROLE, _BOOTSTRAP_ROLE))


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


def generate_training_partition(count, heldout_count, seed, dataset_path=None, *, sampling_strategy=None):
    """Reserve labeled examples; exclude their texts and any declared source groups."""
    if sampling_strategy is not None:
        validate_contextual_sampling_strategy(sampling_strategy, count)
        if heldout_count != 16:
            raise ValueError("Contextual role-quota sampling requires exactly 16 held-out examples.")
    if heldout_count < 2:
        raise ValueError("Held-out evaluation needs at least two examples.")
    rng = random.Random(seed + 1)  # nosec B311
    seeds = load_prompt_dataset(dataset_path)
    if sampling_strategy is not None:
        for item in seeds:
            _contextual_role(item)
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
    if sampling_strategy is None:
        training = generate_training_prompts(
            count, seed, dataset_path, excluded_texts=tuple(item.text for item in heldout),
            excluded_group_ids=tuple(sorted(reserved_groups)),
        )
    else:
        training = _generate_contextual_role_quota(seeds, seed, seen, reserved_groups)
    return training, heldout


def validate_contextual_sampling_strategy(strategy, count):
    """Fail closed on undeclared sampling modes and their fixed row budget."""
    if strategy != CONTEXTUAL_ROLE_QUOTA_STRATEGY or type(strategy) is not str:
        raise ValueError("Unsupported contextual sampling strategy.")
    if type(count) is not int or count != 256:
        raise ValueError("Contextual role-quota sampling requires exactly 256 training examples.")


def _contextual_role(item):
    role = item.metadata.get("training_role")
    if type(role) is not str or role not in _CONTEXTUAL_ROLES:
        raise ValueError("Contextual role-quota dataset contains an unknown training role.")
    if _group_id(item) is None:
        raise ValueError("Contextual role-quota sampling requires declared source groups.")
    return role


def _generate_contextual_role_quota(seeds, seed, excluded_texts, excluded_groups):
    """Expose distinct contextual rows, exhausting groups before sibling variants."""
    rng = random.Random(seed)  # nosec B311
    eligible = [item for item in seeds if _group_id(item) not in excluded_groups]
    partitions = (
        ([item for item in eligible if _contextual_role(item) == _AUTHORED_ROLE
          and item.classification.is_sensitive()], 32),
        ([item for item in eligible if _contextual_role(item) == _AUTHORED_ROLE
          and not item.classification.is_sensitive()], 32),
        ([item for item in eligible if _contextual_role(item) in (_PUBLIC_ROLE, _BOOTSTRAP_ROLE)], 192),
    )
    chosen = []
    seen = set(excluded_texts)
    for candidates, quota in partitions:
        grouped = {}
        for item in candidates:
            grouped.setdefault(_group_id(item), []).append(item)
        groups = list(grouped.values())
        rng.shuffle(groups)
        for variants in groups:
            rng.shuffle(variants)
        supplied = 0
        queues = [deque(variants) for variants in groups]
        # Each seed is rendered at most once. Exhaust collisions inside a group
        # before moving on, so every usable group precedes its sibling variants.
        while supplied < quota:
            progressed = False
            for variants in queues:
                while variants:
                    item = variants.popleft()
                    text = _render_prompt(item.template, rng)
                    key = training_text_key(text)
                    if not key or key in seen:
                        continue
                    seen.add(key)
                    metadata = dict(item.metadata)
                    metadata.update(generator="prompt_generation", generation_seed=str(seed),
                                    packed_classification=str(item.packed_classification))
                    chosen.append(BatchTrainingExample(text, item.classification, metadata=metadata))
                    supplied += 1
                    progressed = True
                    break
                if supplied == quota:
                    break
            if not progressed:
                raise ValueError("Dataset cannot supply the contextual role quota without replacement.")
    rng.shuffle(chosen)
    result = [BatchTrainingExample(item.text, item.expected_classification, weight=item.weight,
                                  metadata={**item.metadata, "generation_index": str(index)})
              for index, item in enumerate(chosen)]
    contextual_sampling_audit(result)
    return result


def contextual_sampling_audit(training):
    """Audit actual selected rows; counts describe groups, not independent evidence."""
    counts = Counter()
    authored_groups = {False: set(), True: set()}
    keys = set()
    for item in training:
        role = _contextual_role(item)
        target = item.expected_classification
        if target is None:
            raise ValueError("Contextual role-quota rows require explicit classification targets.")
        sensitive = target.is_sensitive()
        counts[(role, sensitive)] += 1
        key = training_text_key(item.text)
        if not key or key in keys:
            raise ValueError("Contextual role-quota training texts must be distinct and nonempty.")
        keys.add(key)
        if role == _AUTHORED_ROLE:
            authored_groups[sensitive].add(_group_id(item))
    authored_sensitive = counts[(_AUTHORED_ROLE, True)]
    authored_clean = counts[(_AUTHORED_ROLE, False)]
    public = sum(counts[(_PUBLIC_ROLE, flag)] for flag in (False, True))
    bootstrap = sum(counts[(_BOOTSTRAP_ROLE, flag)] for flag in (False, True))
    if len(training) != 256 or authored_sensitive != 32 or authored_clean != 32 or public + bootstrap != 192:
        raise ValueError("Actual contextual role-quota selection does not satisfy its declared quotas.")
    return {
        CONTEXTUAL_SAMPLING_STRATEGY_KEY: CONTEXTUAL_ROLE_QUOTA_STRATEGY,
        "sampling_training_rows": str(len(training)),
        "sampling_training_unique_texts": str(len(keys)),
        "sampling_authored_sensitive_rows": str(authored_sensitive),
        "sampling_authored_clean_rows": str(authored_clean),
        "sampling_public_negative_rows": str(public),
        "sampling_bootstrap_replay_rows": str(bootstrap),
        "sampling_training_sensitive_rows": str(sum(value for (_, sensitive), value in counts.items() if sensitive)),
        "sampling_training_clean_rows": str(sum(value for (_, sensitive), value in counts.items() if not sensitive)),
        "sampling_authored_groups": str(len(authored_groups[False] | authored_groups[True])),
        "sampling_authored_sensitive_groups": str(len(authored_groups[True])),
        "sampling_authored_clean_groups": str(len(authored_groups[False])),
    }


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
