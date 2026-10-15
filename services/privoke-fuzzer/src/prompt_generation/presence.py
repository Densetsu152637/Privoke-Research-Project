"""Strict binary annotation-presence curriculum loading and partitioning."""

from __future__ import annotations

import random
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from json_records import load_json_records
from privoke_model.training_data import training_text_key


@dataclass(frozen=True)
class PresenceExample:
    text: str
    sensitive: bool
    example_id: str
    group_id: str
    weight: float = 1.0


def load_presence_dataset(dataset_path: str | Path) -> list[PresenceExample]:
    """Load JSONL rows without converting binary labels into contextual grades."""
    rows = load_json_records(
        dataset_path,
        collection_keys=("examples", "data"),
        missing_message="Presence dataset does not exist",
        shape_message="Presence dataset must be a JSON array or JSONL file.",
    )
    examples = []
    ids = set()
    normalized = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("Presence dataset entries must be objects.")
        example_id, text, sensitive, group_id = (
            row.get("id"), row.get("text"), row.get("sensitive"), row.get("group_id")
        )
        if not isinstance(example_id, str) or not example_id.strip():
            raise ValueError("Presence dataset entries need a nonempty string id.")
        example_id = example_id.strip()
        if example_id in ids:
            raise ValueError("Presence dataset ids must be unique.")
        if not isinstance(text, str) or not text.strip():
            raise ValueError("Presence dataset entries need nonempty text.")
        if type(sensitive) is not bool:
            raise ValueError("Presence dataset sensitive labels must be strict booleans.")
        if not isinstance(group_id, str) or not group_id.strip():
            raise ValueError("Presence dataset entries need a nonempty group_id.")
        group_id = group_id.strip()
        key = training_text_key(text)
        if not key:
            raise ValueError("Presence dataset text must remain nonempty after normalization.")
        if key in normalized and normalized[key] != sensitive:
            raise ValueError("Normalized presence text has conflicting binary labels.")
        normalized[key] = sensitive
        ids.add(example_id)
        examples.append(PresenceExample(text, sensitive, example_id, group_id))
    return examples


def generate_presence_training_partition(count: int, heldout_count: int, seed: int,
                                         dataset_path: str | Path):
    """Select disjoint normalized texts and source groups, retaining both strata."""
    if count < 2 or heldout_count < 2:
        raise ValueError("Presence training requires at least two training and two held-out examples.")
    if not dataset_path:
        raise ValueError("A prepared presence curriculum dataset path is required.")
    rows = load_presence_dataset(dataset_path)
    by_label = {False: [], True: []}
    for row in rows:
        by_label[row.sensitive].append(row)
    if any(len(items) < 2 for items in by_label.values()):
        raise ValueError("Presence dataset needs at least two examples in each binary stratum.")
    rng = random.Random(seed)  # nosec B311
    for items in by_label.values():
        rng.shuffle(items)

    heldout = []
    heldout_groups, heldout_texts = set(), set()
    cursors = {False: 0, True: 0}
    # Alternate labels first so held-out data always contains both strata.
    for index in range(heldout_count):
        label = bool(index % 2)
        chosen = _next_disjoint(by_label[label], cursors, label, heldout_groups, heldout_texts)
        if chosen is None:
            raise ValueError("Presence dataset cannot supply enough distinct held-out examples or source groups.")
        heldout.append(chosen)
        heldout_groups.add(chosen.group_id)
        heldout_texts.add(training_text_key(chosen.text))

    remaining = [row for label in (False, True) for row in by_label[label]
                 if row.group_id not in heldout_groups and training_text_key(row.text) not in heldout_texts]
    rng.shuffle(remaining)
    selected = []
    seen_texts = set(heldout_texts)
    required_labels = (False, True) if count >= 2 else (remaining[0].sensitive,)
    for label in required_labels:
        first_in_stratum = next((row for row in remaining if row.sensitive is label), None)
        if first_in_stratum is None:
            raise ValueError("Presence dataset cannot supply training examples across both strata.")
        selected.append(first_in_stratum)
        seen_texts.add(training_text_key(first_in_stratum.text))
    for row in remaining:
        if len(selected) == count:
            break
        if row in selected:
            continue
        key = training_text_key(row.text)
        if key in seen_texts:
            continue
        selected.append(row)
        seen_texts.add(key)
        if len(selected) == count:
            break
    if len(selected) != count or {row.sensitive for row in selected} != {False, True}:
        raise ValueError("Presence dataset cannot supply the requested training examples across both strata and disjoint groups.")
    return selected, heldout


def _next_disjoint(items, cursors, label, groups, texts):
    while cursors[label] < len(items):
        row = items[cursors[label]]
        cursors[label] += 1
        if row.group_id not in groups and training_text_key(row.text) not in texts:
            return row
    return None
