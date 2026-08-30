"""JSON/JSONL record loading shared by prompt and training datasets."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


def load_json_records(
    path: str | Path,
    *,
    collection_keys: Sequence[str],
    missing_message: str,
    shape_message: str,
) -> list[Any]:
    record_path = Path(path)
    if not record_path.exists():
        raise FileNotFoundError(f"{missing_message}: {record_path}")

    if record_path.suffix.lower() == ".jsonl":
        records = [
            json.loads(line)
            for line in record_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    else:
        payload = json.loads(record_path.read_text(encoding="utf-8"))
        records = _records_from_payload(payload, collection_keys)

    if not isinstance(records, list):
        # A malformed data file is a value error at this public loader boundary.
        raise ValueError(shape_message)  # noqa: TRY004
    return records


def string_metadata(raw_metadata: object) -> dict[str, str]:
    if not isinstance(raw_metadata, Mapping):
        return {}
    return {str(key): str(value) for key, value in raw_metadata.items()}


def first_value(item: Mapping[str, object], *keys: str) -> object | None:
    return next((item[key] for key in keys if item.get(key)), None)


def _records_from_payload(
    payload: object,
    collection_keys: Sequence[str],
) -> object:
    if not isinstance(payload, Mapping):
        return payload
    return next(
        (payload[key] for key in collection_keys if payload.get(key)),
        [],
    )
