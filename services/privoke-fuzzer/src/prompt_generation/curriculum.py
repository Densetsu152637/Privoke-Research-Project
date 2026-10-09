"""Immutable synthetic curriculum and durable, idempotent batch allocation.

Held-out families never enter training or replay. The cursor advances when a
request is reserved, including candidates rejected by the publication gate.
Retries reuse that reservation; this explores new batches without weakening
the gate or training on evaluation outcomes.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from contextlib import closing
from pathlib import Path

from privoke_model.training_data import training_text_key
from training.io import training_example_from_mapping

ROLES = ("grammar", "teacher", "evolved")
CATEGORIES = {"HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL",
              "SEXUAL", "CHILD", "LOCATION", "IDENTITY", "THIRD_PARTY"}


@dataclass(frozen=True)
class Curriculum:
    curriculum_id: str
    manifest_sha256: str
    splits: dict[str, tuple[dict, ...]]


@dataclass(frozen=True)
class CurriculumBatch:
    examples: tuple
    replay: tuple
    heldout: tuple
    audit: dict[str, str]


def load_curriculum(manifest_path: str) -> Curriculum:
    """Validate content hashes, explicit targets and separation before sampling."""
    path = Path(manifest_path).resolve(strict=True)
    payload = path.read_bytes()
    manifest = json.loads(payload)
    if manifest.get("schema_version") != 1 or not manifest.get("curriculum_id"):
        raise ValueError("Curriculum requires schema_version=1 and curriculum_id.")
    splits = {}
    seen_ids, seen_texts, split_groups = set(), set(), set()
    for split in ("train", "replay", "heldout"):
        entry = manifest["splits"][split]
        relative = Path(entry["path"])
        target = (path.parent / relative).resolve(strict=True)
        if relative.is_absolute() or not target.is_relative_to(path.parent):
            raise ValueError("Curriculum split paths must remain inside its directory.")
        data = target.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError(f"Curriculum {split} hash does not match its manifest.")
        rows = tuple(json.loads(line) for line in data.splitlines() if line.strip())
        if not rows or len(rows) > 100_000:
            raise ValueError("Curriculum split must contain between 1 and 100000 rows.")
        groups = set()
        for row in rows:
            label, metadata = row.get("classification", {}), row.get("metadata", {})
            if (label.get("sensitivity") not in {"S0", "S1", "S2", "S3"}
                    or label.get("visibility") not in {"P0", "P1", "P2", "P3", "P4", "PU"}
                    or not isinstance(label.get("categories"), list)
                    or not set(label["categories"]).issubset(CATEGORIES)):
                raise ValueError("Curriculum rows require explicit valid contextual targets.")
            if (metadata.get("label_status") != "assistant_provisional"
                    or not metadata.get("group_id") or not isinstance(metadata.get("parent_id"), str)
                    or not metadata.get("generator")):
                raise ValueError("Curriculum rows require provisional provenance and parent families.")
            if split == "train" and metadata.get("curriculum_role") not in ROLES:
                raise ValueError("Training rows require grammar, teacher or evolved roles.")
            if split == "replay" and metadata.get("curriculum_role") != "replay":
                raise ValueError("Replay rows require the replay role.")
            row_id = row.get("id")
            example = _example(row)
            if not isinstance(row_id, str) or not row_id or row_id in seen_ids:
                raise ValueError("Curriculum IDs must be unique non-empty strings.")
            key = training_text_key(example.text)
            if key in seen_texts:
                raise ValueError("Curriculum canonical texts must be globally unique.")
            seen_ids.add(row_id)
            seen_texts.add(key)
            groups.add(metadata["group_id"])
        if groups & split_groups:
            raise ValueError("Curriculum parent families overlap between splits.")
        split_groups.update(groups)
        if {_sensitive(row) for row in rows} != {False, True}:
            raise ValueError("Every curriculum split must contain both classes.")
        splits[split] = rows
    for split, rows in splits.items():
        by_id = {row["id"]: row for row in rows}
        for row in rows:
            parent = row["metadata"]["parent_id"]
            if parent and (parent not in by_id or by_id[parent]["metadata"]["group_id"] != row["metadata"]["group_id"]):
                raise ValueError("Curriculum descendants must reference a parent in the same split and family.")
    if len(splits["heldout"]) != 16 or len(splits["replay"]) < 64:
        raise ValueError("Curriculum requires exactly 16 fixed gate rows and at least 64 replay anchors.")
    return Curriculum(str(manifest["curriculum_id"]), hashlib.sha256(payload).hexdigest(), splits)


def request_fingerprint(request, curriculum: Curriculum, settings: dict | None = None) -> str:
    return hashlib.sha256(b"synthetic-curriculum:v1\0" +
                          curriculum.manifest_sha256.encode() + b"\0" +
                          json.dumps(settings or {}, sort_keys=True, separators=(",", ":")).encode() + b"\0" +
                          request.SerializeToString(deterministic=True)).hexdigest()


def _sensitive(row: dict) -> bool:
    label = row["classification"]
    return label["sensitivity"] != "S0" or bool(label["categories"])


def _family_order(rows: list[dict]) -> list[dict]:
    """Interleave parent families before revisiting their lexical descendants."""
    families = {}
    for row in sorted(rows, key=lambda item: item["id"]):
        families.setdefault(row["metadata"]["group_id"], []).append(row)
    return [family[index] for index in range(max(map(len, families.values()), default=0))
            for family in families.values() if index < len(family)]


def reserve_batch(curriculum: Curriculum, state_path: str, request,
                  count: int, replay_fraction: float = 0.25, *,
                  fingerprint: str | None = None, model_id: str | None = None) -> CurriculumBatch:
    """Reserve a balanced batch once; persist IDs rather than prompt text."""
    stage = request.metadata.get("curriculum_stage", "all")
    if stage not in (*ROLES, "all"):
        raise ValueError("curriculum_stage must be all, grammar, teacher or evolved.")
    hard_ids = json.loads(request.metadata.get("curriculum_hard_ids", "[]"))
    if (not isinstance(hard_ids, list) or len(hard_ids) > 8
            or any(not isinstance(item, str) for item in hard_ids)
            or len(set(hard_ids)) != len(hard_ids)):
        raise ValueError("curriculum_hard_ids must contain at most eight distinct training IDs.")
    train_rows = [row for row in curriculum.splits["train"]
                  if stage == "all" or row["metadata"]["curriculum_role"] == stage]
    eligible = {row["id"]: row for row in train_rows}
    if any(row_id not in eligible for row_id in hard_ids):
        raise ValueError("Hard-example mining may only select eligible TRAIN rows.")
    replay_count = int(count * replay_fraction)
    new_count = count - replay_count
    if replay_count < 2 or new_count < max(2, len(hard_ids)):
        raise ValueError("Curriculum batches must include both new and replay classes.")
    fingerprint = fingerprint or request_fingerprint(request, curriculum, {"count": count, "replay_fraction": replay_fraction})
    model_id = model_id or request.model_id
    identity = json.dumps([request.source_id, model_id, request.request_id])
    state = Path(state_path)
    state.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(state, timeout=30)) as database, database:
        database.execute("CREATE TABLE IF NOT EXISTS batches (identity TEXT PRIMARY KEY, fingerprint TEXT, allocation TEXT)")
        database.execute("CREATE TABLE IF NOT EXISTS cursors (identity TEXT PRIMARY KEY, position INTEGER)")
        database.execute("BEGIN IMMEDIATE")
        prior = database.execute("SELECT fingerprint, allocation FROM batches WHERE identity=?", (identity,)).fetchone()
        if prior:
            if prior[0] != fingerprint:
                raise ValueError("request_id belongs to a different curriculum request.")
            allocation = json.loads(prior[1])
        else:
            chosen = list(hard_ids)
            roles = ROLES if stage == "all" else (stage,)
            strata = [(role, sensitive) for role in roles for sensitive in (False, True)]
            # Balance both labels and roles, including any hard examples already selected.
            targets = {key: new_count // len(strata) for key in strata}
            for key in strata[:new_count % len(strata)]:
                targets[key] += 1
            for role, sensitive in strata:
                pool = _family_order([row for row in train_rows
                                      if row["metadata"]["curriculum_role"] == role
                                      and _sensitive(row) == sensitive])
                required = targets[(role, sensitive)] - sum(
                    eligible[item]["metadata"]["curriculum_role"] == role
                    and _sensitive(eligible[item]) == sensitive for item in chosen)
                if required < 0 or len(pool) < targets[(role, sensitive)]:
                    raise ValueError("Curriculum pool or hard examples cannot satisfy balanced quotas.")
                _take(database, curriculum, model_id, f"{role}:{sensitive}", pool, required, chosen)
            replay = []
            for sensitive, required in ((False, replay_count // 2), (True, replay_count - replay_count // 2)):
                pool = _family_order([row for row in curriculum.splits["replay"] if _sensitive(row) == sensitive])
                if len(pool) < required:
                    raise ValueError("Replay pool cannot satisfy this batch size.")
                _take(database, curriculum, model_id, f"replay:{sensitive}", pool, required, replay)
            allocation = {"train": chosen, "replay": replay}
            database.execute("INSERT INTO batches VALUES (?, ?, ?)", (identity, fingerprint, json.dumps(allocation)))
    by_id = {row["id"]: row for rows in curriculum.splits.values() for row in rows}
    examples = tuple(_example(by_id[item]) for item in allocation["train"])
    replay = tuple(_example(by_id[item]) for item in allocation["replay"])
    gate = tuple(_example(row) for row in curriculum.splits["heldout"])
    audit = {"curriculum_id": curriculum.curriculum_id,
             "curriculum_manifest_sha256": curriculum.manifest_sha256,
             "curriculum_stage": stage, "curriculum_new_count": str(len(examples)),
             "curriculum_replay_count": str(len(replay)), "curriculum_hard_count": str(len(hard_ids)),
             "curriculum_train_ids_sha256": _digest(allocation["train"]),
             "curriculum_gate_ids_sha256": _digest([row["id"] for row in curriculum.splits["heldout"]])}
    return CurriculumBatch(examples, replay, gate, audit)


def _take(database, curriculum, model_id, stratum, pool, count, chosen):
    key = json.dumps([curriculum.manifest_sha256, model_id, stratum])
    stored = database.execute("SELECT position FROM cursors WHERE identity=?", (key,)).fetchone()
    position = stored[0] if stored else 0
    for _ in range(count):
        while pool[position % len(pool)]["id"] in chosen:
            position += 1
        chosen.append(pool[position % len(pool)]["id"])
        position += 1
    database.execute("INSERT OR REPLACE INTO cursors VALUES (?, ?)", (key, position))


def _digest(ids):
    return hashlib.sha256(json.dumps(ids, separators=(",", ":")).encode()).hexdigest()


def _example(row):
    # Only the validated contextual target is authoritative. Packed or top-level
    # legacy fields cannot silently override it; replay weighting belongs to the trainer.
    return training_example_from_mapping({"text": row["text"],
                                          "classification": row["classification"],
                                          "metadata": row["metadata"]})
