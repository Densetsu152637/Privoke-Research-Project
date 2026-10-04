"""Isolated train-only fitter for the fixed S1 and six scratch study arms.

This module has no evaluation, fixture, validation, test, serving or catalogue
reader. Input hashes bind bytes; externally trusted receipts are recorded as
claims and are not independently proof of human labels or allocation truth.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import stat
import sys
import time
import warnings
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Callable
import importlib
from importlib import metadata as importlib_metadata

import numpy as np
import torch

from privoke_model.artifact import artifact_checksum, validate_artifact
from privoke_model.fingerprint import parameter_fingerprint
from privoke_model.presence import SparsePresenceModel
from privoke_model.scratch_presence import (
    SCRATCH_PROFILES,
    scratch_presence_tensor_shapes,
    scratch_presence_trainable_names,
    validate_scratch_artifact,
)
from privoke_model.training_data import training_text_key
from privoke_eval import in_house_presence_training as scratch_mechanics
from privoke_eval.in_house_study_contract import (
    ARM_KEYS,
    ARMS,
    PIN_ITEMS,
    epoch_batches,
    permutation_sha256,
    training_budget,
)
from src.detection.preprocessing import normalize_text
from src.transformer_encoder import EncoderConfig, NumpyTransformerEncoder, TOKEN_PATTERN


TRAINING_ROWS = 7832
ORIGINAL_ROWS = 3832
ADDED_ROWS = 4000
BATCH_SIZE = 16
EPOCHS = 5
THREADS = 4
MAX_WALL_SECONDS = 7200
S1_THRESHOLD = 0.5
S1_C = 1.0
TRAINING_SEED = 12102026
MAX_TRAIN_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_EXPECTED_BYTES = 64 * 1024
INPUTS_KIND = "privoke-in-house-fit-inputs-v1"
VIEW_KIND = "privoke-in-house-training-view-v1"
RUN_KIND = "privoke-in-house-study-fit-run-v1"
_HASH = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_IMAGE_ID = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")
_ROW_KEYS = frozenset(("id", "group_id", "text", "text_key", "expected_has_pii"))
_INPUT_KEYS = frozenset((
    "schema_version", "kind", "arm_key", "programme_sha256",
    "programme_input_raw_sha256", "prepared_manifest_raw_sha256",
    "training_view_manifest_raw_sha256", "train_raw_sha256",
    "original_train_raw_sha256", "train_prefix_bytes",
    "trainer_contract_sha256", "allocation_receipt_sha256",
    "reviewed_labels_receipt_sha256", "initialization_fingerprints",
    "source_revision", "actual_training_image_id", "dependency_lock_sha256",
))
_VIEW_KEYS = frozenset((
    "schema_version", "kind", "source_revision", "programme_sha256",
    "programme_input_raw_sha256", "prepared_manifest_raw_sha256",
    "train_raw_sha256", "original_train_raw_sha256", "train_prefix_bytes",
    "trainer_contract_sha256", "allocation_receipt_sha256",
    "reviewed_labels_receipt_sha256", "row_count", "original_row_count",
    "addition_row_count", "initialization_fingerprints",
))
_SOURCE_FILES = (
    "evaluation/privoke_eval/in_house_presence_training.py",
    "evaluation/privoke_eval/in_house_study_contract.py",
    "evaluation/privoke_eval/presence_training.py",
    "models/generate_baseline.py",
    "shared/python/privoke_model/scratch_presence.py",
    "shared/python/privoke_model/presence.py",
    "shared/python/privoke_model/artifact.py",
    "shared/python/privoke_model/fingerprint.py",
    "shared/python/privoke_model/training_data.py",
    "extension/client-runtime/src/model.py",
    "extension/client-runtime/src/transformer_encoder.py",
    "extension/client-runtime/src/detection/preprocessing.py",
)
_IMPORTED_SOURCES = {
    "privoke_eval.in_house_presence_training": "evaluation/privoke_eval/in_house_presence_training.py",
    "privoke_eval.in_house_study_contract": "evaluation/privoke_eval/in_house_study_contract.py",
    "generate_baseline": "models/generate_baseline.py",
    "privoke_model.scratch_presence": "shared/python/privoke_model/scratch_presence.py",
    "privoke_model.artifact": "shared/python/privoke_model/artifact.py",
    "privoke_model.fingerprint": "shared/python/privoke_model/fingerprint.py",
    "privoke_model.training_data": "shared/python/privoke_model/training_data.py",
    "src.model": "extension/client-runtime/src/model.py",
    "src.transformer_encoder": "extension/client-runtime/src/transformer_encoder.py",
    "src.detection.preprocessing": "extension/client-runtime/src/detection/preprocessing.py",
}
_PARITY_TEXTS = (
    "", "Synthetic fullwidth Ａｌｉｃｅ 🧪", "x",
    "synthetic truncation probe " * 180,
)


class StudyFitError(ValueError):
    """Sanitized input, fit or output failure; never includes row contents."""


def _fail(message: str = "Study fit inputs or execution are invalid.") -> None:
    raise StudyFitError(message)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _package_version(name: str) -> str | None:
    try:
        return importlib_metadata.version(name)
    except importlib_metadata.PackageNotFoundError:
        return None


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _reject_constant(_value: str):
    _fail("Non-finite JSON values are forbidden.")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("Duplicate JSON object fields are forbidden.")
        result[key] = value
    return result


def _json_object(raw: bytes) -> dict:
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"),
                           object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant)
    except StudyFitError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        _fail("Input JSON is invalid UTF-8 or malformed.")
    if type(value) is not dict:
        _fail("Input JSON must be an object.")
    return value


def _require_hash(value: object) -> str:
    if type(value) is not str or not _HASH.fullmatch(value):
        _fail("A required SHA-256 commitment is invalid.")
    return value


def _require_revision(value: object) -> str:
    if type(value) is not str or not _REVISION.fullmatch(value):
        _fail("Source revision is invalid.")
    return value


def _safe_text(value: object, *, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not value.strip()):
        _fail("Training row fields have invalid types or lengths.")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        _fail("Training row contains invalid Unicode.")
    if len(encoded) > 2 * 1024 * 1024 or any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        _fail("Training row fields exceed the bounded Unicode contract.")
    return value


def _reject_reparse_path(path: Path, *, include_final: bool = True) -> None:
    """Reject symlinks and Windows reparse points in a path's existing prefix."""
    absolute = path.absolute()
    parts = absolute.parents
    chain = list(reversed(parts)) + [absolute]
    if not include_final:
        chain = chain[:-1]
    for candidate in chain:
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            _fail("A filesystem path cannot be inspected safely.")
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        attributes = getattr(info, "st_file_attributes", 0)
        if stat.S_ISLNK(info.st_mode) or (reparse_flag and attributes & reparse_flag):
            _fail("Symlink or reparse paths are not accepted.")


@dataclass(frozen=True)
class FitInputs:
    arm_key: str
    programme_sha256: str
    programme_input_raw_sha256: str
    prepared_manifest_raw_sha256: str
    training_view_manifest_raw_sha256: str
    train_raw_sha256: str
    original_train_raw_sha256: str
    train_prefix_bytes: int
    trainer_contract_sha256: str
    allocation_receipt_sha256: str
    reviewed_labels_receipt_sha256: str
    initialization_fingerprints: Mapping[str, str]
    source_revision: str
    actual_training_image_id: str
    dependency_lock_sha256: str

    @classmethod
    def from_bytes(cls, raw: bytes, *, pinned_sha256: str,
                   expected_arm: str, expected_revision: str) -> "FitInputs":
        if len(raw) > MAX_EXPECTED_BYTES or _sha256(raw) != _require_hash(pinned_sha256):
            _fail("Externally pinned expected-input bytes do not match.")
        value = _json_object(raw)
        if (set(value) != _INPUT_KEYS or type(value.get("schema_version")) is not int
                or value.get("schema_version") != 1 or value.get("kind") != INPUTS_KIND):
            _fail("Expected-input schema is not the closed study-fit contract.")
        arm = value["arm_key"]
        allowed = set(ARM_KEYS) - {"S0"}
        if type(arm) is not str or arm not in allowed or arm != expected_arm:
            _fail("The requested arm is not the exact externally pinned fit arm.")
        revision = _require_revision(value["source_revision"])
        if revision != _require_revision(expected_revision):
            _fail("Requested source revision differs from the pinned fit inputs.")
        hashes = {}
        for key in (
            "programme_sha256", "programme_input_raw_sha256",
            "prepared_manifest_raw_sha256", "training_view_manifest_raw_sha256",
            "train_raw_sha256", "original_train_raw_sha256",
            "trainer_contract_sha256", "allocation_receipt_sha256",
            "reviewed_labels_receipt_sha256", "dependency_lock_sha256",
        ):
            hashes[key] = _require_hash(value[key])
        prefix_bytes = value["train_prefix_bytes"]
        if type(prefix_bytes) is not int or not 0 < prefix_bytes <= MAX_TRAIN_BYTES:
            _fail("Original training prefix length is invalid.")
        image_id = value["actual_training_image_id"]
        if type(image_id) is not str or not _IMAGE_ID.fullmatch(image_id):
            _fail("Training image identity is invalid.")
        fingerprints = value["initialization_fingerprints"]
        if (type(fingerprints) is not dict or set(fingerprints) != set(SCRATCH_PROFILES)
                or any(type(name) is not str for name in fingerprints)):
            _fail("Initialization fingerprints must name all fixed profiles.")
        frozen_fingerprints = MappingProxyType({
            name: _require_hash(fingerprints[name]) for name in sorted(SCRATCH_PROFILES)
        })
        return cls(
            arm_key=arm,
            source_revision=revision,
            actual_training_image_id=image_id,
            train_prefix_bytes=prefix_bytes,
            initialization_fingerprints=frozen_fingerprints,
            **hashes,
        )


@dataclass(frozen=True)
class TrainingRow:
    row_id: str
    group_id: str
    text: str
    text_key: str
    target: bool


@dataclass(frozen=True)
class TrainingRows:
    rows: tuple[TrainingRow, ...]
    raw_sha256: str
    manifest_raw_sha256: str
    original_prefix_sha256: str
    original_count: int
    added_count: int
    positive_count: int
    absent_count: int
    manifest: Mapping[str, object]


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def imported_source_inventory() -> tuple[tuple[str, str], ...]:
    """Hash the fixed mechanics source bundle and require imports from this tree."""
    root = _repository_root()
    import sys
    entries = []
    for relative in _SOURCE_FILES:
        path = root / Path(relative)
        try:
            if path.is_symlink() or not path.is_file():
                _fail("A pinned trainer source file is missing or redirected.")
            raw = path.read_bytes()
        except OSError:
            _fail("A pinned trainer source file cannot be read.")
        entries.append((relative, _sha256(raw)))
    for module_name, relative in _IMPORTED_SOURCES.items():
        module = sys.modules.get(module_name)
        if module is None or not getattr(module, "__file__", None):
            _fail("A required trainer dependency was not imported from the pinned tree.")
        try:
            actual = Path(module.__file__).resolve(strict=True)
            expected = (root / Path(relative)).resolve(strict=True)
        except OSError:
            _fail("An imported trainer dependency cannot be located safely.")
        if actual != expected:
            _fail("A trainer dependency was imported from an unexpected source tree.")
    return tuple(entries)


def trainer_contract_sha256() -> str:
    """Canonical source-bundle hash; root separately attests the image/revision."""
    return _sha256(_canonical_json([
        {"path": path, "sha256": digest}
        for path, digest in imported_source_inventory()
    ]))


def _verify_source(expected: FitInputs) -> tuple[tuple[str, str], ...]:
    inventory = source_file_inventory()
    actual = _sha256(_canonical_json([
        {"path": path, "sha256": digest} for path, digest in inventory
    ]))
    if actual != expected.trainer_contract_sha256:
        _fail("Imported trainer source bundle differs from the externally pinned digest.")
    _verify_imported_sources()
    return inventory


def source_file_inventory() -> tuple[tuple[str, str], ...]:
    """Read the fixed source bundle; no training JSON is decoded in this phase."""
    root = _repository_root()
    entries = []
    for relative in _SOURCE_FILES:
        path = root / Path(relative)
        try:
            _reject_reparse_path(path)
            if not path.is_file():
                _fail("A pinned trainer source file is missing.")
            raw = path.read_bytes()
        except OSError:
            _fail("A pinned trainer source file cannot be read.")
        entries.append((relative, _sha256(raw)))
    return tuple(entries)


def _verify_imported_sources() -> None:
    root = _repository_root()
    import sys
    for module_name, relative in _IMPORTED_SOURCES.items():
        module = sys.modules.get(module_name)
        if module is None or not getattr(module, "__file__", None):
            _fail("A required trainer dependency was not imported from the pinned tree.")
        try:
            actual = Path(module.__file__).resolve(strict=True)
            expected = (root / Path(relative)).resolve(strict=True)
        except OSError:
            _fail("An imported trainer dependency cannot be located safely.")
        if actual != expected:
            _fail("A trainer dependency was imported from an unexpected source tree.")


def parse_expected_inputs(raw: bytes, *, pinned_sha256: str,
                          expected_arm: str, expected_revision: str) -> FitInputs:
    """Hash-authenticate closed operator inputs before opening the train view."""
    return FitInputs.from_bytes(raw, pinned_sha256=pinned_sha256,
                                expected_arm=expected_arm,
                                expected_revision=expected_revision)


def _prepare_arm_dependencies(arm_key: str) -> None:
    if arm_key != "S1":
        return
    try:
        module = importlib.import_module("privoke_eval.presence_training")
    except (ImportError, ModuleNotFoundError):
        _fail("S1 requires its separately pinned scikit-learn training dependency.")
    expected = (_repository_root() / "evaluation/privoke_eval/presence_training.py").resolve()
    if Path(module.__file__).resolve() != expected:
        _fail("S1 sparse trainer was imported from an unexpected source tree.")
    presence_module = importlib.import_module("privoke_model.presence")
    expected_presence = (_repository_root() / "shared/python/privoke_model/presence.py").resolve()
    if Path(presence_module.__file__).resolve() != expected_presence:
        _fail("S1 shared sparse runtime was imported from an unexpected source tree.")


def _view_manifest(raw: bytes, expected: FitInputs) -> dict:
    if len(raw) > MAX_MANIFEST_BYTES or _sha256(raw) != expected.training_view_manifest_raw_sha256:
        _fail("Training-view manifest bytes do not match the external pin.")
    value = _json_object(raw)
    if (set(value) != _VIEW_KEYS or type(value.get("schema_version")) is not int
            or value.get("schema_version") != 1 or value.get("kind") != VIEW_KIND):
        _fail("Training-view manifest schema is not the frozen closed contract.")
    hashes = {
        "source_revision": expected.source_revision,
        "programme_sha256": expected.programme_sha256,
        "programme_input_raw_sha256": expected.programme_input_raw_sha256,
        "prepared_manifest_raw_sha256": expected.prepared_manifest_raw_sha256,
        "train_raw_sha256": expected.train_raw_sha256,
        "original_train_raw_sha256": expected.original_train_raw_sha256,
        "trainer_contract_sha256": expected.trainer_contract_sha256,
        "allocation_receipt_sha256": expected.allocation_receipt_sha256,
        "reviewed_labels_receipt_sha256": expected.reviewed_labels_receipt_sha256,
    }
    for key, pinned in hashes.items():
        if value.get(key) != pinned:
            _fail("Training-view provenance differs from externally pinned inputs.")
    if (type(value.get("train_prefix_bytes")) is not int
            or value.get("train_prefix_bytes") != expected.train_prefix_bytes):
        _fail("Training-view original prefix length differs from its external pin.")
    if any(type(value.get(name)) is not int for name in
           ("row_count", "original_row_count", "addition_row_count")) or (
            value.get("row_count") != TRAINING_ROWS
            or value.get("original_row_count") != ORIGINAL_ROWS
            or value.get("addition_row_count") != ADDED_ROWS):
        _fail("Training-view row counts do not match the fixed study allocation.")
    fingerprints = value.get("initialization_fingerprints")
    if type(fingerprints) is not dict or fingerprints != dict(expected.initialization_fingerprints):
        _fail("Training-view initialization commitments differ from the programme.")
    return value


def _parse_rows(train_bytes: bytes, expected_count: int = TRAINING_ROWS) -> tuple[TrainingRow, ...]:
    if not train_bytes or not train_bytes.endswith(b"\n"):
        _fail("Training JSONL must be nonempty and newline-terminated.")
    result = []
    seen_ids = set()
    seen_text_keys = set()
    try:
        for raw_line in train_bytes.splitlines(keepends=True):
            if not raw_line.endswith(b"\n") or raw_line in (b"\n", b"\r\n"):
                _fail("Training JSONL contains a blank or unterminated row.")
            value = _json_object(raw_line[:-1].removesuffix(b"\r"))
            if set(value) != _ROW_KEYS:
                _fail("Training row does not match the closed five-field schema.")
            row_id = _safe_text(value["id"])
            group_id = _safe_text(value["group_id"])
            text = _safe_text(value["text"], allow_empty=True)
            text_key = _safe_text(value["text_key"], allow_empty=True)
            if type(value["expected_has_pii"]) is not bool:
                _fail("Training targets must be explicit booleans.")
            if row_id in seen_ids:
                _fail("Training contains a duplicate row ID.")
            seen_ids.add(row_id)
            if text_key != training_text_key(text):
                _fail("Training normalized-text key does not match its source text.")
            if text_key in seen_text_keys:
                _fail("Training contains duplicate normalized text keys.")
            seen_text_keys.add(text_key)
            result.append(TrainingRow(row_id, group_id, text, text_key, value["expected_has_pii"]))
            if len(result) > expected_count:
                _fail("Training view exceeds the fixed row count.")
    except StudyFitError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        _fail("Training JSONL contains an invalid row.")
    if len(result) != expected_count:
        _fail("Training view does not contain the required exact row count.")
    return tuple(result)


def load_verified_training(train_bytes: bytes, manifest_bytes: bytes,
                           expected: FitInputs) -> TrainingRows:
    """Verify source/input commitments and exact original prefix before training."""
    if not isinstance(expected, FitInputs):
        _fail("Externally pinned fit inputs are required.")
    _verify_source(expected)
    if type(train_bytes) is not bytes or len(train_bytes) > MAX_TRAIN_BYTES:
        _fail("Training view exceeds its bounded byte contract.")
    if _sha256(train_bytes) != expected.train_raw_sha256:
        _fail("Training-view bytes do not match the external pin.")
    view = _view_manifest(manifest_bytes, expected)
    prefix = train_bytes[:expected.train_prefix_bytes]
    if len(prefix) != expected.train_prefix_bytes or _sha256(prefix) != expected.original_train_raw_sha256:
        _fail("Original training prefix bytes differ from the pinned source.")
    if not prefix.endswith(b"\n"):
        _fail("Original training prefix must end on an exact JSONL row boundary.")
    rows = _parse_rows(train_bytes)
    prefix_rows = _parse_rows(prefix, ORIGINAL_ROWS)
    if len(prefix_rows) != ORIGINAL_ROWS:
        _fail("Original training prefix does not contain exactly 3,832 rows.")
    for index, original in enumerate(prefix_rows):
        if rows[index] != original:
            _fail("Original training row order or content changed in the augmented view.")
    original_groups = {row.group_id for row in prefix_rows}
    added_rows = rows[ORIGINAL_ROWS:]
    if original_groups.intersection(row.group_id for row in added_rows):
        _fail("Added training rows overlap an original training component.")
    original_text_keys = {row.text_key for row in prefix_rows}
    if original_text_keys.intersection(row.text_key for row in added_rows):
        _fail("Added training rows duplicate original normalized text.")
    positives = sum(row.target for row in rows)
    absents = len(rows) - positives
    if positives == 0 or absents == 0:
        _fail("Training view must contain both explicit binary classes.")
    return TrainingRows(
        rows=rows, raw_sha256=expected.train_raw_sha256,
        manifest_raw_sha256=expected.training_view_manifest_raw_sha256,
        original_prefix_sha256=expected.original_train_raw_sha256,
        original_count=ORIGINAL_ROWS, added_count=ADDED_ROWS,
        positive_count=positives, absent_count=absents,
        manifest=MappingProxyType(dict(view)),
    )


def _sha_rows(rows: Sequence[TrainingRow]) -> str:
    return _sha256(_canonical_json([
        {"row_id": row.row_id, "group_id": row.group_id, "target": row.target}
        for row in rows
    ]))


def _check_scratch_export(trainer, artifact: Mapping[str, object]) -> dict[str, object]:
    """Reload strict float32 artifact and check an independent synthetic panel."""
    validate_scratch_artifact(dict(artifact))
    validate_artifact(dict(artifact))
    canonical = _canonical_json(artifact) + b"\n"
    decoded = _json_object(canonical[:-1])
    validate_scratch_artifact(decoded)
    validate_artifact(decoded)
    cfg = decoded["config"]
    arrays = {
        name: np.asarray(tensor["values"], dtype=np.float32).reshape(tensor["shape"])
        for name, tensor in decoded["parameters"].items()
    }
    expected_shapes = scratch_presence_tensor_shapes(cfg)
    if set(arrays) != set(expected_shapes) or any(arrays[n].shape != expected_shapes[n] for n in arrays):
        _fail("Scratch artifact tensor shapes differ from the frozen profile.")
    expected_trainable = set(scratch_presence_trainable_names(cfg))
    for name, tensor in decoded["parameters"].items():
        if tensor["trainable"] != (name in expected_trainable):
            _fail("Scratch artifact trainability differs from its fixed mode.")
    fp = parameter_fingerprint(
        {name: tensor["values"] for name, tensor in decoded["parameters"].items()},
        {name: tensor["shape"] for name, tensor in decoded["parameters"].items()},
    )
    if trainer.config != cfg or int(decoded["metadata"]["training_steps"]) != trainer.successful_steps:
        _fail("Scratch artifact metadata does not match the completed trainer.")
    trained_arrays = trainer.export_parameters()
    expected_fp = parameter_fingerprint(
        {name: array.ravel().tolist() for name, array in trained_arrays.items()},
        {name: array.shape for name, array in trained_arrays.items()},
    )
    if fp != _artifact_fingerprint(decoded) or fp != expected_fp:
        _fail("Scratch transported float32 parameter fingerprint changed on reload.")

    encoder_cfg = EncoderConfig.from_mapping(cfg)
    encoder_arrays = {name: value for name, value in arrays.items() if not name.startswith("head.")}
    encoder = NumpyTransformerEncoder(encoder_cfg, encoder_arrays)
    texts = _PARITY_TEXTS
    ids, mask = trainer.tensor_batch(texts)
    trainer_logits = trainer.logits(ids, mask).detach().cpu().numpy()
    weight = arrays["head.presence.weight"]
    bias = arrays["head.presence.bias"]
    parity_max_abs = 0.0
    for index, text in enumerate(texts):
        pooled = encoder.encode(normalize_text(text))
        logit = (pooled @ weight + bias).reshape(-1)
        expected_logit = float(np.clip(logit[0], -30.0, 30.0))
        actual_logit = float(trainer_logits[index])
        if not math.isclose(actual_logit, expected_logit, rel_tol=2e-5, abs_tol=2e-6):
            _fail("Scratch encoder export failed the frozen synthetic parity panel.")
        parity_max_abs = max(parity_max_abs, abs(actual_logit - expected_logit))
    return {
        "artifact_checksum": decoded["checksum"],
        "parameter_fingerprint": fp,
        "parity_probe_rows": len(texts),
        "parity_max_abs_logit_error": parity_max_abs,
        "parity_atol": 2e-6,
        "parity_rtol": 2e-5,
        "profile": cfg["profile"],
        "training_mode": cfg["training_mode"],
        "stored_threshold": cfg["threshold"],
    }


def _artifact_fingerprint(artifact: Mapping[str, object]) -> str:
    return parameter_fingerprint(
        {name: tensor["values"] for name, tensor in artifact["parameters"].items()},
        {name: tensor["shape"] for name, tensor in artifact["parameters"].items()},
    )


def _row_stats(rows: Sequence[TrainingRow]) -> dict[str, int]:
    return {
        "row_count": len(rows),
        "positive_count": sum(row.target for row in rows),
        "absent_count": sum(not row.target for row in rows),
        "distinct_groups": len({row.group_id for row in rows}),
    }


def _token_stats(trainer, texts: Sequence[str]) -> dict[str, int]:
    _, mask = trainer.tensor_batch(texts)
    encoded = [int(value) for value in mask.sum(dim=1).tolist()]
    raw_counts = [len(TOKEN_PATTERN.findall(normalize_text(text).lower())) for text in texts]
    return {
        "encoded_tokens_including_cls": sum(encoded),
        "content_tokens_before_truncation": sum(raw_counts),
        "truncated_rows": sum(count > trainer.config["max_tokens"] - 1 for count in raw_counts),
    }


def _train_scratch_arm(rows: Sequence[TrainingRow], *, arm_key: str,
                       expected: FitInputs,
                       expected_initialization_sha256: str,
                       deadline_monotonic: float,
                       checkpoint_callback: Callable[[int, object, Mapping], Mapping]) -> list[dict]:
    definition = next((arm for arm in ARMS if arm.key == arm_key), None)
    if definition is None or definition.key not in set(ARM_KEYS) - {"S0", "S1"}:
        _fail("Requested arm is not one of the six fixed scratch arms.")
    budget = training_budget(TRAINING_ROWS)
    if (budget.epochs != EPOCHS or budget.steps_per_epoch != 490
            or budget.total_steps != 2450):
        _fail("Frozen scratch training budget has changed.")
    head, full = scratch_mechanics.create_paired_trainers(definition.profile)
    trainer = head if definition.training_mode == "head_only" else full
    if trainer is head:
        del full
    else:
        del head
    if trainer.initialization_sha256 != expected_initialization_sha256:
        _fail("Scratch arm initialization differs from the externally pinned profile.")
    torch.set_num_threads(THREADS)
    if torch.get_num_threads() != THREADS:
        _fail("Scratch trainer did not obtain the fixed CPU thread count.")
    records = []
    texts = tuple(row.text for row in rows)
    targets = tuple(row.target for row in rows)
    for epoch in range(1, EPOCHS + 1):
        started = time.monotonic()
        batches = epoch_batches(definition.profile, epoch, TRAINING_ROWS)
        if sum(len(batch) for batch in batches) != TRAINING_ROWS or len(batches) != 490:
            _fail("Frozen epoch permutation did not include every training row.")
        loss_weighted = 0.0
        gradient_norm_max = 0.0
        token_totals = {"encoded_tokens_including_cls": 0,
                        "content_tokens_before_truncation": 0, "truncated_rows": 0}
        examples = steps = 0
        for batch in batches:
            if time.monotonic() >= deadline_monotonic:
                _fail("Fixed two-hour training job budget was exhausted.")
            batch_texts = [texts[index] for index in batch]
            batch_targets = [targets[index] for index in batch]
            token_stats = _token_stats(trainer, batch_texts)
            for key, value in token_stats.items():
                token_totals[key] += value
            metrics = trainer.step(batch_texts, batch_targets)
            loss_weighted += metrics.loss * len(batch)
            gradient_norm_max = max(gradient_norm_max, metrics.gradient_norm_before_clip)
            examples += len(batch)
            steps += 1
        if steps != 490 or examples != TRAINING_ROWS or trainer.successful_steps != epoch * 490:
            _fail("Scratch epoch did not complete its immutable full batch schedule.")
        artifact = trainer.build_artifact(
            source_revision=expected.source_revision,
            study_plan_sha256=dict(PIN_ITEMS)["plan"],
            prepared_manifest_sha256=expected.prepared_manifest_raw_sha256,
            trainer_contract_sha256=expected.trainer_contract_sha256,
            checkpoint_epoch=epoch,
            generated_at_unix=int(time.time()),
        )
        if time.monotonic() >= deadline_monotonic:
            _fail("Fixed two-hour training job budget was exhausted before checkpoint export.")
        records.append(dict(checkpoint_callback(epoch, trainer, {
            "artifact": artifact,
            "mean_loss": loss_weighted / examples,
            "max_gradient_norm_before_clip": gradient_norm_max,
            "steps": steps,
            "examples": examples,
            "permutation_sha256": permutation_sha256(definition.profile, epoch, TRAINING_ROWS),
            **token_totals,
            "elapsed_seconds": time.monotonic() - started,
        })))
    if len(records) != EPOCHS:
        _fail("Scratch arm did not produce all five full-epoch checkpoints.")
    return records


def _fit_s1_model(rows: Sequence[TrainingRow], expected: FitInputs) -> tuple[dict, dict]:
    """Private train-only mechanics seam; production passes only its fixed 7,832 rows."""
    if expected.arm_key != "S1":
        _fail("S1 fitter received an incompatible arm.")
    try:
        from sklearn.exceptions import ConvergenceWarning
        from sklearn.linear_model import LogisticRegression
        from threadpoolctl import threadpool_limits
        from privoke_eval.presence_training import (
            artifact_identity as sparse_artifact_identity,
            build_artifact as build_sparse_artifact,
            make_vectorizer,
        )
    except (ImportError, ModuleNotFoundError):
        _fail("S1 requires its separately pinned scikit-learn training dependency.")
    vectorizer = make_vectorizer("balanced")
    train_docs = [training_text_key(row.text) for row in rows]
    estimator = LogisticRegression(
        C=S1_C, class_weight="balanced", solver="lbfgs", max_iter=1000,
        tol=1e-4, random_state=TRAINING_SEED,
    )
    with threadpool_limits(limits=THREADS), warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        matrix = vectorizer.fit_transform(train_docs)
        estimator.fit(matrix, np.asarray([int(row.target) for row in rows], dtype=np.int8))
    warning_records = [
        {"category": item.category.__name__, "message": str(item.message)}
        for item in caught
    ]
    if any(issubclass(item.category, ConvergenceWarning) for item in caught):
        _fail("S1 fixed C1 logistic fit did not converge; no rescue fit is permitted.")
    if matrix.shape[0] != len(rows) or matrix.shape[1] <= 0:
        _fail("S1 vectorizer did not produce the fixed nonempty train matrix.")
    metadata = {
        "training_strategy": "train_only_sparse_tfidf_logistic_c1",
        "training_revision": "0",
        "training_seed": str(TRAINING_SEED),
        "selected_C": "1.0",
        "source_revision": expected.source_revision,
        "study_plan_sha256": dict(PIN_ITEMS)["plan"],
        "prepared_manifest_sha256": expected.prepared_manifest_raw_sha256,
        "programme_sha256": expected.programme_sha256,
        "allocation_receipt_sha256": expected.allocation_receipt_sha256,
        "reviewed_labels_receipt_sha256": expected.reviewed_labels_receipt_sha256,
        "trainer_contract_sha256": expected.trainer_contract_sha256,
        "training_image_id": expected.actual_training_image_id,
        "dependency_lock_sha256": expected.dependency_lock_sha256,
        "training_rows_sha256": expected.train_raw_sha256,
    }
    artifact = build_sparse_artifact(
        vectorizer, estimator, "balanced", S1_THRESHOLD, metadata,
    )
    validate_artifact(artifact)
    if artifact["config"]["threshold"] != S1_THRESHOLD:
        _fail("S1 stored threshold differs from the frozen 0.5 decision.")
    model = SparsePresenceModel.from_artifact(artifact)
    # Exercise only a fixed public synthetic parity panel. No real-row
    # probabilities or validation threshold selection are computed here.
    for text in _PARITY_TEXTS:
        probability = model.predict_probability(text)
        if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
            _fail("S1 artifact failed synthetic finite-probability validation.")
    identity = sparse_artifact_identity(artifact)
    return artifact, {
        "artifact_checksum": artifact["checksum"],
        "parameter_fingerprint": identity["parameter_fingerprint"],
        "profile": "balanced", "selected_C": S1_C,
        "stored_threshold": S1_THRESHOLD,
        "feature_counts": {name: len(artifact["config"]["branches"][name]["features"])
                           for name in ("word", "char")},
        "parameter_value_count": sum(len(tensor["values"]) for tensor in artifact["parameters"].values()),
        "warning_categories": [item["category"] for item in warning_records],
        "converged": True,
    }


def _fit_s1(rows: Sequence[TrainingRow], expected: FitInputs) -> tuple[dict, dict]:
    if len(rows) != TRAINING_ROWS:
        _fail("Production S1 fit requires the immutable 7,832-row training view.")
    return _fit_s1_model(rows, expected)


def _read_nofollow(path: Path, limit: int) -> bytes:
    _reject_reparse_path(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                _fail("Input must be a bounded regular file.")
            chunks = []
            total = 0
            while True:
                chunk = os.read(fd, min(1024 * 1024, limit + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > limit:
                    _fail("Input exceeds the bounded file size.")
            after = os.fstat(fd)
            try:
                path_after = path.lstat()
            except OSError:
                _fail("Input pathname changed during capture.")
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
            ) or total != after.st_size or stat.S_ISLNK(path_after.st_mode) or (
                path_after.st_dev, path_after.st_ino
            ) != (after.st_dev, after.st_ino):
                _fail("Input file changed during capture.")
            return b"".join(chunks)
        finally:
            os.close(fd)
    except StudyFitError:
        raise
    except OSError:
        _fail("Input file could not be opened safely.")


class _FreshOutput:
    """Exclusive private directory and safe fixed-name artifact writer."""
    def __init__(self, path: Path):
        _reject_reparse_path(path, include_final=False)
        try:
            path.lstat()
        except FileNotFoundError:
            pass
        else:
            _fail("Output must be a fresh nonexistent directory.")
        parent = path.parent
        _reject_reparse_path(parent)
        if not parent.is_dir():
            _fail("Output parent must be an existing nonsymlink directory.")
        try:
            path.mkdir(mode=0o700, parents=False, exist_ok=False)
            if os.name != "nt":
                os.chmod(path, 0o700)
            self.path = path
            self.fd = (None if os.name == "nt" else os.open(
                path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            ))
            info = path.lstat() if self.fd is None else os.fstat(self.fd)
            if not stat.S_ISDIR(info.st_mode):
                _fail("Fresh output is not a directory.")
            self._dir_identity = (info.st_dev, info.st_ino)
            self._manifest_identity = None
            self._dir_fd_supported = (self.fd is not None and os.open in os.supports_dir_fd
                                      and os.replace in os.supports_dir_fd)
        except StudyFitError:
            raise
        except OSError:
            _fail("Fresh output directory could not be created safely.")

    def _verify_dir(self):
        try:
            path_info = self.path.lstat()
        except OSError:
            _fail("Output directory path changed during the run.")
        info = path_info if self.fd is None else os.fstat(self.fd)
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(path_info.st_mode)
                or (info.st_dev, info.st_ino) != self._dir_identity
                or (path_info.st_dev, path_info.st_ino) != self._dir_identity):
            _fail("Output directory path changed during the run.")

    def write_exclusive(self, name: str, raw: bytes) -> str:
        if name != Path(name).name or not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", name):
            _fail("Output filename is outside the fixed artifact namespace.")
        self._verify_dir()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            if self._dir_fd_supported:
                fd = os.open(name, flags, 0o600, dir_fd=self.fd)
            else:
                fd = os.open(self.path / name, flags, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError:
            _fail("Exclusive output artifact write failed.")
        return _sha256(raw)

    def write_manifest(self, value: Mapping[str, object]) -> str:
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                         allow_nan=False).encode("utf-8") + b"\n"
        self._verify_dir()
        temp = f".run-manifest.{time.time_ns()}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            if self._dir_fd_supported:
                fd = os.open(temp, flags, 0o600, dir_fd=self.fd)
                temp_source, target = temp, "run-manifest.json"
            else:
                fd = os.open(self.path / temp, flags, 0o600)
                temp_source, target = self.path / temp, self.path / "run-manifest.json"
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            if self._manifest_identity is None:
                if self._dir_fd_supported:
                    os.replace(temp_source, target, src_dir_fd=self.fd, dst_dir_fd=self.fd)
                else:
                    os.replace(temp_source, target)
            else:
                existing = (os.stat("run-manifest.json", dir_fd=self.fd, follow_symlinks=False)
                            if self._dir_fd_supported else (self.path / "run-manifest.json").lstat())
                if (existing.st_dev, existing.st_ino) != self._manifest_identity:
                    _fail("Run manifest identity changed during the fit.")
                if self._dir_fd_supported:
                    os.replace(temp_source, target, src_dir_fd=self.fd, dst_dir_fd=self.fd)
                else:
                    os.replace(temp_source, target)
            current = (os.stat("run-manifest.json", dir_fd=self.fd, follow_symlinks=False)
                       if self._dir_fd_supported else (self.path / "run-manifest.json").lstat())
            if not stat.S_ISREG(current.st_mode):
                _fail("Run manifest is not a regular file.")
            self._manifest_identity = (current.st_dev, current.st_ino)
            if os.name != "nt":
                os.fsync(self.fd)
        except StudyFitError:
            raise
        except OSError:
            _fail("Run manifest could not be atomically committed.")
        return _sha256(raw)

    def close(self):
        if getattr(self, "fd", None) is not None:
            os.close(self.fd)
            self.fd = None


def _artifact_bytes(artifact: Mapping[str, object]) -> bytes:
    return json.dumps(artifact, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"


def run_fit(*, arm_key: str, train_file: Path, training_manifest: Path,
            expected_inputs_file: Path, expected_inputs_sha256: str,
            output: Path, source_revision: str) -> dict[str, object]:
    """Execute one fixed train-only arm into a new private output directory."""
    if type(arm_key) is not str or arm_key not in set(ARM_KEYS) - {"S0"}:
        _fail("Only S1 or a fixed scratch arm can be fitted.")
    started_monotonic = time.monotonic()
    deadline_monotonic = started_monotonic + MAX_WALL_SECONDS
    output_store = _FreshOutput(output)
    manifest: dict[str, object] = {
        "schema_version": 1, "kind": RUN_KIND, "status": "running",
        "phase": "expected_inputs", "arm_key": arm_key,
        "source_revision": source_revision, "started_at_unix": int(time.time()),
        "research_data_rows_read": 0, "test_scored": False,
        "validation_read": False, "checkpoint_records": [],
        "artifact_files_written": [],
        "external_truth_note": "Receipt digests are pinned claims; fitter does not adjudicate human labels or protection truth.",
    }
    output_store.write_manifest(manifest)
    phase = "expected_inputs"
    try:
        expected_bytes = _read_nofollow(expected_inputs_file, MAX_EXPECTED_BYTES)
        expected = parse_expected_inputs(
            expected_bytes, pinned_sha256=expected_inputs_sha256,
            expected_arm=arm_key, expected_revision=source_revision,
        )
        phase = "source_attestation"
        source_inventory = _verify_source(expected)
        _prepare_arm_dependencies(arm_key)
        if expected.source_revision != source_revision:
            _fail("Source revision differs from externally pinned fit inputs.")
        manifest.update({
            "phase": "input_capture", "inputs_sha256": {
                "expected_inputs_raw": _sha256(expected_bytes),
                "training_view_manifest_raw": expected.training_view_manifest_raw_sha256,
                "train_raw": expected.train_raw_sha256,
                "original_train_prefix_raw": expected.original_train_raw_sha256,
                "prepared_manifest_raw": expected.prepared_manifest_raw_sha256,
                "programme_input_raw": expected.programme_input_raw_sha256,
                "programme": expected.programme_sha256,
                "allocation_receipt": expected.allocation_receipt_sha256,
                "reviewed_labels_receipt": expected.reviewed_labels_receipt_sha256,
                "trainer_contract": expected.trainer_contract_sha256,
                "dependency_lock": expected.dependency_lock_sha256,
            },
            "source_files": [{"path": path, "sha256": digest} for path, digest in source_inventory],
            "actual_training_image_id": expected.actual_training_image_id,
            "environment": {
                "python": sys.version.split()[0], "platform": platform.platform(),
                "numpy": np.__version__, "torch": torch.__version__,
                "scikit_learn": _package_version("scikit-learn"),
                "scipy": _package_version("scipy"),
                "threads": THREADS,
            },
        })
        output_store.write_manifest(manifest)
        phase = "training_input_verification"
        train_bytes = _read_nofollow(train_file, MAX_TRAIN_BYTES)
        manifest_bytes = _read_nofollow(training_manifest, MAX_MANIFEST_BYTES)
        verified = load_verified_training(train_bytes, manifest_bytes, expected)
        rows = verified.rows
        manifest.update({
            "phase": "fitting", "research_data_rows_read": len(rows),
            "training_view_manifest_raw_sha256": verified.manifest_raw_sha256,
            "training_rows": _row_stats(rows),
            "prefix_row_count": verified.original_count,
            "addition_row_count": verified.added_count,
        })
        output_store.write_manifest(manifest)

        if arm_key == "S1":
            phase = "s1_train_only_fit"
            artifact, diagnostics = _fit_s1(rows, expected)
            if time.monotonic() >= deadline_monotonic:
                _fail("Fixed two-hour training job budget was exhausted before checkpoint export.")
            artifact_raw = _artifact_bytes(artifact)
            artifact_hash = output_store.write_exclusive("checkpoint-epoch-00.json", artifact_raw)
            manifest["artifact_files_written"].append({
                "artifact_file": "checkpoint-epoch-00.json",
                "artifact_sha256": artifact_hash,
                "validation_status": "pending",
            })
            output_store.write_manifest(manifest)
            loaded = _json_object(artifact_raw[:-1])
            validate_artifact(loaded)
            if loaded != artifact:
                _fail("S1 artifact changed during canonical serialization.")
            manifest["artifact_files_written"][0]["validation_status"] = "validated"
            identity = {
                "model_id": loaded["model_id"],
                "model_version": loaded["version"],
                "artifact_checksum": loaded["checksum"],
                "parameter_fingerprint": diagnostics["parameter_fingerprint"],
            }
            checkpoint = {
                "epoch": 0, "steps": 0, "examples": TRAINING_ROWS,
                "fit_calls": 1, "initialization_sha256": None,
                "permutation_sha256": None,
                "artifact_file": "checkpoint-epoch-00.json",
                "artifact_sha256": artifact_hash,
                "artifact_checksum": loaded["checksum"],
                "parameter_fingerprint": identity["parameter_fingerprint"],
                "identity": {
                    "model_id": identity["model_id"],
                    "version": identity["model_version"],
                    "artifact_sha256": artifact_hash,
                    "artifact_checksum": identity["artifact_checksum"],
                    "parameter_fingerprint": identity["parameter_fingerprint"],
                },
                "s1_export": diagnostics,
            }
            checkpoints = [checkpoint]
            selection = {"selected_epoch": 0, "stored_threshold": S1_THRESHOLD,
                         "selected_C": S1_C, "validation_used": False}
        else:
            phase = "scratch_fit"
            arm = next(item for item in ARMS if item.key == arm_key)
            profile_init = expected.initialization_fingerprints[arm.profile]

            def save_checkpoint(epoch: int, trainer, stats: Mapping[str, object]) -> Mapping[str, object]:
                artifact = stats["artifact"]
                artifact_raw = _artifact_bytes(artifact)
                name = f"checkpoint-epoch-{epoch:02d}.json"
                raw_hash = output_store.write_exclusive(name, artifact_raw)
                artifact_ledger = manifest["artifact_files_written"]
                artifact_ledger.append({
                    "artifact_file": name, "artifact_sha256": raw_hash,
                    "validation_status": "pending",
                })
                output_store.write_manifest(manifest)
                decoded = _json_object(artifact_raw[:-1])
                verify = _check_scratch_export(trainer, decoded)
                artifact_ledger[-1]["validation_status"] = "validated"
                identity = {
                    "model_id": decoded["model_id"], "version": decoded["version"],
                    "artifact_sha256": raw_hash, "artifact_checksum": decoded["checksum"],
                    "parameter_fingerprint": verify["parameter_fingerprint"],
                }
                record = {
                    "epoch": epoch, "steps": stats["steps"], "examples": stats["examples"],
                    "permutation_sha256": stats["permutation_sha256"],
                    "initialization_sha256": trainer.initialization_sha256,
                    "mean_loss": stats["mean_loss"],
                    "max_gradient_norm_before_clip": stats["max_gradient_norm_before_clip"],
                    "encoded_tokens_including_cls": stats["encoded_tokens_including_cls"],
                    "content_tokens_before_truncation": stats["content_tokens_before_truncation"],
                    "truncated_rows": stats["truncated_rows"],
                    "elapsed_seconds": stats["elapsed_seconds"],
                    "artifact_file": name, "artifact_sha256": raw_hash,
                    "artifact_checksum": decoded["checksum"],
                    "parameter_fingerprint": verify["parameter_fingerprint"],
                    "identity": identity, "export_parity": verify,
                }
                checkpoints.append(record)
                manifest["checkpoint_records"] = list(checkpoints)
                manifest["phase"] = f"checkpoint_{epoch}"
                output_store.write_manifest(manifest)
                return record

            checkpoints = []
            _train_scratch_arm(
                rows, arm_key=arm_key, expected=expected,
                expected_initialization_sha256=profile_init,
                deadline_monotonic=deadline_monotonic,
                checkpoint_callback=save_checkpoint,
            )
            if len(checkpoints) != EPOCHS or [c["epoch"] for c in checkpoints] != [1, 2, 3, 4, 5]:
                _fail("Scratch checkpoint inventory is not the exact five-epoch set.")
            selection = {"selected_epoch": None, "stored_threshold": 0.5,
                         "validation_used": False,
                         "note": "Checkpoint selection is reserved for the separate frozen full-pipeline validation consumer."}
        manifest.update({
            "status": "complete", "phase": "complete",
            "checkpoint_records": checkpoints, "checkpoint_count": len(checkpoints),
            "selection": selection, "finished_at_unix": int(time.time()),
            "training_image_identity_source": "externally supplied FitInputs; root supervisor must independently verify actual running image",
            "study_result": False,
        })
        output_store.write_manifest(manifest)
        return manifest
    except Exception as exc:
        manifest.update({
            "status": "failed", "phase": phase,
            "failure": {"error_type": type(exc).__name__,
                        "reason": "fit failed; raw exception text and training rows are withheld"},
            "finished_at_unix": int(time.time()),
            "checkpoint_records": manifest.get("checkpoint_records", []),
            "study_result": False,
        })
        try:
            output_store.write_manifest(manifest)
        except Exception:
            pass
        raise StudyFitError(f"Study fit failed in phase {phase} ({type(exc).__name__}).") from None
    finally:
        output_store.close()


__all__ = [
    "ADDED_ROWS", "BATCH_SIZE", "EPOCHS", "FitInputs", "ORIGINAL_ROWS",
    "RUN_KIND", "StudyFitError", "TRAINING_ROWS", "TrainingRow",
    "TrainingRows", "imported_source_inventory", "load_verified_training",
    "parse_expected_inputs", "run_fit", "trainer_contract_sha256",
]
