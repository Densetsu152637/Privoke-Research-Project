"""Strict local byte-verification and serialization for protected key unions.

This adapter accepts only the already prepared, fixed files. It does not fetch
data, inspect development/final selections, infer labels, or emit input keys to
logs. The pure protection builder remains the authority for parsed key closure.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Callable, Mapping, Sequence

from .clean_augmentation_protection import ProtectedKeyUnion, build_full_protected_key_union


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_PREPARED_MANIFEST_SHA256 = "2b8a63b168d72510ce4e61e03748bf5f7858bdc33b41d15f0095780164658e1c"
_EXCLUSION_INDEX_SHA256 = "c0700613a965e26b85a2511c8a721b2f808536f215b8fe6f18f0d3890634fc2d"
_REFERENCE_TRAIN_SHA256 = "da9a1b095587264714c5ae99c8a0f92329a04f6fc237a8ace7d71e837ede429d"
_REFERENCE_TRAIN_BYTES = 1_257_228
_REFERENCE_VALIDATION_SHA256 = "d2d0c538e49f5bbc7a8f85887b9b8cfddb188a5ab9aae55c69ce26ae932be6d1"
_BOOTSTRAP_SHA256 = "75422c421d1a80d0cc3321979fb049f1045f02f334586d6fe62d8832f8a5a7dd"
_TRAINING_DATA_SHA256 = "1bdeeff73310808a3468eb54f6d94a16a008b02e027ba3f9d749602636024f0b"
_PROTOCOL_LF_SHA256 = "3991777aedadc8d50b7395a9ce8ef2aebfec946603229b823f1b6c118a16cbdf"
_RUBRIC_LF_SHA256 = "203f37b4c77789a0f9c0838905954b9e1b76acf4f7906ab7717849e94616fcd7"
_PREPARATION_SOURCE_REVISION = "85c7f475fb8ebd1529254e4135b774d98505ddb1"
_PARTITION_SHA256 = {
    "train": "d762747b88e1c55e0877c64e7f0760efac49670a1c3fb33712dba00e29374c8b",
    "validation": _REFERENCE_VALIDATION_SHA256,
    "nemotron_heldout": "e55595a9b91f160788422a1ca274577b7fc7383380de2be57915f17e06326a44",
    "meddies_heldout": "cfff4d0ddd694b82c3e3399ccebe800f05c785331d3ec1380cef133cc430073a",
}
_ROW_COUNTS = {
    "train": 19_993,
    "validation": 968,
    "nemotron_heldout": 1_000,
    "meddies_heldout": 999,
}
_FILES = {
    "train": "train.jsonl",
    "validation": "validation.jsonl",
    "nemotron_heldout": "nemotron-heldout.jsonl",
    "meddies_heldout": "meddies-heldout.jsonl",
}
_REFERENCE_FILES = {"train": "train.jsonl", "validation": "validation.jsonl"}
_SOURCE_PINS = {
    "nemotron-pii": {
        "repo_id": "nvidia/Nemotron-PII", "revision": "b70ffaf5ff39e079776134c5bf4381f00a9fd1ed",
        "config": "default", "split": "train", "source_rows": 100_000,
        "license": "cc-by-4.0", "path": "data/train-00000-of-00001.parquet",
    },
    "meddies-pii": {
        "repo_id": "Meddies/meddies-pii", "revision": "6a5c8f5441e3b421d983c9741770262365acdd77",
        "config": "english", "split": "train", "source_rows": 47_744,
        "license": "cc-by-nc-4.0", "path": "english/train-00000-of-00001.parquet",
    },
}


@dataclass(frozen=True)
class _Contract:
    """Internal dependency injection seam for synthetic-only tests."""

    prepared_manifest_sha256: str = _PREPARED_MANIFEST_SHA256
    exclusion_index_sha256: str = _EXCLUSION_INDEX_SHA256
    reference_train_sha256: str = _REFERENCE_TRAIN_SHA256
    reference_train_bytes: int = _REFERENCE_TRAIN_BYTES
    reference_validation_sha256: str = _REFERENCE_VALIDATION_SHA256
    bootstrap_sha256: str = _BOOTSTRAP_SHA256
    training_data_sha256: str = _TRAINING_DATA_SHA256
    protocol_lf_sha256: str = _PROTOCOL_LF_SHA256
    rubric_lf_sha256: str = _RUBRIC_LF_SHA256
    partition_sha256: Mapping[str, str] = None  # type: ignore[assignment]
    rows: Mapping[str, int] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.partition_sha256 is None:
            object.__setattr__(self, "partition_sha256", dict(_PARTITION_SHA256))
        if self.rows is None:
            object.__setattr__(self, "rows", dict(_ROW_COUNTS))


_FROZEN = _Contract()


class ProtectionInputError(ValueError):
    """Safe, non-content-bearing input validation error."""


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_lf_sha256(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ProtectionInputError("A pinned text input is not valid UTF-8.") from None
    return _sha256(text.replace("\r\n", "\n").encode("utf-8"))


def _fixed_file(parent: Path, name: str) -> Path:
    if name not in {"manifest.json", "exclusion-index.json", *_FILES.values(), *_REFERENCE_FILES.values()}:
        raise ProtectionInputError("An input file is outside the fixed allowlist.")
    if parent.is_symlink():
        raise ProtectionInputError("An input directory cannot be a symlink.")
    path = parent / name
    if path.is_symlink() or not path.is_file():
        raise ProtectionInputError("A fixed input file is missing or unsafe.")
    try:
        if path.resolve(strict=True).parent != parent.resolve(strict=True):
            raise ProtectionInputError("An input path escaped its approved directory.")
    except OSError:
        raise ProtectionInputError("An input path is unavailable.") from None
    return path


def _read_verified(path: Path, expected_sha256: str) -> bytes:
    raw = path.read_bytes()
    if _sha256(raw) != expected_sha256:
        raise ProtectionInputError("An input byte commitment does not match.")
    return raw


def _json_bytes(raw: bytes, *, jsonl: bool = False) -> object:
    try:
        text = raw.decode("utf-8", errors="strict")
        if jsonl:
            return [json.loads(line) for line in text.splitlines() if line]
        return json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProtectionInputError("A hash-verified input has invalid JSON/UTF-8 encoding.") from None


def _check_manifest(manifest: object, contract: _Contract) -> None:
    if not isinstance(manifest, dict):
        raise ProtectionInputError("Prepared manifest schema is invalid.")
    expected_rows = dict(contract.rows)
    expected_files = dict(_FILES)
    expected_sources = {
        key: {field: pin[field] for field in ("repo_id", "revision", "config", "split", "license")}
        for key, pin in _SOURCE_PINS.items()
    }
    if (
        manifest.get("schema_version") != 1
        or manifest.get("status") != "prepared"
        or manifest.get("partition_files") != expected_files
        or manifest.get("partition_sha256") != dict(contract.partition_sha256)
        or manifest.get("rows") != expected_rows
        or manifest.get("source_revision") != _PREPARATION_SOURCE_REVISION
        or manifest.get("prepared_reference") != {
            "train_sha256": contract.reference_train_sha256,
            "validation_sha256": contract.reference_validation_sha256,
            "train_bytes": contract.reference_train_bytes,
        }
        or manifest.get("exclusion_index_file") != "exclusion-index.json"
        or manifest.get("exclusion_index_sha256") != contract.exclusion_index_sha256
        or manifest.get("bootstrap_source_sha256") != contract.bootstrap_sha256
        or manifest.get("training_text_key_source_sha256") != contract.training_data_sha256
        or manifest.get("protocol_sha256") != contract.protocol_lf_sha256
        or not isinstance(manifest.get("protected_selection_sha256"), str)
        or _SHA256.fullmatch(manifest.get("protected_selection_sha256", "")) is None
    ):
        raise ProtectionInputError("Prepared manifest does not match the frozen input contract.")
    # Pin the two source declarations without depending on mutable audit metadata.
    sources = manifest.get("sources")
    if not isinstance(sources, dict) or set(sources) != set(expected_sources):
        raise ProtectionInputError("Prepared source declarations are invalid.")
    for source, expected in expected_sources.items():
        entry = sources[source]
        if not isinstance(entry, dict):
            raise ProtectionInputError("Prepared source declaration is invalid.")
        for field, value in expected.items():
            if entry.get(field) != value:
                raise ProtectionInputError("Prepared source pin differs from the frozen contract.")
        file = entry.get("file")
        if (not isinstance(file, dict)
                or file.get("row_count") != _SOURCE_PINS[source]["source_rows"]
                or file.get("path") != _SOURCE_PINS[source]["path"]
                or file.get("lfs_sha256") is None
                or _SHA256.fullmatch(file.get("lfs_sha256", "")) is None):
            raise ProtectionInputError("Prepared source row count differs from the frozen contract.")


def _safe_training_samples(source: bytes) -> list[str]:
    """Extract authored sample strings from the constrained source AST only."""
    try:
        tree = ast.parse(source.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, SyntaxError):
        raise ProtectionInputError("The pinned bootstrap source is invalid.") from None
    functions = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and node.name == "training_samples"]
    if len(functions) != 1 or not isinstance(functions[0], ast.FunctionDef):
        raise ProtectionInputError("The pinned bootstrap function is missing or ambiguous.")
    function = functions[0]
    assignments = [node for node in function.body if isinstance(node, ast.Assign)
                   and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                   and node.targets[0].id == "category_phrases"]
    if len(assignments) != 1:
        raise ProtectionInputError("The bootstrap phrase table shape changed.")
    try:
        phrase_map = ast.literal_eval(assignments[0].value)
    except (ValueError, TypeError, SyntaxError):
        raise ProtectionInputError("The bootstrap phrase table is not a literal.") from None
    if not isinstance(phrase_map, dict) or any(
        not isinstance(category, str) or not isinstance(phrases, tuple)
        or any(not isinstance(phrase, str) for phrase in phrases)
        for category, phrases in phrase_map.items()
    ):
        raise ProtectionInputError("The bootstrap phrase table has an unsupported structure.")
    comprehensions = [node for node in ast.walk(function) if isinstance(node, ast.ListComp)
                      and isinstance(node.elt, ast.Tuple) and len(node.elt.elts) == 4]
    if len(comprehensions) != 1:
        raise ProtectionInputError("The bootstrap authored sample expression changed.")
    comp = comprehensions[0]
    if len(comp.generators) != 2 or any(generator.is_async for generator in comp.generators):
        raise ProtectionInputError("The bootstrap authored sample expression is unsupported.")
    first, second = comp.generators
    first_iter_ok = (isinstance(first.iter, ast.Call)
                     and isinstance(first.iter.func, ast.Attribute)
                     and first.iter.func.attr == "items"
                     and isinstance(first.iter.func.value, ast.Name)
                     and first.iter.func.value.id == "category_phrases"
                     and not first.iter.args and not first.iter.keywords)
    first_target_ok = (isinstance(first.target, ast.Tuple) and len(first.target.elts) == 2
                       and all(isinstance(item, ast.Name) for item in first.target.elts)
                       and [item.id for item in first.target.elts] == ["category", "phrases"])
    if not (first_target_ok and first_iter_ok
            and isinstance(second.target, ast.Name) and second.target.id == "phrase"
            and isinstance(second.iter, ast.Name) and second.iter.id == "phrases"):
        raise ProtectionInputError("The bootstrap authored sample expression changed.")
    phrases = [phrase for category in phrase_map for phrase in phrase_map[category]]
    # The source also appends 13 authored examples; extract only literal tuple data.
    extensions = [node for node in ast.walk(function) if isinstance(node, ast.Call)
                  and isinstance(node.func, ast.Attribute) and node.func.attr == "extend"
                  and isinstance(node.func.value, ast.Name) and node.func.value.id == "samples"]
    if len(extensions) != 1:
        raise ProtectionInputError("The bootstrap authored additions changed.")
    try:
        additions = ast.literal_eval(extensions[0].args[0])
    except (IndexError, ValueError, TypeError, SyntaxError):
        raise ProtectionInputError("The bootstrap additions are not literal data.") from None
    if not isinstance(additions, list) or any(not isinstance(row, tuple) or len(row) != 4 for row in additions):
        raise ProtectionInputError("The bootstrap additions have an unsupported structure.")
    result = phrases + [row[0] for row in additions]
    if len(result) != 43 or any(not isinstance(text, str) or not text.strip() for text in result):
        raise ProtectionInputError("The pinned bootstrap sample count is invalid.")
    return result


def _parse_rows(raw: bytes) -> list[Mapping[str, object]]:
    rows = _json_bytes(raw, jsonl=True)
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ProtectionInputError("A prepared JSONL partition is malformed.")
    return rows


def _write_exclusive(path: Path, data: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def build_from_files(
    *,
    reference_dir: Path,
    expansion_dir: Path,
    bootstrap_source: Path,
    protocol_file: Path,
    rubric_file: Path,
    output_dir: Path,
    source_revision: str,
    _contract: _Contract = _FROZEN,
    _union_builder: Callable[..., ProtectedKeyUnion] = build_full_protected_key_union,
    _test_only_allow_output_outside_results: bool = False,
) -> dict[str, object]:
    """Verify all fixed bytes, build the protected union and write its receipt.

    The underscored injection arguments exist only for synthetic unit tests.
    The command-line caller never supplies them and always uses the frozen pins.
    """
    output_dir = Path(output_dir)
    output_created = False
    try:
        if not _GIT_SHA.fullmatch(source_revision):
            raise ProtectionInputError("Execution source revision is malformed.")
        if output_dir.exists() or output_dir.is_symlink():
            raise ProtectionInputError("Refusing an existing or unsafe output directory.")
        if not _test_only_allow_output_outside_results:
            results_root = Path(__file__).resolve().parents[1] / "results"
            if not output_dir.resolve().is_relative_to(results_root.resolve()):
                raise ProtectionInputError("Output must be a fresh child under evaluation/results.")
        output_dir.mkdir(parents=True, exist_ok=False)
        output_created = True

        reference_dir, expansion_dir = Path(reference_dir), Path(expansion_dir)
        reference_train_path = _fixed_file(reference_dir, _REFERENCE_FILES["train"])
        reference_val_path = _fixed_file(reference_dir, _REFERENCE_FILES["validation"])
        manifest_path = _fixed_file(expansion_dir, "manifest.json")
        index_path = _fixed_file(expansion_dir, "exclusion-index.json")
        partition_paths = {name: _fixed_file(expansion_dir, filename) for name, filename in _FILES.items()}
        for path in (bootstrap_source, protocol_file, rubric_file):
            if Path(path).is_symlink() or not Path(path).is_file():
                raise ProtectionInputError("A pinned source file is missing or unsafe.")

        # Read bytes and verify every commitment before decoding or parsing any input.
        manifest_raw = _read_verified(manifest_path, _contract.prepared_manifest_sha256)
        index_raw = _read_verified(index_path, _contract.exclusion_index_sha256)
        reference_train_raw = _read_verified(reference_train_path, _contract.reference_train_sha256)
        reference_val_raw = _read_verified(reference_val_path, _contract.reference_validation_sha256)
        bootstrap_raw = _read_verified(Path(bootstrap_source), _contract.bootstrap_sha256)
        protocol_raw = Path(protocol_file).read_bytes()
        rubric_raw = Path(rubric_file).read_bytes()
        if (_canonical_lf_sha256(protocol_raw) != _contract.protocol_lf_sha256
                or _canonical_lf_sha256(rubric_raw) != _contract.rubric_lf_sha256):
            raise ProtectionInputError("Protocol or rubric content differs from the frozen contract.")
        partition_raw = {
            name: _read_verified(path, _contract.partition_sha256[name]) for name, path in partition_paths.items()
        }
        if len(reference_train_raw) != _contract.reference_train_bytes:
            raise ProtectionInputError("Original training byte length differs from the frozen contract.")
        if not partition_raw["train"].startswith(reference_train_raw):
            raise ProtectionInputError("Expanded training bytes do not preserve the original prefix.")
        training_data_path = Path(__file__).resolve().parents[2] / "shared/python/privoke_model/training_data.py"
        if training_data_path.is_symlink() or _sha256(training_data_path.read_bytes()) != _contract.training_data_sha256:
            raise ProtectionInputError("Shared training normalizer source differs from the frozen contract.")

        manifest = _json_bytes(manifest_raw)
        _check_manifest(manifest, _contract)
        index = _json_bytes(index_raw)
        if (not isinstance(index, dict)
                or manifest.get("protected_selection_sha256") != index.get("sorted_records_sha256")):
            raise ProtectionInputError("Prepared manifest and protected selection commitment disagree.")
        reference_train = _parse_rows(reference_train_raw)
        reference_validation = _parse_rows(reference_val_raw)
        external_train = _parse_rows(partition_raw["train"])
        validation = _parse_rows(partition_raw["validation"])
        nemotron_heldout = _parse_rows(partition_raw["nemotron_heldout"])
        meddies_heldout = _parse_rows(partition_raw["meddies_heldout"])
        if validation != reference_validation:
            raise ProtectionInputError("Prepared validation rows differ from the byte-verified reference.")
        bootstrap_texts = _safe_training_samples(bootstrap_raw)
        if len(external_train) != _contract.rows["train"] or len(validation) != _contract.rows["validation"]:
            raise ProtectionInputError("Prepared partition cardinality differs from the frozen contract.")
        if len(nemotron_heldout) != _contract.rows["nemotron_heldout"] or len(meddies_heldout) != _contract.rows["meddies_heldout"]:
            raise ProtectionInputError("Held-out partition cardinality differs from the frozen contract.")

        commitments = {
            "prepared_manifest_sha256": _contract.prepared_manifest_sha256,
            "exclusion_index_sha256": _contract.exclusion_index_sha256,
            "reference_train_sha256": _contract.reference_train_sha256,
            "reference_validation_sha256": _contract.reference_validation_sha256,
            "bootstrap_source_sha256": _contract.bootstrap_sha256,
            "partition_sha256": dict(_contract.partition_sha256),
        }
        union = _union_builder(
            approved_index=index,
            reference_train=reference_train,
            reference_validation=reference_validation,
            bootstrap_texts=bootstrap_texts,
            external_train=external_train,
            nemotron_heldout=nemotron_heldout,
            meddies_heldout=meddies_heldout,
            verified_commitments=commitments,
        )
        keys = {
            "ids": sorted(union.keys.ids),
            "groups": sorted(union.keys.groups),
            "exact_text_sha256": sorted(union.keys.exact_text_sha256),
            "normalized_texts": sorted(union.keys.normalized_texts),
        }
        artifact = {
            "schema_version": 1,
            "kind": "privoke-clean-protected-union",
            "union_sha256": union.union_sha256,
            "coverage_counts": dict(union.coverage_counts),
            "verified_commitments": commitments,
            "keys": keys,
        }
        artifact_raw = _canonical_json(artifact)
        input_hashes = {
            "prepared_manifest": _contract.prepared_manifest_sha256,
            "exclusion_index": _contract.exclusion_index_sha256,
            "reference_train": _contract.reference_train_sha256,
            "reference_validation": _contract.reference_validation_sha256,
            "bootstrap_source": _contract.bootstrap_sha256,
            "protocol_canonical_lf": _contract.protocol_lf_sha256,
            "rubric_canonical_lf": _contract.rubric_lf_sha256,
            "training_data_source": _contract.training_data_sha256,
            **{f"partition_{name}": digest for name, digest in _contract.partition_sha256.items()},
        }
        _write_exclusive(output_dir / "protected-union.json", artifact_raw)
        receipt = {
            "schema_version": 1,
            "status": "protected_union_built",
            "source_revision": source_revision,
            "prepared_source_revision": _PREPARATION_SOURCE_REVISION,
            "artifact_file": "protected-union.json",
            "artifact_sha256": _sha256(artifact_raw),
            "union_sha256": union.union_sha256,
            "coverage_counts": dict(union.coverage_counts),
            "input_source_hashes": input_hashes,
            "helper_source_hashes": {
                "protection_io_sha256": _sha256(Path(__file__).read_bytes()),
                "protection_core_sha256": _sha256(Path(__file__).with_name("clean_augmentation_protection.py").read_bytes()),
                "grouping_core_sha256": _sha256(Path(__file__).with_name("clean_augmentation_grouping.py").read_bytes()),
                "training_data_sha256": _contract.training_data_sha256,
            },
            "packages": {"python": ".".join(map(str, sys.version_info[:3]))},
            "limitations": [
                "The protected union excludes known study groups and training texts only; it does not validate labels.",
                "The caller independently verifies its input files and this artifact before use.",
            ],
        }
        receipt_raw = _canonical_json(receipt)
        _write_exclusive(output_dir / "manifest.json", receipt_raw)
        return receipt
    except Exception as exc:
        if output_created:
            failure = {"schema_version": 1, "status": "failed", "source_revision": source_revision,
                       "failure_type": type(exc).__name__}
            try:
                _write_exclusive(output_dir / "failure.json", _canonical_json(failure))
            except OSError:
                pass
        if isinstance(exc, ProtectionInputError):
            raise
        raise ProtectionInputError("Protected union generation failed; see the count-free failure receipt.") from None


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Build the frozen local protected-key union.")
    parser.add_argument("--prepared-reference", type=Path, required=True)
    parser.add_argument("--prepared-expansion", type=Path, required=True)
    parser.add_argument("--bootstrap-source", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--rubric", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args(argv)
    try:
        receipt = build_from_files(
            reference_dir=args.prepared_reference,
            expansion_dir=args.prepared_expansion,
            bootstrap_source=args.bootstrap_source,
            protocol_file=args.protocol,
            rubric_file=args.rubric,
            output_dir=args.output,
            source_revision=args.source_revision,
        )
    except ProtectionInputError as exc:
        print(json.dumps({"status": "failed", "reason": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({
        "status": receipt["status"],
        "artifact_sha256": receipt["artifact_sha256"],
        "union_sha256": receipt["union_sha256"],
        "coverage_counts": receipt["coverage_counts"],
    }, sort_keys=True))
    return 0
