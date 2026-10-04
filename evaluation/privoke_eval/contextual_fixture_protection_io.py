"""Private, snapshot-based I/O adapter for the contextual fixture add-on.

The adapter captures only the reviewed fixture, rubric, review metadata and
the small set of pinned helper source files. It never reads prompt-level rows
into logs, scans source corpora, or performs graph closure.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Mapping

from privoke_eval.contextual_fixture_protection import (
    ADDON_FILENAME,
    DEFAULT_POLICY,
    FixtureProtectionError,
    FixtureProtectionPolicy,
    build_fixture_addon,
)


_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_INPUT_PATHS = {
    "fixture": Path("evaluation/datasets/contextual-cascade-regressions.jsonl"),
    "rubric": Path("paper/research/contextual-cascade-rubric.md"),
    "review": Path("paper/research/contextual-cascade-fixture-review.json"),
}
_HELPER_PATHS = {
    "grouping": Path("evaluation/privoke_eval/clean_augmentation_grouping.py"),
    "normalizer": Path("shared/python/privoke_model/training_data.py"),
    "fixture_validator": Path("evaluation/privoke_eval/contextual_fixture_protection.py"),
    "adapter": Path("evaluation/privoke_eval/contextual_fixture_protection_io.py"),
}
_INPUT_LIMITS = {
    "fixture": 1_048_576,
    "rubric": 262_144,
    "review": 65_536,
}
_CODE_LIMIT = 1_048_576
_OUTPUT_ARTIFACT = ADDON_FILENAME
_OUTPUT_PURE_RECEIPT = "contextual-fixture-addon-receipt.json"
_OUTPUT_MANIFEST = "manifest.json"


class FixtureProtectionIOError(ValueError):
    """Sanitized I/O boundary failure without paths or captured values."""


@dataclass(frozen=True)
class FixtureProtectionIOResult:
    output_directory: Path
    artifact_sha256: str
    pure_receipt_sha256: str
    io_receipt_sha256: str
    coverage_counts: Mapping[str, int]


@dataclass(frozen=True)
class _Captured:
    data: bytes
    sha256: str
    signature: tuple[int, int, int, int, int]


def _fail() -> None:
    raise FixtureProtectionIOError("Fixture add-on I/O validation failed.")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                          allow_nan=False).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeError):
        _fail()


def _is_reparse(info: os.stat_result) -> bool:
    reparse_bit = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(info, "st_file_attributes", 0) & reparse_bit)


def _signature(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (int(info.st_dev), int(info.st_ino), int(info.st_size),
            int(info.st_mtime_ns), int(info.st_ctime_ns))


def _check_chain(root: Path, target: Path, *, directory: bool = False) -> None:
    try:
        root_info = os.lstat(root)
        if not stat.S_ISDIR(root_info.st_mode) or _is_reparse(root_info):
            _fail()
        relative = target.relative_to(root)
        current = root
        parts = relative.parts
        for index, part in enumerate(parts):
            current = current / part
            info = os.lstat(current)
            final = index == len(parts) - 1
            if _is_reparse(info) or (not final and not stat.S_ISDIR(info.st_mode)):
                _fail()
            if final:
                expected_dir = directory
                if expected_dir and not stat.S_ISDIR(info.st_mode):
                    _fail()
                if not expected_dir and not stat.S_ISREG(info.st_mode):
                    _fail()
    except (OSError, ValueError, RuntimeError):
        _fail()


def _check_absolute_directory_chain(path: Path) -> None:
    """Reject symlink/reparse components before resolving any caller path."""
    try:
        if not path.is_absolute() or ".." in path.parts:
            _fail()
        current = Path(path.anchor)
        for part in path.parts[1:]:
            current = current / part
            info = os.lstat(current)
            if _is_reparse(info) or not stat.S_ISDIR(info.st_mode):
                _fail()
    except FixtureProtectionIOError:
        raise
    except (OSError, ValueError, RuntimeError):
        _fail()


def _bounded_capture(root: Path, relative: Path, limit: int) -> _Captured:
    path = root / relative
    _check_chain(root, path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        _fail()
    flags |= nofollow
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or _is_reparse(before):
            _fail()
        path_before = os.lstat(path)
        if _signature(path_before) != _signature(before):
            _fail()
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        path_after = os.lstat(path)
        if _signature(after) != _signature(before) or _signature(path_after) != _signature(before):
            _fail()
        if len(data) > limit:
            _fail()
        return _Captured(data=data, sha256=_sha(data), signature=_signature(after))
    except FixtureProtectionIOError:
        raise
    except (OSError, OverflowError, ValueError):
        _fail()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _canonical_lf(data: bytes) -> bytes:
    try:
        text = data.decode("utf-8", errors="strict")
        return text.replace("\r\n", "\n").encode("utf-8")
    except UnicodeError:
        _fail()


def _validate_digest_map(value: object, names: set[str]) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != names:
        _fail()
    result = dict(value)
    if any(not isinstance(item, str) or not _HEX64.fullmatch(item) for item in result.values()):
        _fail()
    return result


def _validate_bindings(source_revision: str, expected_raw_hashes: Mapping[str, str],
                       helper_hashes: Mapping[str, str], adapter_hash: str) -> tuple[dict[str, str], dict[str, str]]:
    if not isinstance(source_revision, str) or not _HEX40.fullmatch(source_revision):
        _fail()
    raw = _validate_digest_map(expected_raw_hashes, set(_INPUT_PATHS))
    helpers = _validate_digest_map(helper_hashes, set(_HELPER_PATHS) - {"adapter"})
    if not isinstance(adapter_hash, str) or not _HEX64.fullmatch(adapter_hash):
        _fail()
    return raw, helpers


def _capture_set(root: Path, expected_raw: Mapping[str, str]) -> dict[str, _Captured]:
    captured: dict[str, _Captured] = {}
    for name, relative in _INPUT_PATHS.items():
        captured[name] = _bounded_capture(root, relative, _INPUT_LIMITS[name])
    if any(captured[name].sha256 != expected_raw[name] for name in _INPUT_PATHS):
        _fail()
    return captured


def _code_hashes(root: Path) -> tuple[dict[str, str], str]:
    hashes: dict[str, str] = {}
    for name, relative in _HELPER_PATHS.items():
        item = _bounded_capture(root, relative, _CODE_LIMIT)
        hashes[name] = item.sha256
    adapter_hash = hashes.pop("adapter")
    return hashes, adapter_hash


def _verify_snapshot(root: Path, captured: Mapping[str, _Captured]) -> None:
    for name, original in captured.items():
        current = _bounded_capture(root, _INPUT_PATHS[name], _INPUT_LIMITS[name])
        if current.sha256 != original.sha256 or current.signature != original.signature:
            _fail()


def _verify_code(root: Path, expected_helpers: Mapping[str, str], expected_adapter: str) -> None:
    helpers, adapter = _code_hashes(root)
    if helpers != dict(expected_helpers) or adapter != expected_adapter:
        _fail()


def _safe_output_directory(project_root: Path, output: Path) -> Path:
    try:
        _check_absolute_directory_chain(project_root)
        root = project_root / "evaluation" / "results"
        _check_absolute_directory_chain(root)
        if not output.is_absolute() or ".." in output.parts:
            _fail()
        normalized_output = Path(os.path.abspath(output))
        if normalized_output != output:
            _fail()
        parent = normalized_output.parent
        if parent != root or output.name in {"", ".", ".."}:
            _fail()
        try:
            os.lstat(normalized_output)
        except FileNotFoundError:
            pass
        else:
            _fail()
        return root
    except FixtureProtectionIOError:
        raise
    except (OSError, ValueError, RuntimeError):
        _fail()


def _create_private_output(output: Path) -> None:
    descriptor = -1
    try:
        os.mkdir(output, 0o700)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(output, flags)
        os.fchmod(descriptor, 0o700)
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or _is_reparse(info):
            _fail()
    except FixtureProtectionIOError:
        raise
    except OSError:
        _fail()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _exclusive_write(path: Path, payload: bytes) -> str:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                _fail()
            offset += written
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or _is_reparse(info):
            _fail()
        return _sha(payload)
    except FixtureProtectionIOError:
        raise
    except OSError:
        _fail()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _io_receipt(source_revision: str, captured: Mapping[str, _Captured], canonical: Mapping[str, bytes],
                helpers: Mapping[str, str], adapter_hash: str, artifact_bytes: bytes,
                pure_receipt_bytes: bytes, coverage_counts: Mapping[str, int]) -> bytes:
    return _canonical_json({
        "schema_version": 1,
        "kind": "privoke-contextual-fixture-addon-io-receipt-v1",
        "status": "fixture_protection_addon_io_built",
        "source_revision": source_revision,
        "input_files": {
            name: {
                "path": relative.as_posix(),
                "raw_sha256": captured[name].sha256,
                "canonical_lf_sha256": _sha(canonical[name]),
            }
            for name, relative in _INPUT_PATHS.items()
        },
        "helper_source_hashes": dict(helpers),
        "adapter_source_sha256": adapter_hash,
        "artifact_file": _OUTPUT_ARTIFACT,
        "artifact_sha256": _sha(artifact_bytes),
        "pure_receipt_file": _OUTPUT_PURE_RECEIPT,
        "pure_receipt_sha256": _sha(pure_receipt_bytes),
        "coverage_counts": dict(coverage_counts),
        "private_output_mode": {"directory": "0700", "files": "0600", "verified": True,
                                "platform": "posix"},
    })


def _build_fixture_protection_addon_io(project_root: Path, output_directory: Path, *,
                                       source_revision: str,
                                       expected_input_raw_sha256: Mapping[str, str],
                                       expected_helper_source_sha256: Mapping[str, str],
                                       expected_adapter_source_sha256: str,
                                       policy: FixtureProtectionPolicy) -> FixtureProtectionIOResult:
    """Internal policy-injectable boundary for synthetic tests; no CLI exposes it."""
    if os.name == "nt":
        _fail()  # Windows ACL verification is an operator/root gate, not chmod evidence.
    try:
        root = Path(project_root)
        output = Path(output_directory)
        if not root.is_absolute() or not output.is_absolute():
            _fail()
        _check_absolute_directory_chain(root)
        root = Path(os.path.abspath(root))
        raw_hashes, helper_hashes = _validate_bindings(
            source_revision, expected_input_raw_sha256, expected_helper_source_sha256,
            expected_adapter_source_sha256)
        _safe_output_directory(root, output)
        _verify_code(root, helper_hashes, expected_adapter_source_sha256)

        # Capture all three original files before the pure validator/builder runs.
        captured = _capture_set(root, raw_hashes)
        canonical = {name: _canonical_lf(captured[name].data) for name in ("fixture", "rubric")}
        canonical_sha = {name: _sha(data) for name, data in canonical.items()}
        if (canonical_sha["fixture"] != policy.fixture_sha256 or
                canonical_sha["rubric"] != policy.rubric_sha256 or
                captured["review"].sha256 != policy.review_sha256 or
                raw_hashes["review"] != policy.review_sha256):
            _fail()

        _verify_snapshot(root, captured)
        _verify_code(root, helper_hashes, expected_adapter_source_sha256)
        artifact_bytes, pure_receipt_bytes = build_fixture_addon(
            canonical["fixture"], canonical["rubric"], captured["review"].data,
            source_revision=source_revision, helper_source_hashes=helper_hashes, policy=policy,
        )
        artifact = json.loads(artifact_bytes.decode("utf-8"))
        coverage = artifact.get("coverage_counts")
        if not isinstance(coverage, dict) or set(coverage) != {"ids", "groups", "exact_text_sha256", "normalized_texts"}:
            _fail()
        if any(type(value) is not int or value < 0 for value in coverage.values()):
            _fail()

        _verify_snapshot(root, captured)
        _verify_code(root, helper_hashes, expected_adapter_source_sha256)
        _safe_output_directory(root, output)
        _create_private_output(output)
        artifact_sha = _exclusive_write(output / _OUTPUT_ARTIFACT, artifact_bytes)
        pure_sha = _exclusive_write(output / _OUTPUT_PURE_RECEIPT, pure_receipt_bytes)
        _verify_snapshot(root, captured)
        _verify_code(root, helper_hashes, expected_adapter_source_sha256)
        io_receipt = _io_receipt(source_revision, captured, {
            "fixture": canonical["fixture"], "rubric": canonical["rubric"],
            "review": _canonical_lf(captured["review"].data),
        }, helper_hashes, expected_adapter_source_sha256, artifact_bytes, pure_receipt_bytes, coverage)
        io_sha = _exclusive_write(output / _OUTPUT_MANIFEST, io_receipt)
        _verify_snapshot(root, captured)
        _verify_code(root, helper_hashes, expected_adapter_source_sha256)
        return FixtureProtectionIOResult(output, artifact_sha, pure_sha, io_sha, dict(coverage))
    except FixtureProtectionIOError:
        raise
    except (FixtureProtectionError, OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        _fail()


def build_fixture_protection_addon_io(project_root: Path, output_directory: Path, *,
                                      source_revision: str,
                                      expected_input_raw_sha256: Mapping[str, str],
                                      expected_helper_source_sha256: Mapping[str, str],
                                      expected_adapter_source_sha256: str) -> FixtureProtectionIOResult:
    """Build into a new POSIX-private result directory using frozen default pins.

    Windows execution fails closed pending a separately reviewed ACL verifier.
    Production code must not surface a policy override or reuse an output path.
    """
    return _build_fixture_protection_addon_io(
        project_root, output_directory, source_revision=source_revision,
        expected_input_raw_sha256=expected_input_raw_sha256,
        expected_helper_source_sha256=expected_helper_source_sha256,
        expected_adapter_source_sha256=expected_adapter_source_sha256,
        policy=DEFAULT_POLICY,
    )
