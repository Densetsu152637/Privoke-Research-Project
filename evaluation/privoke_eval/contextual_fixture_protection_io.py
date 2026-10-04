"""Private, snapshot-based I/O adapter for the contextual fixture add-on.

The adapter captures only the reviewed fixture, rubric, review metadata and
the small set of pinned helper source files. It never reads prompt-level rows
into logs, scans source corpora, or performs graph closure.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import stat
import sys
import types
from typing import Mapping

import privoke_eval.clean_augmentation_grouping as grouping_module
import privoke_eval.contextual_fixture_protection as fixture_module
import privoke_model.training_data as training_data_module
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
_SOURCE_MODULES = {
    "grouping": grouping_module,
    "normalizer": training_data_module,
    "fixture_validator": fixture_module,
    "adapter": sys.modules[__name__],
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


@dataclass
class _OutputContext:
    project_root: Path
    results_path: Path
    output_path: Path
    output_name: str
    chain_identity: tuple[tuple[int, int, int], ...]
    results_fd: int
    results_identity: tuple[int, int, int]
    output_fd: int | None = None
    output_identity: tuple[int, int, int] | None = None


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


def _identity(info: os.stat_result) -> tuple[int, int, int]:
    return (int(info.st_dev), int(info.st_ino), stat.S_IFMT(info.st_mode))


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


def _code_captures(root: Path) -> dict[str, _Captured]:
    captures: dict[str, _Captured] = {}
    for name, relative in _HELPER_PATHS.items():
        captures[name] = _bounded_capture(root, relative, _CODE_LIMIT)
    return captures


def _verify_snapshot(root: Path, captured: Mapping[str, _Captured]) -> None:
    for name, original in captured.items():
        current = _bounded_capture(root, _INPUT_PATHS[name], _INPUT_LIMITS[name])
        if current.sha256 != original.sha256 or current.signature != original.signature:
            _fail()


def _compiled_code_index(code: types.CodeType) -> dict[tuple[str, int], types.CodeType]:
    found: dict[tuple[str, int], types.CodeType] = {}
    pending = [code]
    while pending:
        item = pending.pop()
        found[(item.co_qualname, item.co_firstlineno)] = item
        pending.extend(value for value in item.co_consts if isinstance(value, types.CodeType))
    return found


def _source_bindings(
    source_text: str,
) -> tuple[tuple[str, ...], tuple[tuple[str | None, str, int], ...]]:
    try:
        tree = ast.parse(source_text)
    except SyntaxError:
        _fail()
    classes: list[str] = []
    bindings: list[tuple[str | None, str, int]] = []

    def visit(body: list[ast.stmt], class_name: str | None = None) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                bindings.append((class_name, node.name, node.lineno))
            elif isinstance(node, ast.ClassDef):
                qualified = f"{class_name}.{node.name}" if class_name else node.name
                classes.append(qualified)
                visit(node.body, qualified)
            else:
                for field_name in ("body", "orelse", "finalbody"):
                    nested = getattr(node, field_name, None)
                    if isinstance(nested, list) and all(isinstance(item, ast.stmt) for item in nested):
                        visit(nested, class_name)
                handlers = getattr(node, "handlers", None)
                if isinstance(handlers, list):
                    for handler in handlers:
                        visit(handler.body, class_name)
                cases = getattr(node, "cases", None)
                if isinstance(cases, list):
                    for case in cases:
                        visit(case.body, class_name)

    visit(tree.body)
    return tuple(classes), tuple(bindings)


def _resolve_class(module: object, qualified_name: str) -> type:
    value: object = module
    for part in qualified_name.split("."):
        if inspect.ismodule(value):
            value = vars(value).get(part)
        elif inspect.isclass(value):
            value = vars(value).get(part)
        else:
            _fail()
    if not inspect.isclass(value):
        _fail()
    return value


def _bound_source_function(module: object, class_name: str | None, name: str) -> object:
    if class_name is None:
        return vars(module).get(name)
    owner = _resolve_class(module, class_name)
    return vars(owner).get(name)


def _live_callable_candidates(value: object) -> tuple[types.FunctionType, ...]:
    if isinstance(value, property):
        return tuple(item for item in (value.fget, value.fset, value.fdel) if inspect.isfunction(item))
    if isinstance(value, (staticmethod, classmethod)):
        value = value.__func__
    return (value,) if inspect.isfunction(value) else ()


def _verify_loaded_module(root: Path, name: str, source: _Captured) -> None:
    module = _SOURCE_MODULES[name]
    expected_path = Path(os.path.abspath(root / _HELPER_PATHS[name]))
    module_path = getattr(module, "__file__", None)
    spec = getattr(module, "__spec__", None)
    origin = getattr(spec, "origin", None)
    if not isinstance(module_path, str) or not isinstance(origin, str):
        _fail()
    if Path(os.path.abspath(module_path)) != expected_path or Path(os.path.abspath(origin)) != expected_path:
        _fail()
    try:
        source_text = source.data.decode("utf-8", errors="strict")
        compiled = compile(source_text, str(expected_path), "exec", dont_inherit=True)
    except (UnicodeError, SyntaxError, ValueError, TypeError):
        _fail()
    loader = getattr(module, "__loader__", None)
    get_code = getattr(loader, "get_code", None)
    if not callable(get_code):
        _fail()
    try:
        loaded_module_code = get_code(module.__name__)
    except (ImportError, OSError, ValueError):
        _fail()
    if not isinstance(loaded_module_code, types.CodeType) or loaded_module_code != compiled:
        _fail()
    compiled_objects = _compiled_code_index(compiled)
    module_name = module.__name__
    class_names, definitions = _source_bindings(source_text)
    if not definitions and not class_names:
        _fail()
    for qualified_name in class_names:
        live_class = _resolve_class(module, qualified_name)
        if (live_class.__module__ != module_name or
                live_class.__qualname__ != qualified_name):
            _fail()
    for class_name, name, line in definitions:
        qualified_name = f"{class_name}.{name}" if class_name else name
        key = (qualified_name, line)
        expected = compiled_objects.get(key)
        value = _bound_source_function(module, class_name, name)
        candidates = _live_callable_candidates(value)
        if expected is None or not candidates:
            _fail()
        matching = [candidate for candidate in candidates if candidate.__code__.co_firstlineno == line]
        if len(matching) != 1:
            _fail()
        live = matching[0]
        if live.__module__ != module_name or live.__code__ != expected:
            _fail()
    # Dataclass-generated methods have no AST binding and are deliberately not
    # treated as source-defined live bindings.


def _verify_code(root: Path, expected_helpers: Mapping[str, str], expected_adapter: str) -> None:
    captures = _code_captures(root)
    hashes = {name: item.sha256 for name, item in captures.items()}
    adapter = hashes.pop("adapter")
    helpers = hashes
    if helpers != dict(expected_helpers) or adapter != expected_adapter:
        _fail()
    for name, capture in captures.items():
        _verify_loaded_module(root, name, capture)
    if (build_fixture_addon is not fixture_module.build_fixture_addon or
            DEFAULT_POLICY is not fixture_module.DEFAULT_POLICY or
            FixtureProtectionPolicy is not fixture_module.FixtureProtectionPolicy or
            FixtureProtectionError is not fixture_module.FixtureProtectionError or
            ADDON_FILENAME != fixture_module.ADDON_FILENAME or
            fixture_module.opaque_exclusion_key is not grouping_module.opaque_exclusion_key or
            fixture_module.ProtectedKeys is not grouping_module.ProtectedKeys or
            fixture_module.training_text_key is not training_data_module.training_text_key or
            _INPUT_PATHS != {
                "fixture": Path("evaluation/datasets/contextual-cascade-regressions.jsonl"),
                "rubric": Path("paper/research/contextual-cascade-rubric.md"),
                "review": Path("paper/research/contextual-cascade-fixture-review.json"),
            } or
            _HELPER_PATHS != {
                "grouping": Path("evaluation/privoke_eval/clean_augmentation_grouping.py"),
                "normalizer": Path("shared/python/privoke_model/training_data.py"),
                "fixture_validator": Path("evaluation/privoke_eval/contextual_fixture_protection.py"),
                "adapter": Path("evaluation/privoke_eval/contextual_fixture_protection_io.py"),
            } or
            _SOURCE_MODULES.get("grouping") is not grouping_module or
            _SOURCE_MODULES.get("normalizer") is not training_data_module or
            _SOURCE_MODULES.get("fixture_validator") is not fixture_module or
            _SOURCE_MODULES.get("adapter") is not sys.modules.get(__name__)):
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


def _directory_chain_identity(project_root: Path, results_path: Path) -> tuple[tuple[int, int, int], ...]:
    _check_absolute_directory_chain(project_root)
    _check_absolute_directory_chain(results_path)
    identities = []
    for path in (project_root, project_root / "evaluation", results_path):
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or _is_reparse(info):
            _fail()
        identities.append(_identity(info))
    return tuple(identities)


def _open_output_context(project_root: Path, output: Path) -> _OutputContext:
    results_path = _safe_output_directory(project_root, output)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        _fail()
    descriptor = -1
    try:
        identities = _directory_chain_identity(project_root, results_path)
        flags = os.O_RDONLY | directory | nofollow
        descriptor = os.open(results_path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode) or _identity(info) != identities[-1] or _is_reparse(info):
            _fail()
        try:
            os.stat(output.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            _fail()
        context = _OutputContext(project_root, results_path, output, output.name, identities,
                                 descriptor, _identity(info))
        descriptor = -1
        return context
    except FixtureProtectionIOError:
        raise
    except OSError:
        _fail()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _verify_output_context(context: _OutputContext, *, require_output: bool = True) -> None:
    try:
        if _directory_chain_identity(context.project_root, context.results_path) != context.chain_identity:
            _fail()
        parent_info = os.fstat(context.results_fd)
        if (not stat.S_ISDIR(parent_info.st_mode) or _is_reparse(parent_info) or
                _identity(parent_info) != context.results_identity or
                _identity(os.lstat(context.results_path)) != context.results_identity):
            _fail()
        if context.output_fd is None:
            if require_output:
                _fail()
            return
        output_info = os.fstat(context.output_fd)
        entry_info = os.stat(context.output_name, dir_fd=context.results_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(output_info.st_mode) or not stat.S_ISDIR(entry_info.st_mode) or
                _is_reparse(output_info) or _is_reparse(entry_info) or
                _identity(output_info) != context.output_identity or
                _identity(entry_info) != context.output_identity):
            _fail()
        _check_absolute_directory_chain(context.output_path)
        if _identity(os.lstat(context.output_path)) != context.output_identity:
            _fail()
    except FixtureProtectionIOError:
        raise
    except (OSError, ValueError, RuntimeError):
        _fail()


def _create_output_directory(context: _OutputContext) -> None:
    _verify_output_context(context, require_output=False)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        _fail()
    descriptor = -1
    try:
        os.mkdir(context.output_name, 0o700, dir_fd=context.results_fd)
        flags = os.O_RDONLY | directory | nofollow
        descriptor = os.open(context.output_name, flags, dir_fd=context.results_fd)
        os.fchmod(descriptor, 0o700)
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or _is_reparse(info):
            _fail()
        context.output_fd = descriptor
        context.output_identity = _identity(info)
        descriptor = -1
        _verify_output_context(context)
    except FixtureProtectionIOError:
        raise
    except OSError:
        _fail()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_output_file(context: _OutputContext, filename: str, payload: bytes) -> str:
    if filename not in {_OUTPUT_ARTIFACT, _OUTPUT_PURE_RECEIPT, _OUTPUT_MANIFEST}:
        _fail()
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        _fail()
    _verify_output_context(context)
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow
        descriptor = os.open(filename, flags, 0o600, dir_fd=context.output_fd)
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
        _verify_output_context(context)
        return _sha(payload)
    except FixtureProtectionIOError:
        raise
    except OSError:
        _fail()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _close_output_context(context: _OutputContext) -> None:
    failed = False
    for descriptor in (context.output_fd, context.results_fd):
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                failed = True
    if failed:
        _fail()


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
                                       policy: FixtureProtectionPolicy,
                                       source_root: Path | None = None) -> FixtureProtectionIOResult:
    """Internal policy-injectable boundary for synthetic tests; no CLI exposes it."""
    if os.name == "nt":
        _fail()  # Windows ACL verification is an operator/root gate, not chmod evidence.
    context: _OutputContext | None = None
    try:
        root = Path(project_root)
        output = Path(output_directory)
        if not root.is_absolute() or not output.is_absolute():
            _fail()
        _check_absolute_directory_chain(root)
        root = Path(os.path.abspath(root))
        trusted_source_root = root if source_root is None else Path(source_root)
        if not trusted_source_root.is_absolute():
            _fail()
        _check_absolute_directory_chain(trusted_source_root)
        trusted_source_root = Path(os.path.abspath(trusted_source_root))
        raw_hashes, helper_hashes = _validate_bindings(
            source_revision, expected_input_raw_sha256, expected_helper_source_sha256,
            expected_adapter_source_sha256)
        context = _open_output_context(root, output)
        _verify_code(trusted_source_root, helper_hashes, expected_adapter_source_sha256)

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
        _verify_code(trusted_source_root, helper_hashes, expected_adapter_source_sha256)
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
        _verify_code(trusted_source_root, helper_hashes, expected_adapter_source_sha256)
        _verify_output_context(context, require_output=False)
        _create_output_directory(context)
        artifact_sha = _write_output_file(context, _OUTPUT_ARTIFACT, artifact_bytes)
        pure_sha = _write_output_file(context, _OUTPUT_PURE_RECEIPT, pure_receipt_bytes)
        _verify_snapshot(root, captured)
        _verify_code(trusted_source_root, helper_hashes, expected_adapter_source_sha256)
        io_receipt = _io_receipt(source_revision, captured, {
            "fixture": canonical["fixture"], "rubric": canonical["rubric"],
            "review": _canonical_lf(captured["review"].data),
        }, helper_hashes, expected_adapter_source_sha256, artifact_bytes, pure_receipt_bytes, coverage)
        io_sha = _write_output_file(context, _OUTPUT_MANIFEST, io_receipt)
        _verify_snapshot(root, captured)
        _verify_code(trusted_source_root, helper_hashes, expected_adapter_source_sha256)
        _verify_output_context(context)
        return FixtureProtectionIOResult(output, artifact_sha, pure_sha, io_sha, dict(coverage))
    except FixtureProtectionIOError:
        raise
    except (FixtureProtectionError, OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        _fail()
    finally:
        if context is not None:
            _close_output_context(context)


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
