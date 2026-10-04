"""Bounded, addon-aware I/O boundary for private blind-review preparation.

The protection preflight and preparation use the same twelve captured inputs.
Neither operation assigns review labels or allocates a review partition.
"""
from __future__ import annotations

import ast
from collections.abc import Mapping
from contextlib import contextmanager
import contextlib
from dataclasses import dataclass, fields as dataclass_fields, is_dataclass
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
import types
from types import MappingProxyType
from typing import Any

import privoke_eval.advpii_native as native
import privoke_eval.advpii_review as review
import privoke_eval.advpii_structure as structure
import privoke_eval.clean_augmentation_grouping as grouping
import privoke_eval.clean_augmentation_protection as protection_core
import privoke_eval.clean_augmentation_protection_io as protection_io
import privoke_eval.contextual_fixture_protection as fixture
import privoke_eval.in_house_advpii_review as in_house
import privoke_model.training_data as training_data
from privoke_eval.advpii_native import parse_native_row, validate_arrow_schema
from privoke_eval.advpii_review import ReviewBindings, ValidatedNativeSpanInput, build_review_pool, protected_keys_digest
from privoke_eval.advpii_structure import (
    PARQUET_ROWS, aggregate_scan, canonical_json_bytes, open_verified_parquet,
    require_frozen_text_inputs, validate_protected_union, validate_source_audit,
    validate_training_data_source, verify_parquet_bytes,
)
from privoke_eval.clean_augmentation_grouping import ProtectedKeys
from privoke_eval.contextual_fixture_protection import validate_fixture_addon
from privoke_eval.in_house_advpii_review import (
    EXECUTION_CODE_ROLES, InHouseProtectionBindings, InHouseReviewBindings,
    build_in_house_review_pool,
)

_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_INPUT_ROLES = (
    "parquet", "source_audit", "protocol", "rubric", "protected_union",
    "protection_receipt", "pin_manifest", "fixture", "fixture_rubric",
    "fixture_review", "addon_artifact", "addon_receipt",
)
_INPUT_BASENAMES = {
    "parquet": "source.parquet", "source_audit": "source-audit.json",
    "protocol": "protocol.md", "rubric": "rubric.json",
    "protected_union": "protected-union.json", "protection_receipt": "receipt.json",
    "pin_manifest": "pin-manifest.json",
    "fixture": "contextual-cascade-regressions.jsonl",
    "fixture_rubric": "contextual-cascade-rubric.md",
    "fixture_review": "contextual-cascade-fixture-review.json",
    "addon_artifact": "contextual-fixture-addon.json",
    "addon_receipt": "contextual-fixture-addon-receipt.json",
}
_CODE_PATHS = {
    "parser": Path("evaluation/privoke_eval/advpii_native.py"),
    "structure": Path("evaluation/privoke_eval/advpii_structure.py"),
    "grouping": Path("evaluation/privoke_eval/clean_augmentation_grouping.py"),
    "review_helper": Path("evaluation/privoke_eval/advpii_review.py"),
    "protection_core": Path("evaluation/privoke_eval/clean_augmentation_protection.py"),
    "protection_io": Path("evaluation/privoke_eval/clean_augmentation_protection_io.py"),
    "fixture_validator": Path("evaluation/privoke_eval/contextual_fixture_protection.py"),
    "normalizer": Path("shared/python/privoke_model/training_data.py"),
    "in_house_review": Path("evaluation/privoke_eval/in_house_advpii_review.py"),
    "in_house_review_io": Path("evaluation/privoke_eval/in_house_advpii_review_io.py"),
    "cli": Path("evaluation/prepare-in-house-advpii-review.py"),
}
_SOURCE_MODULES = {
    "parser": native, "structure": structure, "grouping": grouping,
    "review_helper": review, "protection_core": protection_core,
    "protection_io": protection_io, "fixture_validator": fixture,
    "normalizer": training_data, "in_house_review": in_house,
    "in_house_review_io": sys.modules[__name__],
}
_INPUT_LIMITS = {
    "parquet": 64 * 1024 * 1024,
    "source_audit": 2 * 1024 * 1024, "protocol": 4 * 1024 * 1024,
    "rubric": 4 * 1024 * 1024, "protected_union": 32 * 1024 * 1024,
    "protection_receipt": 2 * 1024 * 1024, "pin_manifest": 2 * 1024 * 1024,
    "fixture": 1_048_576, "fixture_rubric": 262_144,
    "fixture_review": 65_536, "addon_artifact": 4_194_304,
    "addon_receipt": 262_144,
}
_MAX_INPUT_TOTAL = 128 * 1024 * 1024
_CODE_LIMIT = 2 * 1024 * 1024
_PIN_KIND = "privoke-in-house-review-code-pins-v1"
_PRIVATE_OUTPUTS = {"review-packages.jsonl", "private-review-map.jsonl", "manifest.json", "failure.json"}


class InHousePreparationError(ValueError):
    """Sanitized preparation-boundary error."""


@dataclass(frozen=True)
class InHouseReviewIOPaths:
    parquet: Path
    source_audit: Path
    protocol: Path
    rubric: Path
    protected_union: Path
    protection_receipt: Path
    pin_manifest: Path
    fixture: Path
    fixture_rubric: Path
    fixture_review: Path
    addon_artifact: Path
    addon_receipt: Path
    output: Path


@dataclass(frozen=True)
class InHousePreparationTrust:
    source_revision: str
    input_raw_sha256: Mapping[str, str]
    pin_manifest_raw_sha256: str
    historical_receipt_raw_sha256: str
    addon_receipt_raw_sha256: str
    addon_producer_revision: str
    addon_helper_raw_sha256: Mapping[str, str]
    execution_code_raw_sha256: Mapping[str, str]
    study_plan_lf_sha256: str
    preparation_design_sha256: str
    allocator_design_sha256: str
    expected_protection_bindings: Mapping[str, Any] | str | InHouseProtectionBindings | None = None

    def __post_init__(self):
        for name in ("input_raw_sha256", "addon_helper_raw_sha256", "execution_code_raw_sha256"):
            value = getattr(self, name)
            if isinstance(value, Mapping):
                object.__setattr__(self, name, MappingProxyType(dict(value)))
        expected = self.expected_protection_bindings
        if isinstance(expected, Mapping):
            object.__setattr__(self, "expected_protection_bindings", _freeze_mapping(expected))


def _freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType({key: _freeze_value(item) for key, item in value.items()})


def _freeze_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _freeze_mapping(value)
    if type(value) is list:
        return tuple(_freeze_value(item) for item in value)
    if type(value) is tuple:
        return tuple(_freeze_value(item) for item in value)
    return value


@dataclass(frozen=True)
class InHouseProtectionPreflight:
    bindings: InHouseProtectionBindings
    coverage_counts: Mapping[str, int]
    input_raw_sha256: Mapping[str, str]
    execution_code_raw_sha256: Mapping[str, str]


@dataclass(frozen=True)
class InHousePreparationResult:
    status: str
    output_directory: Path
    preparation_identity: str | None
    review_pool_sha256: str | None
    output_sha256: Mapping[str, str]
    counts: Mapping[str, int]


@dataclass(frozen=True)
class _Capture:
    source_path: Path
    snapshot_path: Path
    data: bytes
    sha256: str
    identity: tuple[int, int, int]


def _fail(stage: str = "validate_inputs", code: str = "preparation_failed") -> None:
    raise InHousePreparationError(f"{stage}:{code}")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _valid_sha(value: object) -> bool:
    return type(value) is str and _HEX64.fullmatch(value) is not None


def _strict_json(raw: bytes, stage: str) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _fail(stage, "duplicate_json_key")
            result[key] = value
        return result
    try:
        return json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs,
                          parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except InHousePreparationError:
        raise
    except (UnicodeError, ValueError, json.JSONDecodeError):
        _fail(stage, "malformed_json")


def _canonical_lf(raw: bytes) -> bytes:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        _fail("decode_text", "invalid_utf8")
    return text.replace("\r\n", "\n").encode("utf-8")


def _identity(info: os.stat_result) -> tuple[int, int, int]:
    return info.st_dev, info.st_ino, info.st_mode


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _platform_supported() -> bool:
    return (os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
            and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd)


def _trusted_maps(trust: InHousePreparationTrust) -> None:
    if (type(trust.source_revision) is not str or _HEX40.fullmatch(trust.source_revision) is None
            or type(trust.addon_producer_revision) is not str
            or _HEX40.fullmatch(trust.addon_producer_revision) is None):
        _fail("validate_trust", "bad_revision")
    if any(not _valid_sha(getattr(trust, name)) for name in
           ("pin_manifest_raw_sha256", "historical_receipt_raw_sha256", "addon_receipt_raw_sha256")):
        _fail("validate_trust", "bad_digest")
    if not isinstance(trust.input_raw_sha256, Mapping) or set(trust.input_raw_sha256) != set(_INPUT_ROLES):
        _fail("validate_trust", "bad_input_pins")
    if any(not _valid_sha(value) for value in trust.input_raw_sha256.values()):
        _fail("validate_trust", "bad_input_pins")
    if trust.input_raw_sha256["pin_manifest"] != trust.pin_manifest_raw_sha256:
        _fail("validate_trust", "pin_mismatch")
    if trust.input_raw_sha256["protection_receipt"] != trust.historical_receipt_raw_sha256:
        _fail("validate_trust", "receipt_mismatch")
    if trust.input_raw_sha256["addon_receipt"] != trust.addon_receipt_raw_sha256:
        _fail("validate_trust", "addon_receipt_mismatch")
    if not isinstance(trust.addon_helper_raw_sha256, Mapping) or set(trust.addon_helper_raw_sha256) != {
            "grouping", "normalizer", "fixture_validator"} or any(
            not _valid_sha(value) for value in trust.addon_helper_raw_sha256.values()):
        _fail("validate_trust", "bad_addon_code_pins")
    if not isinstance(trust.execution_code_raw_sha256, Mapping) or set(trust.execution_code_raw_sha256) != set(
            EXECUTION_CODE_ROLES) or any(not _valid_sha(value) for value in trust.execution_code_raw_sha256.values()):
        _fail("validate_trust", "bad_code_pins")
    if (trust.study_plan_lf_sha256 != in_house.PLAN_SHA256
            or trust.preparation_design_sha256 != in_house.PREPARATION_DESIGN_SHA256
            or trust.allocator_design_sha256 != in_house.ALLOCATOR_DESIGN_SHA256):
        _fail("validate_trust", "design_pin_mismatch")


def _safe_input_path(path: Path) -> None:
    try:
        if not isinstance(path, Path) or not path.is_absolute():
            _fail("validate_paths", "bad_input_path")
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or _is_reparse(info) or path.is_symlink():
            _fail("validate_paths", "unsafe_input")
    except InHousePreparationError:
        raise
    except OSError:
        _fail("validate_paths", "missing_input")


def _input_paths(paths: InHouseReviewIOPaths) -> dict[str, Path]:
    if type(paths) is not InHouseReviewIOPaths:
        _fail("validate_paths", "bad_path_record")
    values = {role: getattr(paths, role) for role in _INPUT_ROLES}
    for role, path in values.items():
        _safe_input_path(path)
    return values


def _open_read_nofollow(path: Path) -> tuple[int, os.stat_result]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or _is_reparse(info):
            os.close(fd)
            _fail("capture_inputs", "unsafe_input")
        return fd, info
    except InHousePreparationError:
        raise
    except OSError:
        _fail("capture_inputs", "input_open_failed")


def _capture_file(path: Path, role: str, snapshot_root: Path) -> _Capture:
    limit = _INPUT_LIMITS[role]
    fd, before = _open_read_nofollow(path)
    try:
        chunks: list[bytes] = []
        total = 0
        while total <= limit:
            chunk = os.read(fd, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(fd)
        if (total > limit or _identity(before) != _identity(after) or before.st_size != after.st_size
                or total != before.st_size):
            _fail("capture_inputs", "input_changed_or_oversize")
    finally:
        os.close(fd)
    directory = snapshot_root / role
    directory.mkdir(mode=0o700)
    target = directory / _INPUT_BASENAMES[role]
    out_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(raw)
        pos = 0
        while pos < len(view):
            written = os.write(out_fd, view[pos:])
            if written <= 0:
                _fail("capture_inputs", "snapshot_write_failed")
            pos += written
        os.fsync(out_fd)
        os.fchmod(out_fd, 0o600)
    finally:
        os.close(out_fd)
    return _Capture(path, target, raw, _sha(raw), _identity(before))


@contextmanager
def _capture_all(paths: InHouseReviewIOPaths, trust: InHousePreparationTrust):
    values = _input_paths(paths)
    total = 0
    with tempfile.TemporaryDirectory(prefix="privoke-inhouse-snapshot-") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        captures: dict[str, _Capture] = {}
        for role in _INPUT_ROLES:
            item = _capture_file(values[role], role, root)
            total += len(item.data)
            if total > _MAX_INPUT_TOTAL:
                _fail("capture_inputs", "input_total_oversize")
            captures[role] = item
        if {key: value.sha256 for key, value in captures.items()} != dict(trust.input_raw_sha256):
            _fail("capture_inputs", "input_hash_mismatch")
        # Establish that the original paths still identify the bytes captured
        # for every role before any captured JSON or Parquet is interpreted.
        _recheck_inputs(captures)
        yield values, captures, root


def _recheck_inputs(captures: Mapping[str, _Capture]) -> None:
    for item in captures.values():
        fd, before = _open_read_nofollow(item.source_path)
        try:
            if _identity(before) != item.identity:
                _fail("recheck_inputs", "input_identity_changed")
            digest = hashlib.sha256()
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            after = os.fstat(fd)
            if _identity(after) != item.identity or digest.hexdigest() != item.sha256:
                _fail("recheck_inputs", "input_changed")
        finally:
            os.close(fd)


def _code_capture(source_root: Path, role: str) -> tuple[bytes, Path]:
    relative = _CODE_PATHS[role]
    try:
        if Path(os.path.abspath(source_root)) != source_root or source_root.resolve(strict=True) != source_root:
            _fail("attest_code", "unsafe_source_root")
        path = source_root / relative
        current = source_root
        for part in relative.parts[:-1]:
            current = current / part
            info = os.lstat(current)
            if not stat.S_ISDIR(info.st_mode) or _is_reparse(info) or current.is_symlink():
                _fail("attest_code", "unsafe_source_path")
        if path.is_symlink() or not path.is_file():
            _fail("attest_code", "unsafe_source")
    except InHousePreparationError:
        raise
    except OSError:
        _fail("attest_code", "unsafe_source")
    fd, before = _open_read_nofollow(path)
    try:
        raw = os.read(fd, _CODE_LIMIT + 1)
        after = os.fstat(fd)
        if len(raw) > _CODE_LIMIT or len(raw) != before.st_size or _identity(before) != _identity(after):
            _fail("attest_code", "source_changed_or_oversize")
    finally:
        os.close(fd)
    return raw, Path(os.path.abspath(path))


def _compiled_objects(root: types.CodeType) -> dict[tuple[str, int], types.CodeType]:
    result = {}
    stack = [root]
    while stack:
        current = stack.pop()
        result[(current.co_qualname, current.co_firstlineno)] = current
        stack.extend(item for item in current.co_consts if isinstance(item, types.CodeType))
    return result


def _source_bindings(text: str) -> tuple[set[str], list[tuple[str | None, str, int]]]:
    tree = ast.parse(text)
    classes: set[str] = set()
    functions: list[tuple[str | None, str, int]] = []
    def walk(nodes: list[ast.stmt], owner: str | None = None, *, live_binding: bool = True) -> None:
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if live_binding:
                    first_line = min((item.lineno for item in node.decorator_list), default=node.lineno)
                    functions.append((owner, node.name, first_line))
                # Nested functions are represented in, and verified through,
                # their live parent function's exact compiled code object.
                walk(node.body, owner, live_binding=False)
            elif isinstance(node, ast.ClassDef):
                name = f"{owner}.{node.name}" if owner else node.name
                if live_binding:
                    classes.add(name)
                walk(node.body, name, live_binding=live_binding)
            else:
                for field_name in ("body", "orelse", "finalbody"):
                    nested = getattr(node, field_name, None)
                    if isinstance(nested, list):
                        walk([item for item in nested if isinstance(item, ast.stmt)], owner,
                             live_binding=False)
                for field_name in ("handlers", "cases"):
                    for block in getattr(node, field_name, ()):
                        walk(getattr(block, "body", ()), owner, live_binding=False)
    walk(tree.body)
    return classes, functions


def _assigned_names(target: ast.expr) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        return set().union(*(_assigned_names(item) for item in target.elts)) if target.elts else set()
    return set()


def _module_binding_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Import):
            names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module == "__future__":
                continue
            names.update(alias.asname or alias.name for alias in node.names if alias.name != "*")
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                names.update(_assigned_names(target))
        elif isinstance(node, ast.AnnAssign):
            names.update(_assigned_names(node.target))
    return names


def _semantic_value_equal(actual: Any, expected: Any, *, actual_module: object | None = None,
                          scratch_module: object | None = None) -> bool:
    """Compare source-derived module values without trusting repr or coercions."""
    if actual is actual_module and expected is scratch_module:
        return True
    if (is_dataclass(actual) and not isinstance(actual, type)
            and is_dataclass(expected) and not isinstance(expected, type)):
        class_matches = (type(actual) is type(expected)
                         or (actual_module is not None and scratch_module is not None
                             and type(actual).__module__ == getattr(actual_module, "__name__", None)
                             and type(expected).__module__ == getattr(scratch_module, "__name__", None)))
        return (class_matches and type(actual).__qualname__ == type(expected).__qualname__
                and tuple(item.name for item in dataclass_fields(actual))
                == tuple(item.name for item in dataclass_fields(expected))
                and all(_semantic_value_equal(getattr(actual, item.name), getattr(expected, item.name),
                                              actual_module=actual_module, scratch_module=scratch_module)
                        for item in dataclass_fields(actual)))
    if type(actual) is not type(expected):
        return False
    if inspect.ismodule(actual) or inspect.isclass(actual) or inspect.isfunction(actual):
        return actual is expected
    if isinstance(actual, re.Pattern):
        return actual.pattern == expected.pattern and actual.flags == expected.flags
    if type(actual) in (tuple, list):
        return len(actual) == len(expected) and all(
            _semantic_value_equal(left, right, actual_module=actual_module, scratch_module=scratch_module)
            for left, right in zip(actual, expected, strict=True))
    if type(actual) in (dict, MappingProxyType):
        return (set(actual) == set(expected)
                and all(_semantic_value_equal(actual[key], expected[key], actual_module=actual_module,
                                              scratch_module=scratch_module) for key in actual))
    if type(actual) in (set, frozenset):
        return actual == expected
    if actual is None or type(actual) in (str, int, float, bool, bytes):
        return actual == expected
    try:
        value = actual == expected
        return type(value) is bool and value
    except Exception:
        return actual is expected


def _class_assignment_names(node: ast.ClassDef) -> set[str]:
    names: set[str] = set()
    for item in node.body:
        if isinstance(item, ast.Assign):
            for target in item.targets:
                names.update(_assigned_names(target))
        elif isinstance(item, ast.AnnAssign):
            names.update(_assigned_names(item.target))
    return names


def _attest_module_globals(module: object, scratch: object, tree: ast.Module,
                           functions: list[tuple[str | None, str, int]]) -> None:
    function_names = {(owner, name) for owner, name, _line in functions}
    class_nodes: dict[str, ast.ClassDef] = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            class_nodes[node.name] = node
    module_globals = vars(module)
    scratch_globals = vars(scratch)
    for name in _module_binding_names(tree):
        actual, expected = module_globals.get(name), scratch_globals.get(name)
        if (None if name not in module_globals else 1) != (None if name not in scratch_globals else 1):
            _fail("attest_code", "source_global_binding_mismatch")
        if name in class_nodes:
            node = class_nodes[name]
            actual_class = _class_at(module, name)
            expected_class = _class_at(scratch, name)
            expected_attrs = vars(expected_class)
            if not _semantic_value_equal(vars(actual_class).get("__annotations__"),
                                         expected_attrs.get("__annotations__"),
                                         actual_module=module, scratch_module=scratch):
                _fail("attest_code", "source_class_annotation_mismatch")
            for attr in _class_assignment_names(node):
                if not _semantic_value_equal(vars(actual_class).get(attr), expected_attrs.get(attr),
                                             actual_module=module, scratch_module=scratch):
                    _fail("attest_code", "source_class_global_mismatch")
            if is_dataclass(actual_class) and is_dataclass(expected_class):
                actual_fields = dataclass_fields(actual_class)
                expected_fields = dataclass_fields(expected_class)
                if tuple(field.name for field in actual_fields) != tuple(field.name for field in expected_fields):
                    _fail("attest_code", "source_dataclass_fields_mismatch")
                for attr in ("__init__", "__repr__", "__eq__", "__hash__"):
                    left, right = vars(actual_class).get(attr), expected_attrs.get(attr)
                    if left is None and right is None:
                        continue
                    if (not inspect.isfunction(left) or not inspect.isfunction(right)
                            or left.__code__ != right.__code__
                            or not _semantic_value_equal(left.__defaults__, right.__defaults__,
                                                         actual_module=module, scratch_module=scratch)
                            or not _semantic_value_equal(left.__kwdefaults__, right.__kwdefaults__,
                                                         actual_module=module, scratch_module=scratch)):
                        _fail("attest_code", "source_dataclass_method_mismatch")
            continue
        if (None, name) in function_names:
            actual_fn = module_globals.get(name)
            expected_fn = scratch_globals.get(name)
            if (not inspect.isfunction(actual_fn) or not inspect.isfunction(expected_fn)
                    or not _semantic_value_equal(actual_fn.__defaults__, expected_fn.__defaults__,
                                                 actual_module=module, scratch_module=scratch)
                    or not _semantic_value_equal(actual_fn.__kwdefaults__, expected_fn.__kwdefaults__,
                                                 actual_module=module, scratch_module=scratch)
                    or not _semantic_value_equal(actual_fn.__annotations__, expected_fn.__annotations__,
                                                 actual_module=module, scratch_module=scratch)):
                _fail("attest_code", "source_function_defaults_mismatch")
            continue
        if not _semantic_value_equal(actual, expected, actual_module=module, scratch_module=scratch):
            _fail("attest_code", "source_global_value_mismatch")


def _fresh_source_module(role: str, module: object, compiled: types.CodeType, path: Path) -> object:
    """Execute only the already hash-pinned source in an isolated import namespace."""
    name = f"_privoke_attest_{role}_{secrets.token_hex(8)}"
    scratch = types.ModuleType(name)
    scratch.__file__ = str(path)
    scratch.__package__ = getattr(module, "__package__", "")
    original_path = list(sys.path)
    sys.modules[name] = scratch
    try:
        exec(compiled, vars(scratch), vars(scratch))
    except Exception:
        _fail("attest_code", "trusted_source_replay_failed")
    finally:
        sys.path[:] = original_path
        sys.modules.pop(name, None)
    return scratch


def _class_at(module: object, qualname: str) -> type:
    value: Any = module
    for name in qualname.split("."):
        value = vars(value).get(name) if inspect.ismodule(value) or inspect.isclass(value) else None
    if not inspect.isclass(value):
        _fail("attest_code", "class_binding_mismatch")
    return value


def _function_candidates(value: object) -> tuple[types.FunctionType, ...]:
    if isinstance(value, property):
        values = (value.fget, value.fset, value.fdel)
    elif isinstance(value, (staticmethod, classmethod)):
        values = (value.__func__,)
    else:
        values = (value,)
    result = []
    for item in values:
        try:
            unwrapped = inspect.unwrap(item) if callable(item) else item
        except (ValueError, TypeError):
            continue
        if inspect.isfunction(item) and unwrapped is not item:
            try:
                expected = contextlib.contextmanager(unwrapped)
                closure = lambda function: tuple(cell.cell_contents for cell in (function.__closure__ or ()))
                if (item.__code__ != expected.__code__ or item.__globals__ is not expected.__globals__
                        or item.__defaults__ != expected.__defaults__
                        or item.__kwdefaults__ != expected.__kwdefaults__
                        or closure(item) != closure(expected)
                        or getattr(item, "__wrapped__", None) is not unwrapped):
                    _fail("attest_code", "decorator_wrapper_mismatch")
            except InHousePreparationError:
                raise
            except Exception:
                _fail("attest_code", "decorator_wrapper_mismatch")
        if inspect.isfunction(unwrapped):
            result.append(unwrapped)
    return tuple(result)


def _attest_module(role: str, raw: bytes, path: Path, module_override: object | None = None) -> None:
    module = _SOURCE_MODULES[role] if module_override is None else module_override
    module_file = getattr(module, "__file__", None)
    if not isinstance(module_file, str) or Path(os.path.abspath(module_file)) != path:
        _fail("attest_code", "module_origin_mismatch")
    if role != "cli":
        spec = getattr(module, "__spec__", None)
        if spec is None or Path(os.path.abspath(spec.origin or "")) != path:
            _fail("attest_code", "module_origin_mismatch")
    try:
        text = raw.decode("utf-8", errors="strict")
        compiled = compile(text, str(path), "exec", dont_inherit=True)
    except Exception:
        _fail("attest_code", "module_compile_mismatch")
    loader = getattr(module, "__loader__", None)
    get_code = getattr(loader, "get_code", None)
    if callable(get_code):
        try:
            loaded = get_code(module.__name__)
        except Exception:
            _fail("attest_code", "module_loader_failed")
        if loaded != compiled:
            _fail("attest_code", "loaded_code_mismatch")
    elif role != "cli":
        _fail("attest_code", "module_loader_missing")
    code_index = _compiled_objects(compiled)
    try:
        tree = ast.parse(text)
    except Exception:
        _fail("attest_code", "module_ast_mismatch")
    classes, functions = _source_bindings(text)
    if not classes and not functions:
        _fail("attest_code", "empty_source_bindings")
    scratch = _fresh_source_module(role, module, compiled, path)
    for qualname in classes:
        cls = _class_at(module, qualname)
        if cls.__module__ != module.__name__ or cls.__qualname__ != qualname:
            _fail("attest_code", "class_provenance_mismatch")
    for owner, name, line in functions:
        qualname = f"{owner}.{name}" if owner else name
        expected = code_index.get((qualname, line))
        holder: Any = _class_at(module, owner) if owner else module
        expected_holder: Any = _class_at(scratch, owner) if owner else scratch
        value = vars(holder).get(name)
        expected_value = vars(expected_holder).get(name)
        candidates = [fn for fn in _function_candidates(value) if fn.__code__.co_firstlineno == line]
        expected_candidates = [fn for fn in _function_candidates(expected_value)
                               if fn.__code__.co_firstlineno == line]
        if (expected is None or len(candidates) != 1 or candidates[0].__module__ != module.__name__
                or candidates[0].__globals__ is not vars(module)
                or candidates[0].__code__ != expected or len(expected_candidates) != 1
                or not _semantic_value_equal(candidates[0].__defaults__, expected_candidates[0].__defaults__,
                                             actual_module=module, scratch_module=scratch)
                or not _semantic_value_equal(candidates[0].__kwdefaults__, expected_candidates[0].__kwdefaults__,
                                             actual_module=module, scratch_module=scratch)
                or not _semantic_value_equal(candidates[0].__annotations__, expected_candidates[0].__annotations__,
                                             actual_module=module, scratch_module=scratch)):
            _fail("attest_code", "live_binding_mismatch")
    _attest_module_globals(module, scratch, tree, functions)
    if role == "cli":
        expected_globals = {
            "EXECUTION_CODE_ROLES": EXECUTION_CODE_ROLES,
            "InHousePreparationTrust": InHousePreparationTrust,
            "InHouseReviewIOPaths": InHouseReviewIOPaths,
            "InHousePreparationError": InHousePreparationError,
            "prepare_in_house_protection_bindings": prepare_in_house_protection_bindings,
            "prepare_in_house_review_pool": prepare_in_house_review_pool,
        }
        if any(vars(module).get(name) is not value for name, value in expected_globals.items()):
            _fail("attest_code", "cli_alias_mismatch")
        try:
            expected_eval = path.parent
            expected_root = expected_eval.parent
            if (vars(module).get("EVALUATION_ROOT") != expected_eval
                    or vars(module).get("REPOSITORY_ROOT") != expected_root
                    or vars(module).get("Path") is not Path
                    or vars(module).get("json") is not json
                    or vars(module).get("re") is not re
                    or vars(module).get("sys") is not sys):
                _fail("attest_code", "cli_alias_mismatch")
        except InHousePreparationError:
            raise
        except Exception:
            _fail("attest_code", "cli_alias_mismatch")


_PARSER_CONSTANTS = {
    "_INT32_MIN": -(2 ** 31), "_INT32_MAX": 2 ** 31 - 1,
    "_CATEGORIES": frozenset({"positive", "negative", "hard_negative"}),
    "_SPAN_TYPES": frozenset({"credit_card_number", "phone_number", "iban", "email", "ssn"}),
    "_PII_OPERATIONS": frozenset({"homoglyph", "chunking", "emojify", "char_to_word",
                                   "invisible_chars", "separators"}),
    "_CONTEXT_OPERATIONS": frozenset({"supportive_context", "affix_redacted", "affix_ignore_pii",
                                       "affix_category_prime", "pi_ceo_instruct", "pi_few_shot_safe",
                                       "pi_hypothetical", "pi_educational_framing", "pi_category_prime"}),
    "_TOP_FIELDS": ("uid", "input_id", "category", "attack_target", "llm_input", "pii_spans"),
    "_SPAN_FIELDS": ("type", "start", "end", "value", "value_fuzzy"),
    "_ATTACK_FIELDS": ("pii", "context"),
}
_REVIEW_CONSTANTS = {
    "SOURCE_SHA256": "e97f6a32132e7fa058919798c030fca54aaad3318c47954d281717a435bfeb69",
    "PROTOCOL_SHA256": "3991777aedadc8d50b7395a9ce8ef2aebfec946603229b823f1b6c118a16cbdf",
    "RUBRIC_SHA256": "203f37b4c77789a0f9c0838905954b9e1b76acf4f7906ab7717849e94616fcd7",
    "REFERENCE_TRAIN_SHA256": "da9a1b095587264714c5ae99c8a0f92329a04f6fc237a8ace7d71e837ede429d",
    "POOL_SEED": 13102026, "SPLIT_SEED": 11102026, "ROW_FILL_SEED": 13102026,
    "MAX_REVIEW_POOL": 12096, "MAX_ORDINARY_POOL": 6200,
    "MAX_HARD_NEGATIVE_POOL": 1232, "MAX_POSITIVE_POOL": 4664,
    "MAX_POSITIVE_PER_COMPONENT": 4, "_EVALUATION_COMPONENT_FLOOR": 200,
    "_STRATA": ("positive", "ordinary", "hard"),
    "_CATEGORIES": frozenset({"HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL",
                               "SEXUAL", "CHILD", "LOCATION", "IDENTITY", "THIRD_PARTY"}),
    "_QUOTAS": {
        "test": {"positive": 1000, "ordinary": 750, "hard": 250},
        "validation": {"positive": 1000, "ordinary": 750, "hard": 250},
        "train": {"positive": 2000, "ordinary": 1600, "hard": 400},
    },
}


def _check_semantic_contracts() -> None:
    if (native.GroupingRow is not grouping.GroupingRow
            or native.NativeIdentifier is not grouping.NativeIdentifier
            or native.ParsedNativeRow.__module__ != native.__name__
            or any(not _semantic_value_equal(vars(native).get(name), value)
                   for name, value in _PARSER_CONSTANTS.items())
            or any(not _semantic_value_equal(vars(review).get(name), value)
                   for name, value in _REVIEW_CONSTANTS.items())):
        _fail("attest_code", "semantic_contract_mismatch")


def _attest_code(source_root: Path, trust: InHousePreparationTrust) -> dict[str, str]:
    if not source_root.is_absolute():
        _fail("attest_code", "bad_source_root")
    expected_paths = {
        "parser": Path("evaluation/privoke_eval/advpii_native.py"),
        "structure": Path("evaluation/privoke_eval/advpii_structure.py"),
        "grouping": Path("evaluation/privoke_eval/clean_augmentation_grouping.py"),
        "review_helper": Path("evaluation/privoke_eval/advpii_review.py"),
        "protection_core": Path("evaluation/privoke_eval/clean_augmentation_protection.py"),
        "protection_io": Path("evaluation/privoke_eval/clean_augmentation_protection_io.py"),
        "fixture_validator": Path("evaluation/privoke_eval/contextual_fixture_protection.py"),
        "normalizer": Path("shared/python/privoke_model/training_data.py"),
        "in_house_review": Path("evaluation/privoke_eval/in_house_advpii_review.py"),
        "in_house_review_io": Path("evaluation/privoke_eval/in_house_advpii_review_io.py"),
        "cli": Path("evaluation/prepare-in-house-advpii-review.py"),
    }
    expected_roles = (
        "parquet", "source_audit", "protocol", "rubric", "protected_union", "protection_receipt",
        "pin_manifest", "fixture", "fixture_rubric", "fixture_review", "addon_artifact", "addon_receipt",
    )
    expected_basenames = {
        "parquet": "source.parquet", "source_audit": "source-audit.json", "protocol": "protocol.md",
        "rubric": "rubric.json", "protected_union": "protected-union.json", "protection_receipt": "receipt.json",
        "pin_manifest": "pin-manifest.json", "fixture": "contextual-cascade-regressions.jsonl",
        "fixture_rubric": "contextual-cascade-rubric.md", "fixture_review": "contextual-cascade-fixture-review.json",
        "addon_artifact": "contextual-fixture-addon.json", "addon_receipt": "contextual-fixture-addon-receipt.json",
    }
    expected_limits = {
        "parquet": 64 * 1024 * 1024, "source_audit": 2 * 1024 * 1024,
        "protocol": 4 * 1024 * 1024, "rubric": 4 * 1024 * 1024,
        "protected_union": 32 * 1024 * 1024, "protection_receipt": 2 * 1024 * 1024,
        "pin_manifest": 2 * 1024 * 1024, "fixture": 1_048_576,
        "fixture_rubric": 262_144, "fixture_review": 65_536,
        "addon_artifact": 4_194_304, "addon_receipt": 262_144,
    }
    if (_CODE_PATHS != expected_paths or _INPUT_ROLES != expected_roles
            or _INPUT_BASENAMES != expected_basenames or _INPUT_LIMITS != expected_limits
            or _MAX_INPUT_TOTAL != 128 * 1024 * 1024 or _CODE_LIMIT != 2 * 1024 * 1024
            or _PIN_KIND != "privoke-in-house-review-code-pins-v1"
            or _PRIVATE_OUTPUTS != {"review-packages.jsonl", "private-review-map.jsonl", "manifest.json", "failure.json"}):
        _fail("attest_code", "runtime_configuration_mismatch")
    actual: dict[str, str] = {}
    captured: dict[str, tuple[bytes, Path]] = {}
    for role, relative in _CODE_PATHS.items():
        raw, path = _code_capture(source_root, role)
        digest = _sha(raw)
        actual[role] = digest
        captured[role] = raw, path
    if actual != dict(trust.execution_code_raw_sha256):
        _fail("attest_code", "source_hash_mismatch")
    for role in EXECUTION_CODE_ROLES - {"cli"}:
        raw, path = captured[role]
        _attest_module(role, raw, path)
    # Attest the CLI's live definitions even when the caller uses the API
    # directly instead of executing the script as __main__.
    cli_path = captured["cli"][1]
    invoked = Path(os.path.abspath(sys.argv[0])) if sys.argv and sys.argv[0] else None
    if invoked == cli_path:
        main_module = sys.modules.get("__main__")
        if (main_module is None or Path(os.path.abspath(getattr(main_module, "__file__", ""))) != cli_path):
            _fail("attest_code", "cli_origin_mismatch")
        _attest_module("cli", captured["cli"][0], cli_path, main_module)
    else:
        loaded = []
        for candidate in tuple(sys.modules.values()):
            candidate_file = getattr(candidate, "__file__", None)
            if isinstance(candidate_file, str) and Path(os.path.abspath(candidate_file)) == cli_path:
                loaded.append(candidate)
        if len(loaded) > 1:
            _fail("attest_code", "ambiguous_cli_module")
        if loaded:
            _attest_module("cli", captured["cli"][0], cli_path, loaded[0])
        else:
            name = "_privoke_in_house_cli_attestation"
            spec = importlib.util.spec_from_file_location(name, cli_path)
            if spec is None or spec.loader is None:
                _fail("attest_code", "cli_loader_missing")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            try:
                spec.loader.exec_module(module)
                _attest_module("cli", captured["cli"][0], cli_path, module)
            except InHousePreparationError:
                raise
            except Exception:
                _fail("attest_code", "cli_import_failed")
            finally:
                sys.modules.pop(name, None)
    _recheck_code(source_root, actual)
    if (_SOURCE_MODULES != {
            "parser": native, "structure": structure, "grouping": grouping, "review_helper": review,
            "protection_core": protection_core, "protection_io": protection_io,
            "fixture_validator": fixture, "normalizer": training_data,
            "in_house_review": in_house, "in_house_review_io": sys.modules[__name__]}):
        _fail("attest_code", "source_registry_mismatch")
    if (parse_native_row is not native.parse_native_row
            or validate_arrow_schema is not native.validate_arrow_schema
            or build_review_pool is not review.build_review_pool
            or protected_keys_digest is not review.protected_keys_digest
            or ReviewBindings is not review.ReviewBindings
            or ValidatedNativeSpanInput is not review.ValidatedNativeSpanInput
            or validate_protected_union is not structure.validate_protected_union
            or validate_source_audit is not structure.validate_source_audit
            or verify_parquet_bytes is not structure.verify_parquet_bytes
            or open_verified_parquet is not structure.open_verified_parquet
            or aggregate_scan is not structure.aggregate_scan
            or canonical_json_bytes is not structure.canonical_json_bytes
            or require_frozen_text_inputs is not structure.require_frozen_text_inputs
            or validate_training_data_source is not structure.validate_training_data_source
            or PARQUET_ROWS != structure.PARQUET_ROWS
            or validate_fixture_addon is not fixture.validate_fixture_addon
            or structure.parse_native_row is not native.parse_native_row
            or structure.build_components is not grouping.build_components
            or review.build_components is not grouping.build_components
            or review.training_text_key is not training_data.training_text_key
            or protection_io.build_full_protected_key_union is not protection_core.build_full_protected_key_union
            or fixture.ProtectedKeys is not grouping.ProtectedKeys
            or fixture.training_text_key is not training_data.training_text_key
            or in_house.build_review_pool is not review.build_review_pool
            or in_house.protected_keys_digest is not review.protected_keys_digest
            or in_house.ProtectedKeys is not grouping.ProtectedKeys
            or in_house.combined_protection_digest is not fixture.combined_protection_digest
            or in_house.training_text_key is not training_data.training_text_key
            or in_house.build_in_house_review_pool is not build_in_house_review_pool
            or training_data.training_text_key is not grouping.training_text_key):
        _fail("attest_code", "import_alias_mismatch")
    _check_semantic_contracts()
    return actual


def _recheck_code(source_root: Path, expected: Mapping[str, str]) -> None:
    for role in _CODE_PATHS:
        raw, _ = _code_capture(source_root, role)
        if _sha(raw) != expected[role]:
            _fail("recheck_code", "source_changed")


def _verify_execution_edge(source_root: Path, trust: InHousePreparationTrust,
                           expected: Mapping[str, str], captures: Mapping[str, _Capture] | None = None) -> None:
    if captures is not None:
        _recheck_inputs(captures)
    if _attest_code(source_root, trust) != dict(expected):
        _fail("attest_code", "execution_binding_changed")
    _recheck_code(source_root, expected)


def _parser_contract_snapshot() -> tuple[Any, ...]:
    functions = (native.parse_native_row, native.validate_arrow_schema)
    return (
        parse_native_row, validate_arrow_schema, grouping.GroupingRow, grouping.NativeIdentifier,
        tuple((fn, fn.__code__, fn.__defaults__, fn.__kwdefaults__, fn.__annotations__, fn.__globals__)
              for fn in functions),
        tuple((name, vars(native).get(name)) for name in _PARSER_CONSTANTS),
    )


def _verify_parser_edge(snapshot: tuple[Any, ...]) -> None:
    try:
        parser_alias, schema_alias, row_type, identifier_type, functions, constants = snapshot
        if (parse_native_row is not parser_alias or parse_native_row is not native.parse_native_row
                or parse_native_row.__globals__ is not vars(native)
                or validate_arrow_schema is not schema_alias or validate_arrow_schema is not native.validate_arrow_schema
                or grouping.GroupingRow is not row_type or grouping.NativeIdentifier is not identifier_type
                or native.GroupingRow is not row_type or native.NativeIdentifier is not identifier_type):
            _fail("parse_source", "parser_binding_changed")
        for fn, code, defaults, kwdefaults, annotations, globals_dict in functions:
            if (fn.__code__ is not code or fn.__defaults__ != defaults or fn.__kwdefaults__ != kwdefaults
                    or fn.__annotations__ != annotations or globals_dict is not vars(native)
                    or fn.__globals__ is not vars(native)):
                _fail("parse_source", "parser_function_changed")
        for name, expected in constants:
            if not _semantic_value_equal(vars(native).get(name), expected):
                _fail("parse_source", "parser_constant_changed")
        _check_semantic_contracts()
    except InHousePreparationError:
        raise
    except Exception:
        _fail("parse_source", "parser_binding_changed")


def _decode_pin_manifest(raw: bytes, trust: InHousePreparationTrust, code_hashes: Mapping[str, str],
                         source_root: Path) -> None:
    value = _strict_json(raw, "validate_pin_manifest")
    if (not isinstance(value, dict) or set(value) != {"schema_version", "kind", "source_revision", "files"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["kind"] != _PIN_KIND or value["source_revision"] != trust.source_revision
            or not isinstance(value["files"], dict) or set(value["files"]) != set(_CODE_PATHS)):
        _fail("validate_pin_manifest", "schema_mismatch")
    file_hashes = {}
    for role, item in value["files"].items():
        if (not isinstance(item, dict) or set(item) != {"path", "raw_sha256", "canonical_lf_sha256"}
                or item["path"] != _CODE_PATHS[role].as_posix() or not _valid_sha(item["raw_sha256"])
                or not _valid_sha(item["canonical_lf_sha256"])):
            _fail("validate_pin_manifest", "file_binding_mismatch")
        file_hashes[role] = item["raw_sha256"]
        code_raw, _ = _code_capture(source_root, role)
        canonical_sha = _sha(_canonical_lf(code_raw))
        if item["canonical_lf_sha256"] != canonical_sha:
            _fail("validate_pin_manifest", "canonical_digest_mismatch")
    if file_hashes != dict(code_hashes) or code_hashes != dict(trust.execution_code_raw_sha256):
        _fail("validate_pin_manifest", "external_binding_mismatch")


def _paths_for_captured(paths: InHouseReviewIOPaths, captures: Mapping[str, _Capture]) -> InHouseReviewIOPaths:
    return InHouseReviewIOPaths(**{role: captures[role].snapshot_path for role in _INPUT_ROLES}, output=paths.output)


def _protection_preflight(paths: InHouseReviewIOPaths, captures: Mapping[str, _Capture],
                          trust: InHousePreparationTrust, code_hashes: Mapping[str, str],
                          source_root: Path) -> tuple[InHouseProtectionBindings, dict[str, int], ProtectedKeys]:
    snapshots = _paths_for_captured(paths, captures)
    _verify_execution_edge(source_root, trust, code_hashes, captures)
    _decode_pin_manifest(captures["pin_manifest"].data, trust, code_hashes, source_root)
    _verify_execution_edge(source_root, trust, code_hashes, captures)
    source_meta = validate_source_audit(snapshots.source_audit)
    if source_meta.get("source_audit_sha256") != captures["source_audit"].sha256:
        _fail("validate_source_audit", "captured_hash_mismatch")
    _verify_execution_edge(source_root, trust, code_hashes, captures)
    if verify_parquet_bytes(snapshots.parquet) != captures["parquet"].sha256:
        _fail("verify_parquet", "captured_hash_mismatch")
    _verify_execution_edge(source_root, trust, code_hashes, captures)
    text_meta = require_frozen_text_inputs(snapshots.protocol, snapshots.rubric)
    _verify_execution_edge(source_root, trust, code_hashes, captures)
    historical, historical_meta = validate_protected_union(
        snapshots.protected_union, snapshots.protection_receipt, trust.historical_receipt_raw_sha256)
    if (historical_meta.get("artifact_sha256") != captures["protected_union"].sha256
            or historical_meta.get("receipt_sha256") != captures["protection_receipt"].sha256):
        _fail("validate_historical_protection", "captured_hash_mismatch")
    historical_helpers = historical_meta.get("helper_source_hashes")
    expected_historical = {
        "protection_io_sha256": code_hashes["protection_io"],
        "protection_core_sha256": code_hashes["protection_core"],
        "grouping_core_sha256": code_hashes["grouping"],
        "training_data_sha256": code_hashes["normalizer"],
    }
    if historical_helpers != expected_historical:
        _fail("validate_historical_protection", "helper_pin_mismatch")
    _verify_execution_edge(source_root, trust, code_hashes, captures)
    if validate_training_data_source(source_root / _CODE_PATHS["normalizer"]) != code_hashes["normalizer"]:
        _fail("validate_normalizer", "helper_pin_mismatch")
    _verify_execution_edge(source_root, trust, code_hashes, captures)
    addon = validate_fixture_addon(
        _canonical_lf(captures["fixture"].data), _canonical_lf(captures["fixture_rubric"].data),
        captures["fixture_review"].data, captures["addon_artifact"].data, captures["addon_receipt"].data,
        expected_receipt_sha256=trust.addon_receipt_raw_sha256,
        expected_source_revision=trust.addon_producer_revision,
        expected_helper_source_hashes=trust.addon_helper_raw_sha256,
    )
    if type(addon) is not ProtectedKeys:
        _fail("validate_addon", "invalid_keys")
    _verify_execution_edge(source_root, trust, code_hashes, captures)
    addon_artifact = _strict_json(captures["addon_artifact"].data, "validate_addon")
    addon_content = addon_artifact.get("addon_content_sha256") if isinstance(addon_artifact, dict) else None
    if not _valid_sha(addon_content):
        _fail("validate_addon", "invalid_content_digest")
    _verify_execution_edge(source_root, trust, code_hashes, captures)
    combined = fixture.combine_protected_keys(historical, addon)
    protection_bindings = InHouseProtectionBindings(
        historical_artifact_raw_sha256=captures["protected_union"].sha256,
        historical_receipt_raw_sha256=captures["protection_receipt"].sha256,
        historical_union_content_sha256=historical_meta["union_sha256"],
        addon_artifact_raw_sha256=captures["addon_artifact"].sha256,
        addon_receipt_raw_sha256=captures["addon_receipt"].sha256,
        addon_content_sha256=addon_content,
        combined_protection_sha256=fixture.combined_protection_digest(combined),
        internal_protected_keys_sha256=review.protected_keys_digest(combined),
        fixture_input_raw_sha256={key: captures[role].sha256 for key, role in
                                  (("fixture", "fixture"), ("rubric", "fixture_rubric"), ("review", "fixture_review"))},
        fixture_input_consumed_sha256={
            "fixture": _sha(_canonical_lf(captures["fixture"].data)),
            "rubric": _sha(_canonical_lf(captures["fixture_rubric"].data)),
            "review": captures["fixture_review"].sha256,
        },
        addon_producer_revision=trust.addon_producer_revision,
        addon_helper_raw_sha256=trust.addon_helper_raw_sha256,
    )
    if (protection_bindings.professor_confirmation != "pending"
            or protection_bindings.review_status != "reviewed"):
        _fail("validate_addon", "review_state_mismatch")
    counts = {
        "historical_ids": len(historical.ids), "historical_groups": len(historical.groups),
        "historical_exact_text_hashes": len(historical.exact_text_sha256),
        "historical_normalized_text_keys": len(historical.normalized_texts),
        "addon_ids": len(addon.ids), "addon_groups": len(addon.groups),
        "addon_exact_text_hashes": len(addon.exact_text_sha256),
        "addon_normalized_text_keys": len(addon.normalized_texts),
        "combined_ids": len(combined.ids), "combined_groups": len(combined.groups),
        "combined_exact_text_hashes": len(combined.exact_text_sha256),
        "combined_normalized_text_keys": len(combined.normalized_texts),
    }
    _ = text_meta, source_meta
    return protection_bindings, counts, combined


def prepare_in_house_protection_bindings(paths: InHouseReviewIOPaths, *, trust: InHousePreparationTrust,
                                         source_root: Path) -> InHouseProtectionPreflight:
    """Validate protections from the same twelve snapshots without opening Parquet."""
    try:
        if not _platform_supported():
            _fail("platform", "posix_descriptor_io_required")
        _trusted_maps(trust)
        if trust.expected_protection_bindings is not None:
            _fail("validate_trust", "unexpected_binding_in_preflight")
        code_hashes = _attest_code(source_root, trust)
        with _capture_all(paths, trust) as (_originals, captures, _snapshot_root):
            _verify_execution_edge(source_root, trust, code_hashes, captures)
            binding, counts, _combined = _protection_preflight(paths, captures, trust, code_hashes, source_root)
            _recheck_inputs(captures)
            _recheck_code(source_root, code_hashes)
            return InHouseProtectionPreflight(binding, counts,
                {key: value.sha256 for key, value in captures.items()}, code_hashes)
    except InHousePreparationError:
        raise
    except Exception:
        _fail("protection_preflight", "validation_failed")


class _PrivateOutput:
    def __init__(self, project_root: Path, output: Path):
        self.project_root = project_root
        self.output = output
        self.results = project_root / "evaluation" / "results"
        self.results_fd = -1
        self.root_fd = -1
        self.evaluation_fd = -1
        self.output_fd = -1
        self.results_identity = None
        self.output_identity = None
        self.files: dict[str, tuple[tuple[int, int, int, int], int, str]] = {}

    def __enter__(self):
        try:
            if not _platform_supported() or not self.project_root.is_absolute() or not self.output.is_absolute():
                _fail("output", "posix_descriptor_io_required")
            if self.output.parent != self.results or self.output.exists() or self.output.is_symlink():
                _fail("output", "not_fresh_results_child")
            self._check_dir(self.project_root)
            root_path_identity = _identity(os.lstat(self.project_root))
            self.root_fd = os.open(self.project_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            if _identity(os.fstat(self.root_fd)) != root_path_identity:
                _fail("output", "root_identity_changed")
            evaluation_before = os.stat("evaluation", dir_fd=self.root_fd, follow_symlinks=False)
            if not stat.S_ISDIR(evaluation_before.st_mode) or _is_reparse(evaluation_before):
                _fail("output", "unsafe_directory")
            self.evaluation_fd = os.open("evaluation", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                         dir_fd=self.root_fd)
            self.root_identity = _identity(os.fstat(self.root_fd))
            self.evaluation_identity = _identity(os.fstat(self.evaluation_fd))
            if self.evaluation_identity != _identity(evaluation_before):
                _fail("output", "evaluation_identity_changed")
            results_before = os.stat("results", dir_fd=self.evaluation_fd, follow_symlinks=False)
            if not stat.S_ISDIR(results_before.st_mode) or _is_reparse(results_before):
                _fail("output", "unsafe_directory")
            self.results_fd = os.open("results", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                      dir_fd=self.evaluation_fd)
            self.results_identity = _identity(os.fstat(self.results_fd))
            if self.results_identity != _identity(results_before):
                _fail("output", "results_identity_changed")
            if (_identity(os.lstat(self.project_root)) != self.root_identity
                    or _identity(os.lstat(self.project_root / "evaluation")) != self.evaluation_identity
                    or _identity(os.lstat(self.results)) != self.results_identity):
                _fail("output", "ancestor_path_changed")
            os.mkdir(self.output.name, 0o700, dir_fd=self.results_fd)
            os.fsync(self.results_fd)
            self.output_fd = os.open(self.output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                     dir_fd=self.results_fd)
            os.fchmod(self.output_fd, 0o700)
            info = os.fstat(self.output_fd)
            if stat.S_IMODE(info.st_mode) != 0o700:
                _fail("output", "private_mode_unavailable")
            self.output_identity = _identity(info)
            self.verify()
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    @staticmethod
    def _check_dir(path: Path):
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or _is_reparse(info) or path.is_symlink():
            _fail("output", "unsafe_directory")

    def verify(self):
        self._check_dir(self.results)
        if (_identity(os.lstat(self.project_root)) != self.root_identity
                or _identity(os.lstat(self.project_root / "evaluation")) != self.evaluation_identity
                or _identity(os.lstat(self.results)) != self.results_identity):
            _fail("output", "ancestor_path_changed")
        root_child = os.stat("evaluation", dir_fd=self.root_fd, follow_symlinks=False)
        results_child = os.stat("results", dir_fd=self.evaluation_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(root_child.st_mode) or not stat.S_ISDIR(results_child.st_mode)
                or _identity(root_child) != self.evaluation_identity
                or _identity(results_child) != self.results_identity
                or _identity(os.fstat(self.root_fd)) != self.root_identity
                or _identity(os.fstat(self.evaluation_fd)) != self.evaluation_identity):
            _fail("output", "ancestor_identity_changed")
        if _identity(os.fstat(self.results_fd)) != self.results_identity:
            _fail("output", "results_identity_changed")
        info = os.stat(self.output.name, dir_fd=self.results_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or _identity(info) != self.output_identity
                or _identity(os.fstat(self.output_fd)) != self.output_identity):
            _fail("output", "output_identity_changed")
        self._check_dir(self.output)
        if set(os.listdir(self.output_fd)) != set(self.files):
            _fail("output", "unexpected_output_entry")
        for name, expected in self.files.items():
            self._verify_named_file(name, expected)

    def _verify_named_file(self, filename: str,
                           expected: tuple[tuple[int, int, int], int, str]) -> None:
        expected_identity, expected_size, expected_sha = expected
        try:
            named = os.stat(filename, dir_fd=self.output_fd, follow_symlinks=False)
            if (not stat.S_ISREG(named.st_mode) or _is_reparse(named)
                    or _identity(named) != expected_identity
                    or stat.S_IMODE(named.st_mode) != 0o600
                    or named.st_uid != os.geteuid() or named.st_nlink != 1
                    or named.st_size != expected_size):
                _fail("output", "published_file_identity_changed")
            fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                         dir_fd=self.output_fd)
            try:
                before = os.fstat(fd)
                if (_identity(before) != expected_identity or not stat.S_ISREG(before.st_mode)
                        or stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.geteuid()
                        or before.st_nlink != 1 or before.st_size != expected_size):
                    _fail("output", "published_file_identity_changed")
                digest = hashlib.sha256()
                total = 0
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    digest.update(chunk)
                after = os.fstat(fd)
                if (_identity(after) != expected_identity or total != expected_size
                        or digest.hexdigest() != expected_sha):
                    _fail("output", "published_file_content_changed")
            finally:
                os.close(fd)
        except InHousePreparationError:
            raise
        except OSError:
            _fail("output", "published_file_unavailable")

    def write(self, filename: str, payload: bytes) -> str:
        if filename not in _PRIVATE_OUTPUTS:
            _fail("output", "filename_not_allowed")
        try:
            self.verify()
            fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=self.output_fd)
        except InHousePreparationError:
            raise
        except OSError:
            _fail("output", "exclusive_file_create_failed")
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(payload)
            position = 0
            while position < len(view):
                written = os.write(fd, view[position:])
                if written <= 0:
                    _fail("output", "write_failed")
                position += written
            os.fsync(fd)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_size != len(payload)):
                _fail("output", "file_mode_unavailable")
            expected = (_identity(info), len(payload), _sha(payload))
            self._verify_named_file(filename, expected)
            self.files[filename] = expected
            os.fsync(self.output_fd)
            self.verify()
        except InHousePreparationError:
            raise
        except OSError:
            _fail("output", "private_file_write_failed")
        finally:
            try:
                os.close(fd)
            except OSError:
                _fail("output", "private_file_close_failed")
        return _sha(payload)

    def __exit__(self, exc_type, exc, tb):
        for fd in (self.output_fd, self.results_fd, self.evaluation_fd, self.root_fd):
            if fd >= 0:
                os.close(fd)
        return False


def _span_inputs(raw: Mapping[str, object], parsed: Any) -> tuple[ValidatedNativeSpanInput, ...]:
    spans = raw.get("pii_spans")
    if not isinstance(spans, list):
        _fail("parse_source", "span_shape")
    values = []
    for span in spans:
        if not isinstance(span, Mapping):
            _fail("parse_source", "span_shape")
        base = span.get("value")
        fuzzy = span.get("value_fuzzy")
        literal = fuzzy if isinstance(fuzzy, str) and fuzzy else base
        if not isinstance(literal, str):
            _fail("parse_source", "span_literal")
        values.append(ValidatedNativeSpanInput(span.get("type"), span.get("start"), span.get("end"),
                                               literal, base if isinstance(base, str) else None))
    if len(values) != parsed.valid_span_count:
        _fail("parse_source", "span_count_mismatch")
    return tuple(values)


def _iter_rows(parquet: Any, *, edge_guard=None, parser_snapshot: tuple[Any, ...] | None = None):
    seen: set[int] = set()
    if edge_guard is not None:
        edge_guard()
    for batch in parquet.iter_batches(batch_size=256):
        if edge_guard is not None:
            edge_guard()
        validate_arrow_schema(batch.schema)
        if edge_guard is not None:
            edge_guard()
        rows = batch.to_pylist()
        for raw in rows:
            if parser_snapshot is not None:
                _verify_parser_edge(parser_snapshot)
            if not isinstance(raw, Mapping):
                _fail("parse_source", "row_shape")
            parsed = parse_native_row(raw)
            uid = parsed.grouping_row.uid
            if uid in seen:
                _fail("parse_source", "duplicate_uid")
            seen.add(uid)
            yield raw, parsed


def _expected_bindings(value: Mapping[str, Any] | str | InHouseProtectionBindings | None) -> InHouseProtectionBindings:
    if type(value) is InHouseProtectionBindings:
        return value
    if isinstance(value, str):
        def pairs(items):
            result = {}
            for key, item in items:
                if key in result:
                    raise ValueError("duplicate property")
                result[key] = item
            return result
        try:
            value = json.loads(value, object_pairs_hook=pairs,
                               parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
        except (ValueError, json.JSONDecodeError):
            _fail("compare_protection_bindings", "malformed_expected_binding")
    if not isinstance(value, Mapping):
        _fail("compare_protection_bindings", "expected_binding_required")
    try:
        result = InHouseProtectionBindings(**dict(value))
    except Exception:
        _fail("compare_protection_bindings", "malformed_expected_binding")
    return result


def _source_rows_and_pool(paths: InHouseReviewIOPaths, captures: Mapping[str, _Capture], trust: InHousePreparationTrust,
                          code_hashes: Mapping[str, str], protection_binding: InHouseProtectionBindings,
                          combined: ProtectedKeys, output: _PrivateOutput) -> InHousePreparationResult:
    snapshots = _paths_for_captured(paths, captures)
    def edge():
        _verify_execution_edge(paths.output.parents[2], trust, code_hashes, captures)

    stage = "validate_source_audit"
    try:
        edge()
        source_audit = validate_source_audit(snapshots.source_audit)
        edge()
        text_bindings = require_frozen_text_inputs(snapshots.protocol, snapshots.rubric)
        if source_audit["source_audit_sha256"] != captures["source_audit"].sha256:
            _fail(stage, "captured_source_audit_mismatch")
        edge()
        if verify_parquet_bytes(snapshots.parquet) != captures["parquet"].sha256:
            _fail("verify_parquet", "captured_hash_mismatch")
        edge()
        stage = "open_parquet"
        parquet = open_verified_parquet(snapshots.parquet)
        edge()
        validate_arrow_schema(parquet.schema_arrow)
        edge()
        if parquet.metadata.num_rows != PARQUET_ROWS:
            _fail("validate_parquet", "row_count_mismatch")
        edge()
        parsed_rows = []
        spans_by_uid = {}
        stage = "scan_source"
        parser_snapshot = _parser_contract_snapshot()
        for raw, parsed in _iter_rows(parquet, edge_guard=edge, parser_snapshot=parser_snapshot):
            parsed_rows.append(parsed)
            if parsed.grouping_row.eligible:
                spans_by_uid[parsed.grouping_row.uid] = _span_inputs(raw, parsed)
        if len(parsed_rows) != PARQUET_ROWS:
            _fail("scan_source", "row_count_mismatch")
        edge()
        stage = "close_graph"
        _counts, graph = aggregate_scan(parsed_rows, combined, expected_rows=PARQUET_ROWS)
        edge()
        if (review.protected_keys_digest(combined) != protection_binding.internal_protected_keys_sha256
                or fixture.combined_protection_digest(combined) != protection_binding.combined_protection_sha256):
            _fail("compare_protection_bindings", "key_digest_mismatch")
        legacy = ReviewBindings(
            source_revision=trust.source_revision, source_sha256=captures["parquet"].sha256,
            protocol_sha256=text_bindings["protocol_sha256"], rubric_sha256=text_bindings["rubric_sha256"],
            parser_sha256=code_hashes["parser"], grouping_sha256=code_hashes["grouping"],
            normalizer_sha256=code_hashes["normalizer"],
            protected_union_sha256=protection_binding.historical_union_content_sha256,
            protected_keys_sha256=protection_binding.internal_protected_keys_sha256,
        )
        bindings = InHouseReviewBindings(
            legacy=legacy, protection=protection_binding,
            preparation_pin_manifest_raw_sha256=captures["pin_manifest"].sha256,
            execution_code_raw_sha256=code_hashes,
        )
        stage = "build_pool"
        pool = in_house.build_in_house_review_pool(tuple(parsed_rows), graph, bindings, combined, spans_by_uid)
        edge()
        in_house.validate_in_house_review_pool(pool, trusted_bindings=bindings)
        edge()
        packages_payload = b"".join(canonical_json_bytes({
            "review_id": package.review_id, "text": package.text, "text_sha256": package.text_sha256,
            "rubric_sha256": package.rubric_sha256,
            "native_spans": [{"entity_type": span.entity_type, "start": span.start, "end": span.end}
                             for span in package.native_spans],
        }) + b"\n" for package in pool.core.packages)
        map_payload = b"".join(canonical_json_bytes({
            "review_id": member.review_id, "source_uid": member.uid, "component_id": member.component_id,
            "source_text_sha256": member.exact_text_sha256, "native_category": member.native_category,
            "structural_eligible": member.structural_eligible,
            "native_span_types": [span.entity_type for span in member.native_spans],
        }) + b"\n" for member in pool.core._members)
        edge()
        package_sha = output.write("review-packages.jsonl", packages_payload)
        edge()
        map_sha = output.write("private-review-map.jsonl", map_payload)
        counts = {"source_rows": len(parsed_rows), "pool_size": pool.core.pool_size,
                  "graph_components": graph.component_count, "assignable_rows": graph.assignable_row_count}
        manifest = {
            "schema_version": 1, "kind": "privoke-in-house-blind-review-preparation-v1",
            "status": "complete", "scope": "review_preparation_only", "source_revision": trust.source_revision,
            "preparation_identity": pool.preparation_identity, "review_pool_sha256": pool.review_pool_sha256,
            "bindings": bindings.to_dict(), "input_raw_sha256": {k: captures[k].sha256 for k in _INPUT_ROLES},
            "input_consumed_sha256": {
                role: _sha(_canonical_lf(captures[role].data)
                           if role in {"protocol", "rubric", "fixture", "fixture_rubric"}
                           else captures[role].data)
                for role in _INPUT_ROLES
            },
            "execution_code_raw_sha256": dict(code_hashes), "source_audit_sha256": source_audit["source_audit_sha256"],
            "parquet_sha256": captures["parquet"].sha256, "protocol_sha256": text_bindings["protocol_sha256"],
            "rubric_sha256": text_bindings["rubric_sha256"], "counts": counts,
            "review_status": "assistant_provisional_professor_pending", "no_allocation": True,
            "no_model_scoring": True, "not_authorized_for_fitting": True,
            "review_packages_file": "review-packages.jsonl", "review_packages_sha256": package_sha,
            "private_review_map_file": "private-review-map.jsonl", "private_review_map_sha256": map_sha,
            "legacy_pool_sha256": pool.core.pool_sha256,
            "graph_membership_sha256": pool.core.graph_membership_sha256,
            "private_members_sha256": pool.core.private_members_sha256,
            "private_directory_mode": "0700", "private_file_mode": "0600", "platform": "posix",
        }
        edge()
        manifest_sha = output.write("manifest.json", canonical_json_bytes(manifest) + b"\n")
        return InHousePreparationResult("complete", paths.output, pool.preparation_identity,
                                        pool.review_pool_sha256,
                                        {"review-packages.jsonl": package_sha, "private-review-map.jsonl": map_sha,
                                         "manifest.json": manifest_sha}, counts)
    except InHousePreparationError:
        raise
    except Exception:
        _fail(stage, "preparation_failed")


def _combined_keys_from_binding_sources(paths: InHouseReviewIOPaths, captures: Mapping[str, _Capture],
                                        trust: InHousePreparationTrust) -> ProtectedKeys:
    snapshots = _paths_for_captured(paths, captures)
    historical, _ = validate_protected_union(snapshots.protected_union, snapshots.protection_receipt,
                                               trust.historical_receipt_raw_sha256)
    addon = validate_fixture_addon(_canonical_lf(captures["fixture"].data),
        _canonical_lf(captures["fixture_rubric"].data), captures["fixture_review"].data,
        captures["addon_artifact"].data, captures["addon_receipt"].data,
        expected_receipt_sha256=trust.addon_receipt_raw_sha256,
        expected_source_revision=trust.addon_producer_revision,
        expected_helper_source_hashes=trust.addon_helper_raw_sha256)
    return fixture.combine_protected_keys(historical, addon)


def prepare_in_house_review_pool(paths: InHouseReviewIOPaths, *, trust: InHousePreparationTrust,
                                 source_root: Path, results_root: Path) -> InHousePreparationResult:
    """Revalidate frozen protection bindings, scan all rows, and publish privately."""
    stage = "validate_trust"
    output_context = None
    try:
        if not _platform_supported():
            _fail("platform", "posix_descriptor_io_required")
        _trusted_maps(trust)
        if results_root != source_root / "evaluation" / "results":
            _fail("output", "unapproved_results_root")
        if not source_root.is_absolute() or paths.output.parent != results_root:
            _fail("output", "unapproved_output_path")
        output_context = _PrivateOutput(source_root, paths.output).__enter__()
        stage = "attest_code"
        code_hashes = _attest_code(source_root, trust)
        with _capture_all(paths, trust) as (_originals, captures, _snapshot_root):
            _verify_execution_edge(source_root, trust, code_hashes, captures)
            expected = _expected_bindings(trust.expected_protection_bindings)
            stage = "validate_protection_bindings"
            actual, _counts, combined = _protection_preflight(paths, captures, trust, code_hashes, source_root)
            if actual != expected:
                _fail("validate_protection_bindings", "external_freeze_mismatch")
            _recheck_inputs(captures)
            _recheck_code(source_root, code_hashes)
            stage = "prepare_source"
            result = _source_rows_and_pool(paths, captures, trust, code_hashes, actual, combined, output_context)
            output_context.verify()
            return result
    except Exception:
        if output_context is not None:
            try:
                output_context.verify()
                output_context.write("failure.json", canonical_json_bytes({
                    "schema_version": 1, "status": "failed", "stage": stage,
                    "error_code": "preparation_failed",
                }) + b"\n")
            except Exception:
                pass
        raise InHousePreparationError(f"{stage}:preparation_failed") from None
    finally:
        if output_context is not None:
            output_context.__exit__(None, None, None)
