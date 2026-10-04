"""Synthetic-only tests for the addon-aware private preparation boundary."""
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "evaluation"), str(ROOT / "shared/python")]
import privoke_eval.in_house_advpii_review_io as io
from privoke_eval.in_house_advpii_review import EXECUTION_CODE_ROLES, InHouseProtectionBindings
from privoke_eval.in_house_advpii_review_io import InHousePreparationTrust
from privoke_eval.clean_augmentation_grouping import ProtectedKeys

D = "a" * 64


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def binding() -> InHouseProtectionBindings:
    return InHouseProtectionBindings(
        D, "b" * 64, "c" * 64, "d" * 64, "e" * 64, "f" * 64, "1" * 64, "2" * 64,
        {key: D for key in ("fixture", "rubric", "review")},
        {key: D for key in ("fixture", "rubric", "review")}, "3" * 40,
        {key: D for key in ("grouping", "normalizer", "fixture_validator")},
    )


def make_inputs(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    paths = {}
    for role in io._INPUT_ROLES:
        path = root / f"synthetic-{role}.dat"
        path.write_bytes(("synthetic " + role).encode())
        paths[role] = path
    record = io.InHouseReviewIOPaths(**paths, output=root / "unused-output")
    hashes = {role: sha(path.read_bytes()) for role, path in paths.items()}
    trust = InHousePreparationTrust(
        "4" * 40, hashes, hashes["pin_manifest"], hashes["protection_receipt"],
        hashes["addon_receipt"], "5" * 40,
        {key: D for key in ("grouping", "normalizer", "fixture_validator")},
        {key: D for key in EXECUTION_CODE_ROLES}, io.in_house.PLAN_SHA256,
        io.in_house.PREPARATION_DESIGN_SHA256, io.in_house.ALLOCATOR_DESIGN_SHA256,
    )
    return record, trust


def make_preflight_fixture(root: Path):
    paths, _ = make_inputs(root / "inputs")
    source_root = root / "synthetic-repository"
    code_hashes = {}
    for role, relative in io._CODE_PATHS.items():
        raw = (ROOT / relative).read_bytes()
        destination = source_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        code_hashes[role] = sha(raw)
    paths.addon_artifact.write_bytes(json.dumps({"addon_content_sha256": D}, separators=(",", ":")).encode())
    pin_value = {
        "schema_version": 1, "kind": io._PIN_KIND, "source_revision": "4" * 40,
        "files": {role: {"path": relative.as_posix(), "raw_sha256": code_hashes[role],
                          "canonical_lf_sha256": sha(io._canonical_lf((source_root / relative).read_bytes()))}
                  for role, relative in io._CODE_PATHS.items()},
    }
    paths.pin_manifest.write_bytes(json.dumps(pin_value, sort_keys=True, separators=(",", ":")).encode())
    input_hashes = {role: sha(getattr(paths, role).read_bytes()) for role in io._INPUT_ROLES}
    helper_hashes = {role: code_hashes[role]
                     for role in ("grouping", "normalizer", "fixture_validator")}
    trust = io.InHousePreparationTrust(
        "4" * 40, input_hashes, input_hashes["pin_manifest"], input_hashes["protection_receipt"],
        input_hashes["addon_receipt"], "5" * 40, helper_hashes, code_hashes,
        io.in_house.PLAN_SHA256, io.in_house.PREPARATION_DESIGN_SHA256,
        io.in_house.ALLOCATOR_DESIGN_SHA256,
    )
    return paths, trust, source_root, code_hashes


class FakeBatch:
    def __init__(self, rows, schema="schema"):
        self.rows, self.schema, self.converted = rows, schema, False

    def to_pylist(self):
        self.converted = True
        return self.rows


class FakeParsed:
    def __init__(self, uid, eligible=True, spans=0):
        self.grouping_row = type("GroupRow", (), {"uid": uid, "eligible": eligible})()
        self.valid_span_count = spans


class PreparationIOTests(unittest.TestCase):
    def test_strict_trust_role_maps_and_revision_hash_types(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, trust = make_inputs(Path(temporary) / "input")
        io._trusted_maps(trust)
        with self.assertRaises(io.InHousePreparationError):
            io._trusted_maps(replace(trust, input_raw_sha256={**trust.input_raw_sha256, "unknown": D}))
        with self.assertRaises(io.InHousePreparationError):
            io._trusted_maps(replace(trust, source_revision="A" * 40))
        with self.assertRaises(io.InHousePreparationError):
            io._trusted_maps(replace(trust, execution_code_raw_sha256={"cli": D}))

    def test_trust_copies_and_freezes_caller_owned_mapping_inputs(self):
        input_pins = {role: D for role in io._INPUT_ROLES}
        helper_pins = {role: D for role in ("grouping", "normalizer", "fixture_validator")}
        code_pins = {role: D for role in EXECUTION_CODE_ROLES}
        expected = binding().to_dict()
        trust = io.InHousePreparationTrust(
            "4" * 40, input_pins, D, D, D, "5" * 40, helper_pins, code_pins,
            io.in_house.PLAN_SHA256, io.in_house.PREPARATION_DESIGN_SHA256,
            io.in_house.ALLOCATOR_DESIGN_SHA256, expected,
        )
        input_pins["parquet"] = "e" * 64
        helper_pins["grouping"] = "f" * 64
        code_pins["cli"] = "9" * 64
        expected["fixture_input_raw_sha256"]["fixture"] = "8" * 64
        self.assertEqual(trust.input_raw_sha256["parquet"], D)
        self.assertEqual(trust.addon_helper_raw_sha256["grouping"], D)
        self.assertEqual(trust.execution_code_raw_sha256["cli"], D)
        self.assertEqual(trust.expected_protection_bindings["fixture_input_raw_sha256"]["fixture"], D)
        with self.assertRaises(TypeError):
            trust.expected_protection_bindings["kind"] = "mutated"

    @unittest.skipUnless(io._platform_supported(), "POSIX descriptor protections are required")
    def test_public_preflight_captures_all_inputs_before_validation_and_never_opens_parquet(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths, trust, source_root, code_hashes = make_preflight_fixture(Path(temporary))
            input_hashes = trust.input_raw_sha256
            historical, addon = ProtectedKeys(ids=frozenset({D})), ProtectedKeys(groups=frozenset({"b" * 64}))
            expected_helpers = {
                "protection_io_sha256": code_hashes["protection_io"],
                "protection_core_sha256": code_hashes["protection_core"],
                "grouping_core_sha256": code_hashes["grouping"],
                "training_data_sha256": code_hashes["normalizer"],
            }
            captured_roles = []
            events = []
            capture_file, recheck_inputs, strict_json = io._capture_file, io._recheck_inputs, io._strict_json
            def capture(*args):
                item = capture_file(*args)
                captured_roles.append(args[1])
                return item
            def recheck(captures):
                result = recheck_inputs(captures)
                events.append("rechecked_all_inputs")
                return result
            def strict(raw, stage):
                events.append("decoded_json")
                self.assertEqual(set(captured_roles), set(io._INPUT_ROLES))
                self.assertIn("rechecked_all_inputs", events)
                return strict_json(raw, stage)
            def source_audit(path):
                return {"source_audit_sha256": sha(path.read_bytes())}
            def protected_union(union_path, receipt_path, expected_sha):
                return historical, {"artifact_sha256": sha(union_path.read_bytes()),
                                    "receipt_sha256": sha(receipt_path.read_bytes()),
                                    "union_sha256": "c" * 64,
                                    "helper_source_hashes": expected_helpers}
            with patch.object(io, "_attest_code", side_effect=lambda *_: code_hashes), \
                 patch.object(io, "_capture_file", side_effect=capture), \
                 patch.object(io, "_recheck_inputs", side_effect=recheck), \
                 patch.object(io, "_strict_json", side_effect=strict), \
                 patch.object(io, "validate_source_audit", side_effect=source_audit), \
                 patch.object(io, "verify_parquet_bytes", side_effect=lambda path: sha(path.read_bytes())), \
                 patch.object(io, "require_frozen_text_inputs", return_value={
                     "protocol_sha256": io.review.PROTOCOL_SHA256,
                     "rubric_sha256": io.review.RUBRIC_SHA256}), \
                 patch.object(io, "validate_protected_union", side_effect=protected_union), \
                 patch.object(io, "validate_training_data_source", return_value=code_hashes["normalizer"]), \
                 patch.object(io, "validate_fixture_addon", return_value=addon), \
                 patch.object(io, "open_verified_parquet", side_effect=AssertionError("preflight opened parquet")), \
                 patch.object(io, "aggregate_scan", side_effect=AssertionError("preflight built graph")):
                result = io.prepare_in_house_protection_bindings(paths, trust=trust, source_root=source_root)
            self.assertEqual(result.bindings.historical_artifact_raw_sha256, input_hashes["protected_union"])
            self.assertEqual(result.coverage_counts["combined_ids"], 1)
            self.assertEqual(result.coverage_counts["combined_groups"], 1)
            self.assertEqual(captured_roles, list(io._INPUT_ROLES))

    @unittest.skipUnless(io._platform_supported(), "POSIX descriptor protections are required")
    def test_public_preparation_revalidates_freeze_before_parquet_and_writes_private_outputs(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temporary:
            paths, trust, source_root, code_hashes = make_preflight_fixture(Path(temporary))
            results = source_root / "evaluation" / "results"
            results.mkdir(parents=True)
            paths = replace(paths, output=results / "good-run")
            historical = ProtectedKeys(ids=frozenset({D}))
            addon = ProtectedKeys(groups=frozenset({"b" * 64}))
            expected_helpers = {
                "protection_io_sha256": code_hashes["protection_io"],
                "protection_core_sha256": code_hashes["protection_core"],
                "grouping_core_sha256": code_hashes["grouping"],
                "training_data_sha256": code_hashes["normalizer"],
            }
            def source_audit(path):
                return {"source_audit_sha256": sha(path.read_bytes())}
            def protected_union(union_path, receipt_path, expected_sha):
                return historical, {"artifact_sha256": sha(union_path.read_bytes()),
                                    "receipt_sha256": sha(receipt_path.read_bytes()),
                                    "union_sha256": "c" * 64,
                                    "helper_source_hashes": expected_helpers}
            class FakeParquet:
                schema_arrow = "schema"
                metadata = SimpleNamespace(num_rows=2)
                def iter_batches(self, batch_size):
                    return [FakeBatch([
                        {"uid": 1, "input_id": 12, "category": "negative",
                         "attack_target": {"pii": [], "context": []},
                         "llm_input": "synthetic ordinary request one", "pii_spans": []},
                        {"uid": 2, "input_id": 12, "category": "negative",
                         "attack_target": {"pii": [], "context": []},
                         "llm_input": "synthetic ordinary request two", "pii_spans": []},
                    ])]
            with patch.object(io, "_attest_code", side_effect=lambda *_: code_hashes), \
                 patch.object(io, "validate_source_audit", side_effect=source_audit), \
                 patch.object(io, "verify_parquet_bytes", side_effect=lambda path: sha(path.read_bytes())), \
                 patch.object(io, "require_frozen_text_inputs", return_value={
                     "protocol_sha256": io.review.PROTOCOL_SHA256,
                     "rubric_sha256": io.review.RUBRIC_SHA256}), \
                 patch.object(io, "validate_protected_union", side_effect=protected_union), \
                 patch.object(io, "validate_training_data_source", return_value=code_hashes["normalizer"]), \
                 patch.object(io, "validate_fixture_addon", return_value=addon), \
                 patch.object(io, "PARQUET_ROWS", 2), \
                 patch.object(io, "open_verified_parquet", return_value=FakeParquet()) as open_parquet, \
                 patch.object(io, "validate_arrow_schema", return_value=None), \
                 patch.object(io.review, "SOURCE_SHA256", sha(b"synthetic parquet")), \
                 patch.object(io, "build_in_house_review_pool", wraps=io.build_in_house_review_pool) as pool_builder:
                preflight = io.prepare_in_house_protection_bindings(paths, trust=trust, source_root=source_root)
                prepared_trust = replace(trust, expected_protection_bindings=preflight.bindings)
                result = io.prepare_in_house_review_pool(paths, trust=prepared_trust,
                                                        source_root=source_root, results_root=results)
                self.assertEqual(result.status, "complete")
                self.assertEqual(open_parquet.call_count, 1)
                self.assertEqual(pool_builder.call_count, 1)
                manifest = json.loads((paths.output / "manifest.json").read_text(encoding="utf-8"))
                self.assertEqual(manifest["review_status"], "assistant_provisional_professor_pending")
                self.assertTrue(manifest["no_model_scoring"])
                self.assertEqual(set(manifest["input_consumed_sha256"]), set(io._INPUT_ROLES))
                self.assertEqual(manifest["input_consumed_sha256"]["fixture"],
                                 sha(io._canonical_lf(paths.fixture.read_bytes())))
                self.assertEqual(manifest["input_consumed_sha256"]["addon_artifact"],
                                 sha(paths.addon_artifact.read_bytes()))
                for name in ("legacy_pool_sha256", "graph_membership_sha256", "private_members_sha256"):
                    self.assertRegex(manifest[name], r"^[0-9a-f]{64}$")
                self.assertEqual(manifest["counts"]["source_rows"], 2)
                self.assertEqual(manifest["counts"]["graph_components"], 1)
                self.assertEqual((paths.output / "review-packages.jsonl").stat().st_mode & 0o777, 0o600)

                bad_output = results / "mismatched-freeze"
                bad_paths = replace(paths, output=bad_output)
                bad_binding = replace(preflight.bindings, addon_content_sha256="8" * 64)
                bad_trust = replace(trust, expected_protection_bindings=bad_binding)
                with self.assertRaisesRegex(io.InHousePreparationError, "validate_protection_bindings"):
                    io.prepare_in_house_review_pool(bad_paths, trust=bad_trust,
                                                    source_root=source_root, results_root=results)
                self.assertEqual(open_parquet.call_count, 1)
                self.assertEqual(pool_builder.call_count, 1)
                self.assertTrue((bad_output / "failure.json").exists())

    def test_line_ending_canonicalization_is_crlf_only(self):
        self.assertEqual(io._canonical_lf("Zoë\r\ntext\n".encode()), "Zoë\ntext\n".encode())
        self.assertNotEqual(io._canonical_lf("é".encode()), io._canonical_lf("e\u0301".encode()))
        with self.assertRaises(io.InHousePreparationError):
            io._canonical_lf(b"\xff")

    def test_new_pin_json_rejects_duplicate_keys_and_nonfinite_numbers(self):
        with self.assertRaisesRegex(io.InHousePreparationError, "duplicate_json_key"):
            io._strict_json(b'{"role":"parser","role":"cli"}', "test")
        with self.assertRaises(io.InHousePreparationError):
            io._strict_json(b'{"value":NaN}', "test")

    @unittest.skipUnless(io._platform_supported(), "POSIX descriptor protections are required")
    def test_all_twelve_files_are_captured_under_fixed_snapshot_names_and_rechecked(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths, trust = make_inputs(Path(temporary) / "source")
            for role in io._INPUT_ROLES:
                with io._capture_all(paths, trust) as (_originals, captured, _snapshot):
                    self.assertEqual(set(captured), set(io._INPUT_ROLES))
                    item = captured[role]
                    self.assertEqual(item.snapshot_path.name, io._INPUT_BASENAMES[role])
                    self.assertEqual(item.snapshot_path.parent.name, role)
                    self.assertEqual(item.snapshot_path.read_bytes(), item.data)
                    self.assertEqual(item.snapshot_path.stat().st_mode & 0o777, 0o600)
                    io._recheck_inputs(captured)
                    replacement = item.source_path.with_suffix(".replacement")
                    replacement.write_bytes(item.source_path.read_bytes())
                    item.source_path.unlink()
                    replacement.rename(item.source_path)
                    with self.assertRaises(io.InHousePreparationError):
                        io._recheck_inputs(captured)

    @unittest.skipUnless(io._platform_supported(), "POSIX descriptor protections are required")
    def test_input_symlink_is_rejected_without_following_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths, trust = make_inputs(Path(temporary) / "source")
            victim = paths.fixture
            target = victim.with_suffix(".target")
            victim.rename(target)
            victim.symlink_to(target)
            with self.assertRaises(io.InHousePreparationError):
                with io._capture_all(paths, trust):
                    self.fail("capture must reject symlink")

    def test_platform_refusal_happens_before_any_source_or_input_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths, trust = make_inputs(Path(temporary) / "source")
            with patch.object(io, "_platform_supported", return_value=False), \
                 patch.object(io, "_attest_code") as attest, \
                 patch.object(io, "_capture_all") as capture:
                with self.assertRaisesRegex(io.InHousePreparationError, "posix_descriptor_io_required"):
                    io.prepare_in_house_protection_bindings(paths, trust=trust, source_root=Path(temporary) / "root")
                attest.assert_not_called()
                capture.assert_not_called()

    def test_arrow_batch_schema_check_precedes_conversion_and_duplicate_uid_fails(self):
        batch = FakeBatch([{}])
        order = []
        with patch.object(io, "validate_arrow_schema", side_effect=lambda schema: order.append("schema")), \
             patch.object(io, "parse_native_row", side_effect=lambda _row: (order.append("parse"), FakeParsed(7))[1]):
            rows = list(io._iter_rows(type("Reader", (), {"iter_batches": lambda self, batch_size: [batch]})()))
        self.assertEqual(order, ["schema", "parse"])
        self.assertTrue(batch.converted)
        duplicate = FakeBatch([{}, {}])
        with patch.object(io, "validate_arrow_schema", return_value=None), \
             patch.object(io, "parse_native_row", return_value=FakeParsed(7)):
            reader = type("Reader", (), {"iter_batches": lambda self, batch_size: [duplicate]})()
            with self.assertRaisesRegex(io.InHousePreparationError, "duplicate_uid"):
                list(io._iter_rows(reader))

    def test_parser_alias_mutation_during_schema_callback_stops_before_batch_conversion(self):
        parser_snapshot = io._parser_contract_snapshot()
        order = []
        class Batch:
            schema = "schema"
            def to_pylist(self):
                order.append("converted")
                return [{}]
        batch = Batch()
        checks = 0
        def guard():
            nonlocal checks
            checks += 1
            if checks == 2:
                order.append("post-schema")
                io.parse_native_row = lambda _row: order.append("foreign-parser")
                io._verify_parser_edge(parser_snapshot)
        with patch.object(io, "validate_arrow_schema", return_value=None):
            with self.assertRaisesRegex(io.InHousePreparationError, "parser_binding_changed"):
                list(io._iter_rows(type("Reader", (), {"iter_batches": lambda self, batch_size: [batch]})(),
                                   edge_guard=guard, parser_snapshot=parser_snapshot))
        self.assertEqual(order, ["post-schema"])

    def test_parser_alias_mutation_during_conversion_stops_before_parser(self):
        parser_snapshot = io._parser_contract_snapshot()
        order = []
        class Batch:
            schema = "schema"
            def to_pylist(self):
                order.append("converted")
                io.parse_native_row = lambda _row: order.append("foreign-parser")
                return [{}]
        with patch.object(io, "validate_arrow_schema", return_value=None):
            with self.assertRaisesRegex(io.InHousePreparationError, "parser_binding_changed"):
                list(io._iter_rows(type("Reader", (), {"iter_batches": lambda self, batch_size: [Batch()]})(),
                                   parser_snapshot=parser_snapshot))
        self.assertEqual(order, ["converted"])

    def test_span_adapter_uses_fuzzy_literal_and_preserves_base_identifier(self):
        parsed = FakeParsed(1, spans=1)
        value = io._span_inputs({"pii_spans": [{"type": "email", "start": 2, "end": 8,
                                                "value": "base", "value_fuzzy": "fuzzy!"}]}, parsed)
        self.assertEqual(value[0].literal, "fuzzy!")
        self.assertEqual(value[0].base_value, "base")
        with self.assertRaises(io.InHousePreparationError):
            io._span_inputs({"pii_spans": []}, parsed)

    def test_attestation_ast_binding_inventory_includes_class_methods_and_properties(self):
        source = ("class C:\n    @property\n    def value(self):\n        def local():\n            return 1\n        return local()\n"
                  "\ndef f():\n    def nested():\n        return C()\n    return nested()\n"
                  "if False:\n    def conditional():\n        return None\n")
        classes, functions = io._source_bindings(source)
        self.assertIn("C", classes)
        self.assertIn(("C", "value", 2), functions)
        self.assertIn((None, "f", 8), functions)
        self.assertNotIn(("C", "local", 4), functions)
        self.assertNotIn((None, "nested", 9), functions)
        self.assertNotIn((None, "conditional", 12), functions)

    def test_attestation_accepts_decorated_live_functions_and_all_pinned_modules(self):
        modules = {
            "parser": io.native, "structure": io.structure, "grouping": io.grouping,
            "review_helper": io.review, "protection_core": io.protection_core,
            "protection_io": io.protection_io, "fixture_validator": io.fixture,
            "normalizer": io.training_data, "in_house_review": io.in_house,
            "in_house_review_io": io,
        }
        for role, module in modules.items():
            path = ROOT / io._CODE_PATHS[role]
            io._attest_module(role, path.read_bytes(), path)
        from importlib.util import spec_from_file_location, module_from_spec
        path = ROOT / io._CODE_PATHS["cli"]
        spec = spec_from_file_location("in_house_cli_attestation_test", path)
        self.assertIsNotNone(spec)
        cli = module_from_spec(spec)
        spec.loader.exec_module(cli)
        io._attest_module("cli", path.read_bytes(), path, cli)
        with patch.object(cli, "EXECUTION_CODE_ROLES", frozenset()):
            with self.assertRaisesRegex(io.InHousePreparationError, "source_global|cli_alias_mismatch"):
                io._attest_module("cli", path.read_bytes(), path, cli)
        own_path = ROOT / io._CODE_PATHS["in_house_review_io"]
        original = io._capture_all
        def replacement(*_args, **_kwargs):
            return None
        replacement.__wrapped__ = original.__wrapped__
        with patch.object(io, "_capture_all", replacement):
            with self.assertRaisesRegex(io.InHousePreparationError, "decorator_wrapper_mismatch"):
                io._attest_module("in_house_review_io", own_path.read_bytes(), own_path)

    @unittest.skipUnless(io._platform_supported(), "POSIX descriptor protections are required")
    def test_full_code_attestation_imports_and_checks_cli_for_api_callers(self):
        code_hashes = {role: sha((ROOT / relative).read_bytes())
                       for role, relative in io._CODE_PATHS.items()}
        trust = io.InHousePreparationTrust(
            "4" * 40, {role: D for role in io._INPUT_ROLES}, D, D, D, "5" * 40,
            {key: code_hashes[role] for key, role in
             (("grouping", "grouping"), ("normalizer", "normalizer"), ("fixture_validator", "fixture_validator"))},
            code_hashes, io.in_house.PLAN_SHA256, io.in_house.PREPARATION_DESIGN_SHA256,
            io.in_house.ALLOCATOR_DESIGN_SHA256,
        )
        self.assertEqual(io._attest_code(ROOT, trust), code_hashes)
        with patch.object(io, "_INPUT_ROLES", ("parquet",)), patch.object(io, "_code_capture") as capture:
            with self.assertRaisesRegex(io.InHousePreparationError, "runtime_configuration_mismatch"):
                io._attest_code(ROOT, trust)
            capture.assert_not_called()

    def test_attestation_rejects_parser_alias_and_semantic_constant_changes(self):
        path = ROOT / io._CODE_PATHS["parser"]
        raw = path.read_bytes()
        with patch.object(io.native, "_PII_OPERATIONS", io.native._PII_OPERATIONS | {"unreviewed-op"}):
            with self.assertRaises(io.InHousePreparationError):
                io._attest_module("parser", raw, path)
        with patch.object(io.native, "GroupingRow", lambda **kwargs: kwargs):
            with self.assertRaises(io.InHousePreparationError):
                io._attest_module("parser", raw, path)
        with patch.object(io.native.ParsedNativeRow, "__init__", lambda *_args, **_kwargs: None):
            with self.assertRaises(io.InHousePreparationError):
                io._attest_module("parser", raw, path)

    def test_attestation_rejects_function_default_mutation(self):
        path = ROOT / io._CODE_PATHS["structure"]
        original = dict(io.structure.aggregate_scan.__kwdefaults__ or {})
        self.assertIsNotNone(original)
        io.structure.aggregate_scan.__kwdefaults__ = {**original, "expected_rows": 0}
        try:
            with self.assertRaises(io.InHousePreparationError):
                io._attest_module("structure", path.read_bytes(), path)
        finally:
            io.structure.aggregate_scan.__kwdefaults__ = original

    @unittest.skipUnless(io._platform_supported(), "POSIX descriptor protections are required")
    def test_private_output_is_exclusive_and_uses_private_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "evaluation" / "results").mkdir(parents=True)
            target = root / "evaluation" / "results" / "run-one"
            with io._PrivateOutput(root, target) as output:
                self.assertEqual(target.stat().st_mode & 0o777, 0o700)
                digest = output.write("review-packages.jsonl", b"synthetic package\n")
                self.assertEqual(digest, sha(b"synthetic package\n"))
                self.assertEqual((target / "review-packages.jsonl").stat().st_mode & 0o777, 0o600)
                with self.assertRaises(io.InHousePreparationError):
                    output.write("review-packages.jsonl", b"replacement")
            with self.assertRaises(io.InHousePreparationError):
                io._PrivateOutput(root, target).__enter__()

    @unittest.skipUnless(io._platform_supported(), "POSIX descriptor protections are required")
    def test_named_file_replacement_at_fsync_is_detected_and_sanitized(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "evaluation" / "results").mkdir(parents=True)
            target = root / "evaluation" / "results" / "run-replace-file"
            with io._PrivateOutput(root, target) as output:
                real_fsync = os.fsync
                changed = False

                def replace_after_sync(fd):
                    nonlocal changed
                    result = real_fsync(fd)
                    if not changed:
                        changed = True
                        named = target / "review-packages.jsonl"
                        named.unlink()
                        named.write_bytes(b"different bytes")
                    return result

                with patch.object(io.os, "fsync", side_effect=replace_after_sync):
                    with self.assertRaisesRegex(io.InHousePreparationError, "published_file_identity_changed"):
                        output.write("review-packages.jsonl", b"original bytes")
                self.assertTrue(changed)

    @unittest.skipUnless(io._platform_supported(), "POSIX descriptor protections are required")
    def test_output_directory_substitution_stops_publication_outside_held_descriptor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results = root / "evaluation" / "results"
            results.mkdir(parents=True)
            target = results / "run-race"
            outside = root / "outside"
            outside.mkdir()
            with io._PrivateOutput(root, target) as output:
                output.write("review-packages.jsonl", b"private synthetic content")
                moved = results / "moved-output"
                target.rename(moved)
                target.symlink_to(outside, target_is_directory=True)
                with self.assertRaises(io.InHousePreparationError):
                    output.write("private-review-map.jsonl", b"must not escape")
            self.assertEqual(list(outside.iterdir()), [])
            self.assertEqual((moved / "review-packages.jsonl").read_bytes(), b"private synthetic content")

    def test_expected_binding_decoder_is_not_called_before_attestation_and_capture(self):
        value = binding()
        events = []
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            results = source / "evaluation" / "results"
            output_path = results / "synthetic-run"
            input_paths = {role: Path(temporary) / f"{role}.unused" for role in io._INPUT_ROLES}
            paths = io.InHouseReviewIOPaths(**input_paths, output=output_path)
            raw_input_hashes = {role: D for role in io._INPUT_ROLES}
            raw_input_hashes["pin_manifest"] = D
            raw_input_hashes["protection_receipt"] = "b" * 64
            raw_input_hashes["addon_receipt"] = "c" * 64
            expected_input = value.to_dict()
            trust = io.InHousePreparationTrust(
                "4" * 40, raw_input_hashes, D, "b" * 64, "c" * 64, "5" * 40,
                {key: D for key in ("grouping", "normalizer", "fixture_validator")},
                {key: D for key in EXECUTION_CODE_ROLES}, io.in_house.PLAN_SHA256,
                io.in_house.PREPARATION_DESIGN_SHA256, io.in_house.ALLOCATOR_DESIGN_SHA256,
                expected_input,
            )
            captures = {role: io._Capture(input_paths[role], input_paths[role], b"x", D, (1, 2, 3))
                        for role in io._INPUT_ROLES}

            class Output:
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def verify(self): pass
                def write(self, name, raw): return sha(raw)

            @contextmanager
            def captured(_paths, _trust):
                expected_input["fixture_input_raw_sha256"]["fixture"] = "9" * 64
                events.append("captured_all_12")
                yield input_paths, captures, Path(temporary)

            def decode(value_arg):
                events.append("decode_expected_bindings")
                self.assertEqual(value_arg["fixture_input_raw_sha256"]["fixture"],
                                 value.fixture_input_raw_sha256["fixture"])
                return original_decode(value_arg)

            original_decode = io._expected_bindings
            with patch.object(io, "_platform_supported", return_value=True), \
                 patch.object(io, "_PrivateOutput", return_value=Output()), \
                 patch.object(io, "_attest_code", side_effect=lambda *_: (events.append("attest_code") or {k: D for k in io._CODE_PATHS})), \
                 patch.object(io, "_capture_all", captured), \
                 patch.object(io, "_expected_bindings", side_effect=decode), \
                 patch.object(io, "_protection_preflight", side_effect=lambda *_: (events.append("revalidate_protection") or (value, {}, ProtectedKeys()))), \
                 patch.object(io, "_source_rows_and_pool", side_effect=lambda *_: (events.append("source_stage") or io.InHousePreparationResult("complete", output_path, D, D, {}, {}))), \
                 patch.object(io, "_recheck_inputs"), patch.object(io, "_recheck_code"):
                result = io.prepare_in_house_review_pool(paths, trust=trust, source_root=source,
                                                        results_root=results)
            self.assertEqual(result.status, "complete")
            self.assertLess(events.index("attest_code"), events.index("captured_all_12"))
            self.assertLess(events.index("captured_all_12"), events.index("decode_expected_bindings"))
            self.assertLess(events.index("decode_expected_bindings"), events.index("revalidate_protection"))
            self.assertLess(events.index("revalidate_protection"), events.index("source_stage"))

    def test_cli_has_no_policy_or_source_root_override_flags(self):
        from importlib.util import spec_from_file_location, module_from_spec
        source = ROOT / "evaluation" / "prepare-in-house-advpii-review.py"
        spec = spec_from_file_location("inhouse_cli_test", source)
        module = module_from_spec(spec)
        spec.loader.exec_module(module)
        destinations = {action.dest for action in module.build_parser()._actions}
        self.assertNotIn("policy", destinations)
        self.assertIn("expected_protection_bindings_json", destinations)
        self.assertIn("parquet", destinations)

    def test_cli_passes_raw_expected_binding_json_without_decoding(self):
        from contextlib import redirect_stdout
        from importlib.util import spec_from_file_location, module_from_spec
        from types import SimpleNamespace
        import io as stdio
        source = ROOT / "evaluation" / "prepare-in-house-advpii-review.py"
        spec = spec_from_file_location("in_house_cli_raw_binding_test", source)
        cli = module_from_spec(spec)
        spec.loader.exec_module(cli)
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            args = ["--stage", "prepare", "--output", str(base / "out"),
                    "--source-root", str(base), "--results-root", str(base / "evaluation" / "results"),
                    "--source-revision", "4" * 40, "--pin-manifest-sha256", D,
                    "--historical-receipt-sha256", D, "--addon-receipt-sha256", D,
                    "--addon-producer-revision", "5" * 40, "--study-plan-lf-sha256", D,
                    "--preparation-design-sha256", D, "--allocator-design-sha256", D,
                    "--expected-protection-bindings-json", "intentionally not decoded here"]
            flags = {"parquet": "--parquet", "source_audit": "--source-audit", "protocol": "--protocol",
                     "rubric": "--rubric", "protected_union": "--protected-union",
                     "protection_receipt": "--protection-receipt", "pin_manifest": "--pin-manifest",
                     "fixture": "--fixture", "fixture_rubric": "--fixture-rubric",
                     "fixture_review": "--fixture-review", "addon_artifact": "--addon-artifact",
                     "addon_receipt": "--addon-receipt"}
            for role, flag in flags.items():
                args.extend([flag, str(base / f"unused-{role}")])
                args.extend(["--input-sha256", f"{role}={D}"])
            for role in EXECUTION_CODE_ROLES:
                args.extend(["--execution-code-sha256", f"{role}={D}"])
            for role in ("grouping", "normalizer", "fixture_validator"):
                args.extend(["--addon-helper-sha256", f"{role}={D}"])
            def fake_prepare(_paths, *, trust, source_root, results_root):
                self.assertEqual(trust.expected_protection_bindings, "intentionally not decoded here")
                self.assertEqual(source_root, base)
                self.assertEqual(results_root, base / "evaluation" / "results")
                return SimpleNamespace(status="complete", preparation_identity=D, review_pool_sha256=D,
                                       output_sha256={}, counts={}, output_directory=base / "out")
            output = stdio.StringIO()
            with patch.object(cli, "prepare_in_house_review_pool", side_effect=fake_prepare), \
                 redirect_stdout(output):
                self.assertEqual(cli.main(args), 0)
            self.assertEqual(json.loads(output.getvalue())["status"], "complete")


if __name__ == "__main__":
    unittest.main()
