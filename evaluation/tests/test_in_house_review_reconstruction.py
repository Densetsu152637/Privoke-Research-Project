"""Synthetic source replay and private publication mutation tests."""
from pathlib import Path
from contextlib import ExitStack, contextmanager
from dataclasses import replace
import os
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "evaluation"), str(ROOT / "shared/python"), str(ROOT / "evaluation/tests")]
import privoke_eval.in_house_review_reconstruction as reconstruction
import privoke_eval.in_house_advpii_review_io as io
from test_in_house_dual_review import _pool
from test_in_house_advpii_review_io import make_inputs, FakeBatch, fake_arrow_fixture


class ReconstructionTests(unittest.TestCase):
    def fixture(self, root, rows=None):
        paths, trust = make_inputs(root / "inputs")
        pool = _pool()
        captures = {role: SimpleNamespace(snapshot_path=getattr(paths, role), data=b"synthetic\r\n",
                                         sha256=trust.input_raw_sha256[role]) for role in io._INPUT_ROLES}
        captures["parquet"].sha256 = pool.bindings.legacy.source_sha256
        captures["pin_manifest"].sha256 = pool.bindings.preparation_pin_manifest_raw_sha256
        trust = replace(trust, source_revision=pool.bindings.legacy.source_revision)
        raw_rows = []
        for parsed in rows or pool._source_rows:
            native = pool._native_span_inputs.get(parsed.grouping_row.uid, ())
            raw = {"uid": parsed.grouping_row.uid, "input_id": parsed.grouping_row.input_id,
                   "category": parsed.native_category, "llm_input": parsed.grouping_row.text,
                   "attack_target": {"pii": [], "context": []}, "pii_spans": [{"type": x.entity_type, "start": x.start, "end": x.end,
                                  "value": x.base_value, "value_fuzzy": None} for x in native]}
            raw_rows.append(raw)
        stack = ExitStack()
        arrow, schema = fake_arrow_fixture()
        stack.enter_context(patch.dict(sys.modules, {"pyarrow": arrow}))
        for name, value in {
            "validate_source_audit": lambda p: {"source_audit_sha256": captures["source_audit"].sha256},
            "require_frozen_text_inputs": lambda *a: {"protocol_sha256": pool.bindings.legacy.protocol_sha256,
                                                      "rubric_sha256": pool.bindings.legacy.rubric_sha256},
            "verify_parquet_bytes": lambda p: captures["parquet"].sha256,
            "open_verified_parquet": lambda p: SimpleNamespace(schema_arrow=schema, metadata=SimpleNamespace(num_rows=2),
                iter_batches=lambda **kw: iter([FakeBatch(raw_rows, schema=schema)])),
        }.items():
            stack.enter_context(patch.object(io, name, value))
        stack.enter_context(patch.object(io, "PARQUET_ROWS", 2))
        return stack, paths, trust, captures, pool

    def test_actual_pool_fullgraph_and_exact_producer_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            stack, paths, trust, captures, expected = self.fixture(Path(temp))
            with stack:
                pool, packages, private_map, counts, audit, texts = reconstruction._rebuild(
                    paths, captures, trust, dict(expected.bindings.execution_code_raw_sha256),
                    expected.bindings.protection, expected._combined_keys, lambda: None)
                self.assertEqual(pool, expected)
                self.assertEqual(counts["source_rows"], 2)
                outputs = {}
                sink = SimpleNamespace(write=lambda name, raw: outputs.setdefault(name, raw) and io._sha(raw))
                with patch.object(io, "_verify_execution_edge"):
                    io._source_rows_and_pool(paths, captures, trust, dict(expected.bindings.execution_code_raw_sha256),
                                             expected.bindings.protection, expected._combined_keys, sink)
                manifest = reconstruction._manifest(pool, packages, private_map, counts, audit, texts, captures,
                                                    dict(expected.bindings.execution_code_raw_sha256), trust)
                self.assertEqual(outputs, {"manifest.json": io.canonical_json_bytes(manifest) + b"\n",
                                           "review-packages.jsonl": packages, "private-review-map.jsonl": private_map})
                self.assertIn(b"source_uid", private_map)
                self.assertNotIn(b"source_uid", packages)

    def test_public_gate_rejects_bound_private_map_manifest_and_counts_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            stack, paths, trust, captures, expected = self.fixture(Path(temp))
            trust = replace(trust, expected_protection_bindings=expected.bindings.protection)
            code = dict(expected.bindings.execution_code_raw_sha256)
            with stack:
                pool, packages, private_map, counts, audit, texts = reconstruction._rebuild(
                    paths, captures, trust, code, expected.bindings.protection, expected._combined_keys, lambda: None)
                manifest = reconstruction._manifest(pool, packages, private_map, counts, audit, texts, captures, code, trust)
                raw_manifest = io.canonical_json_bytes(manifest) + b"\n"
                payloads = {"manifest.json": raw_manifest, "review-packages.jsonl": packages,
                            "private-review-map.jsonl": private_map}
                publication = SimpleNamespace(payloads=payloads, verify=lambda: None)
                @contextmanager
                def held(*args):
                    yield publication
                @contextmanager
                def captured(*args):
                    yield None, captures, None
                published = reconstruction.PublishedPreparationTrust(
                    {k: io._sha(v) for k, v in payloads.items()}, "a" * 64, counts)
                with patch.object(reconstruction, "_HeldPublication", held), patch.object(
                        reconstruction, "_attest_adapter"), patch.object(io, "_trusted_maps"), patch.object(
                        io, "_capture_all", captured), patch.object(io, "_attest_code", return_value=code), patch.object(
                        io, "_verify_execution_edge"), patch.object(io, "_protection_preflight", return_value=(
                            expected.bindings.protection, {}, expected._combined_keys)):
                    self.assertEqual(reconstruction.reconstruct_in_house_review_pool(
                        paths, trust=trust, published_trust=published, source_root=ROOT), expected)
                    for name in payloads:
                        original = payloads[name]
                        payloads[name] = original + b" "
                        with self.assertRaises(io.InHousePreparationError):
                            reconstruction.reconstruct_in_house_review_pool(
                                paths, trust=trust, published_trust=published, source_root=ROOT)
                        payloads[name] = original
                    wrong_counts = replace(published, expected_counts={**counts, "pool_size": counts["pool_size"] + 1})
                    with self.assertRaises(io.InHousePreparationError):
                        reconstruction.reconstruct_in_house_review_pool(
                            paths, trust=trust, published_trust=wrong_counts, source_root=ROOT)

    def test_incomplete_complete_source_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            stack, paths, trust, captures, expected = self.fixture(Path(temp), _pool()._source_rows[:1])
            with stack, self.assertRaises(io.InHousePreparationError):
                reconstruction._rebuild(paths, captures, trust, dict(expected.bindings.execution_code_raw_sha256),
                                         expected.bindings.protection, expected._combined_keys, lambda: None)

    def test_protection_binding_mutation_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            stack, paths, trust, captures, expected = self.fixture(Path(temp))
            protection = replace(expected.bindings.protection, combined_protection_sha256="9" * 64)
            with stack, self.assertRaises(io.InHousePreparationError):
                reconstruction._rebuild(paths, captures, trust, dict(expected.bindings.execution_code_raw_sha256),
                                         protection, expected._combined_keys, lambda: None)

    def test_reconstruction_source_is_live_attested(self):
        raw = Path(reconstruction.__file__).read_bytes()
        io._attest_module("reconstruction", raw, Path(reconstruction.__file__), module_override=reconstruction)
        with patch.object(reconstruction, "_FILES", {"manifest.json": 99}), self.assertRaises(io.InHousePreparationError):
            io._attest_module("reconstruction", raw, Path(reconstruction.__file__), module_override=reconstruction)

    @unittest.skipUnless(io._platform_supported(), "POSIX descriptor I/O required")
    def test_private_held_publication_rejects_mutations_and_modes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "evaluation/results/publication"
            output.mkdir(parents=True, mode=0o700)
            pins = {}
            for name in reconstruction._FILES:
                path = output / name
                path.write_bytes(b"synthetic")
                path.chmod(0o600)
                pins[name] = io._sha(b"synthetic")
            with reconstruction._HeldPublication(root, output, pins) as held:
                held.verify()
                (output / "private-review-map.jsonl").write_bytes(b"mutation!")
                with self.assertRaises(io.InHousePreparationError):
                    held.verify()
            (output / "private-review-map.jsonl").write_bytes(b"synthetic")
            (output / "manifest.json").chmod(0o644)
            with self.assertRaises(io.InHousePreparationError):
                with reconstruction._HeldPublication(root, output, pins):
                    pass

    @unittest.skipUnless(io._platform_supported(), "POSIX descriptor I/O required")
    def test_held_ancestors_and_files_reject_link_replacement_and_extra_entry(self):
        for mutation in ("symlink", "hardlink", "replacement", "ancestor", "extra", "directory_mode"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                output = root / "evaluation/results/publication"
                output.mkdir(parents=True, mode=0o700)
                pins = {}
                for name in reconstruction._FILES:
                    path = output / name
                    path.write_bytes(b"synthetic")
                    path.chmod(0o600)
                    pins[name] = io._sha(b"synthetic")
                with reconstruction._HeldPublication(root, output, pins) as held:
                    target = output / "manifest.json"
                    if mutation == "symlink":
                        target.rename(output / "saved")
                        target.symlink_to(output / "saved")
                    elif mutation == "hardlink":
                        os.link(target, root / "linked")
                    elif mutation == "replacement":
                        target.unlink()
                        target.write_bytes(b"synthetic")
                        target.chmod(0o600)
                    elif mutation == "ancestor":
                        output.parent.rename(root / "evaluation/moved")
                        (root / "evaluation/results").mkdir()
                    elif mutation == "extra":
                        (output / "unexpected").write_bytes(b"synthetic")
                    else:
                        output.chmod(0o755)
                    with self.assertRaises((io.InHousePreparationError, OSError)):
                        held.verify()

    @unittest.skipUnless(io._platform_supported(), "POSIX descriptor I/O required")
    def test_final_map_path_replacement_during_held_read_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "evaluation/results/publication"
            output.mkdir(parents=True, mode=0o700)
            pins = {}
            for name in reconstruction._FILES:
                path = output / name
                path.write_bytes(b"synthetic")
                path.chmod(0o600)
                pins[name] = io._sha(b"synthetic")
            with reconstruction._HeldPublication(root, output, pins) as held:
                final_fd = held.files["private-review-map.jsonl"][0]
                original_read = os.read
                replaced = False
                def replace_after_read(fd, count):
                    nonlocal replaced
                    value = original_read(fd, count)
                    if fd == final_fd and value and not replaced:
                        replaced = True
                        target = output / "private-review-map.jsonl"
                        target.rename(root / "original-private-map")
                        target.write_bytes(b"synthetic")
                        target.chmod(0o600)
                    return value
                with patch.object(reconstruction.os, "read", replace_after_read), self.assertRaises(io.InHousePreparationError):
                    held.verify()
                self.assertTrue(replaced)

    def test_unsupported_platform_boundary_fails_closed(self):
        output = ROOT / "evaluation/results/unused"
        pins = {k: "a" * 64 for k in reconstruction._FILES}
        with patch.object(io, "_platform_supported", return_value=False), self.assertRaises(io.InHousePreparationError):
            reconstruction._HeldPublication(ROOT, output, pins).__enter__()


if __name__ == "__main__":
    unittest.main()
