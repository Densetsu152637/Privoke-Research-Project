"""Synthetic dual consensus, frozen-source continuation and quota tests."""
from pathlib import Path
import ast
import hashlib
import os
import sys
import unittest
from dataclasses import replace
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "evaluation"), str(ROOT / "shared/python"), str(ROOT / "evaluation/tests")]
import privoke_eval.in_house_dual_allocation as allocation
import privoke_eval.advpii_review as legacy
from privoke_eval.in_house_dual_review import consume_dual_reviews
from privoke_eval.in_house_advpii_review import build_in_house_review_pool
from privoke_eval.clean_augmentation_grouping import ProtectedKeys, build_components
from test_in_house_dual_review import _pool, _envelope, _raw, _bindings
from test_advpii_review import _parsed


def baseline(pool):
    return {p.review_id: ("present", ("IDENTITY",),
            (("IDENTITY", p.native_spans[0].start, p.native_spans[0].end),), None)
            for p in pool.core.packages if p.native_spans}


def run(pool, left, right):
    first, second = _raw(left), _raw(right)
    # Only source-attestation I/O is replaced for synthetic in-memory fixtures.
    # Genuine envelope consumer, pool validation and allocator all execute.
    def source_open(path):
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        return fd, os.fstat(fd)
    with patch.object(allocation.io, "_open_read_nofollow", source_open), patch.object(allocation.io, "_trusted_maps"), patch.object(
            allocation.io, "_attest_code", return_value=dict(pool.bindings.execution_code_raw_sha256)), patch.object(
            allocation.io, "_attest_module"):
        return allocation.allocate_dual_reviewed_components(
            pool, first, second, source_root=ROOT, preparation_trust=object(),
            expected_adapter_raw_sha256=hashlib.sha256(Path(allocation.__file__).read_bytes()).hexdigest(),
            expected_consumer_raw_sha256=hashlib.sha256(Path(allocation.dual.__file__).read_bytes()).hexdigest(),
            trusted_bindings=pool.bindings, expected_preparation_identity=pool.preparation_identity,
            expected_first_reviewer_id="reviewer-one", expected_second_reviewer_id="reviewer-two",
            expected_first_raw_sha256=hashlib.sha256(first).hexdigest(),
            expected_second_raw_sha256=hashlib.sha256(second).hexdigest())


class DualAllocationTests(unittest.TestCase):
    def test_literal_frozen_continuation_ast(self):
        original = ast.parse(Path(legacy.__file__).read_text())
        copied = ast.parse(Path(allocation.__file__).read_text())
        first = next(n for n in original.body if isinstance(n, ast.FunctionDef) and n.name == "allocate_reviewed_components")
        second = next(n for n in copied.body if isinstance(n, ast.FunctionDef) and n.name == "_allocate_consensus")
        self.assertEqual([ast.dump(n) for n in first.body[2:]], [ast.dump(n) for n in second.body[1:]])

    def test_shortage_agreement_matches_legacy_and_is_deterministic(self):
        pool = _pool()
        left, right = _envelope(pool, "reviewer-one", baseline(pool)), _envelope(pool, "reviewer-two", baseline(pool))
        result, consensus = run(pool, left, right)
        old = legacy.allocate_reviewed_components(pool.core, left["responses"], pool._source_rows,
                                                  pool._graph, pool._combined_keys)
        self.assertEqual(result, old)
        self.assertEqual(run(pool, left, right)[0], result)
        self.assertEqual(consensus.counts["absent"], 1)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.floor_shortages["test"]["positive"], 199)

    def test_disagreement_and_native_negative_present_add_no_capacity(self):
        pool = _pool()
        ordinary = next(p for p in pool.core.packages if not p.native_spans)
        positive = next(p for p in pool.core.packages if p.native_spans)
        span = positive.native_spans[0]
        present = ("present", ("IDENTITY",), (("IDENTITY", span.start, span.end),), None)
        left = _envelope(pool, "reviewer-one", {positive.review_id: present})
        right = _envelope(pool, "reviewer-two", {positive.review_id: ("uncertain", (), (), "synthetic uncertainty")})
        result, consensus = run(pool, left, right)
        self.assertIsNone(consensus.records[positive.review_id].has_pii)
        self.assertEqual(result.capacities["test"]["positive"], 0)
        categories = ("present", ("IDENTITY",), (("IDENTITY", 8, 25),), None)
        left = _envelope(pool, "reviewer-one", {**baseline(pool), ordinary.review_id: categories})
        right = _envelope(pool, "reviewer-two", {**baseline(pool), ordinary.review_id: categories})
        result, consensus = run(pool, left, right)
        self.assertTrue(consensus.records[ordinary.review_id].has_pii)
        self.assertEqual(result.capacities["test"]["ordinary"], 0)
        self.assertEqual(result.capacities["test"]["positive"], 1)

    def test_commitment_and_reviewer_assignment_fail_closed(self):
        pool = _pool()
        left = _envelope(pool, "reviewer-one")
        right = _envelope(pool, "reviewer-one")
        with self.assertRaises(ValueError):
            run(pool, left, right)
        left["responses"][0]["decision"] = "invented"
        with self.assertRaises(ValueError):
            run(pool, left, _envelope(pool, "reviewer-two"))

    def test_present_category_disagreement_excludes_capacity(self):
        pool = _pool()
        ordinary = next(p for p in pool.core.packages if not p.native_spans)
        left = _envelope(pool, "reviewer-one", {**baseline(pool), ordinary.review_id:
                         ("present", ("IDENTITY",), (("IDENTITY", 8, 25),), None)})
        right = _envelope(pool, "reviewer-two", {**baseline(pool), ordinary.review_id:
                          ("present", ("FINANCIAL",), (("FINANCIAL", 32, 35),), None)})
        result, consensus = run(pool, left, right)
        self.assertIsNone(consensus.records[ordinary.review_id].has_pii)
        self.assertEqual(consensus.counts["uncertain"], 1)
        self.assertEqual(result.capacities["test"]["ordinary"], 0)

    def test_continuation_requires_complete_source_and_frozen_graph(self):
        pool = _pool()
        _, consensus = run(pool, _envelope(pool, "reviewer-one", baseline(pool)),
                            _envelope(pool, "reviewer-two", baseline(pool)))
        with self.assertRaisesRegex(ValueError, "complete source"):
            allocation._allocate_consensus(pool.core, consensus.records, pool._source_rows[:1],
                                           pool._graph, pool._combined_keys)
        with self.assertRaisesRegex(ValueError, "full-source graph"):
            allocation._allocate_consensus(pool.core, consensus.records, pool._source_rows,
                                           build_components([]), pool._combined_keys)

    def test_additive_allocator_and_consumer_live_source_attestation(self):
        for module in (allocation, allocation.dual):
            path = Path(module.__file__)
            allocation.io._attest_module("additive", path.read_bytes(), path, module_override=module)
        with patch.object(allocation, "SPLIT_SEED", 1), self.assertRaises(ValueError):
            path = Path(allocation.__file__)
            allocation.io._attest_module("additive", path.read_bytes(), path, module_override=allocation)

    def test_genuine_fixed_quotas_floors_fill_and_disjointness(self):
        rows, spans = [], {}
        uid = 1
        for component in range(1000):
            for category, copies in (("positive", 4), ("negative", 4), ("hard_negative", 1)):
                for _ in range(copies):
                    parsed, native = _parsed(uid, category)
                    parsed = replace(parsed, grouping_row=replace(parsed.grouping_row, input_id=component + 1))
                    rows.append(parsed)
                    spans[uid] = native
                    uid += 1
        keys = ProtectedKeys()
        graph = build_components([x.grouping_row for x in rows], keys)
        pool = build_in_house_review_pool(rows, graph, _bindings(keys), keys, spans)
        decisions = {}
        for package in pool.core.packages:
            if package.native_spans:
                span = package.native_spans[0]
                decisions[package.review_id] = ("present", ("IDENTITY",), (("IDENTITY", span.start, span.end),), None)
        left = _envelope(pool, "reviewer-one", decisions)
        right = _envelope(pool, "reviewer-two", decisions)
        result, consensus = run(pool, left, right)
        old = legacy.allocate_reviewed_components(pool.core, left["responses"], rows, graph, keys)
        self.assertEqual(result, old)
        self.assertEqual(result.status, "complete")
        self.assertEqual({k: len(v) for k, v in result.partitions.items()}, {"test": 2000, "validation": 2000, "train": 4000})
        self.assertEqual(result.represented_components["test"], {"positive": 250, "absent": 250})
        sets = [set(v) for v in result.assigned_component_ids.values()]
        self.assertFalse(sets[0] & sets[1] or sets[0] & sets[2] or sets[1] & sets[2])


if __name__ == "__main__":
    unittest.main()
