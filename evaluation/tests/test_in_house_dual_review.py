"""Synthetic tests for conservative independent-review consensus."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import unittest
from dataclasses import replace
from types import MappingProxyType

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "evaluation"), str(ROOT / "shared/python")]

from privoke_eval.advpii_native import parse_native_row  # noqa: E402
from privoke_eval.advpii_review import (  # noqa: E402
    ReviewBindings, ValidatedNativeSpanInput, PROTOCOL_SHA256, RUBRIC_SHA256,
    SOURCE_SHA256, protected_keys_digest,
)
from privoke_eval.clean_augmentation_grouping import ProtectedKeys, build_components  # noqa: E402
from privoke_eval.contextual_fixture_protection import combined_protection_digest  # noqa: E402
from privoke_eval.in_house_advpii_review import (  # noqa: E402
    EXECUTION_CODE_ROLES, InHouseProtectionBindings, InHouseReviewBindings,
    build_in_house_review_pool,
)
from privoke_eval.in_house_dual_review import consume_dual_reviews  # noqa: E402

D = "a" * 64


def _bindings(keys):
    key_digest = protected_keys_digest(keys)
    protection = InHouseProtectionBindings(
        D, "b" * 64, "c" * 64, "d" * 64, "e" * 64, "f" * 64,
        combined_protection_digest(keys), key_digest,
        {name: D for name in ("fixture", "rubric", "review")},
        {name: D for name in ("fixture", "rubric", "review")}, "1" * 40,
        {name: D for name in ("grouping", "normalizer", "fixture_validator")},
    )
    legacy = ReviewBindings("1" * 40, SOURCE_SHA256, PROTOCOL_SHA256, RUBRIC_SHA256,
                            D, D, D, "c" * 64, key_digest)
    return InHouseReviewBindings(legacy, protection, D,
                                 {name: D for name in EXECUTION_CODE_ROLES})


def _pool():
    positive = "Send to alice@example.test; note Zoë patient."
    start = positive.index("alice@example.test")
    rows = (
        parse_native_row({
            "uid": 7, "input_id": 11, "category": "positive", "llm_input": positive,
            "attack_target": {"pii": [], "context": []},
            "pii_spans": [{"type": "email", "start": start,
                           "end": start + len("alice@example.test"),
                           "value": "alice@example.test", "value_fuzzy": None}],
        }),
        parse_native_row({
            "uid": 9, "input_id": 12, "category": "negative",
            "llm_input": "Contact alex@example.test about $42.",
            "attack_target": {"pii": [], "context": []}, "pii_spans": [],
        }),
    )
    spans = {
        7: (ValidatedNativeSpanInput(
            "email", start, start + len("alice@example.test"),
            "alice@example.test", "alice@example.test",
        ),),
        9: (),
    }
    keys = ProtectedKeys()
    return build_in_house_review_pool(
        rows, build_components([row.grouping_row for row in rows], keys),
        _bindings(keys), keys, spans,
    )


def _response(pool, package, reviewer, decision, categories=(), evidence=(), reason=None):
    return {
        "review_id": package.review_id,
        "source_sha256": SOURCE_SHA256,
        "pool_sha256": pool.core.pool_sha256,
        "rubric_sha256": RUBRIC_SHA256,
        "text_sha256": package.text_sha256,
        "reviewer_id": reviewer,
        "reviewed_at": "2026-10-04T00:00:00Z",
        "full_prompt_reviewed": True,
        "blinding_attestation": {
            "no_detector_outputs": True,
            "no_model_scores_or_vocabularies": True,
            "no_partition_roles": True,
        },
        "decision": decision,
        "categories": list(categories),
        "evidence": [{"category": category, "start": start, "end": end}
                     for category, start, end in evidence],
        "uncertainty_reason": reason,
    }


def _envelope(pool, reviewer, decisions=None):
    decisions = decisions or {}
    responses = []
    for package in pool.core.packages:
        decision, categories, evidence, reason = decisions.get(
            package.review_id, ("absent", (), (), None))
        responses.append(_response(pool, package, reviewer, decision,
                                   categories, evidence, reason))
    return {
        "schema_version": 1,
        "kind": "privoke-in-house-blind-review-responses-v1",
        "preparation_identity": pool.preparation_identity,
        "review_pool_sha256": pool.review_pool_sha256,
        "responses": responses,
    }


def _raw(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _run(pool, first, second):
    left, right = _raw(first), _raw(second)
    return consume_dual_reviews(
        pool, left, right, trusted_bindings=pool.bindings,
        expected_preparation_identity=pool.preparation_identity,
        expected_first_reviewer_id="reviewer-one",
        expected_second_reviewer_id="reviewer-two",
        expected_first_raw_sha256=hashlib.sha256(left).hexdigest(),
        expected_second_raw_sha256=hashlib.sha256(right).hexdigest(),
    )


class InHouseDualReviewTests(unittest.TestCase):
    def setUp(self):
        self.pool = _pool()
        self.assertEqual(self.pool.core.pool_size, 2)
        self.positive = next(p for p in self.pool.core.packages if p.native_spans)
        self.ordinary = next(p for p in self.pool.core.packages if not p.native_spans)
        self.native = self.positive.native_spans[0]

    def _baseline_decisions(self, reviewer):
        return {self.positive.review_id: (
            "present", ("IDENTITY",),
            (("IDENTITY", self.native.start, self.native.end),), None,
        )}

    def test_consensus_requires_same_decision_and_categories_but_keeps_each_evidence(self):
        left_decisions = self._baseline_decisions("reviewer-one")
        right_decisions = self._baseline_decisions("reviewer-two")
        right_decisions[self.positive.review_id] = (
            "present", ("IDENTITY",),
            (("IDENTITY", self.native.start, self.native.end),
             ("IDENTITY", self.positive.text.index("Zoë"),
              self.positive.text.index("Zoë") + len("Zoë"))), None,
        )
        result = _run(self.pool, _envelope(self.pool, "reviewer-one", left_decisions),
                      _envelope(self.pool, "reviewer-two", right_decisions))
        record = result.records[self.positive.review_id]
        self.assertIs(record.has_pii, True)
        self.assertEqual(record.categories, ("IDENTITY",))
        self.assertNotEqual(record.first_evidence, record.second_evidence)
        self.assertEqual(result.counts, {
            "pool_size": 2, "present": 1, "absent": 1, "uncertain": 0,
            "decision_matches": 2, "present_category_matches": 1,
        })
        self.assertEqual(result.consensus_rule_raw_sha256,
                         "50c4cb981ed88f93f275a4cd8459af36b7a9b6434acd1f6b2e2bbe9521587ac2")
        self.assertFalse(result.human_agreement_claimed)
        self.assertFalse(result.label_truth_authenticated)
        self.assertEqual(len(result.first.reviews), self.pool.core.pool_size)
        self.assertEqual(len(result.second.reviews), self.pool.core.pool_size)
        with self.assertRaises(TypeError):
            result.records[self.positive.review_id] = record
        with self.assertRaises(TypeError):
            result.first.reviews[self.positive.review_id] = result.first.reviews[self.positive.review_id]

    def test_decision_category_or_uncertainty_disagreement_is_unknown(self):
        left_decisions = self._baseline_decisions("reviewer-one")
        left_decisions[self.ordinary.review_id] = (
            "present", ("IDENTITY",), ((
                "IDENTITY", self.ordinary.text.index("alex@example.test"),
                self.ordinary.text.index("alex@example.test") + len("alex@example.test"),
            ),), None,
        )
        right_decisions = self._baseline_decisions("reviewer-two")
        right_decisions[self.ordinary.review_id] = (
            "absent", (), (), None,
        )
        result = _run(self.pool, _envelope(self.pool, "reviewer-one", left_decisions),
                      _envelope(self.pool, "reviewer-two", right_decisions))
        self.assertIsNone(result.records[self.ordinary.review_id].has_pii)
        self.assertEqual(result.records[self.ordinary.review_id].reason,
                         "review_uncertain_or_disagreement")

        left_decisions[self.ordinary.review_id] = (
            "present", ("IDENTITY",), ((
                "IDENTITY", self.ordinary.text.index("alex@example.test"),
                self.ordinary.text.index("alex@example.test") + len("alex@example.test"),
            ),), None,
        )
        right_decisions[self.ordinary.review_id] = (
            "present", ("FINANCIAL",), ((
                "FINANCIAL", self.ordinary.text.index("$42"),
                self.ordinary.text.index("$42") + len("$42"),
            ),), None,
        )
        result = _run(self.pool, _envelope(self.pool, "reviewer-one", left_decisions),
                      _envelope(self.pool, "reviewer-two", right_decisions))
        self.assertIsNone(result.records[self.ordinary.review_id].has_pii)

        right_decisions[self.ordinary.review_id] = (
            "uncertain", (), (), "Meaning unresolved",
        )
        result = _run(self.pool, _envelope(self.pool, "reviewer-one", left_decisions),
                      _envelope(self.pool, "reviewer-two", right_decisions))
        self.assertIsNone(result.records[self.ordinary.review_id].has_pii)

    def test_raw_envelope_commitments_and_distinct_reviewer_assignments_are_required(self):
        first = _envelope(self.pool, "reviewer-one", self._baseline_decisions("reviewer-one"))
        second = _envelope(self.pool, "reviewer-two", self._baseline_decisions("reviewer-two"))
        left, right = _raw(first), _raw(second)
        args = dict(
            trusted_bindings=self.pool.bindings,
            expected_preparation_identity=self.pool.preparation_identity,
            expected_first_reviewer_id="reviewer-one",
            expected_second_reviewer_id="reviewer-two",
            expected_first_raw_sha256=hashlib.sha256(left).hexdigest(),
            expected_second_raw_sha256=hashlib.sha256(right).hexdigest(),
        )
        for change in (
            {"expected_first_raw_sha256": "0" * 64},
            {"expected_second_reviewer_id": "reviewer-one"},
            {"expected_preparation_identity": "0" * 64},
        ):
            with self.subTest(change=tuple(change)):
                with self.assertRaises(ValueError):
                    consume_dual_reviews(self.pool, left, right, **(args | change))

        swapped = _raw(_envelope(self.pool, "reviewer-two", self._baseline_decisions("reviewer-two")))
        args["expected_first_raw_sha256"] = hashlib.sha256(swapped).hexdigest()
        with self.assertRaises(ValueError):
            consume_dual_reviews(self.pool, swapped, right, **args)

    def test_incomplete_duplicate_malformed_and_native_contradictory_sets_reject(self):
        left = _envelope(self.pool, "reviewer-one", self._baseline_decisions("reviewer-one"))
        right = _envelope(self.pool, "reviewer-two", self._baseline_decisions("reviewer-two"))
        malformed_cases = [
            (dict(left, responses=left["responses"][:-1]), _raw(right)),
            (dict(left, responses=left["responses"] + [left["responses"][0]]), _raw(right)),
            (_raw(left)[:-2], _raw(right)),
            (b'{"x":1,"x":2}', _raw(right)),
            (b'{"x":NaN}', _raw(right)),
            (b"\xff", _raw(right)),
        ]
        for first_value, second_value in malformed_cases:
            first = first_value if type(first_value) is bytes else _raw(first_value)
            with self.subTest(first_prefix=first[:12]):
                with self.assertRaises(ValueError):
                    consume_dual_reviews(
                        self.pool, first, second_value, trusted_bindings=self.pool.bindings,
                        expected_preparation_identity=self.pool.preparation_identity,
                        expected_first_reviewer_id="reviewer-one",
                        expected_second_reviewer_id="reviewer-two",
                        expected_first_raw_sha256=hashlib.sha256(first).hexdigest(),
                        expected_second_raw_sha256=hashlib.sha256(second_value).hexdigest(),
                    )

        contradictory = self._baseline_decisions("reviewer-two")
        contradictory[self.positive.review_id] = ("absent", (), (), None)
        with self.assertRaises(ValueError):
            _run(self.pool, left, _envelope(self.pool, "reviewer-two", contradictory))

    def test_public_failures_do_not_echo_private_markers(self):
        marker = "PRIVATE_REVIEW_MARKER_dont_echo"
        raw = marker.encode("utf-8")
        with self.assertRaises(ValueError) as caught:
            consume_dual_reviews(
                self.pool, raw, raw, trusted_bindings=self.pool.bindings,
                expected_preparation_identity=self.pool.preparation_identity,
                expected_first_reviewer_id="reviewer-one",
                expected_second_reviewer_id="reviewer-two",
                expected_first_raw_sha256=hashlib.sha256(raw).hexdigest(),
                expected_second_raw_sha256=hashlib.sha256(raw).hexdigest(),
            )
        self.assertNotIn(marker, str(caught.exception))
        self.assertNotIn(marker, repr(caught.exception))


if __name__ == "__main__":
    unittest.main()
