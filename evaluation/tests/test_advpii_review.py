"""Synthetic-only contract tests for role-blind AdvPIIBench review helpers."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evaluation"))
sys.path.insert(0, str(ROOT / "shared/python"))

from privoke_eval.advpii_native import parse_native_row  # noqa: E402
from privoke_eval.advpii_review import (  # noqa: E402
    NativeSpanForReview,
    ReviewBindings,
    ValidatedNativeSpanInput,
    allocate_reviewed_components,
    build_review_pool,
    protected_keys_digest,
    validate_review_responses,
)
from privoke_eval.clean_augmentation_grouping import ProtectedKeys, build_components  # noqa: E402


def _parsed(uid: int, category: str = "positive", text: str | None = None):
    text = text or f"Please contact Alice at alice{uid}@example.test."
    start = text.index(f"alice{uid}@example.test") if category == "positive" else 0
    span = [] if category != "positive" else [{
        "type": "email", "start": start, "end": start + len(f"alice{uid}@example.test"),
        "value": f"alice{uid}@example.test", "value_fuzzy": None,
    }]
    row = {
        "uid": uid, "input_id": uid, "category": category,
        "attack_target": {"pii": [], "context": []}, "llm_input": text,
        "pii_spans": span,
    }
    parsed = parse_native_row(row)
    native = () if not span else (ValidatedNativeSpanInput(
        "email", span[0]["start"], span[0]["end"], span[0]["value"], span[0]["value"]
    ),)
    return parsed, native


def _bindings():
    digest = "a" * 64
    return ReviewBindings("1" * 40, "e97f6a32132e7fa058919798c030fca54aaad3318c47954d281717a435bfeb69",
                          "3991777aedadc8d50b7395a9ce8ef2aebfec946603229b823f1b6c118a16cbdf",
                          "203f37b4c77789a0f9c0838905954b9e1b76acf4f7906ab7717849e94616fcd7",
                          digest, digest, digest, digest, protected_keys_digest(ProtectedKeys()))


def _response(pool, package, decision="present"):
    present = decision == "present"
    evidence = []
    categories = []
    if present:
        span = package.native_spans[0]
        categories = ["IDENTITY"]
        evidence = [{"category": "IDENTITY", "start": span.start, "end": span.end}]
    return {
        "review_id": package.review_id,
        "source_sha256": pool.bindings.source_sha256,
        "pool_sha256": pool.pool_sha256,
        "rubric_sha256": pool.bindings.rubric_sha256,
        "text_sha256": package.text_sha256,
        "reviewer_id": "reviewer-synthetic",
        "reviewed_at": "2026-10-04T12:00:00+00:00",
        "full_prompt_reviewed": True,
        "blinding_attestation": {
            "no_detector_outputs": True,
            "no_model_scores_or_vocabularies": True,
            "no_partition_roles": True,
        },
        "decision": decision,
        "categories": categories,
        "evidence": evidence,
        "uncertainty_reason": "" if decision != "uncertain" else "synthetic uncertainty",
    }


class AdvPiiReviewTests(unittest.TestCase):
    def _one_row_pool(self):
        parsed, spans = _parsed(1)
        rows = (parsed,)
        graph = build_components([parsed.grouping_row])
        pool = build_review_pool(rows, graph, _bindings(), ProtectedKeys(), {1: spans})
        return parsed, graph, pool

    def test_pool_is_masked_and_native_spans_are_unicode_codepoint_checked(self):
        text = "Name: Zoë uses zoe@example.test 🧪"
        start = text.index("zoe@example.test")
        parsed = parse_native_row({
            "uid": 1, "input_id": 1, "category": "positive",
            "attack_target": {"pii": [], "context": []}, "llm_input": text,
            "pii_spans": [{"type": "email", "start": start, "end": start + 16,
                           "value": "zoe@example.test", "value_fuzzy": None}],
        })
        bound_span = ValidatedNativeSpanInput("email", start, start + 16, "zoe@example.test", "zoe@example.test")
        graph = build_components([parsed.grouping_row])
        pool = build_review_pool((parsed,), graph, _bindings(), ProtectedKeys(), {1: (bound_span,)})
        package = pool.packages[0]
        self.assertEqual(package.text, text)
        self.assertEqual(package.native_spans, (NativeSpanForReview("email", start, start + 16),))
        self.assertNotIn("uid", repr(package))
        self.assertNotIn("positive", repr(package))
        bad = ValidatedNativeSpanInput("email", start + 1, start + 17, "zoe@example.test", "zoe@example.test")
        with self.assertRaisesRegex(ValueError, "malformed"):
            build_review_pool((parsed,), graph, _bindings(), ProtectedKeys(), {1: (bad,)})

    def test_response_coverage_binding_and_absent_native_positive_rejected(self):
        _, _, pool = self._one_row_pool()
        response = _response(pool, pool.packages[0], "absent")
        with self.assertRaisesRegex(ValueError, "native-positive"):
            validate_review_responses(pool, [response])
        response = _response(pool, pool.packages[0])
        validate_review_responses(pool, [response])
        tampered = dict(response, text_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "binding"):
            validate_review_responses(pool, [tampered])
        with self.assertRaisesRegex(ValueError, "exactly"):
            validate_review_responses(pool, [])

    def test_protected_key_digest_is_bound_separately_from_artifact_identity(self):
        parsed, graph, _ = self._one_row_pool()
        altered = ProtectedKeys(ids=frozenset({"b" * 64}))
        with self.assertRaisesRegex(ValueError, "protected-key set"):
            build_review_pool((parsed,), graph, _bindings(), altered, {
                1: (ValidatedNativeSpanInput("email", 31, 51, "alice1@example.test", "alice1@example.test"),)
            })
        _, _, pool = self._one_row_pool()
        with self.assertRaisesRegex(ValueError, "protected-key set"):
            allocate_reviewed_components(
                pool, [_response(pool, pool.packages[0])], (parsed,), graph, altered
            )

    def test_uncertain_is_not_false_and_evidence_requires_supported_offsets(self):
        _, _, pool = self._one_row_pool()
        response = _response(pool, pool.packages[0], "uncertain")
        reviewed = validate_review_responses(pool, [response])[pool.packages[0].review_id]
        self.assertIsNone(reviewed.has_pii)
        malformed = _response(pool, pool.packages[0])
        malformed["evidence"] = [{"category": "IDENTITY", "start": -1, "end": 2}]
        with self.assertRaisesRegex(ValueError, "evidence"):
            validate_review_responses(pool, [malformed])

    def test_reviewed_present_native_negative_does_not_supply_absent_capacity(self):
        parsed = parse_native_row({
            "uid": 8, "input_id": 8, "category": "negative",
            "attack_target": {"pii": [], "context": []},
            "llm_input": "My diagnosis is diabetes.", "pii_spans": [],
        })
        graph = build_components([parsed.grouping_row])
        pool = build_review_pool((parsed,), graph, _bindings(), ProtectedKeys(), {8: ()})
        package = pool.packages[0]
        response = _response(pool, package, "absent")
        response["decision"] = "present"
        start = package.text.index("diabetes")
        response["evidence"] = [{"category": "HEALTH", "start": start, "end": start + 8}]
        response["categories"] = ["HEALTH"]
        result = allocate_reviewed_components(pool, [response], (parsed,), graph, ProtectedKeys())
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.capacities["test"]["ordinary"], 0)
        self.assertEqual(result.capacities["test"]["positive"], 0)

    def test_single_pass_allocator_fails_without_retries_when_capacity_short(self):
        parsed, graph, pool = self._one_row_pool()
        responses = [_response(pool, pool.packages[0])]
        result = allocate_reviewed_components(pool, responses, (parsed,), graph, ProtectedKeys())
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.reason, "single_pass_shortage_test")
        self.assertEqual(result.partitions, {})
        self.assertEqual(result.shortages["test"]["positive"], 999)

    def test_greedy_allocator_meets_quotas_and_component_floors_once(self):
        parsed_rows = []
        spans_by_uid = {}
        uid = 1
        for component in range(1000):
            for category, copies in (("positive", 4), ("negative", 4), ("hard_negative", 1)):
                for _ in range(copies):
                    text = f"Synthetic component {component} row {uid} contact x{uid}@example.test"
                    # The synthetic group's parent link is shared across all
                    # rows in the component; native values remain unique.
                    parsed = parse_native_row({
                        "uid": uid, "input_id": component + 1, "category": category,
                        "attack_target": {"pii": [], "context": []}, "llm_input": text,
                        "pii_spans": ([] if category != "positive" else [{
                            "type": "email", "start": text.index(f"x{uid}@example.test"),
                            "end": text.index(f"x{uid}@example.test") + len(f"x{uid}@example.test"),
                            "value": f"x{uid}@example.test", "value_fuzzy": None,
                        }]),
                    })
                    spans = () if category != "positive" else (ValidatedNativeSpanInput(
                        "email", text.index(f"x{uid}@example.test"),
                        text.index(f"x{uid}@example.test") + len(f"x{uid}@example.test"),
                        f"x{uid}@example.test", f"x{uid}@example.test",
                    ),)
                    parsed_rows.append(parsed)
                    spans_by_uid[uid] = spans
                    uid += 1
        original_graph = build_components([row.grouping_row for row in parsed_rows])
        pool = build_review_pool(tuple(parsed_rows), original_graph, _bindings(), ProtectedKeys(), spans_by_uid)
        responses = []
        member_category = {member.review_id: member.native_category for member in pool._members}
        for package in pool.packages:
            positive = member_category[package.review_id] == "positive"
            response = _response(pool, package, "present" if positive else "absent")
            if positive:
                # Source spans are present in the masked package; use an
                # evidence category supported by the synthetic prompt.
                response["categories"] = ["IDENTITY"]
                span = package.native_spans[0]
                response["evidence"] = [{"category": "IDENTITY", "start": span.start, "end": span.end}]
            responses.append(response)
        result = allocate_reviewed_components(
            pool, responses, tuple(parsed_rows), original_graph, ProtectedKeys()
        )
        self.assertEqual(result.status, "complete")
        self.assertEqual({part: len(rows) for part, rows in result.partitions.items()}, {
            "test": 2000, "validation": 2000, "train": 4000,
        })
        self.assertEqual(result.represented_components["test"], {"positive": 250, "absent": 250})
        self.assertEqual(result.capacities["test"], {"positive": 1000, "ordinary": 1000, "hard": 250})
        self.assertEqual(result.capacities["train"], {"positive": 2000, "ordinary": 2000, "hard": 500})
        self.assertFalse(set(result.partitions["test"]) & set(result.partitions["validation"]))
        self.assertFalse(set(result.partitions["validation"]) & set(result.partitions["train"]))
        permuted_graph = build_components([row.grouping_row for row in reversed(parsed_rows)])
        permuted_pool = build_review_pool(tuple(reversed(parsed_rows)), permuted_graph, _bindings(), ProtectedKeys(), spans_by_uid)
        self.assertEqual(permuted_pool.pool_sha256, pool.pool_sha256)
        permuted_member_category = {member.review_id: member.native_category for member in permuted_pool._members}
        permuted_responses = [
            _response(permuted_pool, package,
                      "present" if permuted_member_category[package.review_id] == "positive" else "absent")
            for package in reversed(permuted_pool.packages)
        ]
        permuted_result = allocate_reviewed_components(
            permuted_pool, permuted_responses, tuple(reversed(parsed_rows)), permuted_graph, ProtectedKeys()
        )
        self.assertEqual(dict(permuted_result.partitions), dict(result.partitions))


if __name__ == "__main__":
    unittest.main()
