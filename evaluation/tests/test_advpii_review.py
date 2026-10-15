"""Synthetic-only contract tests for role-blind AdvPIIBench review helpers."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evaluation"))
sys.path.insert(0, str(ROOT / "shared/python"))

from privoke_eval.advpii_native import parse_native_row  # noqa: E402
import privoke_eval.advpii_review as review_module  # noqa: E402
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

    def test_excluded_malformed_rows_keep_bridges_without_span_packages(self):
        invalid_positive = parse_native_row({
            "uid": 10, "input_id": 101, "category": "positive",
            "attack_target": {"pii": [], "context": []}, "llm_input": "A contact is alice@example.test",
            "pii_spans": [{"type": "email", "start": 0, "end": 5,
                           "value": "alice@example.test", "value_fuzzy": None}],
        })
        missing_text = parse_native_row({
            "uid": 11, "input_id": 101, "category": "negative",
            "attack_target": {"pii": [], "context": []}, "llm_input": None, "pii_spans": [],
        })
        eligible_negative = parse_native_row({
            "uid": 12, "input_id": 101, "category": "negative",
            "attack_target": {"pii": [], "context": []}, "llm_input": "What is the weather?", "pii_spans": [],
        })
        rows = (invalid_positive, missing_text, eligible_negative)
        graph = build_components([row.grouping_row for row in rows])
        self.assertEqual(graph.component_count, 1)
        pool = build_review_pool(rows, graph, _bindings(), ProtectedKeys(), {12: ()})
        self.assertEqual(len(pool.packages), 1)
        self.assertEqual(pool._members[0].uid, 12)
        self.assertEqual(pool._members[0].component_id, graph.components[0].component_id)

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
        unrelated = _response(pool, pool.packages[0])
        unrelated["categories"] = ["HEALTH"]
        unrelated["evidence"] = [{
            "category": "HEALTH", "start": pool.packages[0].native_spans[0].start,
            "end": pool.packages[0].native_spans[0].end,
        }]
        with self.assertRaisesRegex(ValueError, "native span category"):
            validate_review_responses(pool, [unrelated])

    def test_timestamp_error_does_not_echo_untrusted_input_in_traceback(self):
        import traceback

        _, _, pool = self._one_row_pool()
        response = _response(pool, pool.packages[0])
        marker = "TIMESTAMP-PRIVATE-MARKER"
        response["reviewed_at"] = marker
        try:
            validate_review_responses(pool, [response])
        except ValueError:
            rendered = traceback.format_exc()
        else:
            self.fail("malformed timestamp was accepted")
        self.assertNotIn(marker, rendered)

    def test_each_native_type_needs_its_mapped_category_and_span_evidence(self):
        text = "Call +1-212-555-0100; card 4111 1111 1111 1111"
        phone, card = "+1-212-555-0100", "4111 1111 1111 1111"
        phone_start, card_start = text.index(phone), text.index(card)
        parsed = parse_native_row({
            "uid": 21, "input_id": 21, "category": "positive",
            "attack_target": {"pii": [], "context": []}, "llm_input": text,
            "pii_spans": [
                {"type": "phone_number", "start": phone_start, "end": phone_start + len(phone),
                 "value": phone, "value_fuzzy": None},
                {"type": "credit_card_number", "start": card_start, "end": card_start + len(card),
                 "value": card, "value_fuzzy": None},
            ],
        })
        spans = (
            ValidatedNativeSpanInput("phone_number", phone_start, phone_start + len(phone), phone, phone),
            ValidatedNativeSpanInput("credit_card_number", card_start, card_start + len(card), card, card),
        )
        graph = build_components([parsed.grouping_row])
        pool = build_review_pool((parsed,), graph, _bindings(), ProtectedKeys(), {21: spans})
        package = pool.packages[0]
        valid = _response(pool, package)
        valid["categories"] = ["IDENTITY", "FINANCIAL"]
        valid["evidence"] = [
            {"category": "IDENTITY", "start": phone_start, "end": phone_start + len(phone)},
            {"category": "FINANCIAL", "start": card_start, "end": card_start + len(card)},
        ]
        validate_review_responses(pool, [valid])
        omitted = dict(valid, categories=["IDENTITY"], evidence=[valid["evidence"][0]])
        with self.assertRaisesRegex(ValueError, "every valid native span category"):
            validate_review_responses(pool, [omitted])

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

    def test_selected_component_counts_exclude_unselected_class_overshoot(self):
        parsed_rows = []
        span_map = {}
        uid = 1
        for component in range(404):
            positive_text = f"Synthetic {component} contact p{component}@example.test"
            start = positive_text.index(f"p{component}@example.test")
            positive_raw = {
                "uid": uid, "input_id": component + 1, "category": "positive",
                "attack_target": {"pii": [], "context": []}, "llm_input": positive_text,
                "pii_spans": [{"type": "email", "start": start,
                               "end": start + len(f"p{component}@example.test"),
                               "value": f"p{component}@example.test", "value_fuzzy": None}],
            }
            positive = parse_native_row(positive_raw)
            parsed_rows.append(positive)
            span_map[uid] = (ValidatedNativeSpanInput(
                "email", start, start + len(f"p{component}@example.test"),
                f"p{component}@example.test", f"p{component}@example.test",
            ),)
            uid += 1
            negative = parse_native_row({
                "uid": uid, "input_id": component + 1, "category": "negative",
                "attack_target": {"pii": [], "context": []},
                "llm_input": f"Synthetic benign prompt {component}.", "pii_spans": [],
            })
            parsed_rows.append(negative)
            span_map[uid] = ()
            uid += 1
            unknown = parse_native_row({
                "uid": uid, "input_id": component + 1, "category": "unknown",
                "attack_target": {"pii": [], "context": []},
                "llm_input": f"Synthetic bridge prompt {component}.", "pii_spans": [],
            })
            parsed_rows.append(unknown)
            span_map[uid] = ()
            uid += 1

        preliminary = build_components([row.grouping_row for row in parsed_rows])
        order = sorted(preliminary.components, key=lambda item: item.component_id)
        import random
        random.Random(review_module.SPLIT_SEED).shuffle(order)
        special_uids = {order[index].member_uids[-1] for index in (200, 401, 402)}
        parsed_rows = [
            (parse_native_row({
                "uid": row.grouping_row.uid,
                "input_id": row.grouping_row.input_id,
                "category": "hard_negative",
                "attack_target": {"pii": [], "context": []},
                "llm_input": row.grouping_row.text, "pii_spans": [],
            }) if row.grouping_row.uid in special_uids else row)
            for row in parsed_rows
        ]
        graph = build_components([row.grouping_row for row in parsed_rows])
        special_components = {component.component_id for component in graph.components
                              if any(uid in special_uids for uid in component.member_uids)}
        self.assertEqual(len(special_components), 3)
        pool = build_review_pool(tuple(parsed_rows), graph, _bindings(), ProtectedKeys(), span_map)
        responses = []
        package_member = {member.review_id: member for member in pool._members}
        for package in pool.packages:
            category = package_member[package.review_id].native_category
            responses.append(_response(pool, package, "present" if category == "positive" else "absent"))

        previous_quotas = review_module._QUOTAS
        review_module._QUOTAS = {
            "test": {"positive": 200, "ordinary": 200, "hard": 1},
            "validation": {"positive": 200, "ordinary": 200, "hard": 1},
            "train": {"positive": 1, "ordinary": 1, "hard": 1},
        }
        try:
            result = allocate_reviewed_components(pool, responses, tuple(parsed_rows), graph, ProtectedKeys())
        finally:
            review_module._QUOTAS = previous_quotas
        self.assertEqual(result.status, "complete")
        self.assertEqual(result.assigned_components_by_class["test"]["positive"], 201)
        self.assertEqual(result.represented_components["test"]["positive"], 200)

    def test_single_pass_allocator_fails_without_retries_when_capacity_short(self):
        parsed, graph, pool = self._one_row_pool()
        responses = [_response(pool, pool.packages[0])]
        result = allocate_reviewed_components(pool, responses, (parsed,), graph, ProtectedKeys())
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.reason, "single_pass_shortage_test:rows_positive,rows_ordinary,rows_hard,floor_positive,floor_absent")
        self.assertEqual(result.partitions, {})
        self.assertEqual(result.shortages["test"]["positive"], 999)
        self.assertEqual(result.floor_shortages["test"], {"positive": 199, "absent": 200})

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
