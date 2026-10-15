"""Synthetic-only versioned bindings, tamper and external-trust checks."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "evaluation"), str(ROOT / "shared/python")]
from privoke_eval.advpii_native import parse_native_row
from privoke_eval.advpii_review import (
    ReviewBindings, ValidatedNativeSpanInput, build_review_pool,
    protected_keys_digest, SOURCE_SHA256, PROTOCOL_SHA256, RUBRIC_SHA256,
)
from privoke_eval.clean_augmentation_grouping import ProtectedKeys, build_components
from privoke_eval.contextual_fixture_protection import combined_protection_digest
from privoke_eval.in_house_advpii_review import (
    EXECUTION_CODE_ROLES, InHouseProtectionBindings, InHouseReviewBindings, InHouseReviewPool,
    build_in_house_review_pool, validate_in_house_review_pool,
    validate_in_house_review_responses,
)

D = "a" * 64


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def bindings(keys=ProtectedKeys()):
    internal = protected_keys_digest(keys)
    protection = InHouseProtectionBindings(
        D, "b" * 64, "c" * 64, "d" * 64, "e" * 64, "f" * 64,
        combined_protection_digest(keys), internal,
        {role: D for role in ("fixture", "rubric", "review")},
        {role: D for role in ("fixture", "rubric", "review")}, "1" * 40,
        {role: D for role in ("grouping", "normalizer", "fixture_validator")},
    )
    legacy = ReviewBindings("1" * 40, SOURCE_SHA256, PROTOCOL_SHA256, RUBRIC_SHA256,
                            D, D, D, "c" * 64, internal)
    return InHouseReviewBindings(legacy, protection, D, {role: D for role in EXECUTION_CODE_ROLES})


def inputs():
    text = "Zo\u00eb contact alice@example.test \U0001f9ea"
    start = text.index("alice@example.test")
    rows = (parse_native_row({
        "uid": 7, "input_id": 4, "category": "positive", "llm_input": text,
        "attack_target": {"pii": [], "context": []},
        "pii_spans": [{"type": "email", "start": start, "end": start + 18,
                       "value": "alice@example.test", "value_fuzzy": None}],
    }),)
    spans = {7: (ValidatedNativeSpanInput("email", start, start + 18,
                                         "alice@example.test", "alice@example.test"),)}
    return rows, spans


def make_pool(keys=ProtectedKeys(), bound=None):
    rows, spans = inputs()
    bound = bindings(keys) if bound is None else bound
    graph = build_components([row.grouping_row for row in rows], keys)
    return build_in_house_review_pool(rows, graph, bound, keys, spans)


def response(pool, decision="present"):
    package = pool.core.packages[0]
    span = package.native_spans[0]
    return {
        "review_id": package.review_id, "source_sha256": SOURCE_SHA256,
        "pool_sha256": pool.core.pool_sha256, "rubric_sha256": RUBRIC_SHA256,
        "text_sha256": package.text_sha256, "reviewer_id": "synthetic",
        "reviewed_at": "2026-10-04T00:00:00Z", "full_prompt_reviewed": True,
        "blinding_attestation": {"no_detector_outputs": True,
                                  "no_model_scores_or_vocabularies": True, "no_partition_roles": True},
        "decision": decision, "categories": ["IDENTITY"] if decision == "present" else [],
        "evidence": [{"category": "IDENTITY", "start": span.start, "end": span.end}]
                    if decision == "present" else [],
        "uncertainty_reason": "Uncertain whole-prompt scope" if decision == "uncertain" else None,
    }


def envelope(pool, responses=None):
    return {"schema_version": 1, "kind": "privoke-in-house-blind-review-responses-v1",
            "preparation_identity": pool.preparation_identity, "review_pool_sha256": pool.review_pool_sha256,
            "responses": [response(pool)] if responses is None else responses}


class InHouseReviewTests(unittest.TestCase):
    def validate(self, pool, expected=None):
        return validate_in_house_review_pool(pool, trusted_bindings=expected or pool.bindings)

    def reviewed(self, pool, value):
        return validate_in_house_review_responses(pool, value, trusted_bindings=pool.bindings,
                                                 expected_preparation_identity=pool.preparation_identity)

    def test_legacy_pool_bytes_selection_and_defaults_remain_exact(self):
        pool = make_pool()
        rows, spans = inputs()
        ordinary = build_review_pool(rows, pool._graph, pool.bindings.legacy, ProtectedKeys(), spans)
        self.assertEqual(pool.core, ordinary)
        self.assertEqual(ordinary.pool_sha256, "19fd528ea6e3bf9368adf65d086169a0d05089fcbdc2852191a419f8327df04c")

        self.assertEqual(pool.core.pool_sha256, canonical_hash([
            {"review_id": p.review_id, "text": p.text, "text_sha256": p.text_sha256,
             "rubric_sha256": p.rubric_sha256,
             "native_spans": [[s.entity_type, s.start, s.end] for s in p.native_spans]}
            for p in ordinary.packages]))
        self.assertEqual(ordinary.bindings.protected_union_sha256, "c" * 64)
        self.assertNotEqual(ordinary.bindings.protected_union_sha256,
                            pool.bindings.protection.historical_artifact_raw_sha256)
        self.validate(pool)

    def test_four_key_domains_and_plan_internal_digest_separation(self):
        empty = ProtectedKeys()
        for role in ("ids", "groups", "exact_text_sha256", "normalized_texts"):
            keys = replace(empty, **{role: frozenset({"0" * 64})})
            self.assertNotEqual(protected_keys_digest(keys), protected_keys_digest(empty))
            self.assertNotEqual(combined_protection_digest(keys), combined_protection_digest(empty))
            self.assertNotEqual(protected_keys_digest(keys), combined_protection_digest(keys))
            pool = make_pool(keys)
            self.validate(pool)
            with self.assertRaises(ValueError):
                make_pool(empty, bindings(keys))

    def test_closed_recursive_immutable_bindings_and_strict_types(self):
        value = bindings()
        source = {role: D for role in EXECUTION_CODE_ROLES}
        copy = replace(value, execution_code_raw_sha256=source)
        source["parser"] = "b" * 64
        self.assertEqual(copy.execution_code_raw_sha256["parser"], D)
        with self.assertRaises(TypeError):
            copy.protection.fixture_input_raw_sha256["fixture"] = "b" * 64
        for field, wrong in (("schema_version", True), ("study_plan_lf_sha256", "0" * 64),
                             ("execution_code_raw_sha256", {"unknown": D}),
                             ("preparation_pin_manifest_raw_sha256", "PRIVATE_MARKER")):
            with self.assertRaises(ValueError) as caught:
                replace(value, **{field: wrong})
            self.assertNotIn("PRIVATE_MARKER", str(caught.exception))
        with self.assertRaises(TypeError):
            InHouseProtectionBindings(**dict(value.protection.to_dict(), unknown=D))
        with self.assertRaises(ValueError):
            replace(value.protection, fixture_input_consumed_sha256={"fixture": D, "rubric": D, "review": "b" * 64})
        with self.assertRaises(ValueError):
            replace(value, legacy=replace(value.legacy, protected_union_sha256=D))

    def test_actual_key_identity_required_before_build(self):
        value = bindings()
        for field in ("combined_protection_sha256", "internal_protected_keys_sha256"):
            protection = replace(value.protection, **{field: "0" * 64})
            legacy = replace(value.legacy, protected_keys_sha256=protection.internal_protected_keys_sha256)
            with self.assertRaises(ValueError):
                make_pool(bound=replace(value, protection=protection, legacy=legacy))

    def test_identical_packages_new_protection_changes_identity_not_legacy_digest(self):
        pool = make_pool()
        alternate = replace(pool.bindings, protection=replace(pool.bindings.protection,
                                                              addon_receipt_raw_sha256="0" * 64))
        other = make_pool(bound=alternate)
        self.assertEqual(other.core.pool_sha256, pool.core.pool_sha256)
        self.assertNotEqual(other.review_pool_sha256, pool.review_pool_sha256)
        self.assertNotEqual(other.preparation_identity, pool.preparation_identity)
        with self.assertRaises(ValueError):
            self.validate(other, pool.bindings)

    def test_tampered_core_records_not_accepted_with_reported_hashes(self):
        pool = make_pool()
        package, member = pool.core.packages[0], pool.core._members[0]
        variants = [replace(pool.core, pool_size=True), replace(pool.core, pool_size=2),
                    replace(pool.core, selection_streams=("changed",)),
                    replace(pool.core, packages=(replace(package, text="CHANGED_PRIVATE_TEXT"),)),
                    replace(pool.core, packages=(replace(package, native_spans=()),)),
                    replace(pool.core, _members=(replace(member, component_id="0" * 64),)),
                    replace(pool.core, _members=(replace(member, structural_eligible=False),)),
                    replace(pool.core, bindings=replace(pool.core.bindings, source_revision="2" * 40))]
        for core in variants:
            with self.assertRaises(ValueError) as caught:
                self.validate(replace(pool, core=core))
            self.assertNotIn("CHANGED_PRIVATE_TEXT", str(caught.exception))

    def test_private_membership_graph_and_versioned_hashes_recomputed(self):
        pool = make_pool()
        for field in ("pool_sha256", "private_members_sha256", "graph_membership_sha256"):
            with self.assertRaises(ValueError):
                self.validate(replace(pool, core=replace(pool.core, **{field: "0" * 64})))
        for field in ("preparation_identity", "review_pool_sha256"):
            with self.assertRaises(ValueError):
                self.validate(replace(pool, **{field: "0" * 64}))
        bad_graph = replace(pool._graph, row_count=2)
        with self.assertRaises(ValueError):
            self.validate(replace(pool, _graph=bad_graph))

    def test_response_envelope_checks_identity_schema_and_exact_coverage(self):
        pool = make_pool()
        self.assertTrue(next(iter(self.reviewed(pool, envelope(pool)).values())).has_pii)
        for field, wrong in (("schema_version", True), ("kind", "legacy"),
                             ("preparation_identity", "0" * 64), ("review_pool_sha256", "0" * 64),
                             ("responses", []), ("responses", [response(pool), response(pool)])):
            with self.assertRaises(ValueError):
                self.reviewed(pool, dict(envelope(pool), **{field: wrong}))
        for value in ([response(pool)], dict(envelope(pool), extra=D),
                      {key: val for key, val in envelope(pool).items() if key != "preparation_identity"}):
            with self.assertRaises(ValueError):
                self.reviewed(pool, value)
        with self.assertRaises(ValueError):
            self.reviewed(pool, envelope(pool, [dict(response(pool), review_id="0" * 64)]))

    def test_uncertain_native_positive_does_not_become_false_or_invent_evidence(self):
        pool = make_pool()
        result = next(iter(self.reviewed(pool, envelope(pool, [response(pool, "uncertain")])).values()))
        self.assertIsNone(result.has_pii)
        self.assertEqual(result.categories, ())
        with self.assertRaises(ValueError):
            self.reviewed(pool, envelope(pool, [response(pool, "absent")]))
        wrong = dict(response(pool), categories=["HEALTH"],
                     evidence=[dict(response(pool)["evidence"][0], category="HEALTH")])
        with self.assertRaises(ValueError):
            self.reviewed(pool, envelope(pool, [wrong]))

    def test_self_consistent_native_span_rehash_cannot_replace_source_provenance(self):
        pool = make_pool()
        package, member = pool.core.packages[0], pool.core._members[0]
        shifted = replace(package.native_spans[0], start=0, end=3)
        package = replace(package, native_spans=(shifted,))
        member = replace(member, native_spans=(shifted,))
        spans = [[shifted.entity_type, shifted.start, shifted.end]]
        core = replace(pool.core, packages=(package,), _members=(member,),
            pool_sha256=canonical_hash([{"review_id": package.review_id, "text": package.text,
                "text_sha256": package.text_sha256, "rubric_sha256": package.rubric_sha256,
                "native_spans": spans}]),
            private_members_sha256=canonical_hash([[member.review_id, member.uid,
                member.component_id, member.native_category, member.exact_text_sha256,
                member.normalized_text_key, member.structural_eligible, spans]]))
        new_pool_sha = canonical_hash({"schema": "privoke-in-house-review-pool-v1",
            "bindings": pool.bindings.to_dict(), "legacy_pool_sha256": core.pool_sha256,
            "graph_membership_sha256": core.graph_membership_sha256,
            "private_members_sha256": core.private_members_sha256, "pool_size": core.pool_size,
            "selection_streams": list(core.selection_streams)})
        preparation = canonical_hash({"schema": "privoke-in-house-review-preparation-v1",
            "review_pool_sha256": new_pool_sha, "bindings": pool.bindings.to_dict()})
        with self.assertRaises(ValueError):
            self.validate(replace(pool, core=core, review_pool_sha256=new_pool_sha,
                                  preparation_identity=preparation))

    def test_excluded_bridge_is_retained_and_private_inputs_are_copied(self):
        rows, spans = inputs()
        bridge = parse_native_row({"uid": 8, "input_id": 4, "category": "negative",
            "llm_input": None, "attack_target": {"pii": [], "context": []}, "pii_spans": []})
        source_rows = list(rows) + [bridge]
        graph = build_components([row.grouping_row for row in source_rows])
        pool = build_in_house_review_pool(source_rows, graph, bindings(), ProtectedKeys(), spans)
        source_rows.clear(); spans.clear()
        self.assertEqual(pool._graph.row_count, 2)
        self.assertEqual(pool._graph.component_count, 1)
        self.assertEqual(pool.core.pool_size, 1)
        self.validate(pool)
        with self.assertRaises(TypeError):
            pool._native_span_inputs[7] = ()
        with self.assertRaises(ValueError):
            build_in_house_review_pool(rows, graph, bindings(), ProtectedKeys(), {7: ()})

    def test_preparation_refuses_preassigned_binary_truth(self):
        rows, spans = inputs()
        labeled = replace(rows[0], grouping_row=replace(rows[0].grouping_row, reviewed_has_pii=True))
        graph = build_components([labeled.grouping_row])
        with self.assertRaises(ValueError):
            build_in_house_review_pool((labeled,), graph, bindings(), ProtectedKeys(), spans)

    def test_dataclass_replacement_rejects_true_and_false_retained_truth(self):
        pool = make_pool()
        for truth in (True, False):
            with self.subTest(truth=truth):
                row = replace(pool._source_rows[0], grouping_row=replace(
                    pool._source_rows[0].grouping_row, reviewed_has_pii=truth))
                graph = build_components([row.grouping_row], pool._combined_keys)
                self.assertNotEqual(graph.assignable_row_count, pool._graph.assignable_row_count)
                with self.assertRaises(ValueError):
                    replace(pool, _source_rows=(row,), _graph=graph)

    def test_public_validators_repeat_truth_guard_before_any_rebuild_or_responses(self):
        pool = make_pool()
        for truth in (True, False):
            with self.subTest(truth=truth):
                row = replace(pool._source_rows[0], grouping_row=replace(
                    pool._source_rows[0].grouping_row, reviewed_has_pii=truth))
                graph = build_components([row.grouping_row], pool._combined_keys)
                # Simulate a retained object reconstructed without constructor
                # checks; validation must independently defend the boundary.
                with patch.object(InHouseReviewPool, "__post_init__", return_value=None):
                    forged = replace(pool, _source_rows=(row,), _graph=graph)
                self.assertEqual(forged.preparation_identity, pool.preparation_identity)
                self.assertEqual(forged.bindings, pool.bindings)
                with patch("privoke_eval.in_house_advpii_review.build_review_pool") as rebuild:
                    with self.assertRaises(ValueError):
                        validate_in_house_review_pool(forged, trusted_bindings=pool.bindings)
                    rebuild.assert_not_called()
                    with patch("privoke_eval.in_house_advpii_review.validate_review_responses") as decisions:
                        with self.assertRaises(ValueError):
                            validate_in_house_review_responses(forged,
                                envelope(pool, [response(pool, "uncertain")]),
                                trusted_bindings=pool.bindings,
                                expected_preparation_identity=pool.preparation_identity)
                        decisions.assert_not_called()
                    rebuild.assert_not_called()

    def test_self_consistent_foreign_pool_requires_external_trust_and_identity(self):
        pool = make_pool()
        other = make_pool(bound=replace(pool.bindings, preparation_pin_manifest_raw_sha256="0" * 64))
        with self.assertRaises(ValueError):
            validate_in_house_review_responses(other, envelope(other), trusted_bindings=pool.bindings,
                                               expected_preparation_identity=pool.preparation_identity)
        with self.assertRaises(ValueError):
            validate_in_house_review_responses(pool, envelope(pool), trusted_bindings=pool.bindings,
                                               expected_preparation_identity=other.preparation_identity)


if __name__ == "__main__":
    unittest.main()
