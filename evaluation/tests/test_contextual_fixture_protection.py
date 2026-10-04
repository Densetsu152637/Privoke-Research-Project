"""Synthetic-only tests for the pure contextual fixture protection add-on."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evaluation"))
sys.path.insert(0, str(ROOT / "shared/python"))

from privoke_eval.clean_augmentation_grouping import ProtectedKeys, opaque_exclusion_key
from privoke_eval.contextual_fixture_protection import (
    ADDON_DOMAIN,
    COMBINED_DOMAIN,
    FixtureProtectionError,
    FixtureProtectionPolicy,
    build_fixture_addon,
    combine_protected_keys,
    combined_protection_digest,
    validate_fixture_addon,
    _json_load,
    _parse_cases,
)
from privoke_model.training_data import training_text_key


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def synthetic_inputs():
    rows = []
    for index in range(48):
        if index < 24:
            truth, ambiguous = False, False
        elif index < 41:
            truth, ambiguous = True, False
        else:
            truth, ambiguous = None, True
        # Two different cases intentionally share exact text. The add-on must
        # preserve actual unique counts instead of assuming one key per row.
        if index in (0, 1):
            text = "synthetic café control"
        elif index == 2:
            text = "synthetic cafe\u0301 control"
        elif index == 3:
            text = "synthetic\u2028line separator remains inside a JSONL value"
        else:
            text = f"synthetic fictional prompt {index}"
        rows.append({
            "case_id": f"synthetic-case-{index}",
            "family_id": f"family-{index // 4}",
            "text": text,
            "required_sensitive": truth,
            "expected_sensitivity": None if ambiguous else "S2",
            "expected_visibility": None if ambiguous else "PU",
            "expected_categories": None if ambiguous else ([] if truth is False else ["HEALTH"]),
            "expected_action": None if ambiguous else ("ALLOW" if truth is False else "WARN"),
            "minimum_action": None if ambiguous else ("ALLOW" if truth is False else "WARN"),
            "allowed_actions": None if ambiguous else (["ALLOW"] if truth is False else ["WARN", "BLOCK"]),
            "context_truth_eligible": not ambiguous,
            "action_accuracy_eligible": not ambiguous,
            "ambiguous": ambiguous,
            "label_status": "assistant_provisional_professor_pending",
            "provisional_annotation_rationale": "Synthetic test-only rationale.",
            "visibility_hint": "P3" if index < 4 else None,
        })
    fixture = b"".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
                      for row in rows)
    rubric = b"# synthetic-only rubric\n"
    counts = {
        "total": 48, "families": 12, "controls": 24, "disclosure_candidates": 17,
        "ambiguous_excluded": 7, "context_truth_eligible": 41,
        "action_accuracy_eligible": 41, "visibility_hints": 4,
    }
    review = {
        "status": "reviewed",
        "case_file": "evaluation/datasets/contextual-cascade-regressions.jsonl",
        "case_file_sha256": sha(fixture),
        "rubric_file": "paper/research/contextual-cascade-rubric.md",
        "rubric_sha256": sha(rubric),
        "reviewer": "assistant independent review",
        "label_review_sha256": "1" * 64,
        "label_review_note_sha256": "2" * 64,
        "source_draft_cases_sha256": "3" * 64,
        "source_draft_rubric_sha256": "4" * 64,
        "source_draft_builder_sha256": "5" * 64,
        "source_revision": "d291f3c544f0cc1d8d2b9ecdcf2e05deedb8819d",
        "professor_confirmation": "pending",
        "case_counts": counts,
        "normalized_text_collision_check": {"fixture_unique_keys": 46, "collisions": {"final": "not opened"}},
    }
    review_bytes = json.dumps(review, sort_keys=True, separators=(",", ":")).encode("utf-8")
    policy = FixtureProtectionPolicy(
        fixture_sha256=sha(fixture), rubric_sha256=sha(rubric), review_sha256=sha(review_bytes),
        review_counts=counts,
    )
    helpers = {"grouping": "a" * 64, "normalizer": "b" * 64, "fixture_validator": "c" * 64}
    return fixture, rubric, review_bytes, policy, helpers


class ContextualFixtureProtectionTests(unittest.TestCase):
    def setUp(self):
        self.fixture, self.rubric, self.review, self.policy, self.helpers = synthetic_inputs()
        self.artifact, self.receipt = build_fixture_addon(
            self.fixture, self.rubric, self.review, source_revision="d" * 40,
            helper_source_hashes=self.helpers, policy=self.policy,
        )

    def validate(self, **overrides):
        args = {
            "fixture_bytes": self.fixture,
            "rubric_bytes": self.rubric,
            "review_bytes": self.review,
            "artifact_bytes": self.artifact,
            "receipt_bytes": self.receipt,
            "expected_receipt_sha256": sha(self.receipt),
            "expected_source_revision": "d" * 40,
            "expected_helper_source_hashes": self.helpers,
            "policy": self.policy,
        }
        args.update(overrides)
        return validate_fixture_addon(**args)

    def test_build_validate_uses_only_id_and_text_and_actual_unique_counts(self):
        keys = self.validate()
        payload = json.loads(self.artifact)
        self.assertEqual(len(keys.ids), 48)
        self.assertEqual(keys.groups, frozenset())
        self.assertEqual(len(keys.exact_text_sha256), 47)
        self.assertEqual(len(keys.normalized_texts), 46)
        self.assertEqual(payload["coverage_counts"], {
            "ids": 48, "groups": 0, "exact_text_sha256": 47, "normalized_texts": 46,
        })
        self.assertNotIn("family-0", self.artifact.decode("utf-8"))
        self.assertNotIn("synthetic-case-0", self.artifact.decode("utf-8"))
        self.assertNotIn("synthetic café control", self.artifact.decode("utf-8"))
        self.assertEqual(payload["keys"]["groups"], [])
        # Composed and decomposed Unicode remain separate exact hashes while
        # the shared NFKC training key collapses their normalized protection.
        self.assertNotEqual(sha("synthetic café control".encode()),
                            sha("synthetic cafe\u0301 control".encode()))
        self.assertEqual(training_text_key("synthetic café control"),
                         training_text_key("synthetic cafe\u0301 control"))

    def test_input_digest_mismatch_fails_before_parsing(self):
        with patch("privoke_eval.contextual_fixture_protection._parse_cases", side_effect=AssertionError("parsed")):
            with self.assertRaises(FixtureProtectionError):
                self.validate(fixture_bytes=self.fixture + b" ")

    def test_receipt_commitment_is_checked_before_json_parse(self):
        with patch("privoke_eval.contextual_fixture_protection._json_load", side_effect=AssertionError("parsed")):
            with self.assertRaises(FixtureProtectionError):
                self.validate(expected_receipt_sha256="0" * 64)

    def test_forged_keys_with_copied_content_digest_are_rejected(self):
        artifact = json.loads(self.artifact)
        artifact["keys"]["ids"][0] = "f" * 64
        forged = json.dumps(artifact, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
        receipt = json.loads(self.receipt)
        receipt["artifact_sha256"] = sha(forged)
        forged_receipt = json.dumps(receipt, sort_keys=True, ensure_ascii=False,
                                    separators=(",", ":")).encode() + b"\n"
        with self.assertRaises(FixtureProtectionError):
            self.validate(artifact_bytes=forged, receipt_bytes=forged_receipt,
                          expected_receipt_sha256=sha(forged_receipt))

    def test_changed_receipt_and_stale_helper_binding_are_rejected(self):
        altered_receipt = self.receipt.replace(b"fixture_protection_addon_built", b"fixture_protection_addon_forged")
        with self.assertRaises(FixtureProtectionError):
            self.validate(receipt_bytes=altered_receipt, expected_receipt_sha256=sha(altered_receipt))
        stale = dict(self.helpers, grouping="e" * 64)
        with self.assertRaises(FixtureProtectionError):
            self.validate(expected_helper_source_hashes=stale)

    def test_review_source_revision_is_required_and_canonical(self):
        review = json.loads(self.review)
        del review["source_revision"]
        missing_bytes = json.dumps(review, sort_keys=True, separators=(",", ":")).encode("utf-8")
        missing_policy = replace(self.policy, review_sha256=sha(missing_bytes))
        with self.assertRaises(FixtureProtectionError):
            build_fixture_addon(self.fixture, self.rubric, missing_bytes,
                                source_revision="d" * 40, helper_source_hashes=self.helpers,
                                policy=missing_policy)

        review["source_revision"] = "not-a-commit"
        malformed_bytes = json.dumps(review, sort_keys=True, separators=(",", ":")).encode("utf-8")
        malformed_policy = replace(self.policy, review_sha256=sha(malformed_bytes))
        with self.assertRaises(FixtureProtectionError):
            build_fixture_addon(self.fixture, self.rubric, malformed_bytes,
                                source_revision="d" * 40, helper_source_hashes=self.helpers,
                                policy=malformed_policy)

    def test_duplicate_json_properties_and_nonfinite_values_fail_closed(self):
        duplicate = b'{"case_id":"a","case_id":"b"}'
        with self.assertRaises(FixtureProtectionError) as caught:
            _json_load(duplicate)
        self.assertNotIn("case_id", str(caught.exception))
        with self.assertRaises(FixtureProtectionError):
            _json_load(b'{"x":NaN}')

    def test_duplicate_case_ids_and_unknown_case_fields_fail_closed(self):
        rows = [json.loads(line) for line in self.fixture.decode("utf-8").split("\n") if line]
        rows[1]["case_id"] = rows[0]["case_id"]
        duplicate_ids = b"".join(json.dumps(row, ensure_ascii=False).encode("utf-8") + b"\n" for row in rows)
        with self.assertRaises(FixtureProtectionError):
            _parse_cases(duplicate_ids, self.policy)
        rows[1]["case_id"] = "synthetic-case-1"
        rows[1]["unrecognized"] = "secret-marker"
        unknown_field = b"".join(json.dumps(row, ensure_ascii=False).encode("utf-8") + b"\n" for row in rows)
        with self.assertRaises(FixtureProtectionError) as caught:
            _parse_cases(unknown_field, self.policy)
        self.assertNotIn("secret-marker", str(caught.exception))

    def test_union_and_combined_digest_are_fieldwise_and_domain_separated(self):
        addon = self.validate()
        historical = ProtectedKeys(ids=frozenset({"1" * 64}), groups=frozenset({"2" * 64}),
                                   exact_text_sha256=frozenset({"3" * 64}),
                                   normalized_texts=frozenset({"4" * 64}))
        combined = combine_protected_keys(historical, addon)
        self.assertIn("1" * 64, combined.ids)
        self.assertIn("2" * 64, combined.groups)
        expected = {
            "schema": COMBINED_DOMAIN,
            "keys": {field: sorted(getattr(combined, field)) for field in
                     ("exact_text_sha256", "groups", "ids", "normalized_texts")},
        }
        manual = hashlib.sha256(json.dumps(expected, sort_keys=True, ensure_ascii=False,
                                            separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()
        self.assertEqual(combined_protection_digest(combined), manual)
        legacy_like = hashlib.sha256(json.dumps({"domain": ADDON_DOMAIN, "keys": json.loads(self.artifact)["keys"]},
                                                sort_keys=True, ensure_ascii=False,
                                                separators=(",", ":")).encode()).hexdigest()
        self.assertNotEqual(manual, legacy_like)


if __name__ == "__main__":
    unittest.main()
