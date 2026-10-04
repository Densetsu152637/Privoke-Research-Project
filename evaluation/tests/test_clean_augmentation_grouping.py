"""Synthetic-only tests for full-transitive clean-augmentation grouping."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evaluation"))
sys.path.insert(0, str(ROOT / "shared/python"))

from privoke_eval.clean_augmentation_grouping import (  # noqa: E402
    GroupingRow,
    NativeIdentifier,
    ProtectedKeys,
    build_components,
    canonical_native_value,
    opaque_exclusion_key,
)
from privoke_model.training_data import training_text_key  # noqa: E402


def _row(
    uid: int,
    input_id: object,
    text: object,
    truth: bool | None,
    values: tuple[NativeIdentifier, ...] = (),
    *,
    eligible: bool = True,
    conflict: bool = False,
) -> GroupingRow:
    return GroupingRow(
        uid=uid,
        input_id=input_id,
        text=text,
        identifiers=values,
        reviewed_has_pii=truth,
        eligible=eligible,
        content_conflict=conflict,
    )


def _person(value: str) -> NativeIdentifier:
    return NativeIdentifier("PERSON", value)


class CleanAugmentationGroupingTests(unittest.TestCase):
    def test_mixed_reviewed_labels_on_different_parent_variants_stay_together(self):
        result = build_components([
            _row(1, 41, "My account belongs to Alice.", True, (_person("Alice"),)),
            _row(2, 41, "What is the weather today?", False),
        ])
        self.assertEqual(result.component_count, 1)
        component = result.components[0]
        self.assertEqual(component.member_uids, (1, 2))
        self.assertEqual(component.assignable_uids, (1, 2))
        self.assertEqual(component.exclusion_reasons, ())
        self.assertEqual((component.positive_rows, component.negative_rows), (1, 1))
        self.assertEqual(result.mixed_label_component_count, 1)

    def test_opposing_truth_on_same_exact_text_excludes_whole_component(self):
        text = "Alice lives in Sydney."
        result = build_components([
            _row(1, 1, text, True, (_person("Alice"),)),
            _row(2, 2, text, False),
            _row(3, 3, "A separate row.", True, (_person("Alice"),)),
        ])
        component = next(item for item in result.components if 1 in item.member_uids)
        self.assertEqual(component.member_uids, (1, 2, 3))
        self.assertIn("opposing_reviewed_truth_on_exact_text", component.exclusion_reasons)
        self.assertEqual(component.assignable_uids, ())

    def test_opposing_truth_on_normalized_collision_excludes_component(self):
        result = build_components([
            _row(1, 1, "Ａlice\tSmith", True, (_person("Alice"),)),
            _row(2, 2, "Alice Smith", False),
        ])
        component = result.components[0]
        self.assertEqual(component.member_uids, (1, 2))
        self.assertIn("opposing_reviewed_truth_on_normalized_text", component.exclusion_reasons)
        self.assertNotIn("opposing_reviewed_truth_on_exact_text", component.exclusion_reasons)

    def test_native_annotation_subsets_do_not_create_truth_conflict(self):
        text = "Alice lives at 3 Example Street."
        result = build_components([
            _row(1, 7, text, True, (_person("Alice"),)),
            _row(2, 8, text, True, (_person("Alice"), NativeIdentifier("ADDRESS", "3 Example Street"))),
        ])
        component = result.components[0]
        self.assertEqual(component.member_uids, (1, 2))
        self.assertEqual(component.assignable_uids, (1, 2))
        self.assertEqual(component.exclusion_reasons, ())

    def test_ineligible_intermediate_keeps_parent_and_value_bridge_to_protected_member(self):
        rows = [
            _row(1, 101, "First prompt.", True, (_person("Shared Native Value"),)),
            _row(2, 202, "Unreviewed bridge.", None, (_person("Shared Native Value"),), eligible=False),
            _row(3, 202, "Protected sibling.", True, (_person("Other Value"),)),
        ]
        protected = ProtectedKeys(ids=frozenset({opaque_exclusion_key("id", "advpiibench:uid:3")}))
        result = build_components(rows, protected)
        component = result.components[0]
        self.assertEqual(component.member_uids, (1, 2, 3))
        self.assertEqual(component.assignable_uids, ())
        self.assertIn("protected_id_overlap", component.exclusion_reasons)
        reasons = dict(result.row_reasons)
        self.assertIn("reviewed_label_unknown", reasons[2])
        self.assertIn("upstream_ineligible", reasons[2])

    def test_native_value_uses_nfkc_casefold_and_unicode_whitespace(self):
        self.assertEqual(canonical_native_value("PERSON", "Ａli\u2009ce"), ("PERSON", "alice"))
        result = build_components([
            _row(1, 1, "Prompt one", True, (_person("Ａli\u2009ce"),)),
            _row(2, 2, "Prompt two", True, (_person("alice"),)),
        ])
        self.assertEqual(result.component_count, 1)
        self.assertEqual(result.components[0].member_uids, (1, 2))

    def test_fuzzy_or_approximate_values_never_create_a_link(self):
        result = build_components([
            _row(1, 1, "First unique prompt.", True, (_person("Alice"),)),
            _row(2, 2, "Second unique prompt.", True, (_person("Alicia"),)),
        ])
        self.assertEqual(result.component_count, 2)
        with self.assertRaises(TypeError):
            NativeIdentifier("PERSON", "Alicia", value_fuzzy="Alice")  # type: ignore[call-arg]

    def test_original_unicode_text_is_unchanged_while_comparison_key_normalizes(self):
        raw = "The name is Cafe\u0301."
        composed = "The name is Café."
        result = build_components([
            _row(1, 1, raw, True, (_person("Cafe\u0301"),)),
            _row(2, 2, composed, True, (_person("Café"),)),
        ])
        self.assertNotEqual(hashlib.sha256(raw.encode("utf-8")).digest(), hashlib.sha256(composed.encode("utf-8")).digest())
        self.assertEqual(training_text_key(raw), training_text_key(composed))
        self.assertEqual(raw, "The name is Cafe\u0301.")
        self.assertEqual(result.component_count, 1)
        self.assertEqual(result.components[0].member_uids, (1, 2))
        self.assertNotIn(raw, repr(result))

    def test_unknown_review_is_not_clean_and_is_counted_as_ineligible(self):
        result = build_components([_row(1, 1, "Unknown review.", None)])
        component = result.components[0]
        self.assertEqual(component.negative_rows, 0)
        self.assertEqual(component.assignable_uids, ())
        self.assertEqual(dict(result.row_reasons)[1], ("reviewed_label_unknown",))
        self.assertEqual(dict(result.row_reason_counts)["reviewed_label_unknown"], 1)

    def test_unusable_identity_parts_fail_closed_but_other_links_still_bridge(self):
        result = build_components([
            _row(1, None, None, True, (_person("Shared"),)),
            _row(2, 9, "Known prompt.", True, (_person("Shared"),)),
        ])
        component = result.components[0]
        self.assertEqual(component.member_uids, (1, 2))
        self.assertEqual(component.assignable_uids, (2,))
        reasons = dict(result.row_reasons)[1]
        self.assertIn("missing_or_unusable_input_id", reasons)
        self.assertIn("missing_or_unusable_text", reasons)
        self.assertEqual(dict(result.relationship_counts)["native_identifier_links"], 2)

    def test_every_protected_key_kind_excludes_the_entire_component(self):
        text = "Protected text with Alice."
        input_id = 99
        cases = (
            ("protected_id_overlap", ProtectedKeys(ids=frozenset({opaque_exclusion_key("id", "advpiibench:uid:1")}))),
            ("protected_group_overlap", ProtectedKeys(groups=frozenset({opaque_exclusion_key("group", "advpiibench:input_id:99")}))),
            ("protected_exact_text_overlap", ProtectedKeys(exact_text_sha256=frozenset({hashlib.sha256(text.encode("utf-8")).hexdigest()}))),
            ("protected_normalized_text_overlap", ProtectedKeys(normalized_texts=frozenset({opaque_exclusion_key("text_key", training_text_key(text))}))),
        )
        for reason, protected in cases:
            with self.subTest(reason=reason):
                result = build_components([
                    _row(1, input_id, text, True, (_person("Alice"),)),
                    _row(2, input_id, "Different sibling text.", False),
                ], protected)
                self.assertEqual(result.components[0].member_uids, (1, 2))
                self.assertIn(reason, result.components[0].exclusion_reasons)
                self.assertEqual(result.components[0].assignable_uids, ())

    def test_reviewed_irreconcilable_content_conflict_excludes_component(self):
        result = build_components([
            _row(1, 1, "Same content.", True, (_person("Alice"),), conflict=True),
            _row(2, 2, "Different sibling.", False),
        ])
        component = result.components[0]
        self.assertIn("irreconcilable_reviewed_content_conflict", component.exclusion_reasons)
        self.assertEqual(component.assignable_uids, ())

    def test_invalid_boolean_contracts_and_duplicate_uids_are_rejected(self):
        with self.assertRaises(TypeError):
            build_components([_row(1, 1, "Text", "false")])  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            build_components([GroupingRow(1, 1, "Text", (), False, eligible=1)])  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            build_components([_row(1, 1, "A", False), _row(1, 2, "B", True, (_person("B"),))])

    def test_group_ids_and_order_are_deterministic(self):
        rows = [
            _row(9, 10, "A", True, (_person("Alice"),)),
            _row(4, 10, "B", False),
            _row(7, 11, "C", True, (_person("ALICE"),)),
        ]
        first = build_components(rows)
        second = build_components(list(reversed(rows)))
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
