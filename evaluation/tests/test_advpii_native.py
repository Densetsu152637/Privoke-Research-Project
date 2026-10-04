"""Synthetic-only tests for the pinned AdvPIIBench native parser."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evaluation"))
sys.path.insert(0, str(ROOT / "shared/python"))

from privoke_eval.advpii_native import (  # noqa: E402
    parse_native_row,
    parse_native_rows,
    validate_arrow_schema,
)
from privoke_eval.clean_augmentation_grouping import build_components  # noqa: E402


def _row(**changes):
    row = {
        "uid": 7,
        "input_id": 11,
        "category": "positive",
        "attack_target": {"pii": [], "context": []},
        "llm_input": "User: Alice uses alice@example.test",
        "pii_spans": [{
            "type": "email",
            "start": 17,
            "end": 35,
            "value": "alice@example.test",
            "value_fuzzy": None,
        }],
    }
    row.update(changes)
    return row


class AdvPiiNativeParserTests(unittest.TestCase):
    def test_native_category_never_becomes_broad_reviewed_truth(self):
        parsed = parse_native_row(_row())
        self.assertIsNone(parsed.grouping_row.reviewed_has_pii)
        self.assertFalse(parsed.grouping_row.content_conflict)
        self.assertEqual(parsed.native_category, "positive")
        self.assertTrue(parsed.grouping_row.eligible)
        self.assertEqual(parsed.recoverable_identifier_count, 1)

    def test_exact_unicode_codepoint_slice_preserves_combining_and_format_chars(self):
        text = "Name: Cafe\u0301\u200b@example.test"
        start = text.index("Cafe")
        literal = text[start:]
        parsed = parse_native_row(_row(
            llm_input=text,
            pii_spans=[{
                "type": "email", "start": start, "end": len(text),
                "value": "cafe@example.test", "value_fuzzy": literal,
            }],
        ))
        self.assertEqual(parsed.valid_span_count, 1)
        self.assertEqual(parsed.grouping_row.identifiers[0].native_value, "cafe@example.test")
        self.assertEqual(parsed.grouping_row.text, text)
        self.assertNotIn("Cafe", repr(parsed))

    def test_boolean_float_negative_and_out_of_range_offsets_are_rejected(self):
        for start, end in ((True, 4), (1.0, 4), (-1, 4), (1, 10_000)):
            with self.subTest(start=start, end=end):
                span = _row()["pii_spans"][0] | {"start": start, "end": end}
                parsed = parse_native_row(_row(pii_spans=[span]))
                self.assertIn("invalid_native_span_offsets", parsed.structural_reasons)
                self.assertEqual(parsed.recoverable_identifier_count, 0)

    def test_invalid_span_keeps_good_sibling_native_link(self):
        spans = _row()["pii_spans"] + [{
            "type": "email", "start": 1.5, "end": 4,
            "value": "bad", "value_fuzzy": None,
        }]
        parsed = parse_native_row(_row(pii_spans=spans))
        self.assertFalse(parsed.grouping_row.eligible)
        self.assertEqual(parsed.recoverable_identifier_count, 1)
        self.assertIn("invalid_native_span_offsets", parsed.structural_reasons)

    def test_fuzzy_literal_does_not_replace_missing_native_base_value(self):
        span = _row()["pii_spans"][0] | {"value": None, "value_fuzzy": "alice@example.test"}
        parsed = parse_native_row(_row(pii_spans=[span]))
        self.assertEqual(parsed.valid_span_count, 1)
        self.assertEqual(parsed.recoverable_identifier_count, 0)
        self.assertIn("positive_without_recoverable_native_value", parsed.structural_reasons)
        self.assertEqual(parsed.grouping_row.identifiers, ())

    def test_malformed_negative_retains_valid_native_link(self):
        span = _row()["pii_spans"][0]
        parsed = parse_native_row(_row(category="negative", pii_spans=[span]))
        self.assertIn("native_negative_has_spans", parsed.structural_reasons)
        self.assertEqual(parsed.recoverable_identifier_count, 1)
        self.assertEqual(parsed.grouping_row.identifiers[0].native_value, span["value"])
        self.assertIsNone(parsed.grouping_row.reviewed_has_pii)

    def test_negative_empty_spans_preserve_parent_component_without_clean_label(self):
        left = parse_native_row(_row(category="negative", pii_spans=[]))
        right = parse_native_row(_row(uid=8, category="hard_negative", pii_spans=[], llm_input="Other text"))
        grouped = build_components([left.grouping_row, right.grouping_row])
        self.assertEqual(grouped.components[0].member_uids, (7, 8))
        self.assertEqual(grouped.components[0].assignable_uids, ())
        self.assertIsNone(left.grouping_row.reviewed_has_pii)
        self.assertEqual(left.recoverable_identifier_count, 0)

    def test_few_shot_row_is_excluded_but_preserves_bridge_identifier(self):
        parsed = parse_native_row(_row(
            attack_target={"pii": [], "context": ["pi_few_shot_safe"]},
        ))
        self.assertTrue(parsed.few_shot_excluded)
        self.assertFalse(parsed.grouping_row.eligible)
        self.assertEqual(parsed.recoverable_identifier_count, 1)
        self.assertIn("excluded_pi_few_shot_safe", parsed.structural_reasons)

    def test_transformation_names_are_never_identifier_values(self):
        parsed = parse_native_row(_row(
            attack_target={"pii": ["homoglyph"], "context": ["supportive_context"]},
        ))
        self.assertEqual(parsed.grouping_row.identifiers[0].native_value, "alice@example.test")
        self.assertNotIn("homoglyph", repr(parsed.grouping_row.identifiers))
        self.assertNotIn("supportive_context", repr(parsed.grouping_row.identifiers))

    def test_missing_fields_are_reasons_and_never_silent_clean_labels(self):
        parsed = parse_native_row(_row(input_id=None, llm_input=None, attack_target=None, pii_spans=None))
        self.assertIsNone(parsed.grouping_row.reviewed_has_pii)
        self.assertFalse(parsed.grouping_row.eligible)
        self.assertIsNone(parsed.grouping_row.input_id)
        self.assertIsNone(parsed.grouping_row.text)
        self.assertIn("missing_or_unusable_input_id", parsed.structural_reasons)
        self.assertIn("missing_or_unusable_text", parsed.structural_reasons)
        self.assertIn("missing_or_invalid_attack_target", parsed.structural_reasons)

    def test_malformed_attack_structure_and_unknown_operations_are_rejected(self):
        for attack in (
            {"pii": [], "context": [], "extra": "x"},
            {"pii": ["unknown"], "context": []},
            {"pii": [], "context": [None]},
            {"pii": None, "context": []},
        ):
            with self.subTest(attack=attack):
                parsed = parse_native_row(_row(attack_target=attack))
                self.assertIn("missing_or_invalid_attack_target", parsed.structural_reasons)

    def test_positive_without_spans_is_ineligible_and_unknown_category_is_not_truth(self):
        positive = parse_native_row(_row(pii_spans=[]))
        unknown = parse_native_row(_row(category="other", pii_spans=[]))
        self.assertIn("native_positive_has_no_spans", positive.structural_reasons)
        self.assertIsNone(positive.grouping_row.reviewed_has_pii)
        self.assertEqual(unknown.native_category, None)
        self.assertIn("missing_or_unknown_native_category", unknown.structural_reasons)

    def test_uid_requires_nonbool_signed_int32_and_full_scan_rejects_duplicates(self):
        for uid in (None, True, 2**31, -(2**31) - 1):
            with self.subTest(uid=uid), self.assertRaises(ValueError):
                parse_native_row(_row(uid=uid))
        with self.assertRaises(ValueError):
            parse_native_rows([_row(), _row(input_id=12)])
        self.assertEqual(parse_native_row(_row(uid=-(2**31))).grouping_row.uid, -(2**31))


class ArrowSchemaGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import pyarrow as pa
        except ImportError:
            cls.pa = None
        else:
            cls.pa = pa

    def _schema(self, *, uid_type=None, span_child="item", extra=False):
        pa = self.pa
        span = pa.struct([
            pa.field("type", pa.string()), pa.field("start", pa.int32()),
            pa.field("end", pa.int32()), pa.field("value", pa.string()),
            pa.field("value_fuzzy", pa.string()),
        ])
        attack = pa.struct([
            pa.field("pii", pa.list_(pa.string())),
            pa.field("context", pa.list_(pa.string())),
        ])
        fields = [
            pa.field("uid", uid_type if uid_type is not None else pa.int32()), pa.field("input_id", pa.int32()),
            pa.field("category", pa.string()), pa.field("attack_target", attack),
            pa.field("llm_input", pa.string()),
            pa.field("pii_spans", pa.list_(pa.field(span_child, span))),
        ]
        if extra:
            fields.append(pa.field("unexpected", pa.string()))
        return pa.schema(fields)

    def test_exact_schema_and_parquet_element_alias_are_accepted(self):
        if self.pa is None:
            self.skipTest("PyArrow is unavailable on this host.")
        validate_arrow_schema(self._schema())
        validate_arrow_schema(self._schema(span_child="element"))

    def test_wrong_integer_width_extra_column_or_child_name_is_rejected(self):
        if self.pa is None:
            self.skipTest("PyArrow is unavailable on this host.")
        for schema in (
            self._schema(uid_type=self.pa.int64()),
            self._schema(extra=True),
            self._schema(span_child="wrong"),
        ):
            with self.subTest(schema=schema), self.assertRaises(ValueError):
                validate_arrow_schema(schema)


if __name__ == "__main__":
    unittest.main()
