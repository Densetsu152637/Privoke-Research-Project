from __future__ import annotations

import unittest
from unittest.mock import patch

from privoke_eval.datasets import (
    DatasetValidationError,
    _parse_spans,
    _finish_positive_only,
    _label_mapping_ground_truth,
    _select_examples,
    _span_ground_truth,
    load_ai4privacy,
    load_gretel_finance,
    load_meddies_pii,
    load_nemotron_pii,
    load_piimb,
)
from privoke_eval.types import EvaluationExample


def example(index: int, sensitive: bool) -> EvaluationExample:
    return EvaluationExample(
        text=f"sample-{index}",
        expected_has_pii=sensitive,
        metadata={"example_id": f"test:{index}"},
    )


class DatasetTests(unittest.TestCase):
    def test_ai4privacy_schema_keeps_only_explicit_pii_rows(self) -> None:
        rows = [
            {
                "id": "positive",
                "source_text": "Email alex@example.com",
                "privacy_mask": [{"label": "EMAIL", "start": 6, "end": 22}],
            },
            {"id": "empty", "source_text": "General text", "privacy_mask": []},
        ]
        with patch("privoke_eval.datasets.load_dataset", return_value=rows):
            result = load_ai4privacy(None, seed=42, strategy="random")

        self.assertEqual(result.selected_label_counts, {"pii": 1, "clean": 0})
        self.assertEqual(result.examples[0].expected_categories, ("EMAIL",))
        self.assertEqual(result.exclusions, {"rows_without_verified_negative_ground_truth": 1})

    def test_public_loader_excludes_and_counts_malformed_source_spans(self) -> None:
        rows = [
            {
                "id": "valid",
                "source_text": "Email alex@example.com",
                "privacy_mask": [{"label": "EMAIL", "start": 6, "end": 22}],
            },
            {
                "id": "invalid",
                "source_text": "short",
                "privacy_mask": [{"label": "EMAIL", "start": 0, "end": 99}],
            },
        ]
        with patch("privoke_eval.datasets.load_dataset", return_value=rows):
            result = load_ai4privacy(None, seed=42, strategy="random")

        self.assertEqual(result.rows_seen, 2)
        self.assertEqual(result.eligible_rows, 1)
        self.assertEqual(result.exclusions, {"malformed_source_annotation_rows": 1})

    def test_nemotron_schema_keeps_only_explicit_pii_rows(self) -> None:
        rows = [
            {
                "uid": "positive",
                "text": "Patient ID 123",
                "spans": '[{"entity_type":"PATIENT_ID","start":11,"end":14}]',
            },
            {"uid": "empty", "text": "General text", "spans": "[]"},
        ]
        with patch("privoke_eval.datasets.load_dataset", return_value=rows):
            result = load_nemotron_pii(None, seed=42, strategy="random")

        self.assertEqual(result.selected_label_counts, {"pii": 1, "clean": 0})
        self.assertEqual(result.examples[0].expected_categories, ("PATIENT_ID",))

    def test_gretel_schema_keeps_only_explicit_pii_rows(self) -> None:
        rows = [
            {
                "index": 1,
                "generated_text": "IBAN GB29NWBK60161331926819",
                "pii_spans": '[{"label":"iban","start":5,"end":27}]',
            },
            {"index": 2, "generated_text": "Financial template", "pii_spans": "[]"},
        ]
        with patch("privoke_eval.datasets.load_dataset", return_value=rows):
            result = load_gretel_finance(None, seed=42, strategy="random")

        self.assertEqual(result.selected_label_counts, {"pii": 1, "clean": 0})
        self.assertEqual(result.examples[0].expected_categories, ("iban",))

    def test_meddies_schema_keeps_only_explicit_pii_rows(self) -> None:
        rows = [
            {
                "id": "positive",
                "raw": "Patient Alex",
                "label": '{"human_name":["Alex"]}',
            },
            {"id": "empty", "raw": "General clinical guidance", "label": "{}"},
        ]
        with patch("privoke_eval.datasets.load_dataset", return_value=rows):
            result = load_meddies_pii(None, seed=42, strategy="random")

        self.assertEqual(result.selected_label_counts, {"pii": 1, "clean": 0})
        self.assertEqual(result.examples[0].expected_categories, ("human_name",))

    def test_piimb_schema_keeps_explicit_positive_and_clean_rows(self) -> None:
        rows = [
            {
                "uid": "positive",
                "text": "Email alex@example.com",
                "entities": [{"label": "EMAIL", "start": 6, "end": 22}],
            },
            {"uid": "clean", "text": "General text", "entities": []},
        ]
        with patch("privoke_eval.datasets.load_dataset", return_value=rows):
            result = load_piimb(None, seed=42, strategy="balanced")

        self.assertEqual(result.selected_label_counts, {"pii": 1, "clean": 1})
        self.assertEqual(result.population_label_counts, {"pii": 1, "clean": 1})

    def test_piimb_english_filter_runs_before_sampling(self) -> None:
        rows = [
            {
                "uid": "english-pii",
                "parent_id": "doc-1",
                "language": "en",
                "text": "Email alex@example.com",
                "entities": [{"label": "EMAIL", "start": 6, "end": 22}],
            },
            {
                "uid": "english-clean",
                "parent_id": "doc-2",
                "language": "en",
                "text": "General text",
                "entities": [],
            },
            {
                "uid": "french-pii",
                "parent_id": "doc-3",
                "language": "fr",
                "text": "Courriel alex@example.com",
                "entities": [{"label": "EMAIL", "start": 9, "end": 25}],
            },
        ]
        with patch("privoke_eval.datasets.load_dataset", return_value=rows):
            result = load_piimb(2, seed=42, strategy="balanced", english_only=True)

        self.assertEqual(result.selected_label_counts, {"pii": 1, "clean": 1})
        self.assertEqual(result.exclusions, {"non_english_language_rows": 1})
        self.assertEqual(result.rows_seen, 3)

    def test_balanced_sampling_is_reproducible(self) -> None:
        rows = [example(index, index < 8) for index in range(10)]
        first = _select_examples(rows, 4, seed=17, strategy="balanced")
        second = _select_examples(rows, 4, seed=17, strategy="balanced")

        self.assertEqual(first.selected_label_counts, {"pii": 2, "clean": 2})
        self.assertEqual(first.population_label_counts, {"pii": 8, "clean": 2})
        self.assertEqual(
            [item.metadata["example_id"] for item in first.examples],
            [item.metadata["example_id"] for item in second.examples],
        )

    def test_stratified_sampling_preserves_population_ratio(self) -> None:
        rows = [example(index, index < 2) for index in range(10)]
        result = _select_examples(rows, 5, seed=42, strategy="stratified")
        self.assertEqual(result.selected_label_counts, {"pii": 1, "clean": 4})

    def test_duplicate_text_is_removed(self) -> None:
        rows = [example(1, True), EvaluationExample("sample-1", True)]
        result = _select_examples(rows, None, seed=42, strategy="balanced")
        self.assertEqual(result.duplicate_rows, 1)
        self.assertEqual(result.eligible_rows, 1)

    def test_conflicting_duplicate_labels_are_rejected(self) -> None:
        rows = [example(1, True), EvaluationExample("sample-1", False)]
        with self.assertRaises(DatasetValidationError):
            _select_examples(rows, None, seed=42, strategy="balanced")

    def test_public_conflicting_duplicate_labels_are_excluded(self) -> None:
        rows = [
            example(1, True),
            EvaluationExample("sample-1", False),
            EvaluationExample("sample-1", True),
            example(2, False),
        ]
        result = _select_examples(
            rows,
            None,
            seed=42,
            strategy="balanced",
            strict_conflicts=False,
        )
        self.assertEqual([item.text for item in result.examples], ["sample-2"])
        self.assertEqual(result.population_label_counts, {"pii": 0, "clean": 1})
        self.assertEqual(result.exclusions, {"conflicting_duplicate_label_rows": 3})

    def test_malformed_spans_fail_instead_of_becoming_clean(self) -> None:
        with self.assertRaises(DatasetValidationError):
            _parse_spans("not valid json or a literal", "test row")

    def test_unlabelled_span_entries_are_rejected(self) -> None:
        with self.assertRaises(DatasetValidationError):
            _span_ground_truth([{"start": 0, "end": 5}], "test row")

    def test_span_outside_source_text_is_rejected(self) -> None:
        with self.assertRaises(DatasetValidationError):
            _span_ground_truth(
                [{"label": "EMAIL", "start": 0, "end": 99}],
                "test row",
                "short text",
            )

    def test_empty_meddies_label_values_are_not_pii(self) -> None:
        expected, categories = _label_mapping_ground_truth(
            {"human_name": [], "email_address": ""},
            "test row",
        )
        self.assertFalse(expected)
        self.assertEqual(categories, ())

    def test_prompts_that_only_differ_by_outer_whitespace_are_duplicates(self) -> None:
        rows = [
            EvaluationExample(" sample ", True),
            EvaluationExample("sample", True),
        ]
        # _example performs the same outer-whitespace normalization as /analyze.
        from privoke_eval.datasets import _example

        normalized_rows = [
            _example("test", row.text, row.expected_has_pii, (), {}, index)
            for index, row in enumerate(rows)
        ]
        result = _select_examples(normalized_rows, None, seed=42, strategy="balanced")
        self.assertEqual(result.eligible_rows, 1)
        self.assertEqual(result.duplicate_rows, 1)

    def test_positive_only_mode_excludes_unverified_negatives(self) -> None:
        rows = [example(1, True), example(2, False), example(3, True)]
        result = _finish_positive_only(rows, None, seed=42, strategy="random")

        self.assertEqual(result.rows_seen, 3)
        self.assertEqual(result.eligible_rows, 2)
        self.assertEqual(result.population_label_counts, {"pii": 2, "clean": 0})
        self.assertEqual(
            result.exclusions,
            {"rows_without_verified_negative_ground_truth": 1},
        )

if __name__ == "__main__":
    unittest.main()
