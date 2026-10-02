from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
for path in (PACKAGE_ROOT, PACKAGE_ROOT.parents[1] / 'shared/python'):
    sys.path.insert(0, str(path))

from src.classification import (
    Category, ClassificationResult, PriVokeAction, Sensitivity, Visibility,
    initialise_unpacked,
)
from src.detection.preprocessing import normalize_text, normalize_with_offsets
from src.hosting.analyzer import analyse_prompt
from src.hosting.models import PromptInspectionRequest
from src.hosting.serialization import parse_prompt_request, serialize_analysis_response
from src.pipeline import LayerExecution, PipelineAnalysis, analyse_text, strongest_result


def finding(sensitivity=Sensitivity.S1, visibility=Visibility.PU,
            categories=(Category.IDENTITY,), confidence=0.9, section='alex', span=(0, 4)):
    return ClassificationResult(initialise_unpacked(sensitivity, visibility, categories),
                                section, 'detector evidence', span, confidence)


class EvidenceAggregationTests(unittest.TestCase):
    def test_allow_evidence_is_preserved(self):
        result, action = strongest_result([finding()])
        self.assertEqual(action, PriVokeAction.ALLOW)
        self.assertEqual(result.classification.sensitivity(), Sensitivity.S1)
        self.assertEqual(result.classification.categories(), [Category.IDENTITY])

    def test_private_hint_promotes_identity_evidence(self):
        with patch('src.pipeline._detector_for', return_value=lambda text: [finding()]):
            response = analyse_prompt(PromptInspectionRequest(text='alex',
                                      visibility_hint=Visibility.P4), layers=['regex']).response()
        self.assertEqual(response['action'], 'WARN')
        self.assertEqual(response['classification']['sensitivity'], 'S1')
        self.assertEqual(response['classification']['visibility'], 'P4')
        self.assertEqual(response['masked_text'], '[PRIVOKE_MASKED]')

    def test_visibility_only_results_are_preserved(self):
        result, action = strongest_result([finding(Sensitivity.S0, Visibility.P3, ())])
        self.assertEqual(action, PriVokeAction.ALLOW)
        self.assertEqual(result.classification.visibility(), Visibility.P3)

    def test_private_visibility_combines_with_identity(self):
        identity = finding()
        visibility = finding(Sensitivity.S0, Visibility.P4, (), section='private', span=None)
        result, action = strongest_result([visibility, identity])
        self.assertEqual(action, PriVokeAction.WARN)
        self.assertEqual(result.section_of_text, 'alex')
        self.assertEqual(result.classification.visibility(), Visibility.P4)

    def test_identifier_and_location_combine(self):
        result, action = strongest_result([finding(), finding(categories=(Category.LOCATION,))])
        self.assertEqual(action, PriVokeAction.WARN)
        self.assertEqual(set(result.classification.categories()), {Category.IDENTITY, Category.LOCATION})

    def test_weak_certain_result_does_not_amplify_uncertain_sensitive_result(self):
        result, action = strongest_result([
            finding(Sensitivity.S2, confidence=0.95),
            finding(Sensitivity.S3, confidence=0.2),
        ])
        self.assertEqual(action, PriVokeAction.WARN)
        self.assertEqual(result.action(), PriVokeAction.WARN)
        self.assertEqual(result.confidence, 0.2)

    def test_confident_block_is_preserved(self):
        _, action = strongest_result([finding(Sensitivity.S3), finding(confidence=0.1)])
        self.assertEqual(action, PriVokeAction.BLOCK)

    def test_empty_results_remain_clean(self):
        self.assertEqual(strongest_result([]), (None, PriVokeAction.ALLOW))

    def test_hint_cannot_downgrade_error_block(self):
        execution = PipelineAnalysis((LayerExecution('regex', 'ok', (finding(),)),
                                      LayerExecution('semantic', 'error', error='invalid output')))
        with patch('src.hosting.analyzer.analyse_text', return_value=execution):
            response = analyse_prompt(PromptInspectionRequest(text='alex',
                                      visibility_hint=Visibility.P4)).response()
        self.assertEqual(response['action'], 'BLOCK')
        self.assertFalse(response['allowed'])
        self.assertEqual(response['errors'], ['semantic: invalid output'])
        self.assertEqual(response['reason'], 'PriVoke could not complete analysis safely.')


class OriginalSpanTests(unittest.TestCase):
    def test_canonical_behavior_and_original_interval(self):
        cases = [
            ('Hello     @alex', '@alex', '@alex'),
            ('  HELLO\t\t@Alex  ', '@alex', '@Alex'),
            ('A\n\nB @Alex', '@alex', '@Alex'),
            ('Number: 1 2\t3 4', '1234', '1 2\t3 4'),
            ('Alex[at]example.com', '@', '[at]'),
            ('Alex(at)example.com', '@', '(at)'),
            ('Mark: \ufb03', 'ffi', '\ufb03'),
            ('HELLO \uff20\uff21\uff4c\uff45\uff58', '@alex', '\uff20\uff21\uff4c\uff45\uff58'),
            ('Cafe\u0301', '\u00e9', 'e\u0301'),
            ('\u0130 @alex', 'i\u0307', '\u0130'),
            ('\u1100\u1161', '\uac00', '\u1100\u1161'),
        ]
        for original, needle, expected in cases:
            with self.subTest(original=original):
                normalized = normalize_with_offsets(original)
                start = normalized.text.index(needle)
                span = normalized.original_span((start, start + len(needle)))
                self.assertEqual(original[slice(*span)], expected)
                self.assertEqual(normalize_text(original), normalized.text)

    def test_normalization_matches_existing_transforms(self):
        self.assertEqual(normalize_text('  ALEX[at]Example.COM 1 2\t3\n\nTEST  '),
                         'alex@example.com 123\ntest')

    def test_invalid_offsets_cannot_be_mapped(self):
        normalized = normalize_with_offsets('hello')
        for span in ((-1, 2), (2, 1), (0, 6), (True, 2), (0, 0)):
            self.assertIsNone(normalized.original_span(span))

    def test_regex_mask_uses_original_offsets(self):
        for text in ('Hello     @alex', '  Hello\t\t@Alex  ', '\ufb03 Hello @Alex'):
            with self.subTest(text=text):
                request = parse_prompt_request({'text': text})
                response = analyse_prompt(request, layers=['regex']).response()
                self.assertEqual(response['masked_text'], text[:text.index('@')] +
                                 '[PRIVOKE_MASKED]' + text[text.index('@') + 5:])
                start, end = response['evidence']['span']
                self.assertEqual(text[start:end], response['evidence']['section_of_text'])

    def test_ner_and_semantic_results_share_original_span_contract(self):
        text = 'Hello     Alex'
        for layer in ('ner', 'semantic'):
            with self.subTest(layer=layer), patch('src.pipeline._detector_for',
                    return_value=lambda text: [finding(Sensitivity.S2, section='alex', span=(6, 10))]):
                analysis = analyse_text(text, layers=[layer])
                self.assertEqual(analysis.layers[0].results[0].span, (10, 14))
                self.assertEqual(analysis.result.section_of_text, 'Alex')

    def test_invalid_or_mismatched_span_is_not_masked(self):
        request = PromptInspectionRequest(text='Hello alex')
        for span in ((True, 5), (-1, 5), (0, 5), (0, 100)):
            response = serialize_analysis_response(request, finding(Sensitivity.S2, span=span),
                                                   PriVokeAction.WARN, 0)
            self.assertIsNone(response['masked_text'])

    def test_pipeline_does_not_retarget_mismatched_detector_evidence(self):
        with patch('src.pipeline._detector_for',
                   return_value=lambda text: [finding(span=(0, 5))]):
            result = analyse_text('Hello alex', layers=['ner']).result
        self.assertIsNone(result.span)
        self.assertEqual(result.section_of_text, 'alex')

    def test_missing_span_can_use_unique_exact_evidence(self):
        with patch('src.pipeline._detector_for', return_value=lambda text: [finding(span=None)]):
            analysis = analyse_text('Hello     Alex', layers=['semantic'])
        self.assertEqual(analysis.result.span, (10, 14))

    def test_missing_span_does_not_guess_repeated_evidence(self):
        with patch('src.pipeline._detector_for', return_value=lambda text: [finding(span=None)]):
            analysis = analyse_text('Alex Alex', layers=['semantic'])
        self.assertIsNone(analysis.result.span)


if __name__ == '__main__':
    unittest.main()
