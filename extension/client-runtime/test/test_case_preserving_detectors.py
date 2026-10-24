from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from src import pipeline
from src.detection.preprocessing import normalize_text, normalize_with_offsets
from src.pipeline import LayerExecution


class CasePreservingNormalizationTests(unittest.TestCase):
    def test_default_lowercases(self) -> None:
        self.assertEqual(normalize_text("Alice Smith  Works AT Acme"), "alice smith works at acme")
        self.assertEqual(normalize_with_offsets("Hello").text, "hello")

    def test_case_preserved_text(self) -> None:
        normalised = normalize_with_offsets("Alice  Smith\n\n\nBob", lowercase=False)
        self.assertEqual(normalised.text, "Alice Smith\nBob")

    def test_offsets_map_back_to_original(self) -> None:
        original = "  Call Alice   Smith now "
        normalised = normalize_with_offsets(original, lowercase=False)
        start = normalised.text.index("Alice Smith")
        span = normalised.original_span((start, start + len("Alice Smith")))
        self.assertEqual(original[slice(*span)], "Alice   Smith")

    def test_at_collapsing_is_case_insensitive_without_lowercasing(self) -> None:
        for token in ("[at]", "[AT]", "(At)", "(aT)"):
            normalised = normalize_with_offsets(f"Bob{token}Example.com", lowercase=False)
            self.assertEqual(normalised.text, "Bob@Example.com", token)
            span = normalised.original_span((3, 4))
            self.assertEqual(f"Bob{token}Example.com"[slice(*span)], token)

    def test_at_collapsing_matches_lowercase_mode(self) -> None:
        self.assertEqual(normalize_text("Bob[AT]Example.com"), "bob@example.com")

    def test_only_case_differs_for_ascii(self) -> None:
        text = "Email  Bob[AT]X.com or (At) 1 2 3"
        preserved = normalize_with_offsets(text, lowercase=False)
        lowered = normalize_with_offsets(text)
        self.assertEqual(preserved.text.lower(), lowered.text)
        self.assertEqual(preserved.origins, lowered.origins)


class CasePreservingPipelineTests(unittest.TestCase):
    def _run(self, flag: bool):
        seen: dict[str, str] = {}

        def fake_execute(layer, text, **_kwargs):
            seen[layer] = text
            return LayerExecution(layer, "ok")

        with mock.patch.object(pipeline.GLOBAL_CONFIG, "case_preserving_detectors", flag), \
                mock.patch.object(pipeline, "_execute_layer", side_effect=fake_execute):
            pipeline.analyse_text(
                "Alice Smith[AT]Example.com",
                layers=[pipeline.REGEX_LAYER, pipeline.NER_LAYER, pipeline.SEMANTIC_LAYER],
                regex_first=False,
            )
        return seen

    def test_default_all_layers_lowercase(self) -> None:
        self.assertFalse(pipeline.GLOBAL_CONFIG.case_preserving_detectors)
        seen = self._run(False)
        self.assertEqual(set(seen.values()), {"alice smith@example.com"})

    def test_flag_preserves_case_for_regex_and_ner_only(self) -> None:
        seen = self._run(True)
        self.assertEqual(seen["regex"], "Alice Smith@Example.com")
        self.assertEqual(seen["ner"], "Alice Smith@Example.com")
        self.assertEqual(seen["semantic"], "alice smith@example.com")

    def test_flag_regex_first_path(self) -> None:
        seen: dict[str, str] = {}

        def fake_execute(layer, text, **_kwargs):
            seen[layer] = text
            return LayerExecution(layer, "ok")

        with mock.patch.object(pipeline.GLOBAL_CONFIG, "case_preserving_detectors", True), \
                mock.patch.object(pipeline, "_execute_layer", side_effect=fake_execute):
            pipeline.analyse_text("Alice", layers=["regex", "semantic"], regex_first=True)
        self.assertEqual(seen["regex"], "Alice")
        self.assertEqual(seen["semantic"], "alice")


if __name__ == "__main__":
    unittest.main()
