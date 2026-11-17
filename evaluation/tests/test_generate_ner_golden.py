"""Mechanics of the privoke-ner-layer golden generator (RUST-S13), without any recorded dataset."""

from __future__ import annotations

import base64
import importlib
import json
import sys
import unicodedata
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "evaluation"))
golden = importlib.import_module("generate_ner_golden")

RUST_COMMON = REPO / "rust" / "crates" / "privoke-ner-layer" / "tests" / "common" / "mod.rs"
FIXTURE = REPO / "rust" / "crates" / "privoke-ner-layer" / "tests" / "fixtures" / "synthetic_golden.b64"


def runtime_available() -> bool:
    try:
        golden.bootstrap()
        from src import pipeline  # noqa: F401
        import spacy

        spacy.load("en_core_web_sm")
    except Exception:  # noqa: BLE001 - generated clients, spaCy or the model are missing
        return False
    return True


class GeneratorMechanicsTest(unittest.TestCase):
    def test_final_endpoint_is_never_opened(self) -> None:
        with self.assertRaises(SystemExit):
            golden.refuse_final(Path("evaluation/results/locked-public/final.jsonl"))
        golden.refuse_final(Path("evaluation/results/locked-public/development.jsonl"))

    def test_lone_surrogates_are_detected(self) -> None:
        self.assertTrue(golden.has_surrogate("a\ud800b"))
        self.assertFalse(golden.has_surrogate("a\U0001f600b"))

    def test_configurations_match_the_rust_harness(self) -> None:
        source = RUST_COMMON.read_text(encoding="utf-8")
        for name in (*golden.LAYER_CONFIGS, *golden.PATTERN_CONFIGS):
            self.assertIn(f'"{name}"', source, f"configuration {name} is missing from the Rust harness")
        # The default and caseless settings, and each robustness flag, are exercised.
        self.assertEqual(golden.LAYER_CONFIGS["default"], (True, False, False, False, False, True))
        self.assertTrue(golden.LAYER_CONFIGS["caseless"][4])
        self.assertTrue(golden.LAYER_CONFIGS["format"][1])
        self.assertTrue(golden.LAYER_CONFIGS["digits"][2])
        self.assertTrue(golden.LAYER_CONFIGS["email"][3])
        for flags in golden.LAYER_CONFIGS.values():
            self.assertEqual(len(flags), 6)

    def test_the_rust_harness_flags_equal_the_python_flags(self) -> None:
        source = RUST_COMMON.read_text(encoding="utf-8")
        for name, flags in golden.LAYER_CONFIGS.items():
            tuple_text = "(" + ", ".join(str(flag).lower() for flag in flags) + ")"
            self.assertIn(f'("{name}", {tuple_text})', source)
        for name, flags in golden.PATTERN_CONFIGS.items():
            tuple_text = "(" + ", ".join(str(flag).lower() for flag in flags) + ")"
            self.assertIn(f'("{name}", {tuple_text})', source)

    def test_the_generator_never_requests_an_empty_or_wider_layer_list(self) -> None:
        source = (REPO / "evaluation" / "generate_ner_golden.py").read_text(encoding="utf-8")
        self.assertIn('layers=["ner"]', source)
        self.assertNotIn("layers=[]", source)
        self.assertNotIn("layers=None", source)
        self.assertIn("requested by an NER-only run", source)

    def test_synthetic_inputs_are_generic_and_stable(self) -> None:
        rows = golden.synthetic_inputs()
        ids = [row_id for row_id, _ in rows]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(rows), 100)
        self.assertEqual(golden.synthetic_inputs(), rows)
        for _, text in rows:
            self.assertFalse(golden.has_surrogate(text))

    def test_fuzz_rows_are_seeded(self) -> None:
        self.assertEqual(golden.fuzz_rows(count=20, seed=1), golden.fuzz_rows(count=20, seed=1))
        self.assertNotEqual(golden.fuzz_rows(count=20, seed=1), golden.fuzz_rows(count=20, seed=2))

    def test_unicode_tables_state_their_version_and_cover_the_predicates(self) -> None:
        text = golden.generate_tables()
        self.assertIn(f'UNICODE_VERSION: &str = "{unicodedata.unidata_version}"', text)
        for table in ("ALPHA", "UPPER", "LOWER", "PUNCT"):
            self.assertIn(f"pub static {table}:", text)

    def test_the_committed_fixture_is_a_replay_of_the_python_runs(self) -> None:
        payload = json.loads(base64.b64decode(FIXTURE.read_text(encoding="ascii")))
        self.assertEqual(payload["unicode"], unicodedata.unidata_version)
        self.assertTrue(payload["lexicon"])
        for row in payload["rows"]:
            self.assertEqual(set(row["layer"]), set(golden.LAYER_CONFIGS))
            self.assertEqual(set(row["pattern"]), set(golden.PATTERN_CONFIGS))
            self.assertTrue(row["spacy"] is not None)
        self.assertEqual(len(payload["rows"]), len(golden.synthetic_inputs()))


@unittest.skipUnless(runtime_available(), "the client runtime, spaCy or the model is not installed")
class RuntimeRunTest(unittest.TestCase):
    def test_a_layer_run_selects_only_the_ner_layer_and_records_decisions(self) -> None:
        runtime = golden.Runtime()
        row = golden.golden_row(runtime, "t", "My name is Alice Smith and I live in Paris.", ["default", "caseless", "no-postfilter"], ["default"])
        self.assertEqual(row["layer"]["default"]["results"][0]["text"], "Alice Smith")
        self.assertTrue(row["layer"]["default"]["decisions"])
        self.assertEqual(row["layer"]["no-postfilter"]["decisions"], [])
        self.assertIn("results", row["pattern"]["default"])

    def test_a_non_ner_layer_request_is_refused(self) -> None:
        runtime = golden.Runtime()
        with self.assertRaises(AssertionError):
            runtime.pipeline._detector_for("regex")

    def test_the_caseless_gate_changes_what_spacy_sees(self) -> None:
        runtime = golden.Runtime(record_spacy=True)
        text = "ALICE SMITH LIVES IN PARIS"
        runtime.nlp.reset()
        runtime.layer(text, "caseless")
        folded = {record["text"] for record in runtime.nlp.log if record["sel"] == "full"}
        self.assertEqual(folded, {text.lower()})
        runtime.nlp.reset()
        runtime.layer(text, "default")
        self.assertEqual({record["text"] for record in runtime.nlp.log if record["sel"] == "full"}, {text})


if __name__ == "__main__":
    unittest.main()
