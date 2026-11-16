"""Mechanics of the privoke-semantic golden generator (RUST-S14), without any recorded dataset."""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "evaluation"))
golden = importlib.import_module("generate_semantic_golden")

FIXTURES = REPO / "rust" / "crates" / "privoke-semantic" / "tests" / "fixtures"
RUST_TESTS = REPO / "rust" / "crates" / "privoke-semantic" / "tests"


def runtime_available() -> bool:
    try:
        golden.bootstrap()
        import torch  # noqa: F401
        import transformers  # noqa: F401
        from src import pipeline  # noqa: F401
        from src.LLM.privoke.streamed_model import StreamedTransformerPrivacyModel  # noqa: F401
    except Exception:  # noqa: BLE001 - torch, transformers or the generated protobuf clients are missing
        return False
    return True


class FakePipeline:
    """Returns a chosen layer execution so that the layer assertions can be exercised."""

    def __init__(self, layers):
        self.layers = layers
        self._detector_for = lambda layer, semantic_model_id=None: None

    def analyse_text(self, text, layers=None):
        self.requested = layers
        return types.SimpleNamespace(layers=self.layers)


def execution(layer: str, status: str = "ok"):
    return types.SimpleNamespace(layer=layer, status=status, error=None, results=())


class GeneratorMechanicsTest(unittest.TestCase):
    def test_only_the_semantic_layer_is_ever_requested(self) -> None:
        source = (REPO / "evaluation" / "generate_semantic_golden.py").read_text(encoding="utf-8")
        self.assertIn('layers=["semantic"]', source)
        for forbidden in ('layers=[]', 'layers=None', '"regex"', '"ner"', "layers=()"):
            self.assertNotIn(forbidden, source, forbidden)

    def test_run_layer_sends_the_explicit_list_and_asserts_the_execution(self) -> None:
        fake = FakePipeline((execution("semantic"),))
        record = golden.run_layer(fake, lambda text: [], "text")
        self.assertEqual(fake.requested, ["semantic"])
        self.assertEqual(record, {"status": "ok", "error": None, "results": []})
        for layers in ((), (execution("regex"),), (execution("semantic"), execution("ner")), (execution("semantic", "skipped"),)):
            with self.assertRaises(AssertionError, msg=repr(layers)):
                golden.run_layer(FakePipeline(layers), lambda text: [], "text")

    def test_the_detector_hook_is_restored(self) -> None:
        fake = FakePipeline((execution("semantic"),))
        original = fake._detector_for
        golden.run_layer(fake, lambda text: [], "text")
        self.assertIs(fake._detector_for, original)

    def test_prompts_cover_the_edge_cases_and_are_stable(self) -> None:
        texts = golden.synthetic_texts()
        self.assertIn("", texts)
        self.assertTrue(any(len(text) > 1500 for text in texts))
        self.assertTrue(any("[CLS]" in text for text in texts))
        self.assertTrue(any(ord(ch) > 0xFFFF for text in texts for ch in text))
        self.assertEqual(golden.fuzz_texts(10), golden.fuzz_texts(10))
        self.assertFalse(any(golden.has_surrogate(text) for text in texts + golden.fuzz_texts()))
        ids = [row_id for row_id, _ in golden.prompt_rows()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_sampling_is_even_and_deterministic(self) -> None:
        rows = list(range(1000))
        picked = golden.sample(rows, 10)
        self.assertEqual([i for i, _ in picked], [0, 100, 200, 300, 400, 500, 600, 700, 800, 900])
        self.assertEqual(golden.sample(rows[:5], 10), list(enumerate(rows[:5])))
        self.assertEqual(len(golden.sample(rows, 0)), 1000)

    def test_the_synthetic_vocabulary_is_a_bert_vocabulary(self) -> None:
        vocab = golden.synthetic_vocab()
        self.assertEqual(vocab[:5], ["[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]"])
        self.assertEqual(len(vocab), len(set(vocab)))
        self.assertIn("##a", vocab)

    def test_the_head_label_inventories_are_the_runtime_contract(self) -> None:
        golden.bootstrap()
        from privoke_model.v3_contract import LABELS

        self.assertEqual(golden.LABELS, LABELS)


class CommittedFixtureTest(unittest.TestCase):
    def test_v3_golden_is_semantic_only_and_complete(self) -> None:
        data = json.loads((FIXTURES / "v3_synthetic" / "golden.json").read_text(encoding="utf-8"))
        self.assertEqual(data["meta"]["layers"], ["semantic"])
        self.assertEqual(data["meta"]["threads"], golden.THREADS)
        self.assertEqual([row["id"] for row in data["rows"]], [row_id for row_id, _ in golden.prompt_rows()])
        self.assertEqual([row["text"] for row in data["rows"]], [text for _, text in golden.prompt_rows()])
        errors = [row for row in data["rows"] if "error" in row]
        self.assertEqual(len(errors), 2)
        for row in data["rows"]:
            self.assertEqual(row["layer"]["status"], "error" if "error" in row else "ok")

    def test_tiny_golden_is_semantic_only_and_the_tracked_models_have_not_changed(self) -> None:
        for name in ("legacy", "task_query"):
            data = json.loads((FIXTURES / f"tiny_synthetic_{name}.golden.json").read_text(encoding="utf-8"))
            self.assertEqual(data["meta"]["layers"], ["semantic"])
            self.assertEqual(len(data["rows"]), len(golden.prompt_rows()))
        tracked = json.loads((FIXTURES / "tiny_tracked.golden.json").read_text(encoding="utf-8"))
        self.assertEqual(tracked["meta"]["layers"], ["semantic"])
        self.assertEqual(sorted(tracked["models"]), sorted(golden.TINY_MODELS))
        for name, digest in tracked["meta"]["sha256"].items():
            self.assertEqual(hashlib.sha256((REPO / "models" / f"{name}.json").read_bytes()).hexdigest(), digest, f"{name} changed; regenerate the golden")

    def test_the_rust_tests_use_the_same_fixture_names(self) -> None:
        source = "".join(path.read_text(encoding="utf-8") for path in RUST_TESTS.glob("*.rs"))
        for name in ("v3_synthetic", "golden.json", "tiny_synthetic_legacy", "tiny_synthetic_task_query", "tiny_tracked.golden.json", "model.safetensors"):
            self.assertIn(name, source)
        for name in golden.TINY_MODELS:
            self.assertIn(name, source)


@unittest.skipUnless(runtime_available(), "torch, transformers or the generated protobuf clients are not available")
class RegenerationTest(unittest.TestCase):
    def test_the_synthetic_release_is_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            torch, pipeline, model, inventory, config = golden.build_synthetic_v3(Path(tmp))
            for name in ("model.safetensors", "vocab.txt", "config.json"):
                self.assertEqual((Path(tmp) / name).read_bytes(), (FIXTURES / "v3_synthetic" / name).read_bytes(), name)
            self.assertEqual(config["hidden_size"], 32)
            self.assertEqual(len(inventory), 61)
            committed = json.loads((FIXTURES / "v3_synthetic" / "golden.json").read_text(encoding="utf-8"))
            row = golden.v3_row(torch, pipeline, model, "s004", golden.synthetic_texts()[4])
            self.assertEqual(row["ids"], committed["rows"][4]["ids"])
            self.assertEqual(row["logits"], committed["rows"][4]["logits"])
            self.assertEqual(row["layer"], committed["rows"][4]["layer"])


if __name__ == "__main__":
    unittest.main()
