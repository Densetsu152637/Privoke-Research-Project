"""Mechanics of the Rust analysis runtime golden generator (RUST-S17), plus a regeneration check.

The fixture checks run anywhere (standard library only): they parse the committed request bytes by hand and assert that
no request has an empty layer list, names the semantic layer or names the runtime layer. The regeneration check needs
the client runtime's Python environment and the generated protobuf clients, and is skipped without them.
"""

from __future__ import annotations

import base64
import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "evaluation"))
golden = importlib.import_module("generate_runtime_golden")

FIXTURE = REPO / "rust" / "services" / "runtime" / "tests" / "fixtures" / "runtime_golden.json"


def varint(data: bytes, offset: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7


def request_layers(data: bytes) -> list[int]:
    """The ``layers`` field (7) of an ``AnalyzePromptRequest``: packed or unpacked varints."""
    layers: list[int] = []
    offset = 0
    while offset < len(data):
        key, offset = varint(data, offset)
        field, wire = key >> 3, key & 7
        if wire == 0:
            value, offset = varint(data, offset)
            if field == 7:
                layers.append(value)
        elif wire == 2:
            length, offset = varint(data, offset)
            body = data[offset:offset + length]
            offset += length
            if field == 7:
                position = 0
                while position < len(body):
                    value, position = varint(body, position)
                    layers.append(value)
        elif wire == 1:
            offset += 8
        elif wire == 5:
            offset += 4
        else:
            raise AssertionError(f"unexpected wire type {wire}")
    return layers


def runtime_available() -> bool:
    try:
        golden.bootstrap()
        from src import pipeline  # noqa: F401
        import spacy

        spacy.load("en_core_web_sm")
    except Exception:  # noqa: BLE001 - generated clients, spaCy or the model are missing
        return False
    return True


class FixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_every_request_selects_regex_and_ner_layers_explicitly(self) -> None:
        for case in self.document["cases"]:
            layers = request_layers(base64.b64decode(case["request"]))
            self.assertTrue(layers, f"{case['id']} sends an empty layer list")
            if case["scope"] != "validation":
                self.assertTrue(set(layers) <= {2, 3}, f"{case['id']} names {layers}")
            self.assertNotIn(1, layers, f"{case['id']} names the runtime layer")
            self.assertNotIn(4, layers, f"{case['id']} names the semantic layer")

    def test_the_fixture_is_not_llm_only_evidence(self) -> None:
        self.assertIn("never LLM-only evidence", self.document["scope_note"])
        self.assertTrue({case["scope"] for case in self.document["cases"]} <= {"detector_ablation", "product_pipeline", "validation"})

    def test_the_w1_capture_digests_are_reproduced(self) -> None:
        captured = [case for case in self.document["cases"] if "capture_sha256" in case]
        self.assertGreaterEqual(len(captured), 60)
        self.assertTrue(all(case["capture_match"] for case in captured))

    def test_every_recorded_response_is_normalised(self) -> None:
        # elapsed_ms is field 11 (double, tag 0x59) and metadata["elapsed_ms"] an entry of field 8: neither is recorded.
        for case in self.document["cases"]:
            response = base64.b64decode(case["response"])
            self.assertNotIn(b"elapsed_ms", response, case["id"])

    def test_the_cases_cover_the_stated_surface(self) -> None:
        ids = [case["id"] for case in self.document["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        for fragment in ("/regex", "/ner", "/regex+ner", "hint/P2", "validation/empty", "validation/too-long", "layers/duplicates"):
            self.assertTrue(any(fragment in case_id for case_id in ids), fragment)


@unittest.skipUnless(runtime_available(), "the client runtime environment, the protobuf clients or spaCy are missing")
class RegenerationTest(unittest.TestCase):
    def test_regeneration_is_byte_identical_to_the_committed_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "runtime_golden.json"
            golden.write(target)
            self.assertEqual(target.read_bytes(), FIXTURE.read_bytes())


if __name__ == "__main__":
    unittest.main()
