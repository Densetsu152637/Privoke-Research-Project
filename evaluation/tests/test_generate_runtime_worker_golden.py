"""Mechanics of the Rust worker golden generator (RUST-S17A), plus a regeneration check.

The fixture checks run anywhere (standard library only): they parse the committed request bytes by hand and assert that
no request has an empty layer list or names the runtime layer or the NER layer, that every presence and gradient request
selects exactly the semantic layer, that the committed synthetic artifacts carry valid checksums, and that no recorded
response holds a wall-clock field. The regeneration check needs the client runtime's Python environment with Torch and the
generated protobuf clients, and is skipped without them.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "evaluation"))
golden = importlib.import_module("generate_runtime_worker_golden")

FIXTURE = REPO / "rust" / "services" / "runtime" / "tests" / "fixtures" / "worker_golden.json"
MODELS = REPO / "rust" / "services" / "runtime" / "tests" / "fixtures" / "worker_models"
# The field number of `layers` in each request message, by W1 method tag.
LAYERS_FIELD = {1: 7, 2: 4, 4: 7, 5: 7, 6: 7}


def varint(data: bytes, offset: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7


def request_layers(data: bytes, field_number: int) -> list[int]:
    """The ``layers`` field of a request message: packed or unpacked varints."""
    layers: list[int] = []
    offset = 0
    while offset < len(data):
        key, offset = varint(data, offset)
        field, wire = key >> 3, key & 7
        if wire == 0:
            value, offset = varint(data, offset)
            if field == field_number:
                layers.append(value)
        elif wire == 2:
            length, offset = varint(data, offset)
            body = data[offset:offset + length]
            offset += length
            if field == field_number:
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


def artifact_checksum(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    canonical = canonical.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def runtime_available() -> bool:
    try:
        golden.bootstrap()
        import grpc  # noqa: F401
        import numpy  # noqa: F401
        import torch  # noqa: F401
        from privoke.v1 import runtime_pb2  # noqa: F401
        from src import worker_main  # noqa: F401
    except Exception:  # noqa: BLE001 - Torch, the generated clients or the runtime are missing
        return False
    return True


class FixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_every_request_names_its_layers_explicitly_and_never_empty(self) -> None:
        for case in self.document["cases"]:
            layers = request_layers(base64.b64decode(case["request"]), LAYERS_FIELD[case["method"]])
            self.assertTrue(layers, f"{case['id']} sends an empty layer list")
            self.assertNotIn(1, layers, f"{case['id']} names the runtime layer")
            self.assertNotIn(3, layers, f"{case['id']} names the NER layer")
            if case["method"] != 1:
                self.assertTrue(layers == [4] or case["scope"] == "validation", f"{case['id']} names {layers}")
            if case["scope"] == "llm_only":
                self.assertEqual(layers, [4], case["id"])

    def test_only_gate_rows_add_the_regex_layer_and_they_are_product_pipeline_rows(self) -> None:
        for case in self.document["cases"]:
            layers = request_layers(base64.b64decode(case["request"]), LAYERS_FIELD[case["method"]])
            if 2 in layers and case["method"] == 1:
                self.assertIn(case["scope"], ("product_pipeline", "validation"), case["id"])
                self.assertTrue(case["id"].startswith(("gate-product", "validation/gate")), case["id"])

    def test_the_admission_header_travels_only_on_gradient_rows(self) -> None:
        for case in self.document["cases"]:
            if case["metadata"]:
                self.assertIn(case["method"], (4, 5), case["id"])
                self.assertEqual([pair[0] for pair in case["metadata"]], ["x-privoke-training-admission-v1"])

    def test_every_recorded_response_is_normalised(self) -> None:
        # elapsed_ms of an AnalyzePromptResponse is field 11 and a metadata entry; of a presence response, field 9.
        for case in self.document["cases"]:
            if "response" in case:
                self.assertNotIn(b"elapsed_ms", base64.b64decode(case["response"]), case["id"])

    def test_the_cases_cover_the_stated_surface(self) -> None:
        ids = [case["id"] for case in self.document["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        for fragment in (
            "privoke-presence-efficient/", "privoke-presence-balanced/", "gate/privoke-presence-balanced/", "gate-product/block",
            "validation/gate-threshold-nan", "synthetic-taskquery-sum/full_encoder", "synthetic-legacy-legacy/heads",
            "admission/full-adam-missing", "admission/differs", "presence-gradients/", "validation/overlength",
        ):
            self.assertTrue(any(fragment in case_id for case_id in ids), fragment)
        self.assertEqual({case["method"] for case in self.document["cases"]}, {1, 2, 4, 5, 6})

    def test_the_synthetic_artifacts_carry_valid_checksums(self) -> None:
        names = sorted(path.name for path in MODELS.glob("*.json"))
        self.assertEqual(len(names), len(self.document["models"]))
        for path in MODELS.glob("*.json"):
            payload = json.loads(path.read_text(encoding="utf-8"))
            checksum = payload.pop("checksum")
            self.assertEqual(checksum, artifact_checksum(payload), path.name)
            self.assertEqual(payload["model_id"] + ".json", path.name)


@unittest.skipUnless(runtime_available(), "Torch, the generated protobuf clients or the client runtime are missing")
class RegenerationTest(unittest.TestCase):
    def test_regeneration_is_byte_identical_to_the_committed_fixtures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "worker_golden.json"
            models = Path(directory) / "worker_models"
            golden.write(target, models)
            self.assertEqual(target.read_bytes(), FIXTURE.read_bytes())
            for path in MODELS.glob("*.json"):
                self.assertEqual((models / path.name).read_bytes(), path.read_bytes(), path.name)


if __name__ == "__main__":
    unittest.main()
