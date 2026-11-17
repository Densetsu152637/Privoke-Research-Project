"""Mechanics of the fuzzer golden generator (RUST-S21), without the generated protobuf clients or recorded studies."""

from __future__ import annotations

import base64
import importlib
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "evaluation"))
golden = importlib.import_module("generate_fuzzer_golden")


class _Message:
    def __init__(self, payload: bytes):
        self.payload = payload

    def SerializeToString(self, deterministic=False):  # noqa: N802 - protobuf API name
        return self.payload


class GeneratorMechanicsTest(unittest.TestCase):
    def test_the_fake_channel_logs_requests_and_answers_from_its_table(self) -> None:
        log = []
        channel = golden.FakeChannel({"/svc/Method": lambda request: "answer"}, log)
        with channel as opened:
            call = opened.unary_unary("/svc/Method", request_serializer=None, response_deserializer=None, _registered_method=True)
            self.assertEqual(call(_Message(b"wire"), timeout=1.0), "answer")
        self.assertEqual(log, [("/svc/Method", b"wire")])

    def test_abort_raises_with_the_code_and_message(self) -> None:
        with self.assertRaises(golden.Aborted) as caught:
            golden.Context().abort("FAILED_PRECONDITION", "message")
        self.assertEqual((caught.exception.code, caught.exception.message), ("FAILED_PRECONDITION", "message"))
        self.assertTrue(golden.Context().is_active())

    def test_the_dump_snapshot_reads_evidence_and_reservations(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            directory = Path(scratch)
            record = directory / "training-cycles" / "id" / "fingerprint.json"
            record.parent.mkdir(parents=True)
            record.write_text('{"a": 1}\n', encoding="utf-8")
            connection = sqlite3.connect(directory / "training-reservations.sqlite3")
            connection.execute("CREATE TABLE requests (identity TEXT PRIMARY KEY, fingerprint TEXT NOT NULL)")
            connection.execute("INSERT INTO requests VALUES ('b', 'two'), ('a', 'one')")
            connection.commit()
            connection.close()
            snapshot = golden.collect_dump(directory)
        self.assertEqual(snapshot["evidence"], {"training-cycles/id/fingerprint.json": '{"a": 1}\n'})
        self.assertEqual(snapshot["reservations"], [["a", "one"], ["b", "two"]])

    def test_the_runtime_is_never_asked_for_a_detector_pipeline(self) -> None:
        source = (REPO / "evaluation" / "generate_fuzzer_golden.py").read_text(encoding="utf-8")
        for forbidden in ("analyse_text", "AnalyzePrompt", '"regex"', '"ner"'):
            self.assertNotIn(forbidden, source, forbidden)


class CommittedGoldenTest(unittest.TestCase):
    path = REPO / "rust/services/fuzzer/tests/fixtures/fuzzer_cycles_golden.json"

    def setUp(self) -> None:
        if not self.path.exists():
            self.skipTest("the golden has not been generated")
        self.document = json.loads(self.path.read_text(encoding="utf-8"))

    def test_both_outcomes_and_the_curriculum_state_are_recorded(self) -> None:
        sequences = {sequence["label"]: sequence for sequence in self.document["sequences"]}
        self.assertEqual(set(sequences), {"recorded-passed", "recorded-rejected", "curriculum-sqlite"})
        self.assertIn("ok", sequences["recorded-passed"]["cycles"][0]["outcome"])
        self.assertEqual(sequences["recorded-rejected"]["cycles"][0]["outcome"]["abort"][0], "FAILED_PRECONDITION")
        self.assertTrue(sequences["curriculum-sqlite"]["curriculum"]["cursors"])

    def test_every_cycle_carries_semantic_only_gradient_requests(self) -> None:
        for sequence in self.document["sequences"]:
            for cycle in sequence["cycles"]:
                self.assertTrue(cycle["runtime_rpc"].startswith("/privoke.v1.PrivokeRuntimeService/Compute"))
                self.assertIsNotNone(cycle["status_request"])
                wire = base64.b64decode(cycle["runtime_request"])
                # Field 7 (layers), packed varint [4]: tag 0x3a, length 1, value 4.
                self.assertIn(bytes((0x3A, 0x01, 0x04)), wire)


if __name__ == "__main__":
    unittest.main()
