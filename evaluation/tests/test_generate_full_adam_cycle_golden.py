"""Mechanics of the FULL Adam cycle golden generator (RUST-S21F), without the generated protobuf clients or recorded studies."""

from __future__ import annotations

import importlib
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "evaluation"))
golden = importlib.import_module("generate_full_adam_cycle_golden")


class _Message:
    def __init__(self, payload: bytes):
        self.payload = payload

    def SerializeToString(self, deterministic=False):  # noqa: N802 - protobuf API name
        return self.payload


class GeneratorMechanicsTest(unittest.TestCase):
    def test_the_channel_logs_the_invocation_metadata_and_the_deadline(self) -> None:
        log, calls = [], []
        channel = golden.MetadataChannel({"/svc/Method": lambda request: "answer"}, log, calls)
        call = channel.unary_unary("/svc/Method", request_serializer=None, response_deserializer=None, _registered_method=True)
        self.assertEqual(call(_Message(b"wire"), timeout=180.0, metadata=(("x-privoke-training-admission-v1", "{}"),)), "answer")
        self.assertEqual(log, [("/svc/Method", b"wire")])
        self.assertEqual(calls, [{"path": "/svc/Method", "timeout": 180.0, "metadata": [["x-privoke-training-admission-v1", "{}"]]}])

    def test_timestamps_become_ordinals_and_the_dump_path_becomes_a_placeholder(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            directory = Path(scratch) / "dump"
            attempts = directory / "backtracking-attempts" / "digest" / "attempts"
            admission = directory / "backtracking-attempts" / "digest" / "admission" / "attempts"
            attempts.mkdir(parents=True)
            admission.mkdir(parents=True)
            attempt = attempts / "1791731100297953089.json"
            attempt.write_text('{"a": 1}\n', encoding="utf-8")
            (admission / "1791731100297999999.json").write_text(json.dumps({"physical_attempt": str(attempt)}) + "\n", encoding="utf-8")
            (directory / "full-adam-runtime" / "x").mkdir(parents=True)
            (directory / "full-adam-runtime" / "x" / "started.json").write_text("{}", encoding="utf-8")
            connection = sqlite3.connect(directory / "training-reservations.sqlite3")
            connection.execute("CREATE TABLE requests (identity TEXT PRIMARY KEY, fingerprint TEXT NOT NULL)")
            connection.commit()
            connection.close()
            files = golden.normalised_dump(directory)
        self.assertEqual(sorted(files), [
            "backtracking-attempts/digest/admission/attempts/0000.json",
            "backtracking-attempts/digest/attempts/0000.json",
            "full-adam-runtime/x/started.json",
        ])
        self.assertEqual(json.loads(files["backtracking-attempts/digest/admission/attempts/0000.json"]),
                         {"physical_attempt": "<DUMP>/backtracking-attempts/digest/attempts/0000.json"})

    def test_the_policy_request_names_the_exact_full_adam_contract(self) -> None:
        metadata = golden.policy_metadata(lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")), {"steps": 64})
        self.assertEqual(metadata["expected_contextual_training_scope"], "full_encoder")
        self.assertEqual(metadata["expected_full_projected_adam_config_v1"], '{"steps":64}')
        self.assertEqual(golden.policy_metadata(str, {}, expected_contextual_training_scope="heads")["expected_contextual_training_scope"], "heads")

    def test_the_runtime_is_never_asked_for_a_detector_pipeline(self) -> None:
        source = (REPO / "evaluation" / "generate_full_adam_cycle_golden.py").read_text(encoding="utf-8")
        for forbidden in ("analyse_text", "AnalyzePrompt", '"regex"', '"ner"'):
            self.assertNotIn(forbidden, source, forbidden)


if __name__ == "__main__":
    unittest.main()
