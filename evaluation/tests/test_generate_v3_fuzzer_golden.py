"""Mechanics and end-to-end run of the V3 fuzzer golden generator (RUST-S21B).

The mechanics tests need nothing but the standard library. The end-to-end test runs the maintained Python `FuzzerServer` in
process against scripted services over the committed fixtures, so it needs the generated protobuf clients: set
`PRIVOKE_GENERATED` to a directory holding `privoke/v1` and `privoke/experimental` (for example
`<main checkout>/extension/client-runtime/generated`) and run with a host environment that has `grpcio` and `protobuf`
(`evaluation/.venv-v1-v3-pipeline`). It is skipped when the variable is not set.
"""

from __future__ import annotations

import importlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "evaluation"))
golden = importlib.import_module("generate_v3_fuzzer_golden")
GENERATED = os.environ.get("PRIVOKE_GENERATED")


class _Message:
    def __init__(self, payload: bytes):
        self.payload = payload

    def SerializeToString(self, deterministic=False):  # noqa: N802 - protobuf API name
        return self.payload


class GeneratorMechanicsTest(unittest.TestCase):
    def test_the_channel_answers_unary_and_streaming_methods_and_logs_each_request(self) -> None:
        log = []
        channel = golden.make_channel({"/svc/Unary": lambda request: "one", "/svc/Stream": lambda request: ["a", "b"]}, log)
        unary = channel.unary_unary("/svc/Unary", request_serializer=None, response_deserializer=None, _registered_method=True)
        stream = channel.unary_stream("/svc/Stream", request_serializer=None, response_deserializer=None, _registered_method=True)
        self.assertEqual(unary(_Message(b"wire"), timeout=1.0), "one")
        self.assertEqual(list(stream(_Message(b"ref"), timeout=1.0)), ["a", "b"])
        self.assertEqual(log, [("/svc/Unary", b"wire"), ("/svc/Stream", b"ref")])
        with self.assertRaises(NotImplementedError):
            channel.stream_unary("/svc/Client")(iter(()))

    def test_the_work_directory_and_the_rows_are_snapshotted_by_digest(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            state = Path(scratch)
            digest = lambda raw: golden.sha(raw)  # noqa: E731
            self.assertEqual(golden.snapshot_work(state, "missing", digest), {"work_dir": None, "files": {}})
            work = state / golden.sha(b"cycle")
            work.mkdir()
            (work / "receipt.pb").write_bytes(b"abc")
            snapshot = golden.snapshot_work(state, "cycle", digest)
            self.assertEqual(snapshot["work_dir"], work.name)
            self.assertEqual(snapshot["files"], {"receipt.pb": [golden.sha(b"abc"), 3]})
            connection = sqlite3.connect(state / "cycles.sqlite")
            connection.execute("CREATE TABLE cycles(id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, response BLOB)")
            connection.execute("INSERT INTO cycles VALUES ('b', 'two', NULL)")
            connection.execute("INSERT INTO cycles VALUES ('a', 'one', x'0102')")
            connection.commit()
            connection.close()
            self.assertEqual(golden.snapshot_rows(state), [["a", "one", golden.b64(b"\x01\x02")], ["b", "two", None]])

    def test_the_frozen_inputs_are_the_committed_fixtures(self) -> None:
        for relative, fixture in golden.BC01_FIXTURES.items():
            self.assertTrue(relative.startswith("evaluation/results/iterative_fuzzer_20261011/"), relative)
            self.assertTrue((golden.FIXTURES / fixture).is_file(), fixture)
        with tempfile.TemporaryDirectory() as scratch:
            root = golden.prepare_input_root(Path(scratch))
            for relative, fixture in golden.BC01_FIXTURES.items():
                self.assertEqual((root / relative).read_bytes(), (golden.FIXTURES / fixture).read_bytes())

    def test_no_detector_layer_is_ever_requested(self) -> None:
        source = (REPO / "evaluation" / "generate_v3_fuzzer_golden.py").read_text(encoding="utf-8")
        for forbidden in ("analyse_text", "AnalyzePrompt", '"regex"', '"ner"', "layers=[]"):
            self.assertNotIn(forbidden, source, forbidden)

    def test_the_summary_counts_each_kind_of_outcome(self) -> None:
        document = golden.document("synthetic", [{"cycles": [{"outcome": {"ok": "x"}}, {"outcome": {"abort": ["A", "b"]}}, {"outcome": {"error": ["E", "m"]}}], "sqlite": [1, 2]}])
        self.assertEqual(golden.summary(document), {"kind": "synthetic", "sequences": 1, "cycles": 3, "ok": 1, "abort": 1, "error": 1, "sqlite_rows": 2})


@unittest.skipUnless(GENERATED, "PRIVOKE_GENERATED (the generated protobuf clients) is not set")
class OracleRunTest(unittest.TestCase):
    """The maintained Python service, run against scripted services."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = golden.synthetic_golden(Path(GENERATED))

    def test_every_scripted_case_has_the_intended_outcome(self) -> None:
        self.assertEqual(golden.summary(self.document), {"kind": "synthetic", "sequences": 3, "cycles": 19, "ok": 8, "abort": 3, "error": 8, "sqlite_rows": 14})
        outcomes = {(sequence["label"], cycle["label"]): cycle["outcome"] for sequence in self.document["sequences"] for cycle in sequence["cycles"]}
        first = "synthetic-bc01-pilot"
        self.assertEqual(outcomes[(first, "the same identity in the other scope is refused")]["abort"][0], "ALREADY_EXISTS")
        self.assertEqual(outcomes[(first, "a budget that is not the frozen one")]["abort"][0], "INVALID_ARGUMENT")
        self.assertEqual(outcomes[(first, "an identity whose outcome is unknown is never replayed")]["abort"][0], "FAILED_PRECONDITION")
        self.assertEqual(outcomes[(first, "a fit whose response is lost")]["error"][0], "RuntimeError")
        self.assertEqual(outcomes[(first, "a commit whose outcome is unknown")]["error"][1], "Commit outcome unknown; stop without replay.")
        self.assertIn("ok", outcomes[(first, "a commit whose acknowledgement is lost but applied")])

    def test_a_fit_is_dispatched_once_per_identity_and_always_semantic_only(self) -> None:
        fits = 0
        for sequence in self.document["sequences"]:
            for cycle in sequence["cycles"]:
                dispatched = [path for path, _, _ in cycle["wire"] if path.endswith("/FitCandidate")]
                fits += len(dispatched)
                if dispatched:
                    self.assertEqual(cycle["answers"]["fit_layers"], [4], cycle["label"])
        self.assertEqual(fits, 11)

    def test_the_work_directory_keeps_the_failure_markers(self) -> None:
        names = {name for sequence in self.document["sequences"] for cycle in sequence["cycles"] for name in cycle["files"]}
        self.assertTrue({"cycle-request.pb", "source.json", "fit-request.pb", "fit-response.pb", "evidence.json", "commit-request.pb", "receipt.pb",
                         "fit-status-after-error.pb", "unknown-commit.pb"} <= names)

    def test_the_document_serialises_deterministically(self) -> None:
        text = json.dumps(self.document, indent=1, sort_keys=True)
        self.assertEqual(json.loads(text), self.document)


if __name__ == "__main__":
    unittest.main()
