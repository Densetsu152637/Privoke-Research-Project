"""Mechanics of the telemetry client golden generator (RUST-S18): determinism, currency and oracle agreement."""

from __future__ import annotations

import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "evaluation"))
golden = importlib.import_module("generate_telemetry_client_golden")

FIXTURES = REPO / "rust" / "crates" / "privoke-telemetry-client" / "tests" / "fixtures"
COMMITTED = FIXTURES / "golden.json"
COMMITTED_LEDGER = FIXTURES / "python_written_ledger.sqlite3"


class GoldenGeneratorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        cls.out = root / "golden.json"
        cls.ledger = root / "ledger.sqlite3"
        assert golden.main(["--out", str(cls.out), "--ledger-out", str(cls.ledger)]) == 0
        cls.document = json.loads(cls.out.read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.directory.cleanup()

    def test_committed_fixture_is_what_the_generator_writes(self) -> None:
        self.assertEqual(COMMITTED.read_bytes(), self.out.read_bytes())
        self.assertEqual(COMMITTED_LEDGER.read_bytes(), self.ledger.read_bytes())

    def test_oracle_sources_are_pinned(self) -> None:
        oracle = self.document["oracle"]
        self.assertEqual(oracle["privacy_py_sha256_lf"], golden.sha256_lf(golden.TELEMETRY / "privacy.py"))
        self.assertEqual(oracle["event_emitter_py_sha256_lf"], golden.sha256_lf(golden.TELEMETRY / "event_emitter.py"))

    def test_boundary_draws_flip_exactly_at_the_threshold_grid_point(self) -> None:
        by_label: dict[str, list[bool]] = {}
        for case in self.document["grr"]["cases"]:
            if "boundary" in case:
                by_label.setdefault(case["boundary"]["label"], []).append(case["output"] == case["value"])
        self.assertTrue(all(by_label["zero"]) and all(by_label["below"]))
        self.assertFalse(any(by_label["at"]) or any(by_label["above"]) or any(by_label["max"]))

    def test_every_recorded_draw_holds_at_least_one_seven_byte_read(self) -> None:
        for case in self.document["grr"]["cases"]:
            self.assertGreaterEqual(len(case["bytes"]), 14, case)

    def test_reporter_scenarios_never_refund(self) -> None:
        spent = {scenario["name"]: scenario["spent_after"] for scenario in self.document["reporter"]}
        self.assertEqual(spent["delivery_failures_do_not_refund"], golden.fbits(7.0))
        self.assertEqual(spent["queue_overflow_is_not_refunded"], golden.fbits(4.0))
        self.assertEqual(spent["failed_build_is_not_refunded"], golden.fbits(0.5))

    def test_concurrent_reservations_never_overspend(self) -> None:
        concurrent = self.document["ledger"]["concurrent"]
        self.assertEqual(concurrent["accepted"], 8)
        self.assertTrue(concurrent["next_denied"])

    def test_no_credential_shaped_text_is_recorded(self) -> None:
        text = COMMITTED.read_text(encoding="utf-8")
        for needle in ("BEGIN ", "PRIVATE KEY", "Bearer ", "sk-"):
            self.assertNotIn(needle, text)


if __name__ == "__main__":
    unittest.main()
