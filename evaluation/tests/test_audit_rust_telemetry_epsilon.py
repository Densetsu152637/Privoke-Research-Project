"""The Rust telemetry finite-epsilon audit (RUST-S18): recomputation, invariants and the C34 comparison."""

from __future__ import annotations

import importlib
import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "evaluation"))
audit = importlib.import_module("audit_rust_telemetry_epsilon")

RECORD = REPO / "paper" / "research" / "rust-telemetry-epsilon-audit-20261117.json"


class RustEpsilonAuditTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fresh = audit.build()
        cls.committed = json.loads(RECORD.read_text(encoding="utf-8"))

    def test_the_committed_record_is_what_the_script_computes_on_this_host(self) -> None:
        # Thresholds come from the host libm; a host whose exp differs in the last bit would differ here and is the
        # reason the Rust test compares bits on the CI platform instead.
        self.assertEqual(audit.comparable(json.loads(json.dumps(self.fresh))), audit.comparable(self.committed))

    def test_the_nominal_bound_is_exceeded_by_about_1e_15_at_every_audited_epsilon(self) -> None:
        for row in self.committed["event_epsilons"]:
            lower, upper = (float(value) for value in row["signed_excess_over_nominal_enclosure"])
            self.assertFalse(row["nominal_bound_holds"], row["event_epsilon"])
            self.assertTrue(row["excess_strictly_positive"], row["event_epsilon"])
            self.assertTrue(0 < lower <= upper < 1e-13, (lower, upper))

    def test_every_coordinate_is_exact_and_normalised(self) -> None:
        from fractions import Fraction

        for row in self.committed["event_epsilons"]:
            for coordinate in row["coordinates"]:
                m = int(coordinate["grid_points_below_threshold"])
                p = Fraction(int(coordinate["P"]["numerator"]), int(coordinate["P"]["denominator"]))
                q = Fraction(int(coordinate["Q"]["numerator"]), int(coordinate["Q"]["denominator"]))
                self.assertEqual(p, Fraction(m, 1 << 53))
                self.assertEqual(p + (coordinate["domain_size"] - 1) * q, 1)

    def test_rust_formula_equals_the_python_kernel_here_and_c34_numbers_are_matched_not_reused(self) -> None:
        for row in self.committed["event_epsilons"]:
            self.assertTrue(row["equals_python_kernel_in_every_coordinate"], row["event_epsilon"])
        comparison = self.committed["c34_comparison"]
        self.assertTrue(comparison["available"])
        shared = [entry for entry in comparison["per_epsilon"] if entry["in_c34"]]
        self.assertEqual([entry["event_epsilon"] for entry in shared], [0.5, 1.0, 2.0])
        for entry in shared:
            self.assertTrue(entry["signed_excess_identical"] and entry["joint_ratio_identical"] and entry["thresholds_identical"])


if __name__ == "__main__":
    unittest.main()
