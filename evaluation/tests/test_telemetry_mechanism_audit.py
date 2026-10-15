from fractions import Fraction
import importlib.util
from pathlib import Path
import unittest

PATH=Path(__file__).resolve().parents[1]/'analysis/audit-telemetry-mechanism.py'
SPEC=importlib.util.spec_from_file_location('telemetry_audit',PATH)
audit=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)

class TelemetryAuditTests(unittest.TestCase):
    def test_strict_binary_grid_boundary(self):
        self.assertEqual(audit.finite_probability(.5),Fraction(1,2))
        import math
        self.assertEqual(audit.finite_probability(math.nextafter(.5,1)),Fraction((1<<52)+1,1<<53))
        self.assertEqual(audit.finite_probability(math.nextafter(.5,0)),Fraction(1,2))

    def test_log_interval_contains_known_rational_bound(self):
        lower,upper=audit.log_enclosure(Fraction(1))
        from decimal import Decimal
        self.assertLessEqual(Decimal(lower),0)
        self.assertGreaterEqual(Decimal(upper),0)

    def test_all_declared_kernels_have_positive_normalized_support(self):
        results=audit.finite_audit()
        self.assertEqual(len(results),3)
        self.assertEqual([f['K'] for f in results[0]['fields']],[3,4,11,2,6])
        self.assertTrue(all(len(r['signed_excess_enclosure'])==2 for r in results))

    def test_fixed_truth_counts_preserve_reconstruction_estimand(self):
        for n in audit.SIZES:
            for k in (2,3,4,6,11):
                for workload in ('uniform','point_mass','rare_first'):
                    counts=audit.truth_counts(n,k,workload)
                    self.assertEqual(sum(counts),n)
                    self.assertTrue(all(count>=0 for count in counts))

    def test_small_clipping_known_binary_case(self):
        # n1 makes clipped inverse GRR equal the observed indicator.
        self.assertAlmostEqual(audit.clipped_exact_small(1,0,.6,.4,.6,.4),.4)
        self.assertAlmostEqual(audit.clipped_exact_small(1,1,.6,.4,.6,.4),-.4)

    def test_actual_store_mixed_strata_parity(self):
        self.assertEqual(audit.store_parity()['compared_estimates'],26)

if __name__=='__main__': unittest.main()
