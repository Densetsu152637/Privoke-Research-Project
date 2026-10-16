"""Integrity controls for the bounded operational measurement runner."""
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / "run-telemetry-operational-study.py"
SPEC = importlib.util.spec_from_file_location("operational_study", PATH)
study = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(study)


class OperationalStudyTests(unittest.TestCase):
    def test_nearest_rank_quantiles_keep_denominator_and_maximum(self):
        self.assertEqual(study.quantiles([9, 1, 2, 3]), {"n": 4, "p50": 2, "p95": 9, "max": 9})
        self.assertEqual(study.quantiles([]), {"n": 0})

    def test_marginal_reconciliation_rejects_missing_or_extra_reports(self):
        response = study.pb.GetTelemetrySummaryResponse(sample_count=3, dimensions=[
            study.pb.TelemetryDimensionEstimate(dimension=name, values=[
                study.pb.TelemetryCategoryEstimate(value=value, observed_noisy_count=3 if index == 0 else 0)
                for index, value in enumerate(domain)]) for name, domain in study.DOMAINS.items()])
        study.check_marginals(response)
        response.dimensions[0].values[0].observed_noisy_count = 2
        with self.assertRaises(AssertionError):
            study.check_marginals(response)

    def test_marginal_reconciliation_rejects_duplicate_dimensions_and_domain_values(self):
        response = study.pb.GetTelemetrySummaryResponse(dimensions=[
            study.pb.TelemetryDimensionEstimate(dimension=name, values=[
                study.pb.TelemetryCategoryEstimate(value=value) for value in domain])
            for name, domain in study.DOMAINS.items()])
        study.check_marginals(response)
        response.dimensions[0].dimension = response.dimensions[1].dimension
        with self.assertRaises(AssertionError):
            study.check_marginals(response)
        response.dimensions[0].dimension = "action"
        response.dimensions[0].values[0].value = response.dimensions[0].values[1].value
        with self.assertRaises(AssertionError):
            study.check_marginals(response)
        del response.dimensions[0]
        with self.assertRaises(AssertionError):
            study.check_marginals(response)


if __name__ == "__main__":
    unittest.main()
