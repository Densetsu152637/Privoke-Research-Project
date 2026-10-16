"""Integrity controls for the bounded operational measurement runner."""
import importlib.util
from pathlib import Path
import unittest
import json
import subprocess

PATH = Path(__file__).resolve().parents[1] / "run-telemetry-operational-study.py"
SPEC = importlib.util.spec_from_file_location("operational_study", PATH)
study = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(study)


class OperationalStudyTests(unittest.TestCase):
    def test_direct_host_interpreter_has_owned_pid_and_active_grpc_dependency(self):
        executable, environment = study.owned_python()
        process = subprocess.Popen([executable, "-c", "import os,json; from host_owned_service import attest_dependencies; print(json.dumps({'pid':os.getpid(),'environment':attest_dependencies(('grpc','google.protobuf'))}))"],
                                   env=environment, stdout=subprocess.PIPE, text=True)
        output, _ = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0)
        actual = json.loads(output)
        self.assertEqual(actual["pid"], process.pid)
        study.verify_dependencies(actual["environment"], ("grpc", "google.protobuf"))

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
