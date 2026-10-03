import importlib.util
import json
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("ablations", Path(__file__).parents[1] / "run-ablations.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
STUDY_SPEC = importlib.util.spec_from_file_location("profile_study", Path(__file__).parents[1] / "run-model-profile-study.py")
STUDY = importlib.util.module_from_spec(STUDY_SPEC)
STUDY_SPEC.loader.exec_module(STUDY)


class ModelProfileTests(unittest.TestCase):
    def test_runtime_cost_rejects_invalid_duration_instead_of_dropping_rows(self):
        def report(values):
            return {"metadata": {"predictions": [{"elapsed_ms": value} for value in values]}}
        cost = STUDY.runtime_cost(report([30, 1, 2, 3]))
        self.assertEqual(cost["samples"], 4)
        self.assertEqual(cost["first_request_ms"], 30)
        self.assertEqual(cost["median_ms"], 2.5)
        for values in ([], [1, float("nan")], [-1], ["missing"]):
            with self.subTest(values=values), self.assertRaises(ValueError):
                STUDY.runtime_cost(report(values))

    def test_shared_version_does_not_allow_a_different_profile_or_checksum(self):
        artifact = {"model_id": "privoke-quality", "version": "v0.3.0", "checksum": "quality-checksum", "parameters": {}}
        metadata = {"model_id": artifact["model_id"], "model_version": artifact["version"],
                    "artifact_checksum": artifact["checksum"], "parameter_fingerprint": MODULE.parameter_fingerprint({}, {})}
        report = {"metadata": {"predictions": [{"layers": [{"layer": "DETECTION_LAYER_SEMANTIC",
                  "status": "ok", "results": [{"metadata": metadata}]}]}]}}
        MODULE.verify_semantic_identity(report, artifact)
        for key, value in (("model_id", "privoke-balanced"), ("model_version", "v0.3.0+train.1"),
                           ("artifact_checksum", "balanced-checksum"), ("parameter_fingerprint", "different-weights")):
            changed = json.loads(json.dumps(report))
            changed["metadata"]["predictions"][0]["layers"][0]["results"][0]["metadata"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "differs from the artifact"):
                MODULE.verify_semantic_identity(changed, artifact)

    def test_a_streamed_result_without_identity_is_not_eligible(self):
        report = {"metadata": {"predictions": [{"layers": [{"layer": "DETECTION_LAYER_SEMANTIC",
                  "status": "ok", "results": [{"metadata": {}}]}]}]}}
        with self.assertRaises(ValueError):
            MODULE.verify_semantic_identity(report, {"model_id": "quality", "version": "v0.3.0", "checksum": "x", "parameters": {}})
