"""Behavior checks for strict detector scope and action harm calculations."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest
ROOT = Path(os.getenv("CONTROLLED_STUDY_SOURCE", r"D:\Git Repositories\Privoke-Research-Project"))
spec = importlib.util.spec_from_file_location("ablation", Path(__file__).parents[1] / "run-controlled-product-ablation.py")
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
a.initialize(ROOT)
from privoke.v1 import runtime_pb2 as pb
from privoke_contracts.classification import Classification
ENTRY = {"identity": {"model_id": "fixed", "model_version": "1", "artifact_checksum": "a", "parameter_fingerprint": "p"}}

class ScopeTests(unittest.TestCase):
    def request(self, layers):
        return pb.AnalyzePromptRequest(request_id="case", text="prompt", layers=layers)
    def response(self, layers, statuses=None):
        response = pb.AnalyzePromptResponse(request_id="case", action="ALLOW", allowed=True,
            classification=pb.RuntimeClassification(**Classification().to_dict(), packed=Classification().pack()))
        # Runtime Classification packed is validated only for successful response paths.
        for layer, status in zip(layers, statuses or ["ok"] * len(layers)):
            response.layers.add(layer=layer, status=status)
        return response
    def test_explicit_nonempty_configurations(self):
        self.assertEqual(set(tuple(v) for v in a.CONFIGS.values()), {(2,), (3,), (4,), (2,3), (3,4), (2,4), (2,3,4)})
    def test_returned_order_must_match(self):
        response=self.response([4,3])
        value=a.outcome(response.SerializeToString(), ENTRY, self.request([3,4]))
        self.assertEqual(value["status"], "invalid_response")
    def test_semantic_only_skip_rejected(self):
        response=self.response([4], ["skipped"])
        value=a.outcome(response.SerializeToString(), ENTRY, self.request([4]))
        self.assertEqual(value["status"], "invalid_response")
    def test_skip_without_regex_block_rejected(self):
        response=self.response([2,4], ["ok", "skipped"])
        response.layers[1].error="Skipped after regex returned BLOCK."
        self.assertEqual(a.outcome(response.SerializeToString(), ENTRY, self.request([2,4]))["status"], "invalid_response")
    def test_runtime_errors_retained_as_incorrect(self):
        record={"status":"transport_error", "classification":None, "action":None}
        self.assertEqual([a.metric(record,m) for m in ("binary","action","joint")], [0,0,0])
        self.assertIsNone(a.distance(record))
    def test_semantic_success_requires_immutable_identity(self):
        response=self.response([4])
        response.metadata.update({"privoke.semantic."+k:v for k,v in ENTRY["identity"].items()})
        self.assertEqual(a.outcome(response.SerializeToString(), ENTRY, self.request([4]))["status"], "ok")
        response.metadata["privoke.semantic.artifact_checksum"]="wrong"
        self.assertEqual(a.outcome(response.SerializeToString(), ENTRY, self.request([4]))["status"], "invalid_response")
    def test_legitimate_requested_suffix_skip_is_accepted(self):
        response=self.response([2,4], ["ok", "skipped"])
        response.action="BLOCK"
        response.allowed=False
        response.layers[0].results.add(action="BLOCK", classification=pb.RuntimeClassification(**Classification().to_dict(),packed=Classification().pack()))
        response.layers[1].error="Skipped after regex returned BLOCK."
        self.assertEqual(a.outcome(response.SerializeToString(), ENTRY, self.request([2,4]))["status"], "ok")
    def test_directional_distance_for_multiple_allowed_actions(self):
        record={"status":"ok", "action":"ALLOW", "allowed_actions":["WARN","BLOCK"]}
        self.assertEqual(a.distance(record), (1,0))
        record.update(action="BLOCK",allowed_actions=["ALLOW"])
        self.assertEqual(a.distance(record), (0,2))

if __name__ == "__main__":
    unittest.main()
