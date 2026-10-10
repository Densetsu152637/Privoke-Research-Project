"""Admission validates actual execution independently of declared self hashes."""
import base64
import copy
import json
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
SERVICE = Path(__file__).resolve().parents[1]
for path in (ROOT / "shared/python", SERVICE / "generated", SERVICE / "src"):
    sys.path.insert(0, str(path))
from privoke.v1 import runtime_pb2 as pb
from privoke_model.contextual_training import FULL_ENCODER_STRATEGY, HEAD_NAMES
from privoke_model.fingerprint import parameter_fingerprint
from runtime_client import PrivokeRuntimeClient, RuntimeAnalysisError, validate_training_response
from training.types import BatchTrainingExample


def contract(scope="heads"):
    artifact = json.loads((ROOT / "models/privoke-balanced.json").read_text())
    request = pb.ComputeSemanticGradientsRequest(request_id="req", model_id="privoke-balanced",
        layers=[pb.DETECTION_LAYER_SEMANTIC], examples=[pb.RuntimeTrainingExample(text="synthetic train")],
        heldout_examples=[pb.RuntimeTrainingExample(text="synthetic heldout")], max_gradient=.05)
    tensors = {k:v for k,v in artifact["parameters"].items() if scope == "full_encoder" or k in HEAD_NAMES}
    shapes = {k:v["shape"] for k,v in tensors.items()}
    response = pb.ComputeSemanticGradientsResponse(request_id="req", model_id="privoke-balanced", base_version="v0.4.0",
        gradients=[pb.RuntimeParameterDelta(name=name, shape=tensor["shape"], values=[0.0]*len(tensor["values"]))
                   for name,tensor in sorted(tensors.items())],
        executions=[pb.SemanticTrainingExecution(phase=phase, layer=pb.DETECTION_LAYER_SEMANTIC, status="ok", examples=1)
                    for phase in ("training", "base_heldout", "candidate_heldout")],
        metrics={"examples":1,"heldout_examples":1}, metadata={
            "model_config": json.dumps(artifact["config"]), "training_scope":scope,
            "strategy": FULL_ENCODER_STRATEGY if scope == "full_encoder" else "transformer_classification_head_finetune",
            "artifact_training_strategy":FULL_ENCODER_STRATEGY, "underlying_training_available":"true",
            "trained_parameter_names": json.dumps(sorted(tensors)),
            "trained_parameter_inventory_fingerprint": parameter_fingerprint({k:() for k in tensors},shapes),
            "artifact_checksum":"a"*64,"base_parameter_fingerprint":"b"*64,"updated_parameter_fingerprint":"c"*64})
    return request,response


class DualRuntimeContractTests(unittest.TestCase):
    def test_legacy_float32_clip_bound_remains_admitted_but_full_capability_is_strict(self):
        from privoke_model.artifact import float32
        request,response=contract()
        response.gradients[0].values[0]=float32(.001)
        self.assertGreater(response.gradients[0].values[0],.001)
        with self.assertRaises(RuntimeAnalysisError): validate_training_response(request,response,"heads",.001)
        response.metadata["artifact_training_strategy"]="transformer_classification_head_finetune"
        validate_training_response(request,response,"heads",.001)

    def test_both_methods_request_explicit_semantic_and_retain_actual_protobuf(self):
        for scope, method in (("heads","ComputeSemanticGradients"),("full_encoder","ComputeUnderlyingModelGradients")):
            request,response = contract(scope)
            with patch("runtime_client.grpc.insecure_channel"), patch("runtime_client.runtime_pb2_grpc.PrivokeRuntimeServiceStub") as stub:
                getattr(stub.return_value, method).return_value = response
                result = PrivokeRuntimeClient("unused").compute_semantic_gradients(
                    [BatchTrainingExample("synthetic train")], heldout_examples=[BatchTrainingExample("synthetic heldout")],
                    model_id=request.model_id, learning_rate=.03, max_gradient=.05, request_id="req",
                    training_scope=scope, require_full_capability=True)
            sent = getattr(stub.return_value, method).call_args.args[0]
            self.assertEqual(list(sent.layers),[pb.DETECTION_LAYER_SEMANTIC])
            self.assertEqual(base64.b64decode(result["execution_evidence"]["response_protobuf_base64"]), response.SerializeToString(deterministic=True))

    def test_missing_extra_error_wrong_counts_or_identity_rejected(self):
        for mutation in ("missing", "extra", "error", "count", "layer", "model", "request", "checksum", "capability"):
            request,response = contract()
            if mutation=="missing": del response.executions[:]
            elif mutation=="extra": response.executions.add(phase="extra",status="ok")
            elif mutation=="error": response.executions[0].error="failed"
            elif mutation=="count": response.executions[1].examples=2
            elif mutation=="layer": response.executions[0].layer=pb.DETECTION_LAYER_REGEX
            elif mutation=="model": response.model_id="privoke-quality"
            elif mutation=="request": response.request_id="wrong"
            elif mutation=="checksum": response.metadata["artifact_checksum"]="missing"
            elif mutation=="capability": response.metadata["underlying_training_available"]="false"
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeAnalysisError):
                validate_training_response(request,response,"heads",.05,require_full_capability=True)

    def test_full_inventory_cannot_self_attest_only_heads_or_wrong_shapes(self):
        request,response=contract("full_encoder")
        heads=[p for p in response.gradients if p.name in HEAD_NAMES]
        del response.gradients[:]
        response.gradients.extend(heads)
        response.metadata["trained_parameter_names"]=json.dumps(sorted(HEAD_NAMES))
        response.metadata["trained_parameter_inventory_fingerprint"]=parameter_fingerprint({p.name:() for p in heads},{p.name:p.shape for p in heads})
        with self.assertRaises(RuntimeAnalysisError): validate_training_response(request,response,"full_encoder",.05)
        for mutate in ("shape","bound","nan","duplicate"):
            request,response=contract("full_encoder")
            if mutate=="shape": response.gradients[0].shape[0]+=1
            elif mutate=="bound": response.gradients[0].values[0]=.1
            elif mutate=="nan": response.gradients[0].values[0]=float("nan")
            else: response.gradients.add().CopyFrom(response.gradients[0])
            with self.subTest(mutate=mutate),self.assertRaises(RuntimeAnalysisError):
                validate_training_response(request,response,"full_encoder",.05)

    def test_failure_contract_never_reaches_publication_trainer(self):
        request,response=contract()
        response.metadata["underlying_training_available"]="false"
        with patch("runtime_client.grpc.insecure_channel"), patch("runtime_client.runtime_pb2_grpc.PrivokeRuntimeServiceStub") as stub:
            stub.return_value.ComputeSemanticGradients.return_value=response
            with self.assertRaises(RuntimeAnalysisError):
                PrivokeRuntimeClient("unused").compute_semantic_gradients(
                    [BatchTrainingExample("train")],heldout_examples=[BatchTrainingExample("heldout")],
                    model_id=request.model_id,request_id="req",learning_rate=.03,max_gradient=.05,require_full_capability=True)
