"""Opt-in single-direction FULL search through explicit semantic runtime RPC fixtures."""
import copy
import json
import math
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
import numpy as np
from privoke_model.artifact import float32, updated_parameter_values, apply_parameter_update
from privoke_model.contextual_training import *
from privoke_model.fingerprint import parameter_fingerprint
from src.LLM.privoke.streamed_model import StreamedTransformerPrivacyModel, GLOBAL_STREAMED_MODEL_CACHE
from src.LLM.privoke.training import _local_training_losses
from src.hosting.grpc_server import PrivokeRuntimeService
from privoke.v1 import runtime_pb2 as RP
from test_training_adaptation import snapshot
import test_full_encoder_training as fixture


class AdmissionContext:
    def __init__(self, values): self.values = values
    def invocation_metadata(self): return self.values


@unittest.skipUnless(fixture.torch is not None, "CPU Torch dependency unavailable")
class BacktrackingTests(unittest.TestCase):
    def setUp(self):
        fixture.FullEncoderTrainingTests.setUp(self)
        self.server = PrivokeRuntimeService()

    def prepared(self, objective=LEGACY_OBJECTIVE):
        controlled = prepare_training_policy_artifact(self.artifact, objective=objective, diagnostics=TRAIN_DIAGNOSTICS_POLICY)
        preparation = {"schema": 1, **{k: "a" * 64 for k in ("baseline_checksum", "baseline_fingerprint", "protocol_sha256", "source_sha256")}}
        return prepare_training_backtracking_artifact(controlled, preparation=preparation)

    def expectations(self, artifact):
        return {"expected_objective": artifact["metadata"].get(OBJECTIVE_KEY, LEGACY_OBJECTIVE),
                "expected_diagnostics_policy": TRAIN_DIAGNOSTICS_POLICY, "expected_backtracking_policy": BACKTRACKING_POLICY,
                "expected_backtracking_preparation_sha256": validate_backtracking_policy(artifact["metadata"])}

    def request(self, rows=None, rate=.003, bound=.05):
        def convert(rows):
            return [RP.RuntimeTrainingExample(text=r.text, target=RP.RuntimeClassification(packed=r.target.pack()),
                                              has_target=r.target is not None, weight=r.weight) for r in rows]
        return RP.ComputeSemanticGradientsRequest(request_id="bs01", model_id=self.artifact["model_id"],
            examples=convert(rows or self.rows), heldout_examples=convert(self.heldout), learning_rate=rate,
            max_gradient=bound, layers=[RP.DETECTION_LAYER_SEMANTIC])

    def call(self, artifact, *, request=None, head=False, headers=None):
        wrapper = StreamedTransformerPrivacyModel(snapshot(artifact))
        before = {n: p.copy() for n, p in wrapper.model.parameters.items()}
        request = request or self.request()
        self.assertEqual(list(request.layers), [RP.DETECTION_LAYER_SEMANTIC])
        if headers is None and BACKTRACKING_KEY in artifact["metadata"] and not head:
            headers = training_admission_metadata(self.expectations(artifact))
        with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=wrapper):
            method = self.server.ComputeSemanticGradients if head else self.server.ComputeUnderlyingModelGradients
            response = method(request, AdmissionContext(headers or ()))
        for n, p in before.items(): np.testing.assert_array_equal(wrapper.model.parameters[n], p)
        if response.error == BACKTRACKING_REJECTION:
            self.assertEqual([(e.phase, e.examples) for e in response.executions], [("training", len(request.examples))])
        elif not response.error:
            self.assertEqual([(e.phase, e.examples) for e in response.executions], [("training", len(request.examples)), ("base_heldout", 2), ("candidate_heldout", 2)])
        for e in response.executions:
            self.assertEqual((e.layer, e.status, e.error), (RP.DETECTION_LAYER_SEMANTIC, "ok", ""))
        return response, wrapper

    def test_real_gradient_both_objectives_selected_delta_diagnostics_and_updater_transport(self):
        from src.LLM.privoke.supervised_training import supervised_last_block_deltas
        for objective in (LEGACY_OBJECTIVE, CLASS_BALANCED_OBJECTIVE):
            artifact = self.prepared(objective)
            with patch("src.LLM.privoke.supervised_training.supervised_last_block_deltas", wraps=supervised_last_block_deltas) as gradient:
                response, wrapper = self.call(artifact)
            self.assertFalse(response.error, response.error)
            self.assertEqual(gradient.call_count, 1)
            delta = {p.name: tuple(p.values) for p in response.gradients}
            candidate = {n: tuple(float32(v) for v in updated_parameter_values(values, delta[n])) for n, values in wrapper.snapshot.parameters.items()}
            self.assertEqual(parameter_fingerprint(candidate), response.metadata["updated_parameter_fingerprint"])
            applied = apply_parameter_update(artifact, base_version=artifact["version"], deltas=delta, source_id="bs01-test")
            self.assertEqual(parameter_fingerprint({n: tuple(float32(v) for v in t["values"]) for n, t in applied["parameters"].items()}), response.metadata["updated_parameter_fingerprint"])
            header, trials = validate_backtracking_trace(response.metadata, examples=2, requested_rate=.003)
            self.assertGreater(header["base"][1][-1] - trials[-1][1][-1], BACKTRACKING_DECREASE)
            self.assertEqual(response.metrics["backtracking_semantic_examples"], 2 * len(trials))
            self.assertEqual(json.loads(response.metadata[DIAGNOSTICS_KEY])["loss"], [header["base"][1], trials[-1][1]])

    def test_original_raw_direction_before_clipping_first_stop_and_five_rejection(self):
        artifact = self.prepared()
        # One encoder direction makes a visible FULL change, while a huge head direction clips at early rates.
        raw = {n: tuple(0. for _ in t["values"]) for n, t in artifact["parameters"].items()}
        raw["token_embedding"] = (1.,) + raw["token_embedding"][1:]
        raw["head.sensitivity.bias"] = (100.,) + raw["head.sensitivity.bias"][1:]
        for wanted, losses in ((0, [3., 2.]), (2, [3., 4., 4., 2.]), (None, [3.] * 6)):
            seen = []
            state_losses = {}
            def score(model, examples, objective, **kwargs):
                seen.append(float(model.parameters["head.sensitivity.bias"].flat[0]))
                state = float(model.parameters["token_embedding"].flat[0])
                if state not in state_losses:
                    state_losses[state] = losses[min(len(state_losses), len(losses)-1)]
                value = state_losses[state]
                return [value, 0., 0., value]
            with patch("src.LLM.privoke.supervised_training.supervised_last_block_deltas", return_value=(raw, 3.)) as gradient, \
                 patch("src.LLM.privoke.training._local_training_losses", side_effect=score):
                response, wrapper = self.call(artifact, request=self.request(rate=.03))
            self.assertEqual(gradient.call_count, 1)
            header, trials = validate_backtracking_trace(response.metadata, examples=2, requested_rate=.03, rejected=wanted is None)
            self.assertEqual(header["selected"], wanted)
            self.assertEqual(len(trials), 5 if wanted is None else wanted+1)
            # Both early head deltas remain capped: rescaling the first clipped delta would fail this assertion.
            if len(trials) > 1:
                self.assertEqual(seen[1], seen[2])
                self.assertGreater(trials[0][2], 0)
                self.assertGreater(trials[1][2], 0)
            if wanted is not None:
                delta = {p.name:tuple(p.values) for p in response.gradients}
                candidate = {n:tuple(float32(v) for v in updated_parameter_values(values,delta[n])) for n,values in wrapper.snapshot.parameters.items()}
                self.assertEqual(parameter_fingerprint(candidate),trials[-1][6])
                self.assertEqual(parameter_fingerprint(delta,wrapper.snapshot.shapes),trials[-1][5])
                self.assertEqual(float(response.metadata["effective_learning_rate"]),.03*BACKTRACKING_SCALES[wanted])
            if wanted is None:
                self.assertEqual(response.error, BACKTRACKING_REJECTION)
                self.assertFalse(response.gradients)
                self.assertEqual(response.metrics["gradient_fits"], 1)
                self.assertNotIn(DIAGNOSTICS_KEY, response.metadata)

    def test_strict_decrease_threshold_exact_below_and_above(self):
        artifact=self.prepared()
        raw={n:tuple(0. for _ in t["values"]) for n,t in artifact["parameters"].items()}
        raw["token_embedding"]=(1.,)+raw["token_embedding"][1:]
        cases=(("below",math.nextafter(BACKTRACKING_DECREASE,0.),False),("exact",BACKTRACKING_DECREASE,False),("above",math.nextafter(BACKTRACKING_DECREASE,math.inf),True))
        for label,baseline,selected in cases:
            base_state=[]
            def loss(model,examples,objective,**kwargs):
                state=float(model.parameters["token_embedding"].flat[0])
                if not base_state:base_state.append(state)
                value=baseline if state==base_state[0] else 0.
                return [value,0.,0.,value]
            with self.subTest(boundary=label),patch("src.LLM.privoke.supervised_training.supervised_last_block_deltas",return_value=(raw,baseline)) as gradient,patch("src.LLM.privoke.training._local_training_losses",side_effect=loss):
                response,_=self.call(artifact)
            self.assertEqual(gradient.call_count,1)
            header,trials=validate_backtracking_trace(response.metadata,examples=2,requested_rate=.003,rejected=not selected)
            self.assertEqual(header["base"][1],[baseline,0.,0.,baseline])
            self.assertTrue(all(row[1]==[0.,0.,0.,0.] and row[9] for row in trials))
            self.assertEqual(len(trials),1 if selected else 5)
            self.assertEqual(header["selected"],0 if selected else None)
            self.assertEqual(response.error,"" if selected else BACKTRACKING_REJECTION)
        print(json.dumps({"witness":"strict_decrease_threshold","threshold":BACKTRACKING_DECREASE,"below":cases[0][1],"exact":cases[1][1],"above":cases[2][1],"new_real_backward_calls":0}))

    def test_improving_head_only_direction_zero_encoder_rejects_all_trials_and_client(self):
        from privoke_model.artifact import artifact_checksum
        from runtime_client import PrivokeRuntimeClient,TrainingStepRejected
        from training.types import BatchTrainingExample
        artifact=self.prepared()
        # Fixed point of actual round8/float32 transport: zero encoder deltas cannot move it by rounding alone.
        for tensor in artifact["parameters"].values():
            tensor["values"]=[float32(round(float32(v),8)) for v in tensor["values"]]
            self.assertEqual(tensor["values"],[float32(v) for v in updated_parameter_values(tensor["values"],[0.]*len(tensor["values"]))])
        artifact["checksum"]=artifact_checksum({k:v for k,v in artifact.items() if k!="checksum"})
        raw={n:tuple(0. for _ in t["values"]) for n,t in artifact["parameters"].items()}
        raw["head.sensitivity.bias"]=(1.,)+raw["head.sensitivity.bias"][1:]
        base_state=[]
        def loss(model,examples,objective,**kwargs):
            state=float(model.parameters["head.sensitivity.bias"].flat[0])
            if not base_state:base_state.append(state)
            value=3. if state==base_state[0] else 2.
            return [value,0.,0.,value]
        with patch("src.LLM.privoke.supervised_training.supervised_last_block_deltas",return_value=(raw,3.)) as gradient,patch("src.LLM.privoke.training._local_training_losses",side_effect=loss):
            response,_=self.call(artifact)
        self.assertEqual(gradient.call_count,1)
        header,trials=validate_backtracking_trace(response.metadata,examples=2,requested_rate=.003,rejected=True)
        self.assertEqual(len(trials),5);self.assertIsNone(header["selected"])
        self.assertTrue(all(row[1][-1]==2. and not row[9] for row in trials))
        self.assertEqual(response.error,BACKTRACKING_REJECTION);self.assertFalse(response.gradients)
        self.assertEqual([(e.phase,e.examples) for e in response.executions],[("training",2)])
        self.assertEqual(response.metrics["gradient_fits"],1)
        expected=self.expectations(artifact)
        with tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,{"PRIVOKE_FUZZER_DUMP_DIR":directory}),patch("runtime_client.grpc.insecure_channel"),patch("runtime_client.runtime_pb2_grpc.PrivokeRuntimeServiceStub") as stub,patch("training.parameter_updates.emit_parameter_update") as submit:
            stub.return_value.ComputeUnderlyingModelGradients.return_value=response
            with self.assertRaises(TrainingStepRejected):
                PrivokeRuntimeClient("unused").compute_underlying_gradients([BatchTrainingExample(r.text,r.target,r.weight) for r in self.rows],heldout_examples=[BatchTrainingExample(r.text,r.target,r.weight) for r in self.heldout],model_id=artifact["model_id"],learning_rate=.003,max_gradient=.05,request_id="bs01",**expected)
            submit.assert_not_called()
        print(json.dumps({"witness":"zero_encoder_improving_loss_rejection","trials":5,"gradient_calls":1,"real_backward_calls":0,"guard_executions":0,"submitted_updates":0}))

    def test_failed_numeric_forward_counts_attempts_and_structural_error_propagates(self):
        from src.model import TinyTransformerModel
        from privoke_model.artifact import ModelArtifactError
        artifact=self.prepared()
        raw={n:tuple(.001 for _ in t["values"]) for n,t in artifact["parameters"].items()}
        original=TinyTransformerModel.predict_many
        calls=[]
        def fail_after_base(model,texts):
            calls.append(len(texts))
            if len(calls)>1: raise FloatingPointError("synthetic failed forward")
            return original(model,texts)
        with patch("src.LLM.privoke.supervised_training.supervised_last_block_deltas",return_value=(raw,3.)) as gradient, patch.object(TinyTransformerModel,"predict_many",new=fail_after_base):
            response,_=self.call(artifact)
        self.assertEqual(gradient.call_count,1)
        self.assertEqual(response.error,BACKTRACKING_REJECTION)
        self.assertEqual(response.metrics["backtracking_semantic_examples"],0)
        self.assertEqual(response.metrics["backtracking_forward_attempts"],5)
        self.assertEqual(response.metrics["backtracking_attempted_semantic_examples"],10)
        trials=json.loads(response.metadata[BACKTRACKING_TRIALS_KEY])
        self.assertEqual([(r[7],r[8],r[10]) for r in trials],[("invalid_numeric",0,2)]*5)
        self.assertEqual(calls,[2]*6)
        with patch("src.LLM.privoke.supervised_training.supervised_last_block_deltas",return_value=(raw,3.)) as gradient, patch("src.LLM.privoke.training._transport_local_parameters",side_effect=ModelArtifactError("Parameter and delta lengths must match.")):
            response,_=self.call(artifact)
        self.assertEqual(gradient.call_count,1)
        self.assertIn("Parameter and delta lengths must match.",response.error)
        self.assertNotEqual(response.error,BACKTRACKING_REJECTION)

    def test_semantic_checked_passive_on_off_identity_and_independent_losses_matrix(self):
        from src.model import TinyTransformerModel
        from src.LLM.privoke.training import _class_balanced_examples
        from src.classification import initialise_unpacked,Sensitivity,Visibility,Category
        original=TinyTransformerModel.predict_many
        comparisons=0
        for objective in (LEGACY_OBJECTIVE,CLASS_BALANCED_OBJECTIVE):
            for head in (True,False):
                for bound in (.05,.000001):
                    off=prepare_training_policy_artifact(self.artifact,objective=objective)
                    on=prepare_training_policy_artifact(self.artifact,objective=objective,diagnostics=TRAIN_DIAGNOSTICS_POLICY)
                    plain,_=self.call(off,head=head,request=self.request(bound=bound))
                    captured=[]
                    def capture(model,texts):
                        result=original(model,texts);captured.append((model,result));return result
                    with patch.object(TinyTransformerModel,"predict_many",new=capture):
                        actual,_=self.call(on,head=head,request=self.request(bound=bound))
                    self.assertFalse(plain.error or actual.error)
                    self.assertEqual(plain.gradients,actual.gradients)
                    self.assertEqual(plain.metrics,actual.metrics)
                    self.assertEqual(plain.executions,actual.executions)
                    self.assertEqual(plain.metadata["updated_parameter_fingerprint"],actual.metadata["updated_parameter_fingerprint"])
                    record=json.loads(actual.metadata[DIAGNOSTICS_KEY]);self.assertEqual(record["counts"],[2,1,1])
                    if bound==.000001:self.assertGreater(record["update"][1],0)
                    model,predictions=captured[-1] # already executed inside the checked semantic request; no auxiliary model calls
                    rows=self.rows if objective==LEGACY_OBJECTIVE else _class_balanced_examples(self.rows)[0]
                    total=math.fsum(r.weight for r in rows);expected=[0.,0.,0.];hits=[0]*6
                    for row,prediction in zip(rows,predictions):
                        for index,task in enumerate(("sensitivity","visibility","category")):
                            logits=np.asarray(prediction.pooled,dtype=np.float32)@model.parameters[f"head.{task}.weight"]+model.parameters[f"head.{task}.bias"]
                            if task=="category":
                                targets={c.name for c in row.target.categories()}
                                loss=math.fsum(max(float(v),0)-float(v)*float(label in targets)+math.log1p(math.exp(-abs(float(v)))) for v,label in zip(logits,model.config.category_labels))
                            else:
                                index_target=getattr(model.config,task+"_labels").index(getattr(row.target,task)().name)
                                maximum=float(max(logits));loss=maximum+math.log(math.fsum(math.exp(float(v)-maximum) for v in logits))-float(logits[index_target])
                            expected[index]+=loss*row.weight/total
                        predicted=initialise_unpacked(Sensitivity[prediction.sensitivity],Visibility[prediction.visibility],[Category[c] for c in prediction.categories])
                        hits[0]+=row.target.pack()==predicted.pack();hits[1]+=row.target.sensitivity()==predicted.sensitivity();hits[2]+=row.target.visibility()==predicted.visibility();hits[3]+=set(row.target.categories())==set(predicted.categories());hits[4]+=not row.target.is_sensitive() and not predicted.is_sensitive();hits[5]+=row.target.is_sensitive() and predicted.is_sensitive()
                    np.testing.assert_allclose(record["loss"][1][:3],expected,atol=1e-6,rtol=1e-6)
                    self.assertEqual(record["accuracy"][1],[h/d for h,d in zip(hits,[2,2,2,2,1,1])])
                    comparisons+=1
        self.assertEqual(comparisons,8)
        print(json.dumps({"witness":"checked_passive_identity","comparisons":8,"requests":16,"independent_candidate_loss_decisions":8,"auxiliary_model_forwards":0}))

    def test_actual_taxonomy_selected_head_full_wire_and_exact_selected_transport(self):
        from test_taxonomy_coverage import fixture as taxonomy_fixture
        from prompt_generation import taxonomy_coverage as taxonomy
        from training.trainer import train_parameter_batch
        from training.types import BatchTrainingConfig
        from training.evidence import persist_cycle_evidence
        from training.parameter_updates import emit_training_update
        from privoke.v1 import parameters_pb2
        dataset = taxonomy.load_snapshot(taxonomy.canonical_bytes(taxonomy_fixture()))
        originals, guard = taxonomy.generate_partition(dataset, 42)
        prepared = self.prepared(CLASS_BALANCED_OBJECTIVE)
        wrapper = StreamedTransformerPrivacyModel(snapshot(prepared))
        for scope in ("heads", "full_encoder"):
            with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"PRIVOKE_FUZZER_DUMP_DIR": directory}), patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=wrapper), patch("runtime_client.grpc.insecure_channel"), patch("runtime_client.runtime_pb2_grpc.PrivokeRuntimeServiceStub") as stub:
                rpc = stub.return_value.ComputeUnderlyingModelGradients if scope == "full_encoder" else stub.return_value.ComputeSemanticGradients
                def local(request, timeout, metadata=()):
                    self.assertEqual(list(request.layers), [RP.DETECTION_LAYER_SEMANTIC])
                    return (self.server.ComputeUnderlyingModelGradients(request, AdmissionContext(metadata)) if scope == "full_encoder" else self.server.ComputeSemanticGradients(request, AdmissionContext(metadata)))
                rpc.side_effect = local
                extra_policy = {"expected_backtracking_policy": BACKTRACKING_POLICY,"expected_backtracking_preparation_sha256":validate_backtracking_policy(prepared["metadata"])} if scope == "full_encoder" else {}
                update = train_parameter_batch(prepared["model_id"], originals, heldout_examples=guard, taxonomy_dataset=dataset,
                    config=BatchTrainingConfig(seed=42,learning_rate=.003), training_scope=scope, request_id="wire",
                    expected_objective=CLASS_BALANCED_OBJECTIVE, expected_diagnostics_policy=TRAIN_DIAGNOSTICS_POLICY, **extra_policy)
                self.assertEqual(update.metrics["examples"],64)
                self.assertEqual([e["examples"] for e in update.execution_evidence["executions"]],[64,16,16])
                candidate={n:tuple(float32(v) for v in updated_parameter_values(values,update.gradients[n])) if n in update.gradients else tuple(float32(v) for v in values) for n,values in wrapper.snapshot.parameters.items()}
                self.assertEqual(parameter_fingerprint(candidate),update.metadata["updated_parameter_fingerprint"])
                self.assertEqual(json.loads(json.dumps(update.execution_evidence)),update.execution_evidence)
                request=parameters_pb2.FuzzerTrainingRequest(source_id="bs01",request_id="wire")
                extra={"request_source_id":"bs01","request_id":"wire","training_request_fingerprint":"d"*64,"requested_prompt_count":"32","generated_prompt_count":"32","training_pipeline":"semantic"}
                union={**update.metadata,**{k:str(v) for k,v in update.metrics.items()},**extra}
                persist_cycle_evidence(request,update,scope,gate_passed=True)
                with patch("privoke.v1.parameters_pb2_grpc.ParamUpdateServiceStub") as updater:
                    emit_training_update("unused","fixture",update,extra)
                wire=updater.return_value.SubmitParameterUpdate.call_args.args[0]
                self.assertLessEqual(len(wire.metadata),64)
                self.assertTrue(all(len(v.encode())<=2048 for v in wire.metadata.values()))
                from privoke_model.fingerprint import parameter_fingerprint as fp
                self.assertEqual(fp({p.name:tuple(p.values) for p in wire.gradients}, {p.name:tuple(p.shape) for p in wire.gradients}),fp(update.gradients,update.parameter_shapes))
                print(json.dumps({"witness":"bs01_actual_taxonomy_publication","scope":scope,"train":64,"guard":16,"unprojected_entries":len(union),"published_entries":len(wire.metadata),"max_value_bytes":max(len(v.encode()) for v in wire.metadata.values()),"selected_rate":update.metadata.get("effective_learning_rate"),"trials":update.metrics.get("backtracking_trials")}))

    def test_pregradient_admission_misuse_and_dormant_head_compatibility(self):
        artifact = self.prepared()
        headers = training_admission_metadata(self.expectations(artifact))
        changed = json.loads(headers[0][1]); changed["expected_backtracking_preparation_sha256"] = "b"*64
        for head, supplied in ((False, ()), (False, ((BACKTRACKING_HEADER, json.dumps(changed)),)),
                               (False, (headers[0], headers[0])), (True, headers)):
            with patch("src.LLM.privoke.supervised_training.supervised_last_block_deltas") as gradient:
                response, _ = self.call(artifact, head=head, headers=supplied)
            self.assertTrue(response.error)
            gradient.assert_not_called()
        legacy = prepare_training_policy_artifact(self.artifact, diagnostics=TRAIN_DIAGNOSTICS_POLICY)
        plain, _ = self.call(legacy, head=True)
        dormant, _ = self.call(artifact, head=True)
        self.assertFalse(plain.error or dormant.error)
        self.assertEqual(plain.gradients, dormant.gradients)
        self.assertEqual(plain.metrics, dormant.metrics)
        self.assertEqual(plain.executions, dormant.executions)
        self.assertEqual(plain.metadata["updated_parameter_fingerprint"], dormant.metadata["updated_parameter_fingerprint"])
        self.assertNotIn(BACKTRACKING_TRACE_KEY, dormant.metadata)
        off, on = snapshot(legacy), snapshot(artifact)
        self.assertNotEqual(off.cache_key, on.cache_key)
        self.assertIsNot(GLOBAL_STREAMED_MODEL_CACHE._model_for_snapshot(off), GLOBAL_STREAMED_MODEL_CACHE._model_for_snapshot(on))

    def test_pregradient_target_strata_and_unsupported_policies(self):
        artifact = self.prepared()
        request = self.request(); request.examples[0].has_target = False
        for req in (request, self.request(rows=(self.rows[0],))):
            with patch("src.LLM.privoke.supervised_training.supervised_last_block_deltas") as gradient:
                response, _ = self.call(artifact, request=req)
            self.assertTrue(response.error)
            gradient.assert_not_called()
        for key, value in ((BACKTRACKING_KEY, "unknown"), (OPTIMIZER_KEY, LOCAL_SGD_1),
                           (DIAGNOSTICS_POLICY_KEY, "off"), (OBJECTIVE_KEY, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE)):
            changed = copy.deepcopy(artifact); changed["metadata"][key] = value
            with self.assertRaises(ValueError): validate_backtracking_policy(changed["metadata"])


if __name__ == "__main__": unittest.main()
