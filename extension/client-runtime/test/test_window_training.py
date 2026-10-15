"""Synthetic mechanics: genuine64-step gradients; controlled checkpoint outputs for winner/transport integration."""
import copy
from contextlib import contextmanager
from dataclasses import replace
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch,MagicMock

import numpy as np
import torch

from privoke_model import window_training as w,sensitive_retention as legacy
from privoke_model.artifact import artifact_checksum,load_artifact
from privoke_model.contextual_training import (FULL_ENCODER_STRATEGY,prepare_training_policy_artifact,
    CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE,training_admission_metadata,parse_training_admission_metadata)
from privoke_contracts.classification import Classification,initialise_unpacked,Sensitivity,Visibility,Category
from src.LLM.privoke import window_training as runtime
from src.LLM.privoke.training import SemanticTrainingExample,compute_underlying_model_gradients,_class_balanced_examples
from src.LLM.privoke.supervised_training import supervised_last_block_deltas
from src.LLM.privoke.streamed_model import StreamedTransformerPrivacyModel,GLOBAL_STREAMED_MODEL_CACHE
from test_task_query_readout import fixture,model
from test_training_adaptation import snapshot
from privoke.v1 import runtime_pb2

ROOT=Path(__file__).resolve().parents[3]


@contextmanager
def scoped_fuzzer_imports():
    """Exercise cross-component fixtures without ambient paths or leaked generic modules."""
    source=ROOT/"services/privoke-fuzzer/src"
    roots={path.stem for path in source.glob("*.py")} | {
        path.name for path in source.iterdir() if path.is_dir() and (path/"__init__.py").exists()}
    def belongs(name):return name.partition(".")[0] in roots
    saved={name:module for name,module in tuple(sys.modules.items()) if belongs(name)}
    original_path=list(sys.path)
    for name in saved:sys.modules.pop(name,None)
    sys.path.insert(0,str(source))
    try:
        yield
    finally:
        sys.path[:]=original_path
        for name in tuple(sys.modules):
            if belongs(name):sys.modules.pop(name,None)
        sys.modules.update(saved)


def target(s=Sensitivity.S3,v=Visibility.P3,c=(Category.HEALTH,)):
    return initialise_unpacked(s,v,c).pack()


def synthetic_inputs(directory):
    _,teacher=fixture(FULL_ENCODER_STRATEGY)
    teacher["model_id"]="privoke-balanced"
    teacher["checksum"]=artifact_checksum({k:v for k,v in teacher.items() if k!="checksum"})
    teacher=prepare_training_policy_artifact(teacher,objective=CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE,diagnostics=None)
    path=Path(directory)/"teacher.json";path.write_bytes(w.canonical_bytes(teacher))
    teacher_sha=w.sha256(path.read_bytes())
    identity=w.teacher_identity(path,"balanced",teacher_sha)
    bank=[]
    for group in range(20):
        for row in range(10):
            bank.append({"id":f"g{group:02d}/{row:02d}","text":f"manufactured original private marker group {group} row {row}",
                "packed_classification":target(),"metadata":{"split":"train","taxonomy_partition":"train","group_id":f"g{group:02d}"}})
    bank_payload=w.canonical_bytes(bank)
    config=teacher["config"]
    logits={"sensitivity":[-2.,-2.,-2.,2.],"visibility":[-2.]*6,"category":[-2.]*10}
    logits["visibility"][config["visibility_labels"].index("P3")]=2.
    logits["category"][config["category_labels"].index("HEALTH")]=2.
    clean_logits={"sensitivity":[2.,-2.,-2.,-2.],"visibility":[2.,-2.,-2.,-2.,-2.,-2.],"category":[-2.]*10}
    rows=[]
    for source in bank:
        current=logits if source["id"].endswith("/00") else clean_logits
        packed,confidence=w.decoded_logits(current,config)
        rows.append({"id":source["id"],"gold":source["packed_classification"],"original":packed,"confidence":confidence,
            "logits":current,"components":w.component_specs(source["packed_classification"],packed,current,config)})
    references=w.canonical_bytes({"schema":2,"teacher":identity,"bank_sha256":w.sha256(bank_payload),"rows":rows})
    manifest=w.canonical_bytes({"schema":2,"kind":"original_train_component_retention_v2","teacher":identity,
        "bank_sha256":w.sha256(bank_payload),"references_sha256":w.sha256(references),"epsilon":w.EPSILON,"margin_cap":1.,
        "normalization":w.CONFIG["normalization"],"coefficient":1,"fit_release":False})
    release=w.ComponentRelease(bank_payload,references,manifest,str(path),teacher_sha)
    blocks=[]
    for block in range(8):
        block_rows=[]
        for index in range(64):
            sensitivity=Sensitivity.S0 if index%2==0 else Sensitivity.S3
            packed=target(sensitivity,Visibility.P0 if index%2==0 else Visibility.P3,() if index%2==0 else (Category.FINANCIAL,))
            block_rows.append({"text":f"manufactured {'public general' if index%2==0 else 'private financial'} marker block {block} row {index}",
                "packed":packed,"weight":1.,"id":f"b{block}/{index}","group":f"g{index%20:02d}","partition":"train","family_kind":"taxonomy"})
        blocks.append({"seed":block,"rows":block_rows})
    guard=[{"text":f"manufactured distinct guard {i}","packed":target(Sensitivity.S0,Visibility.P0,()) if i%2==0 else target(),
        "weight":1.,"id":f"guard{i}","group":f"guard{i}","partition":"guard","family_kind":"taxonomy"} for i in range(16)]
    window={"schema":1,"sampler":w.SAMPLER,"seed":42,"config":w.CONFIG,"sources":{k:"a"*64 for k in ("taxonomy","benign","pool","proof")},
        "blocks":blocks,"guard":guard,"provenance":{"wire_rows":512,"unique_source_ids":512,"unique_texts":512,
            "taxonomy_families":20,"repeated_source_presentations":0,"fit_release":False}}
    w.validate_window(window)
    artifact=w.prepare_artifact(teacher,w.sha256(w.canonical_bytes(window)),release.sha256)
    def convert(row):return SemanticTrainingExample(row["text"],Classification(row["packed"]),row["weight"])
    examples=tuple(map(convert,w.flat_rows(window)));heldout=tuple(map(convert,guard))
    admission=w.expectations({"expected_contextual_training_optimizer":w.POLICY,"expected_contextual_training_objective":w.OBJECTIVE,
        "expected_contextual_candidate_eligibility":w.ELIGIBILITY,"expected_contextual_training_scope":"full_encoder",
        "expected_"+w.CONFIG_KEY:w.canonical(w.CONFIG),"expected_"+w.WINDOW_KEY:artifact["metadata"][w.WINDOW_KEY],
        "expected_"+w.REFERENCE_KEY:release.sha256})
    return bank_payload,window,release,artifact,examples,heldout,admission


class WindowRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        torch.set_num_threads(1)
        cls.enterClassContext(scoped_fuzzer_imports())

    def test_component_surrogates_finite_difference_and_negative_bits(self):
        config={"sensitivity_labels":["S0","S1","S2","S3"],"visibility_labels":["P0","P1","P2","P3","P4","PU"],
            "category_labels":[c.name for c in Category],"category_threshold":.5}
        original={"sensitivity":[-2.,-1.,0.,3.],"visibility":[-2.,-1.,0.,3.,-3.,-4.],"category":[3.]+[-3.]*9}
        specs=w.component_specs(target(),target(),original,config)
        self.assertEqual(set(specs),{"sensitivity","severity","category","visibility"})
        self.assertTrue(all(entry["target"]==1. for entries in specs.values() for entry in entries))
        current={"sensitivity":[.4,-.2,-.3,.1],"visibility":[.4,-.2,-.3,.1,-.5,-.6],"category":[.2]+[-.2]*9}
        for component,entries in specs.items():
            tensors={k:torch.tensor(v,dtype=torch.float64,requires_grad=True) for k,v in current.items()}
            loss=runtime.component_hinge(tensors,{component:entries},torch);loss.backward()
            self.assertGreater(float(loss.detach()),0.)
            task=entries[0]["task"]
            for index in range(len(current[task])):
                numeric=[]
                for sign in (-1,1):
                    value=copy.deepcopy(current);value[task][index]+=sign*1e-5
                    numeric.append(float(runtime.component_hinge({k:torch.tensor(v,dtype=torch.float64) for k,v in value.items()},
                        {component:entries},torch)))
                self.assertAlmostEqual((numeric[1]-numeric[0])/2e-5,float(tensors[task].grad[index]),places=6)
        self.assertEqual(w.component_specs(target(),target(Sensitivity.S0,c=()),original,config),{})

    def test_unequal_block_mass_estimator_matches_entire_frozen_objective(self):
        _,artifact=fixture(FULL_ENCODER_STRATEGY)
        m=model(artifact)
        examples=[]
        for block in range(8):
            for index in range(2):
                examples.append(SemanticTrainingExample(f"synthetic marker {block} {index}",
                    Classification(target(Sensitivity.S0,c=()) if index==0 else target()),float(block+1)*(1 if index==0 else 3)))
        adjusted,_=_class_balanced_examples(examples)
        total=sum(e.weight for e in adjusted)
        whole,loss=supervised_last_block_deltas(m,adjusted,set(m.parameters),objective=w.OBJECTIVE)
        directions=[];losses=[]
        for block in range(8):
            d,l=supervised_last_block_deltas(m,adjusted[block*2:block*2+2],set(m.parameters),objective=w.OBJECTIVE,
                normalization_denominator=total/8)
            directions.append(d);losses.append(l)
        self.assertAlmostEqual(sum(losses)/8,loss,places=6)
        for name in whole:np.testing.assert_allclose(np.mean([d[name] for d in directions],axis=0),whole[name],atol=2e-7,rtol=2e-5)

    def test_exact_action_parity_with_production_policy(self):
        from src.classification import ClassificationResult
        for severity in Sensitivity:
            for visibility in Visibility:
                for categories in ((),(Category.HEALTH,),(Category.IDENTITY,),(Category.LOCATION,Category.IDENTITY)):
                    packed=target(severity,visibility,categories)
                    for confidence in (None,.1,.499,.5,.999):
                        self.assertEqual(w.action_value(packed,confidence),ClassificationResult(Classification(packed),"","",confidence=confidence).action().value)

    def test_packed_exact_floor_is_separate_from_rounded_confidence_action(self):
        packed=target()
        checkpoint={"predictions":[[packed,.1]]}
        self.assertEqual(w.packed_exact_rate([{"packed":packed}],checkpoint),1.)
        counts=w.checkpoint_counts([packed],checkpoint["predictions"])
        self.assertEqual(counts["sensitive_action"],0)
        self.assertEqual(counts["all_joint"],0)

    def test_service_terminal_replay_and_strict_train_floor_skip_physical_refit(self):
        from config import FuzzerConfig
        from training.types import BatchTrainingUpdate
        from training import window_cycle,window_evidence
        from privoke.v1 import parameters_pb2 as pb
        for status,exact,minimum in (("no_update",0.,0.),("selected",1.,1.),("selected",0.,0.),("selected",1.,0.)):
            with self.subTest(status=status,exact=exact,minimum=minimum),tempfile.TemporaryDirectory() as directory:
                _,window,release,artifact,_,_,_=synthetic_inputs(directory)
                config=FuzzerConfig(param_update_target="unused",privoke_runtime_target="unused",model_id=artifact["model_id"],
                    presence_model_id="unused",fuzzer_id="synthetic",port=50053,timeout_seconds=10,seed=42,max_prompt_count=256,
                    max_concurrent_cycles=1,prompt_dataset_path=None,presence_dataset_path=None,training_learning_rate=.003,
                    training_max_gradient=.05,training_transformations_per_example=1,minimum_exact_match_rate=minimum,
                    heldout_prompt_count=16,window_manifest_sha256=w.sha256(w.canonical_bytes(window)),
                    component_manifest_sha256=release.sha256,component_teacher_sha256=release.teacher_sha256)
                metadata={"contextual_sampling_strategy":w.SAMPLER,"expected_contextual_training_optimizer":w.POLICY,
                    "expected_contextual_training_objective":w.OBJECTIVE,"expected_contextual_candidate_eligibility":w.ELIGIBILITY,
                    "expected_contextual_training_scope":"full_encoder","expected_"+w.CONFIG_KEY:w.canonical(w.CONFIG),
                    "expected_"+w.WINDOW_KEY:config.window_manifest_sha256,"expected_"+w.REFERENCE_KEY:release.sha256}
                request=pb.FuzzerTrainingRequest(source_id="synthetic",request_id="replay",model_id=artifact["model_id"],seed=42,prompt_count=256,metadata=metadata)
                ack=SimpleNamespace(accepted=True,model_id=artifact["model_id"],applied_version="2",message="committed")
                committed=[]
                def previous(*args):return SimpleNamespace(found=bool(committed),ack=ack,base_version="1",prompts_generated=256)
                def submit(*args,**kwargs):committed.append(True);return ack
                service=SimpleNamespace(config=config,_previous_update_for_fingerprint=previous,_submit_update=submit)
                context=MagicMock();context.is_active.return_value=True
                context.abort.side_effect=lambda code,message: (_ for _ in ()).throw(ValueError(message))
                update=BatchTrainingUpdate(artifact["model_id"],"1",{}, {},{"candidate_train_exact_match_rate":exact},
                    {w.TRACE_KEY:"{}","base_parameter_fingerprint":"a"*64},{})
                with patch.dict(os.environ,{"PRIVOKE_FUZZER_DUMP_DIR":directory}),patch.object(w,"read_pinned",return_value=window),\
                    patch.object(w,"load_components",return_value=release),patch.object(window_cycle,"load_dataset"),\
                    patch.object(window_cycle.benign,"load_release"),patch.object(window_cycle.train_window,"validate_sources"),\
                    patch.object(window_cycle,"train_parameter_batch",return_value=update) as fit,\
                    patch.object(window_evidence,"validate_update",return_value={"status":status,"reason":"base_selected"}),\
                    patch.object(window_cycle,"persist_cycle_evidence"),patch("fuzzer_service.validate_training_update"):
                    first=window_cycle.run(service,request,context,training_scope="full_encoder")
                    second=window_cycle.run(service,request,context,training_scope="full_encoder")
                    self.assertEqual(fit.call_count,1);self.assertTrue(first.accepted and second.accepted)
                    self.assertEqual(second.metadata["replayed"],"true")
                    should_publish=status=="selected" and exact>minimum
                    self.assertEqual(bool(committed),should_publish)
                    self.assertEqual(second.applied_version,"2" if should_publish else "1")

    def test_unknown_window_rpc_reservation_rejects_second_physical_attempt(self):
        import grpc
        from training import window_evidence
        with tempfile.TemporaryDirectory() as directory:
            bank,window,release,artifact,_,_,admission=synthetic_inputs(directory)
            examples,guard=__import__("prompt_generation.train_window",fromlist=["examples"]).examples(window)
            client=SimpleNamespace(target="synthetic-unused",timeout_seconds=10)
            with patch.object(legacy,"BANK_SHA256",w.sha256(bank)),patch.dict(os.environ,{"PRIVOKE_FUZZER_DUMP_DIR":directory,
                "FUZZ_WINDOW_MANIFEST_SHA256":w.sha256(w.canonical_bytes(window)),"FUZZ_COMPONENT_MANIFEST_SHA256":release.sha256,
                "FUZZ_COMPONENT_TEACHER_SHA256":release.teacher_sha256}),patch.object(window_evidence.grpc,"insecure_channel"),\
                patch("privoke.v1.runtime_pb2_grpc.PrivokeRuntimeServiceStub") as stub:
                stub.return_value.ComputeUnderlyingModelGradients.side_effect=grpc.RpcError("synthetic unknown")
                arguments=dict(heldout_examples=guard,model_id=artifact["model_id"],request_id="unknown",window=window,
                    release=release,admission=admission,learning_rate=.003,max_gradient=.05)
                with self.assertRaises(grpc.RpcError):window_evidence.compute(client,examples,**arguments)
                with self.assertRaises(FileExistsError):window_evidence.compute(client,examples,**arguments)
                self.assertEqual(stub.return_value.ComputeUnderlyingModelGradients.call_count,1)
                attempts=list(Path(directory).glob("backtracking-attempts/*/attempts/*.json"))
                self.assertEqual(len(attempts),1)
                self.assertEqual(json.loads(attempts[0].read_text())["compute_status"],"transport_outcome_unknown")

    def test_early_auxiliary_failure_preserves_observed_partial_work(self):
        from src.LLM.privoke import supervised_training
        with tempfile.TemporaryDirectory() as directory:
            _,window,release,artifact,examples,guard,admission=synthetic_inputs(directory)
            wrapper=StreamedTransformerPrivacyModel(snapshot(artifact))
            original=supervised_training.supervised_last_block_deltas
            def fail_auxiliary(*args,**kwargs):
                if "retention_components" in kwargs:raise ValueError("synthetic auxiliary failure")
                return original(*args,**kwargs)
            with patch.object(runtime,"load_inputs",return_value=(window,release)),\
                patch.object(GLOBAL_STREAMED_MODEL_CACHE,"model_for_training",return_value=wrapper),\
                patch.object(supervised_training,"supervised_last_block_deltas",side_effect=fail_auxiliary),\
                patch.dict(os.environ,{"OMP_NUM_THREADS":"1","MKL_NUM_THREADS":"1"}):
                with self.assertRaisesRegex(ValueError,"synthetic auxiliary failure") as caught:
                    runtime.compute(examples,model_id=artifact["model_id"],learning_rate=.003,max_gradient=.05,
                        heldout_examples=guard,admission=admission)
            trace=json.loads(caught.exception.training_metadata[w.TRACE_KEY])
            self.assertTrue(trace["partial_counts_are_observed_lower_bounds"])
            self.assertEqual(trace["status"],"partial_error")
            self.assertEqual(trace["main"]["rows_completed"],64)
            self.assertEqual(trace["main"]["directions_completed"],1)
            self.assertEqual(trace["auxiliary"]["directions_attempted"],1)
            self.assertEqual(trace["auxiliary"]["directions_completed"],0)
            self.assertEqual(trace["steps"],[]);self.assertIsNone(trace["guard"])

    def test_runtime_independent_teacher_pin_and_complete_current_config(self):
        with tempfile.TemporaryDirectory() as directory:
            bank,window,release,artifact,examples,guard,admission=synthetic_inputs(directory)
            paths={"PRIVOKE_WINDOW_PATH":w.canonical_bytes(window),"PRIVOKE_COMPONENT_BANK_PATH":bank,
                "PRIVOKE_COMPONENT_REFERENCE_PATH":release.reference_payload,"PRIVOKE_COMPONENT_MANIFEST_PATH":release.manifest_payload}
            environment={"PRIVOKE_WINDOW_MANIFEST_SHA256":w.sha256(w.canonical_bytes(window)),
                "PRIVOKE_COMPONENT_MANIFEST_SHA256":release.sha256,"PRIVOKE_COMPONENT_TEACHER_SHA256":release.teacher_sha256,
                "PRIVOKE_COMPONENT_TEACHER_PATH":release.teacher_path,"OMP_NUM_THREADS":"1","MKL_NUM_THREADS":"1"}
            for name,data in paths.items():
                path=Path(directory)/name;path.write_bytes(data);environment[name]=str(path)
            wrapper=StreamedTransformerPrivacyModel(snapshot(artifact))
            with patch.object(legacy,"BANK_SHA256",w.sha256(bank)),patch.dict(os.environ,environment):
                original_open=Path.open
                teacher_reads=[]
                def one_teacher_read(path,*args,**kwargs):
                    if str(path)==release.teacher_path:
                        teacher_reads.append(path)
                        if len(teacher_reads)>1:raise AssertionError("Teacher must parse the same authenticated bounded read")
                    return original_open(path,*args,**kwargs)
                with patch.object(Path,"open",one_teacher_read):
                    self.assertEqual(w.teacher_identity(release.teacher_path,"balanced",release.teacher_sha256)["file_sha256"],release.teacher_sha256)
                self.assertEqual(len(teacher_reads),1)
                self.assertEqual(runtime.load_inputs(admission,artifact["model_id"])[1].sha256,release.sha256)
                with patch.dict(os.environ,{"PRIVOKE_COMPONENT_TEACHER_SHA256":"0"*64}):
                    with patch.object(GLOBAL_STREAMED_MODEL_CACHE,"model_for_training") as access:
                        with self.assertRaises(ValueError):runtime.compute(examples,model_id=artifact["model_id"],learning_rate=.003,
                            max_gradient=.05,heldout_examples=guard,admission=admission)
                        access.assert_not_called()
                wrapper.model.config=replace(wrapper.model.config,category_threshold=.6)
                with patch.object(GLOBAL_STREAMED_MODEL_CACHE,"model_for_training",return_value=wrapper):
                    with self.assertRaisesRegex(ValueError,"complete config/readout"):
                        runtime.compute(examples,model_id=artifact["model_id"],learning_rate=.003,max_gradient=.05,
                            heldout_examples=guard,admission=admission)

    def test_genuine_schema5_route_and_selected_step16_publication_roundtrip(self):
        self._run_route("selected")

    def test_base_tie_keeps_immutable_base_without_guard_execution(self):
        self._run_route("base")

    def test_selected_guard_failure_keeps_base_without_second_choice(self):
        self._run_route("guard_failed")

    def _run_route(self,mode):
        # Checkpoint outputs are controlled to isolate selection/transport from model quality.
        # All64 main+auxiliary directions and every evaluation execute the real CPU backend.
        with tempfile.TemporaryDirectory() as directory:
            bank,window,release,artifact,examples,guard,admission=synthetic_inputs(directory)
            wrapper=StreamedTransformerPrivacyModel(snapshot(artifact))
            original_score=runtime._score
            def score(*args,**kwargs):
                result=original_score(*args,**kwargs)
                step=result["step"]
                predictions=[[e.target.pack(),.9] for e in examples] if step==16 and mode!="base" else [[target(),.9] for _ in examples]
                result["predictions"]=predictions;result["counts"]=w.checkpoint_counts([e.target.pack() for e in examples],predictions)
                reference_rows=[r for _,r in release.rows if r["components"]]
                result["original_predictions"]=[[r["original"],r["confidence"]] for r in reference_rows]
                result["violations"]=0;result["component_violations"]={c:0 for c in w.COMPONENTS}
                return result
            original_guard=runtime._guard
            def guard_score(*args,**kwargs):
                result=original_guard(*args,**kwargs)
                result.update(before=[[e.target.pack(),.9] for e in guard],after=[[e.target.pack(),.9] for e in guard],
                    base_counts={"exact":16,"recall":8,"specificity":8},candidate_counts={"exact":16,"recall":8,"specificity":8},regression_rate=0.,passed=True)
                if mode=="guard_failed":
                    result.update(after=[[target(Sensitivity.S0,Visibility.P0,()),.9] for _ in guard],
                        candidate_counts={"exact":8,"recall":0,"specificity":8},regression_rate=.5,passed=False)
                return result
            with patch.object(legacy,"BANK_SHA256",w.sha256(bank)),patch.object(runtime,"load_inputs",return_value=(window,release)),\
                    patch.object(GLOBAL_STREAMED_MODEL_CACHE,"model_for_training",return_value=wrapper),\
                    patch.object(runtime,"_score",side_effect=score),patch.object(runtime,"_guard",side_effect=guard_score) as guarded,\
                    patch.dict(os.environ,{"OMP_NUM_THREADS":"1","MKL_NUM_THREADS":"1"}):
                w.validate_component_release(release,trusted_sha256=release.sha256)
                with self.assertRaises(ValueError):w.validate_component_release(replace(release,teacher_sha256="0"*64),trusted_sha256=release.sha256)
                batch=compute_underlying_model_gradients(examples,model_id=artifact["model_id"],learning_rate=.003,max_gradient=.05,
                    heldout_examples=guard,admission=parse_training_admission_metadata(training_admission_metadata(admission)))
                trace=w.validate_trace(batch.metadata,window=window,release=release,gradients=batch.gradients,shapes=batch.shapes)
                contradictory=copy.deepcopy(trace);contradictory["reason"]="guard_passed" if mode=="base" else "base_selected"
                contradictory_raw=w.canonical(contradictory)
                contradictory_metadata={**batch.metadata,w.TRACE_KEY:contradictory_raw,
                    w.SUMMARY_KEY:w.canonical(w.summary(contradictory,contradictory_raw))}
                with self.assertRaisesRegex(ValueError,"contradictory"):
                    w.validate_trace(contradictory_metadata,window=window,release=release,gradients=batch.gradients,shapes=batch.shapes)
                self.assertEqual(trace["selected_step"],0 if mode=="base" else 16);self.assertEqual(len(trace["steps"]),64)
                self.assertNotEqual(trace["selected"],trace["terminal"])
                self.assertEqual(trace["main"]["rows_completed"],4096);self.assertEqual(trace["auxiliary"]["rows_completed"],1280)
                self.assertEqual(guarded.call_count,0 if mode=="base" else 1)
                self.assertEqual(set(k for k in trace["work"]["phases"] if "heldout" in k),set() if mode=="base" else {"base_heldout","candidate_heldout"})
                if mode=="selected":
                    self._publication_roundtrip(directory,bank,window,release,artifact,examples,guard,admission,batch)
                else:
                    self.assertEqual(trace["status"],"no_update");self.assertEqual(batch.gradients,{})
                    self.assertEqual(trace["published"],trace["base"])
                    self.assertEqual(trace["reason"],"base_selected" if mode=="base" else "guard_failed")

    def _publication_roundtrip(self,directory,bank,window,release,artifact,examples,guard,admission,batch):
        from training.window_evidence import persist_inputs,retained_inputs,validate_update,validate_response
        from training.evidence import persist_backtracking_attempt,persist_cycle_evidence
        from training.parameter_updates import emit_training_update
        from training.types import BatchTrainingUpdate
        from privoke.v1 import parameters_pb2 as pb
        from privoke_model.fingerprint import parameter_fingerprint
        def wire(e):return runtime_pb2.RuntimeTrainingExample(text=e.text,has_target=True,weight=e.weight,target=runtime_pb2.RuntimeClassification(packed=e.target.pack()))
        request=runtime_pb2.ComputeSemanticGradientsRequest(request_id="synthetic-window",model_id=artifact["model_id"],layers=[4],
            examples=[wire(e) for e in examples],heldout_examples=[wire(e) for e in guard],learning_rate=.003,max_gradient=.05)
        response=runtime_pb2.ComputeSemanticGradientsResponse(request_id=request.request_id,model_id=batch.model_id,base_version=batch.base_version,
            gradients=[runtime_pb2.RuntimeParameterDelta(name=n,shape=batch.shapes[n],values=v) for n,v in batch.gradients.items()],
            metadata=batch.metadata,metrics=batch.metrics,executions=[runtime_pb2.SemanticTrainingExecution(phase=n,examples=c,layer=4,status="ok") for n,c in batch.executions])
        validate_response(request,response,admission,window,release)
        import base64
        header=training_admission_metadata(admission)
        with patch.dict(os.environ,{"PRIVOKE_FUZZER_DUMP_DIR":directory,"FUZZ_WINDOW_MANIFEST_SHA256":w.sha256(w.canonical_bytes(window)),
            "FUZZ_COMPONENT_MANIFEST_SHA256":release.sha256,"FUZZ_COMPONENT_TEACHER_SHA256":release.teacher_sha256}):
            attempt=persist_backtracking_attempt(request,response,scope="full_encoder",expectations=admission,invocation_metadata=header)
            evidence={"rpc":"ComputeUnderlyingModelGradients","request_layers":[4],"request_protobuf_base64":base64.b64encode(request.SerializeToString(deterministic=True)).decode(),
                "response_protobuf_base64":base64.b64encode(response.SerializeToString(deterministic=True)).decode(),"invocation_metadata":[list(p) for p in header],
                "physical_attempt":str(attempt),"window_inputs":persist_inputs(window,release,directory)}
            update=BatchTrainingUpdate(batch.model_id,batch.base_version,batch.gradients,{n:tuple(v) for n,v in batch.shapes.items()},batch.metrics,batch.metadata,evidence)
            validate_update(update)
            for pin in ("FUZZ_WINDOW_MANIFEST_SHA256","FUZZ_COMPONENT_MANIFEST_SHA256","FUZZ_COMPONENT_TEACHER_SHA256"):
                with patch.dict(os.environ,{pin:"0"*64}):
                    with self.assertRaises(ValueError):validate_update(update)
            # Recomputing a local retained-record hash cannot replace an independently pinned source window.
            local=copy.deepcopy(evidence["window_inputs"]);local_path=Path(local["path"])
            original_bytes=local_path.read_bytes();forged=json.loads(original_bytes)
            forged["window"]["blocks"][0]["rows"][0]["text"]+=" forged"
            local_path.write_bytes(w.canonical_bytes(forged));local["sha256"]=w.sha256(local_path.read_bytes())
            with self.assertRaises(ValueError):retained_inputs(local)
            local_path.write_bytes(original_bytes)
            fuzzer_request=pb.FuzzerTrainingRequest(request_id=request.request_id,source_id="synthetic-source")
            persist_cycle_evidence(fuzzer_request,update,"full_encoder",gate_passed=True)
            captured=[]
            with patch("training.parameter_updates.emit_parameter_update",side_effect=lambda target,payload,**kwargs:captured.append(payload)):
                emit_training_update("unused","synthetic-fuzzer",update,extra_metadata={"request_id":request.request_id,"request_source_id":"synthetic-source","generated_prompt_count":"256"})
            payload=captured[0]
            self.assertLessEqual(len(payload.metadata),64);self.assertTrue(all(len(v.encode())<=2048 for v in payload.metadata.values()))
            self.assertNotIn(w.TRACE_KEY,payload.metadata)
            # Load actual updater modules under private names; no services, ports or real stores.
            updater_path=ROOT/"services/param-update-service/app"
            spec=importlib.util.spec_from_file_location("synthetic_window_updater",updater_path/"server.py")
            module=importlib.util.module_from_spec(spec)
            generic=("audit","config","receipts","fuzzer_requests","validation")
            saved_modules={name:sys.modules.pop(name) for name in generic if name in sys.modules}
            try:
                with patch.object(sys,"path",[str(updater_path),*sys.path]):spec.loader.exec_module(module)
            finally:
                for name in generic:sys.modules.pop(name,None)
                sys.modules.update(saved_modules)
            artifact_path=Path(directory)/"current.json";artifact_path.write_bytes(w.canonical_bytes(artifact))
            service=module.ParamUpdateService(storage_path=Path(directory)/"updates",model_artifact_path=artifact_path,
                expected_model_id=artifact["model_id"],max_abs_gradient=.05)
            update_request=pb.ParameterUpdateRequest(source_id=payload.source_id,model_id=payload.model_id,base_version=payload.base_version,
                gradients=[pb.Parameter(name=n,shape=payload.shapes[n],values=v) for n,v in payload.parameters.items()],metadata=payload.metadata)
            applied=service._apply_update(update_request)
            replay=service._apply_update(update_request)
            self.assertEqual(applied["version"],replay["version"])
            loaded=load_artifact(artifact_path)
            from src.LLM.privoke import parameter_stream
            tensors=sorted(loaded["parameters"].items())
            chunks=[pb.ModelParameterChunk(model_id=loaded["model_id"],version=loaded["version"],generated_at_unix=1,
                parameter=pb.ParameterChunk(name=name,shape=tensor["shape"],values=tensor["values"]),
                metadata=snapshot(loaded).metadata if index==0 else {},chunk_index=index,total_chunks=len(tensors))
                for index,(name,tensor) in enumerate(tensors)]
            client=MagicMock();client.StreamModelParameters.return_value=iter(chunks)
            with patch.object(parameter_stream,"grpc_channel"),patch.object(parameter_stream.parameters_pb2_grpc,"ModelStreamingServiceStub",return_value=client):
                transported=parameter_stream.ModelParameterStreamer(target="synthetic-unused",model_id=loaded["model_id"]).fetch()
            reloaded=StreamedTransformerPrivacyModel(transported)
            self.assertEqual(parameter_fingerprint(reloaded.snapshot.parameters,reloaded.snapshot.shapes),batch.metadata["updated_parameter_fingerprint"])
            wrong=pb.ParameterUpdateRequest();wrong.CopyFrom(update_request)
            wrong.metadata[w.SUMMARY_KEY]=w.canonical({**json.loads(wrong.metadata[w.SUMMARY_KEY]),"selected":json.loads(wrong.metadata[w.SUMMARY_KEY])["terminal"]})
            with self.assertRaises(ValueError):service._apply_update(wrong)
            wrong=runtime_pb2.ComputeSemanticGradientsResponse();wrong.CopyFrom(response);wrong.executions[0].layer=1
            with self.assertRaises(ValueError):validate_response(request,wrong,admission,window,release)


if __name__=="__main__":unittest.main()
