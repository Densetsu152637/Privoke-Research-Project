"""Synthetic PH3 mechanics only: no historical/fresh payloads, fits or serving."""
from __future__ import annotations
import copy
import json
import math
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

CODE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(CODE_ROOT/"evaluation"))
from privoke_eval import privacy_heads_v3 as core
REPOSITORY = Path(os.environ.get("PH3_REPOSITORY",str(CODE_ROOT)))
core.configure_repository(REPOSITORY)
from privoke_eval import privacy_heads_v3_comparison as comparison
import torch
from privoke_contracts.classification import (
    initialise_unpacked, Sensitivity, Visibility, Category)
from privoke.v1 import runtime_pb2 as pb

def heads(hidden=8):
    return torch.nn.ParameterDict({task+"_"+part:torch.nn.Parameter(torch.zeros(shape))
        for task,labels in core.LABELS.items()
        for part,shape in (("weight",(len(labels),hidden)),("bias",(len(labels),)))})

def rows(role="train",count=12):
    result=[]
    for index in range(count):
        category=[Category[core.LABELS["category"][index%10]]] if index%3!=0 else []
        value=initialise_unpacked(Sensitivity[core.LABELS["sensitivity"][index%4]],
                                  Visibility[core.LABELS["visibility"][index%6]],category)
        result.append({"id":role+"-"+str(index),"group_id":role+"-group-"+str(index),
            "family_id":role+"-family-"+str(index),"partition":role,
            "text":role+" synthetic mechanics "+str(index),"classification":value.to_dict(),
            "packed":value.pack(),"allowed_actions":["ALLOW"],"metadata":{"source":"test-only"}})
    return result

def synthetic_truth(count=70):
    return {"sensitivity":torch.arange(count)%4,"visibility":torch.arange(count)%6,
            "category":(torch.arange(count).unsqueeze(1)%10==torch.arange(10).unsqueeze(0)).float()}

def record(target=None,prediction=None,status="ok",action="ALLOW"):
    target=target or {"sensitivity":"S2","visibility":"P2","categories":["HEALTH"]}
    return {"id":"one","group_id":"group-one","family_id":"family-one","target":target,
            "allowed_actions":["WARN"],"classification":prediction or target,
            "action":action,"status":status,"host_elapsed_ns":1000}

class DataBoundaryTests(unittest.TestCase):
    def test_named_packed_mismatch_and_alias_rejected(self):
        row=rows()[0]
        core.validate_row(row,"train")
        altered=copy.deepcopy(row)
        altered["classification"]["sensitivity"]="S3"
        with self.assertRaisesRegex(ValueError,"Named/packed"):
            core.validate_row(altered,"train")
        altered=copy.deepcopy(row)
        altered["packed_classification"]=altered["packed"]+1
        with self.assertRaisesRegex(ValueError,"alias"):
            core.validate_row(altered,"train")

    def test_fresh_payload_never_opened_by_training_api(self):
        with patch.object(core,"read") as read:
            with self.assertRaisesRegex(ValueError,"Fresh evaluation"):
                core.load_partition(Path("nonexistent"),"fresh_eval")
            read.assert_not_called()

    def test_fresh_cannot_open_without_registry_seal(self):
        with patch.object(comparison,"validate_registry",side_effect=ValueError("unsealed")),patch.object(core,"load_partition") as load:
            with self.assertRaisesRegex(ValueError,"unsealed"):
                comparison.evaluation_rows("missing")
            load.assert_not_called()

    def test_fit_gate_precedes_cache_or_model_access(self):
        with tempfile.TemporaryDirectory() as temporary,patch.object(core,"validate_protocol",return_value=({}, {}, [], [])),patch.object(core,"load_cache") as cache:
            with self.assertRaises(FileNotFoundError):
                core.fit(temporary,"efficient")
            cache.assert_not_called()

    def test_manifest_relative_path_cannot_escape(self):
        with self.assertRaisesRegex(ValueError,"escapes"):
            core.relative_file(Path(tempfile.gettempdir())/"safe","../outside")

    def test_partition_hash_and_group_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary)
            payload=b"".join(core.canonical(r) for r in rows("validation"))
            core.retain(directory/"validation.jsonl",payload)
            manifest={"schema":1,"study_id":core.STUDY_ID,"files":{"validation":{
                "path":"validation.jsonl","sha256":core.digest(payload),"rows":12,"groups":12}}}
            core.retain(directory/"manifest.json",manifest)
            self.assertEqual(len(core.load_partition(directory/"manifest.json","validation")),12)
            (directory/"validation.jsonl").write_bytes(payload+b" ")
            with self.assertRaisesRegex(ValueError,"bytes changed"):
                core.load_partition(directory/"manifest.json","validation")

class TrainingMechanicsTests(unittest.TestCase):
    def setUp(self):
        core.deterministic(1)

    def test_train_weights_and_missing_class_rejection(self):
        truth=synthetic_truth()
        weights=core.class_weights(truth)
        self.assertEqual(weights["category"].shape,(10,))
        self.assertTrue(bool(((weights["category"]>=1)&(weights["category"]<=8)).all()))
        truth["category"][:,0]=0
        with self.assertRaisesRegex(ValueError,"positive/negative"):
            core.class_weights(truth)

    def test_weighted_loss_matches_independent_formula(self):
        truth=synthetic_truth(12)
        weights=core.class_weights(truth)
        logits={task:torch.arange(12*len(labels),dtype=torch.float32).reshape(12,len(labels))*.02
                for task,labels in core.LABELS.items()}
        actual=core.loss_parts(logits,truth,weights)
        for task in ("sensitivity","visibility"):
            logp=logits[task]-torch.logsumexp(logits[task],dim=1,keepdim=True)
            chosen=weights[task][truth[task]]
            expected=-(logp[torch.arange(12),truth[task]]*chosen).sum()/chosen.sum()
            self.assertAlmostEqual(float(actual[task]),float(expected),places=6)
        x,y=logits["category"],truth["category"]
        expected=((1-y)*torch.nn.functional.softplus(x)+y*weights["category"]*torch.nn.functional.softplus(-x)).mean()
        self.assertAlmostEqual(float(actual["category"]),float(expected),places=6)

    def test_tail_batch_exposures_and_head_updates(self):
        feature=torch.arange(70*8,dtype=torch.float32).reshape(70,8)/1000
        truth=synthetic_truth()
        parameters=heads()
        output=core.one_epoch(parameters,core.make_optimizer(parameters),feature,truth,core.class_weights(truth),1)
        self.assertEqual(output["train_exposures"],70)
        self.assertEqual(output["optimizer_steps"],2)
        self.assertTrue(any(bool(torch.count_nonzero(p)) for p in parameters.parameters()))

    def test_selection_tolerance_and_patience_share_comparator(self):
        state={"best_loss":1.,"best_epoch":1,"stale_epochs":0,"best_heads":{}}
        parameters=heads()
        self.assertFalse(core.update_selection(state,.99995,2,parameters,core.POLICY))
        self.assertEqual((state["best_epoch"],state["stale_epochs"]),(1,1))
        self.assertTrue(core.update_selection(state,.9998,3,parameters,core.POLICY))
        self.assertEqual((state["best_epoch"],state["stale_epochs"]),(3,0))
        with self.assertRaisesRegex(ValueError,"Nonfinite"):
            core.update_selection(state,float("nan"),4,parameters,core.POLICY)

    def test_checkpoint_resume_matches_uninterrupted_optimizer(self):
        feature=torch.arange(70*8,dtype=torch.float32).reshape(70,8)/1000
        truth=synthetic_truth()
        weights=core.class_weights(truth)
        parameters=heads()
        optimizer=core.make_optimizer(parameters)
        core.one_epoch(parameters,optimizer,feature,truth,weights,1)
        state={"identity":{"test":"synthetic"},"epoch":1,"heads":core.head_state(parameters),
               "optimizer":copy.deepcopy(optimizer.state_dict())}
        with tempfile.TemporaryDirectory() as temporary:
            core.save_checkpoint(temporary,state)
            restored=core.restore_checkpoint(temporary,state["identity"])
            core.one_epoch(parameters,optimizer,feature,truth,weights,2)
            resumed=heads()
            resumed.load_state_dict(restored["heads"])
            new_optimizer=core.make_optimizer(resumed)
            new_optimizer.load_state_dict(restored["optimizer"])
            core.one_epoch(resumed,new_optimizer,feature,truth,weights,2)
            self.assertTrue(all(torch.equal(parameters[k],resumed[k]) for k in parameters))
            with self.assertRaisesRegex(ValueError,"identity"):
                core.restore_checkpoint(temporary,{"test":"drift"})
            pointer=core.read(Path(temporary)/"latest.json")
            (Path(temporary)/(pointer["sha256"]+".pt")).write_bytes(b"corrupt")
            with self.assertRaisesRegex(ValueError,"bytes"):
                core.restore_checkpoint(temporary,state["identity"])

    def test_complete_encoder_inventory_proof(self):
        before={"encoder.embeddings.weight":torch.ones(2,3),"encoder.pooler.bias":torch.ones(3),
                "heads.category_bias":torch.zeros(10)}
        after={k:v.clone() for k,v in before.items()}
        after["heads.category_bias"][0]=1
        proof=core.frozen_proof(core.tensor_inventory(before),core.tensor_inventory(after))
        self.assertEqual(proof["changed_tensors"],["heads.category_bias"])
        after["encoder.pooler.bias"][0]=2
        with self.assertRaisesRegex(ValueError,"Frozen encoder"):
            core.frozen_proof(core.tensor_inventory(before),core.tensor_inventory(after))

    def test_native_cache_parity_restores_zero_heads(self):
        parameters=heads()
        features=torch.arange(6*8,dtype=torch.float32).reshape(6,8)/100
        class Toy:
            heads=parameters
            def __call__(self,texts):
                return core.affine(features[[int(t) for t in texts]],self.heads)
        items=[{"text":str(i)} for i in range(6)]
        report=core.parity_probe(Toy(),items,features,3)
        self.assertEqual(report["max_abs_logit_error"],0)
        self.assertEqual(len(report["probes"]),4)
        self.assertTrue(all(not bool(torch.count_nonzero(p)) for p in parameters.parameters()))

    def test_atomic_pointer_and_lock_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/"pointer"
            core.atomic_write(path,b"first")
            core.atomic_write(path,b"second")
            self.assertEqual(path.read_bytes(),b"second")
            with core.exclusive_run(Path(temporary)/"lock"):
                with self.assertRaises(FileExistsError):
                    with core.exclusive_run(Path(temporary)/"lock"):
                        pass
            self.assertFalse((Path(temporary)/"lock").exists())

class ScoringTests(unittest.TestCase):
    def test_errors_never_earn_conservative_action_credit(self):
        item=record(status="error",action="WARN")
        self.assertFalse(any(comparison.case_metrics(item).values()))
        scores=comparison.category_scores([item])
        self.assertEqual(scores["per_category"]["HEALTH"]["recall"],0)
        self.assertEqual(scores["per_category"]["HEALTH"]["f1"],0)

    def test_contextual_sensitivity_includes_mild_empty_category(self):
        mild={"sensitivity":"S1","visibility":"PU","categories":[]}
        self.assertTrue(comparison.contextual_sensitive(mild))
        item=record(target=mild,prediction=mild,action="WARN")
        summary=comparison.summarize([item])
        self.assertEqual(summary["slices"]["contextual_sensitive_including_S1"]["joint"]["denominator"],1)
        self.assertEqual(summary["slices"]["category_bearing_disclosures"]["joint"]["denominator"],0)

    def test_sensitive_and_category_bearing_slices_not_clean_dominated(self):
        clean={"sensitivity":"S0","visibility":"PU","categories":[]}
        success=record(target=clean,prediction=clean,action="WARN")
        missed=record(prediction=clean,action="WARN")
        missed["id"]="two"
        summary=comparison.summarize([success,missed])
        self.assertEqual(summary["slices"]["all"]["joint"]["correct"],1)
        self.assertEqual(summary["slices"]["category_bearing_disclosures"]["joint"]["correct"],0)
        self.assertEqual(summary["categories"]["per_category"]["HEALTH"]["fn"],1)

    def test_wire_semantic_identity_and_packed_validation(self):
        entry={"family":"v3","name":"v3-efficient","manifest_sha256":"a"*64,
               "identity":{"model_id":"privoke-v3-efficient","artifact_checksum":"a"*64}}
        row=rows()[1]
        request=comparison.request_for(entry,row,"request-one")
        self.assertEqual(list(request.layers),[4])
        response=pb.AnalyzePromptResponse(request_id=request.request_id,action="WARN",
            classification=pb.RuntimeClassification(**row["classification"],packed=row["packed"]),
            layers=[pb.RuntimeLayerExecution(layer=4,status="ok")],
            metadata={"privoke.semantic."+k:v for k,v in entry["identity"].items()})
        self.assertEqual(comparison.response_record(response,entry,request)["status"],"ok")
        response.layers[0].layer=2
        with self.assertRaisesRegex(ValueError,"isolation"):
            comparison.response_record(response,entry,request)
        response.layers[0].layer=4
        response.metadata["privoke.semantic.model_id"]="wrong"
        with self.assertRaisesRegex(ValueError,"identity"):
            comparison.response_record(response,entry,request)

    def test_unknown_reserved_rpc_cannot_replay(self):
        entry={"family":"v1","name":"v1-balanced","identity":{"model_id":"privoke-balanced"}}
        row=rows()[1]
        with tempfile.TemporaryDirectory() as temporary:
            core.retain(Path(temporary)/"request.pb",b"reserved")
            stub=Mock()
            with self.assertRaisesRegex(ValueError,"reserved"):
                comparison.invoke(stub,entry,row,temporary,"id")
            stub.AnalyzePrompt.assert_not_called()

    def test_paired_harms_and_errors(self):
        first=record(action="WARN")
        after=record(action="ALLOW")
        change=comparison.paired([first],[after])
        self.assertEqual(change["action_harms"]["under"],1)
        after["status"]="error"
        change=comparison.paired([first],[after])
        self.assertEqual(change["action_harms"]["comparable"],0)
        self.assertEqual(change["action_harms"]["error_pairs"],1)

if __name__=="__main__":
    unittest.main()
