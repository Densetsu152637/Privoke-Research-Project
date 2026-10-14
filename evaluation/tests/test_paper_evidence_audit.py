"""Behavioral checks for research metrics, dependence and corrupted raw evidence."""
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import numpy as np
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from paper_evidence_audit import canonical, journal, paired_bootstrap, reliability, scores

class EvidenceTests(unittest.TestCase):
    def test_received_invalid_response_wire_is_retained(self):
        from types import SimpleNamespace
        from paper_final_semantic import call_rpc
        response=SimpleNamespace(request_id='x',layers=[SimpleNamespace(layer=2)],SerializeToString=lambda **kwargs:b'invalid-but-received-wire')
        stub=SimpleNamespace(AnalyzePrompt=lambda *args,**kwargs:response)
        terminal,record=call_rpc(stub,SimpleNamespace(request_id='x'),{'identity':{}})
        self.assertFalse(record['valid'])
        self.assertEqual(base64.b64decode(terminal['response_pb']),b'invalid-but-received-wire')
        self.assertIn('sole semantic',terminal['error'])
    def test_authorized_final_branch_uses_metrics_on_invented_fixture(self):
        from unittest.mock import patch
        import paper_final_semantic as final
        from paper_evidence_audit import retained,sha
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);rows=[{'id':str(i),'text':'invented fixture '+str(i),'expected_has_pii':i<236,'group_id':'g'+str(i%8),'metadata':{'source_dataset':'invented'}} for i in range(498)]
            data=root/'invented.jsonl';data.write_bytes(b''.join(canonical(r) for r in rows))
            gate=root/'gate.json';retained(gate,{'status':'passed'})
            names=[f'{family}-{tier}' for family in ('v1','v3') for tier in ('efficient','balanced','quality')]
            freeze={'packages':{n:{} for n in names},'data':{'path':str(data),'expected_sha256':sha(data)},'gate_receipts':{n:{'path':str(gate),'sha256':sha(gate)} for n in ('training_protection','synthetic_tests')}}
            freeze_path=root/'freeze.json';retained(freeze_path,freeze)
            probe_path=root/'probe.json';retained(probe_path,{'status':'passed','freeze_sha256':sha(freeze_path),'synthetic_only':True,'rows_per_arm':4,'arms':names})
            release=root/'release.json';retained(release,{'status':'accepted_for_once_only_final','freeze_sha256':sha(freeze_path),'synthetic_probe':{'path':str(probe_path),'sha256':sha(probe_path)}})
            calls=[]
            def fake_collect(fp,f,r,actual,output,wt,probe):
                calls.append(probe)
                return {n:[{'id':row['id'],'positive':row['expected_has_pii'],'valid':True} for row in actual] for n in names}
            with patch.object(final,'verify',return_value=root),patch.object(final,'configure',return_value=root),patch.object(final,'collect_rpc',side_effect=fake_collect):
                result=final.evaluate(freeze_path,root/'result',root,release=release)
            self.assertEqual(calls,[False]);self.assertEqual(result['status'],'complete')
            self.assertNotIn('synthetic_only',result);self.assertEqual(result['metrics']['v3-balanced']['accuracy_errors_incorrect'],1)
    def test_errors_do_not_become_negative_successes(self):
        result=scores([1,0,1,0],[1,0,0,1],[1,1,0,0])
        self.assertEqual(result['successful_confusion'],{'tp':1,'tn':1,'fp':0,'fn':0})
        self.assertEqual(result['errors'],2)
        self.assertEqual(result['accuracy_errors_incorrect'],.5)
        self.assertEqual(result['recall_full_denominator'],.5)
        self.assertEqual(result['specificity_full_denominator'],.5)
    def test_error_penalized_f_convention(self):
        from paper_final_semantic import metric_with_f
        result=metric_with_f([1,0,1,0],[1,0,0,1],[1,1,0,0])
        self.assertEqual(result['error_penalized_f1'],.5)
        self.assertEqual(result['error_penalized_f2'],.5)
        self.assertEqual(result['errors_by_truth'],{'positive':1,'negative':1})
    def test_confidence_missing_and_endpoint_bins(self):
        result=reliability([0,.1,1],[0,1,1])
        self.assertEqual([b['count'] for b in result['bins']],[1,1,0,0,0,0,0,0,0,1])
        self.assertIsNone(result['ece']);self.assertIsNone(result['brier'])
        self.assertIsNone(result['bins'][2]['mean_score'])
    def test_common_draws_preserve_identical_arm_delta(self):
        truth=[1,0,1,0];pred={'a':[1,1,0,0],'b':[1,1,0,0]};valid={n:[1]*4 for n in pred}
        result=paired_bootstrap(truth,pred,valid,['z','z','a','a'],iterations=100)
        self.assertEqual(result['metrics']['recall']['paired_differences']['b minus a']['interval95'],[0,0])
    def test_zero_class_draws_report_undefined(self):
        result=paired_bootstrap([1,1,0,0],{'a':[1,1,0,0]},{'a':[1]*4},['pos','pos','neg','neg'],iterations=100)
        recall=result['metrics']['recall']['a'];specificity=result['metrics']['specificity']['a']
        self.assertGreater(recall['undefined_replicates'],0);self.assertGreater(specificity['undefined_replicates'],0)
        self.assertEqual(recall['valid_replicates']+recall['undefined_replicates'],100)
    def test_cluster_order_deterministic(self):
        args=([1,0,1,0],{'a':[1,0,1,0],'b':[0,0,1,0]},{'a':[1]*4,'b':[1]*4},['z','a','z','a'])
        self.assertEqual(paired_bootstrap(*args,iterations=50),paired_bootstrap(*args,iterations=50))
    def test_corrupted_or_unresolved_journal_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'raw.jsonl';wire=b'test'
            e={'kind':'reserve','request_id':'x','sequence':0,'previous':'0'*64,'request_pb':base64.b64encode(wire).decode(),'request_sha256':hashlib.sha256(wire).hexdigest()}
            e['sha256']=hashlib.sha256(canonical(e)).hexdigest();path.write_bytes(canonical(e))
            with self.assertRaisesRegex(ValueError,'Unresolved'):journal(path)
            e['sequence']=1;path.write_bytes(canonical(e))
            with self.assertRaisesRegex(ValueError,'chain'):journal(path)

if __name__=='__main__':unittest.main()
