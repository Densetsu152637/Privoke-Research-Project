"""Failure-oriented checks for the real-network harness; no model training."""
import base64
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[3]
for path in (ROOT/'shared/python',ROOT/'extension/client-runtime',ROOT/'extension/client-runtime/generated',Path(__file__).parent):
    sys.path.insert(0,str(path))
from privoke.v1 import runtime_pb2 as R
from privoke_model.contextual_training import full_encoder_tensor_shapes, HEAD_NAMES
from privoke_model.fingerprint import parameter_fingerprint
from semantic_training_smoke import decode_trace, apply_actual_stage, fingerprint


class SemanticTrainingSmokeTests(unittest.TestCase):
    def fixture(self):
        config={'vocab_size':2,'hidden_size':2,'intermediate_size':2,'max_tokens':256,'num_layers':2,
                'sensitivity_labels':['S0','S1','S2','S3'],'visibility_labels':['P0','P1','P2','P3','P4','PU'],
                'category_labels':['HEALTH','POLITICS','RELIGION','CRIMINAL','FINANCIAL','SEXUAL','CHILD','LOCATION','IDENTITY','THIRD_PARTY']}
        shapes=full_encoder_tensor_shapes(config)
        import math
        params={n:tuple([0.]*math.prod(shape)) for n,shape in shapes.items()}
        base={'model_id':'privoke-balanced','version':'v0','parameters':params,'shapes':shapes,'config':config,'fingerprint':fingerprint(params,shapes)}
        request=R.ComputeSemanticGradientsRequest(model_id='privoke-balanced',request_id='heads',layers=[R.DETECTION_LAYER_SEMANTIC],examples=[R.RuntimeTrainingExample(text='train',has_target=True,weight=1)],heldout_examples=[R.RuntimeTrainingExample(text='guard',has_target=True,weight=1)])
        response=R.ComputeSemanticGradientsResponse(model_id=request.model_id,request_id=request.request_id,base_version='v0',metadata={'training_scope':'heads','model_config':json.dumps(config),'base_parameter_fingerprint':base['fingerprint'],'trained_parameter_names':json.dumps(sorted(HEAD_NAMES))})
        for name in sorted(HEAD_NAMES):response.gradients.add(name=name,shape=shapes[name],values=[.01]*len(params[name]))
        for phase in ('training','base_heldout','candidate_heldout'):response.executions.add(phase=phase,layer=R.DETECTION_LAYER_SEMANTIC,status='ok',examples=1)
        from privoke_model.artifact import updated_parameter_values,float32
        candidate=dict(params)
        for delta in response.gradients:candidate[delta.name]=tuple(float32(v) for v in updated_parameter_values(params[delta.name],delta.values))
        response.metadata['updated_parameter_fingerprint']=fingerprint(candidate,shapes)
        response.metadata['trained_parameter_inventory_fingerprint']=parameter_fingerprint({n:() for n in HEAD_NAMES},{n:shapes[n] for n in HEAD_NAMES})
        return base,request,response

    def trace(self,request,response):
        return dict(schema_version=1,training_stage='heads',request_id='heads',source_id='auto',model_id=request.model_id,base_version=response.base_version,metadata=dict(response.metadata),metrics=dict(response.metrics),gate_passed=True,ack=dict(accepted=True,model_id=request.model_id,applied_version='v1'),execution_evidence=dict(rpc='ComputeSemanticGradients',request_layers=list(request.layers),request_protobuf_base64=base64.b64encode(request.SerializeToString()).decode(),response_protobuf_base64=base64.b64encode(response.SerializeToString()).decode(),executions=[dict(phase=e.phase,layer=e.layer,status=e.status,examples=e.examples,error=e.error) for e in response.executions]))

    def test_float32_candidate_reconstruction_preserves_all_encoder_values(self):
        base,req,res=self.fixture();updated=apply_actual_stage(base,self.trace(req,res))
        self.assertEqual(updated['fingerprint'],res.metadata['updated_parameter_fingerprint'])
        self.assertTrue(all(updated['parameters'][n]==base['parameters'][n] for n in base['parameters'] if n not in HEAD_NAMES))

    def test_rejects_empty_layers_even_if_trace_claims_semantic(self):
        _,req,res=self.fixture();trace=self.trace(req,res);req.ClearField('layers')
        trace['execution_evidence']['request_protobuf_base64']=base64.b64encode(req.SerializeToString()).decode()
        with self.assertRaisesRegex(AssertionError,'explicitly semantic'):decode_trace(trace)

    def test_rejects_fabricated_phase_projection_or_missing_actual_phase(self):
        _,req,res=self.fixture();trace=self.trace(req,res);trace['execution_evidence']['executions'][0]['examples']=2
        with self.assertRaisesRegex(AssertionError,'projection'):decode_trace(trace)
        del res.executions[-1]
        with self.assertRaisesRegex(AssertionError,'phases'):decode_trace(self.trace(req,res))

    def test_rejects_wrong_endpoint_and_duplicate_delta_inventory(self):
        base,req,res=self.fixture();trace=self.trace(req,res);trace['execution_evidence']['rpc']='ComputeUnderlyingModelGradients'
        with self.assertRaisesRegex(AssertionError,'endpoint'):decode_trace(trace)
        res.gradients[-1].name=res.gradients[0].name
        with self.assertRaisesRegex(AssertionError,'inventory'):apply_actual_stage(base,self.trace(req,res))

    def test_rejects_stale_base_and_candidate_fingerprint_claim(self):
        base,req,res=self.fixture();res.metadata['base_parameter_fingerprint']='0'*64
        with self.assertRaisesRegex(AssertionError,'stale'):apply_actual_stage(base,self.trace(req,res))
        res.metadata['base_parameter_fingerprint']=base['fingerprint'];res.metadata['updated_parameter_fingerprint']='0'*64
        with self.assertRaisesRegex(AssertionError,'candidate fingerprint'):apply_actual_stage(base,self.trace(req,res))

    def test_real_fixture_preserves_short_output_and_position_prefix_without_training(self):
        import tempfile
        from semantic_training_smoke import prepare_fixture,read_json
        result=ROOT/'evaluation/results/fuzzer_underlying_training_20261010'
        result.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=result) as temporary:
            state=Path(temporary)/'state'
            prepare_fixture(state,'d19ec2e09fcf052af408387b36f4ff033d17913a')
            proof=read_json(state/'fixture.json')
            self.assertTrue(proof['short_output_parity'])
            self.assertTrue(proof['old_position_prefix_preserved'])
            self.assertFalse(proof['training'])
            self.assertEqual(len(read_json(state/'prompts.json')),16)

    def test_fuzzer_enrichment_preserves_actual_runtime_fields(self):
        _,req,res=self.fixture();trace=self.trace(req,res)
        trace['metadata']['transformations_per_example']='0';trace['metrics']['new_examples']=1
        decode_trace(trace)
        trace['metadata']['training_scope']='full_encoder'
        with self.assertRaisesRegex(AssertionError,'overrode'):decode_trace(trace)

    def test_scheduler_uses_one_readonly_terminal_cycle_and_fresh_full_request(self):
        import sqlite3,tempfile
        from contextlib import closing
        from semantic_training_smoke import read_cycle,validate_cycle
        import hashlib
        directory=ROOT/'evaluation/results/fuzzer_underlying_training_20261010'
        with tempfile.TemporaryDirectory(dir=directory) as temporary:
            db=Path(temporary)/'cycles.sqlite3'
            cycle=dict(sequence=0,fingerprint='fixed',state='complete',source_id='auto',seed=1,model_id='privoke-balanced',stages={})
            traces=[]
            for stage,base,applied in [('heads','v0','v1'),('full_encoder','v1','v2')]:
                from privoke.v1 import parameters_pb2 as P
                req=P.FuzzerTrainingRequest(request_id=stage,source_id='auto',model_id='privoke-balanced',seed=1,metadata={'require_full_capability':'true'})
                if stage=='full_encoder':req.metadata['expected_base_version']='v1'
                res=P.FuzzerTrainingResponse(accepted=True,model_id=req.model_id,base_version=base,applied_version=applied)
                cycle['stages'][stage]=dict(state='accepted',request_id=stage,request_protobuf_hex=req.SerializeToString().hex(),response_protobuf_hex=res.SerializeToString().hex())
                traces.append(dict(request_id=stage,model_id=req.model_id,base_version=base,ack={'applied_version':applied}))
            with closing(sqlite3.connect(db,isolation_level=None)) as conn:
                conn.execute('CREATE TABLE cycles(sequence INTEGER PRIMARY KEY,fingerprint TEXT,state TEXT,record TEXT)')
                conn.execute('INSERT INTO cycles VALUES (0,?,?,?)',('fixed','complete',json.dumps(cycle)))
            before=db.read_bytes();loaded=read_cycle(db);self.assertEqual(db.read_bytes(),before)
            validate_cycle(loaded,*traces)
            bad=copy.deepcopy(loaded)
            from privoke.v1 import parameters_pb2 as P
            req=P.FuzzerTrainingRequest.FromString(bytes.fromhex(bad['stages']['full_encoder']['request_protobuf_hex']))
            req.metadata['expected_base_version']='v0';bad['stages']['full_encoder']['request_protobuf_hex']=req.SerializeToString().hex()
            with self.assertRaisesRegex(AssertionError,'not linked'):validate_cycle(bad,*traces)

    def test_full_pair_requires_real_embedding_earlier_block_and_head_changes(self):
        import hashlib
        from semantic_training_smoke import verify_pair,artifact_state
        from privoke_model.artifact import float32,updated_parameter_values
        base,req,res=self.fixture()
        initial=dict(model_id=base['model_id'],version=base['version'],config=base['config'],parameters={n:dict(shape=list(base['shapes'][n]),values=list(v)) for n,v in base['parameters'].items()})
        head=self.trace(req,res)
        s1=apply_actual_stage(base,head)
        full_req=copy.deepcopy(req);full_req.request_id='full'
        full_res=copy.deepcopy(res);full_res.request_id='full';full_res.base_version='v1';full_res.ClearField('gradients')
        full_res.metadata.update(training_scope='full_encoder',base_parameter_fingerprint=s1['fingerprint'],artifact_checksum='a'*64,trained_parameter_names=json.dumps(sorted(base['parameters'])))
        for n in sorted(base['parameters']):full_res.gradients.add(name=n,shape=base['shapes'][n],values=[.01]*len(base['parameters'][n]))
        values={n:tuple(float32(v) for v in updated_parameter_values(s1['parameters'][n],[.01]*len(s1['parameters'][n]))) for n in s1['parameters']}
        full_res.metadata['updated_parameter_fingerprint']=fingerprint(values,base['shapes'])
        full_res.metadata['trained_parameter_inventory_fingerprint']=parameter_fingerprint({n:() for n in base['parameters']},base['shapes'])
        full=self.trace(full_req,full_res);full.update(training_stage='full_encoder',request_id='full',source_id=hashlib.sha256(b'underlying-v1:auto').hexdigest())
        full['ack']['applied_version']='v2';full['execution_evidence']['rpc']='ComputeUnderlyingModelGradients'
        final=dict(base,parameters=values,fingerprint=fingerprint(values,base['shapes']),version='v2')
        proof=verify_pair(initial,head,full,final)
        self.assertEqual(proof['observed_streamed_s2'],final['fingerprint'])
        full_res.gradients[0].values[0]=float('nan')
        bad=self.trace(full_req,full_res);bad.update(training_stage='full_encoder',source_id=full['source_id'])
        bad['execution_evidence']['rpc']='ComputeUnderlyingModelGradients'
        with self.assertRaisesRegex(AssertionError,'Nonfinite'):apply_actual_stage(s1,bad)

if __name__=='__main__':unittest.main()
