"""Behavior tests for complete plans, strict gates and resumable stage controls."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from privoke_eval import accelerated_training_surfaces_study as study
from privoke_eval import accelerated_training_surfaces_report as report
from privoke_eval.accelerated_training_surfaces_presence import validate_presence_execution


class StudyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.path=Path(self.temp.name)

    def test_complete_matrix_and_realized_budget_exceptions(self):
        cells=study.matrix('privoke-all-surfaces-test')
        self.assertEqual((len(cells),sum(c['kind']=='online' for c in cells)),(168,111))
        self.assertEqual(len({c['project'] for c in cells if c['project']}),111)
        self.assertEqual(sum(c['stage_slots'] for c in cells if c['kind']=='online'),10656)
        scratch=[c for c in cells if c['surface']=='scratch_presence']
        self.assertEqual(len(scratch),18);self.assertTrue(all(c['batch_size']==16 for c in scratch))
        sparse=[c for c in cells if c['surface']=='sparse_presence' and c['kind']=='offline']
        self.assertTrue(all(c['optimizer_steps'] is None and c['solver_budget']['solver']=='lbfgs' for c in sparse))
        self.assertEqual(sum(c['optimizer_steps']*c['batch_size'] for c in cells if c['kind']=='offline' and c['optimizer_steps']),119808)

    def test_initial_stream_admission_uses_exact_wire_coordinates_not_decimal_json(self):
        artifact={'parameters':{'head.weight':{'shape':[1],'values':[.1]}}}
        snapshot=self.snapshot();snapshot['parameters']=study.wire_parameters(artifact)
        client=SimpleNamespace(snapshot=lambda _:snapshot)
        # Stop at the first checkpoint, before scoring or requester setup.
        with patch.object(study,'checkpoint',side_effect=RuntimeError('admitted')):
            with self.assertRaisesRegex(RuntimeError,'admitted'):
                study.run_online(client,{}, {'model_id':'m'},self.path/'exact',artifact)
        changed=copy.deepcopy(snapshot)
        changed['parameters']['head.weight']['values'][0]+=1e-7
        client.snapshot=lambda _:changed
        with self.assertRaisesRegex(ValueError,'Fresh serving base differs'):
            study.run_online(client,{}, {'model_id':'m'},self.path/'changed',artifact)
        extra=copy.deepcopy(snapshot);extra['parameters']['unexpected']={'shape':[1],'values':[0.]}
        client.snapshot=lambda _:extra
        with self.assertRaisesRegex(ValueError,'Fresh serving base differs'):
            study.run_online(client,{}, {'model_id':'m'},self.path/'extra',artifact)

    def test_dual_plan_has48cycles_and_does_not_claim96independentseeds(self):
        cell=next(c for c in study.matrix('privoke-all-surfaces-test') if c['scope']=='dual')
        self.assertEqual(cell['cycles'],48)
        self.assertEqual(cell['stage_seed_plan_sha256'],study.digest([42+i//2 for i in range(96)]))

    def snapshot(self,version='v0',head=0.,encoder=0.):
        return {'identity':{'model_id':'m','model_version':version,'artifact_checksum':'a','parameter_fingerprint':'f'},
            'parameters':{'head.weight':{'shape':[1],'values':[head]},'embedding':{'shape':[1],'values':[encoder]}}}

    def test_scope_rejects_encoder_mutation_during_head_training(self):
        with self.assertRaisesRegex(ValueError,'frozen'):
            study.validate_tensor_transition(self.snapshot(),self.snapshot('v1',1.,1.),['head.weight'],accepted=True)
        self.assertEqual(study.validate_tensor_transition(self.snapshot(),self.snapshot('v1',1.,1.),['head.weight','embedding'],accepted=True),['head.weight','embedding'])

    def test_rejection_requires_identical_version_and_weights(self):
        for changed in (self.snapshot('v1'),self.snapshot('v0',1.)):
            with self.assertRaises(ValueError):study.validate_tensor_transition(self.snapshot(),changed,['head.weight'],accepted=False)
        self.assertEqual(study.validate_tensor_transition(self.snapshot(),self.snapshot(),['head.weight'],accepted=False),[])

    def test_nonfinite_and_wrongshape_fail_closed(self):
        bad=self.snapshot('v1',float('nan'))
        with self.assertRaises(ValueError):study.validate_tensor_transition(self.snapshot(),bad,['head.weight'],accepted=True)
        bad=self.snapshot('v1',1.);bad['parameters']['head.weight']['shape']=[2]
        with self.assertRaises(ValueError):study.validate_tensor_transition(self.snapshot(),bad,['head.weight'],accepted=True)

    def test_immutable_receipt_cannot_be_overwritten(self):
        path=self.path/'evidence.json';study.write(path,{'a':1},immutable=True)
        with self.assertRaises(ValueError):study.write(path,{'a':2},immutable=True)
        self.assertEqual(study.read(path),{'a':1})

    def test_strict_json_rejects_duplicate_keys_and_nan(self):
        path=self.path/'bad.json'
        for raw in ('{"x":1,"x":2}','{"x":NaN}'):
            path.write_text(raw)
            with self.assertRaises(ValueError):study.read(path)

    def test_frozen_input_change_fails(self):
        path=self.path/'train.jsonl';path.write_text('{}\n');ref=study.file_commitment(path)
        path.write_text('{"changed":true}\n')
        with self.assertRaises(ValueError):study.verify_files({'train':ref})

    def test_protected_final_input_rejected_before_read(self):
        path=self.path/'protected-final';path.mkdir();(path/'rows.json').write_text('{}')
        with self.assertRaises(ValueError):study.file_commitment(path/'rows.json')

    def test_presence_execution_rejects_ner_and_missing_trace(self):
        identity=dict(model_id='m',model_version='v',artifact_checksum='a',parameter_fingerprint='p')
        response=SimpleNamespace(**identity,error='',probability=.5,threshold=.5,
            executions=[SimpleNamespace(layer=4,status='ok',error='',results=[])])
        self.assertEqual(validate_presence_execution(response,identity,4),identity)
        response.executions[0].layer=3
        with self.assertRaises(ValueError):validate_presence_execution(response,identity,4)
        response.executions=[]
        with self.assertRaises(ValueError):validate_presence_execution(response,identity,4)

    def test_context_client_uses_server_identity_when_clean_prediction_has_no_finding(self):
        from privoke_eval.continual_fuzzer_study import RpcClient, RP
        identity=dict(model_id='m',model_version='v',artifact_checksum='a',parameter_fingerprint='p')
        response=RP.AnalyzePromptResponse(request_id='r',action='ALLOW',
            classification=RP.RuntimeClassification(sensitivity='S0',visibility='PU'),
            layers=[RP.RuntimeLayerExecution(layer=RP.DETECTION_LAYER_SEMANTIC,status='ok')],
            metadata={'privoke.semantic.'+k:v for k,v in identity.items()})
        client=RpcClient.__new__(RpcClient)
        client.runtime=SimpleNamespace(AnalyzePrompt=lambda *a,**k:response)
        actual=client.analyze({'text':'synthetic'},'m','semantic','r')
        self.assertEqual(actual['identities'],[identity])
        del response.metadata['privoke.semantic.artifact_checksum']
        self.assertEqual(client.analyze({'text':'synthetic'},'m','semantic','r')['identities'],[])

    def test_paired_errors_remain_in_fixed_denominator_and_veto(self):
        before=[{'id':'a','group_id':'g','target':True,'predicted_present':False,'status':'ok'},
                {'id':'b','group_id':'g','target':False,'predicted_present':True,'status':'ok'}]
        after=copy.deepcopy(before);after[0]['predicted_present']=True;after[1]={'id':'b','group_id':'g','target':False,'status':'error'}
        result=report.paired_metrics(before,after,task='presence')
        self.assertEqual(result['after']['rows'],2);self.assertEqual(result['after']['accuracy'],.5)
        self.assertFalse(result['qualifies']);self.assertEqual(result['error_observations'],1)

    def test_canceling_prediction_changes_are_reported(self):
        before=[{'id':'a','group_id':'g','target':True,'predicted_present':False,'status':'ok'},
                {'id':'b','group_id':'g','target':True,'predicted_present':True,'status':'ok'}]
        after=copy.deepcopy(before)
        for r in after:r['predicted_present']=not r['predicted_present']
        result=report.paired_metrics(before,after,task='presence')
        self.assertEqual(result['changes']['recall'],0);self.assertEqual(result['exact_prediction_change_count'],2)

    def test_offline_budget_validation_does_not_accept_fake_sparse_steps(self):
        path=self.path/'snapshot.json';path.write_text('{}')
        ref={'path':str(path),'sha256':study.sha(path)}
        cell={'id':'x','surface':'sparse_presence','scope':'heads'}
        result={'schema_version':'accelerated-offline-fit-v1','status':'complete','cell_id':'x','baseline_artifact':ref,'final_artifact':ref,
            'dose':{'optimizer_steps':96,'solver_budget':{}},'tensor_audit':{'encoder_unchanged':True}}
        with self.assertRaises(ValueError):study.validate_offline(result,cell)

    def test_offline_normalization_rejects_unexecuted_or_changed_snapshot(self):
        row={'id':'x','group_id':'g','present':True};snapshot={'sha256':'a'}
        record={'id':'x','status':'complete','present':True,'snapshot_sha256':'a','snapshot_checksum':None,'parameter_fingerprint':'f',
            'requested_model_id':'m','used_model_id':'m','requested_version':'v','used_version':'v','executed_layers':['DETECTION_LAYER_SEMANTIC'],
            'execution_mode':'offline_learned_forward_v1','executions':[{'layer':'DETECTION_LAYER_SEMANTIC','status':'complete','forward_count':1}]}
        self.assertTrue(study.normalize_offline([record],[row],snapshot,'presence')['predictions'][0]['predicted_present'])
        record['snapshot_sha256']='b'
        with self.assertRaises(ValueError):study.normalize_offline([record],[row],snapshot,'presence')
        record['snapshot_sha256']='a';record['executed_layers']=[]
        with self.assertRaises(ValueError):study.normalize_offline([record],[row],snapshot,'presence')

    def test_ontology_and_length_gates_require_exact_source_and_entire_matrix(self):
        receipt=self.path/'gate.json';study.write(receipt,{'status':'accepted'})
        protocol={'source_files':{},'cells':study.matrix('privoke-all-surfaces-test'),
            'inputs':{key:{'path':str(receipt),'sha256':study.sha(receipt)} for key in ('ontology_manifest','length_admissibility','endpoint_ledger')}}
        with self.assertRaisesRegex(ValueError,'commitments'):study.verify_review_gates(protocol)

    def test_offline_adapter_never_receives_assessment_paths(self):
        protocol={'source_revision':'a'*40,'inputs':{'offline':{'tiny':{'train':{},'assets':{},'assessment':{}}}}}
        with self.assertRaises(ValueError):study.offline_inputs(protocol,{'surface':'tiny','profile':'balanced'})


class AutomationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module=study.automation_module()
        from privoke.v1 import parameters_pb2
        cls.P=parameters_pb2

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.path=Path(self.temp.name)
        self.config=self.module.FuzzerRequestConfig('unused',32,'m','s',1,0,0,0,1,42,state_path=str(self.path/'journal.sqlite3'))

    def response(self,accepted=True,base='v0',applied='v1'):
        return self.P.FuzzerTrainingResponse(accepted=accepted,model_id='m',base_version=base,applied_version=applied)

    def test_actual_dual_observes_head_before_full_and_retains_partial(self):
        events=[]
        def send(config,**kwargs):
            events.append(('rpc',kwargs['training_scope'],kwargs.get('expected_base_version')))
            return self.response() if kwargs['training_scope']=='heads' else self.response(False)
        with patch.object(self.module,'request_fuzzer_training',side_effect=send):
            self.module.request_fuzzer_loop(self.config,cycles=1,stage_observer=lambda c,s,e:events.append(('observe',s,e)))
        self.assertLess(events.index(('observe','heads','accepted')),events.index(('rpc','full_encoder','v1')))
        self.assertIn(('observe','full_encoder','rejected'),events)

    def test_head_rejection_skips_full_but_consumes_fixed_cycles(self):
        calls=[]
        with patch.object(self.module,'request_fuzzer_training',side_effect=lambda c,**k:(calls.append((c.seed,k['training_scope'])) or self.response(False))):
            self.module.request_fuzzer_loop(self.config,cycles=3)
        self.assertEqual(calls,[(42,'heads'),(43,'heads'),(44,'heads')])

    def test_observer_failure_stops_before_full_and_resume_reuses_accepted_head(self):
        calls=[]
        def send(config,**kwargs):
            calls.append(kwargs['training_scope']);return self.response(base='v0' if kwargs['training_scope']=='heads' else 'v1',applied='v1' if kwargs['training_scope']=='heads' else 'v2')
        def observe(c,s,e):
            if e=='accepted':raise RuntimeError('capture unavailable')
        with patch.object(self.module,'request_fuzzer_training',side_effect=send):
            with self.assertRaisesRegex(RuntimeError,'capture unavailable'):
                self.module.request_fuzzer_loop(self.config,cycles=1,stage_observer=observe)
            self.module.request_fuzzer_loop(self.config,cycles=1)
        self.assertEqual(calls,['heads','full_encoder'])

    def test_unknown_transport_keeps_exact_pending_request_and_protocol_change_fails(self):
        import grpc
        class Unknown(grpc.RpcError):
            def code(self):return grpc.StatusCode.UNAVAILABLE
        with patch.object(self.module,'request_fuzzer_training',side_effect=Unknown()):
            with self.assertRaisesRegex(RuntimeError,'pending'):
                self.module.request_fuzzer_loop(self.config,cycles=1,request_metadata={'study_gate_diagnostics':'v1'})
        with self.assertRaisesRegex(ValueError,'different'):
            self.module.request_fuzzer_loop(self.config,cycles=2,request_metadata={'study_gate_diagnostics':'v1'})

    def test_bounded_retry_budget_is_not_reset_by_resume(self):
        import grpc
        class Unknown(grpc.RpcError):
            def code(self):return grpc.StatusCode.UNAVAILABLE
        with patch.object(self.module,'request_fuzzer_training',side_effect=Unknown()) as rpc:
            with self.assertRaises(RuntimeError):self.module.request_fuzzer_loop(self.config,cycles=1)
            with self.assertRaisesRegex(RuntimeError,'exhausted'):self.module.request_fuzzer_loop(self.config,cycles=1)
            self.assertEqual(rpc.call_count,1)

    def test_legacy_oneshot_still_executes_one_dual_cycle(self):
        calls=[]
        with patch.object(self.module,'request_fuzzer_training',side_effect=lambda c,**k:(calls.append(k['training_scope']) or self.response(base='v0' if k['training_scope']=='heads' else 'v1'))):
            self.module.request_fuzzer_loop(self.config)
        self.assertEqual(calls,['heads','full_encoder'])

    def test_full_only_public_control_does_not_insert_a_head(self):
        calls=[]
        with patch.object(self.module,'request_fuzzer_training',side_effect=lambda c,**k:(calls.append(k['training_scope']) or self.response())):
            self.module.request_fuzzer_loop(self.config,cycles=1,stages=('full_encoder',))
        self.assertEqual(calls,['full_encoder'])



class ReviewClosureTests(unittest.TestCase):
    def test_midpoint_retains_snapshot_without_scoring(self):
        with tempfile.TemporaryDirectory() as temp:
            snapshot={"identity":{"model_version":"v32"},"parameters":{}}
            with patch.object(study,'endpoint_specs',side_effect=AssertionError('must not score')):
                study.checkpoint(None,{}, {},Path(temp),32,snapshot)
            self.assertTrue((Path(temp)/'snapshot-032.json').exists())
            self.assertFalse((Path(temp)/'assessment-032.json').exists())

    def test_worker_rejects_assessment_fit_before_docker_run(self):
        with tempfile.TemporaryDirectory() as temp:
            protocol={"offline_worker_image":"sha256:"+'a'*64,"source_revision":"revision","source_files":{"evaluation/privoke_eval/accelerated_training_surfaces_offline.py":"b"*64}}
            with patch.object(study,'command',return_value=protocol['offline_worker_image']),patch.object(study.subprocess,'run',side_effect=AssertionError('fit must not run')):
                with self.assertRaisesRegex(ValueError,'assessment'):
                    study.offline_worker(protocol,{}, {'rows':[]},Path(temp),'fit')

    def test_presence_qualification_requires_eight_specificity_and144recall(self):
        def row(i,pred):return {'id':str(i),'group_id':str(i),'target':i<160,'predicted_present':pred,'status':'ok'}
        before=[row(i,i<160 or i<200) for i in range(320)]
        after=[row(i,i<160 or i<192) for i in range(320)]
        self.assertTrue(report.qualification_rule(before,after,'presence',{})['passes'])
        after[143]['predicted_present']=False
        self.assertFalse(report.qualification_rule(before,after,'presence',{})['passes'])

    def test_contextual_overall_gain_cannot_replace_both_subgroup_thresholds(self):
        before=[];after=[]
        for i in range(320):
            target={'sensitivity':'S0' if i<160 else 'S2' if i<280 else 'S1','visibility':'P0','categories':[]}
            row={'id':str(i),'group_id':str(i),'target':target,'classification':{'sensitivity':'S0','visibility':'P0','categories':[]},'action':'ALLOW','allowed_actions':['ALLOW'],'status':'ok'}
            before.append(copy.deepcopy(row));after.append(copy.deepcopy(row))
            if 160<=i<171:after[-1]['classification']=target
        self.assertFalse(report.qualification_rule(before,after,'context',{})['passes'])
        for i in range(171,176):after[i]['classification']=after[i]['target']
        self.assertTrue(report.qualification_rule(before,after,'context',{})['passes'])

    def test_saved_offline_trace_audit_rejects_changed_identity(self):
        identity={'model_id':'m','model_version':'v','artifact_checksum':'s','parameter_fingerprint':'f'}
        row={'status':'ok','snapshot_sha256':'s','snapshot_checksum':'s','executed_layers':['DETECTION_LAYER_SEMANTIC'],'executions':[{'layer':'DETECTION_LAYER_SEMANTIC','forward_count':1,'status':'complete'}],'used_model_id':'wrong','requested_model_id':'m','used_version':'v','requested_version':'v','parameter_fingerprint':'f'}
        observation={'identity':identity,'execution_mode':'offline_learned_forward_v1','snapshot_sha256':'s','endpoints':{'primary':{'layers':{'semantic':{'predictions':[row]}}}}}
        with self.assertRaisesRegex(ValueError,'identity'):
            report.audit_saved_inference(observation,{'kind':'offline'},Path('.'))

    def test_presence_runtime_fingerprint_includes_shapes(self):
        from privoke_model.fingerprint import parameter_fingerprint
        values={'head.presence.bias':[0.]}
        self.assertNotEqual(parameter_fingerprint(values),parameter_fingerprint(values,{'head.presence.bias':[1]}))

    def test_presence_canonical_evidence_excludes_physical_attempt_records(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'training-cycles'/'cycle';(root/'attempts').mkdir(parents=True)
            (root/'base.json').write_text('{}');(root/'attempts'/'1.json').write_text('{}')
            self.assertEqual(len(list((Path(temp)/'training-cycles').glob('*/*.json'))),1)

    def test_error_coverage_separates_assigned_and_success_only_rates(self):
        rows=[{'id':'a','group_id':'g','target':True,'predicted_present':True,'status':'ok'},{'id':'b','group_id':'g','target':True,'status':'error'}]
        m=report.paired_metrics(rows,rows,task='presence',iterations=0)
        self.assertEqual(m['before']['recall'],.5);self.assertEqual(m['success_only']['before']['recall'],1.)
        self.assertEqual(m['coverage']['before'],.5)


class SecondReviewClosureTests(unittest.TestCase):
    def test_native_parity_compares_all_labels_and_action_across_transport_shapes(self):
        direct={'classification':{'sensitivity':'S2','visibility':'P3','categories':['HEALTH','FINANCIAL']},'action':'WARN'}
        network=copy.deepcopy(direct)
        network['classification'].update(packed=562,categories=['FINANCIAL','HEALTH'])
        self.assertEqual(study.contextual_prediction_key(direct),study.contextual_prediction_key(network))
        for key,value in (('sensitivity','S1'),('visibility','P1'),('categories',['HEALTH'])):
            changed=copy.deepcopy(network);changed['classification'][key]=value
            self.assertNotEqual(study.contextual_prediction_key(direct),study.contextual_prediction_key(changed))
        network['action']='ALLOW'
        self.assertNotEqual(study.contextual_prediction_key(direct),study.contextual_prediction_key(network))

    def test_real_compose_construction_all_declared_branches(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            protocol={'images':{service:'sha256:'+'a'*64 for service in study.SERVICES},'ports':{'model':52551,'updater':52552,'fuzzer':52553,'runtime':52554},'inputs':{'curriculum':{'path':str(root/'curriculum/manifest.json')},'presence_train':{'path':str(root/'presence.jsonl')}}}
            base={'id':'cell','project':'privoke-all-surfaces-test','model_id':'privoke-balanced','surface':'tiny','sampling':'procedural'}
            for branch,changes in (('procedural',{}),('curriculum',{'sampling':'curriculum'}),('sparse',{'surface':'sparse_presence'}),('minilm',{'surface':'minilm'}),('scratch',{'surface':'scratch_presence'})):
                directory=root/branch;directory.mkdir()
                assets={'assets':{'model.onnx':{'path':str(root/'assets/model.onnx')}}}
                with patch.object(study,'offline_inputs',return_value=assets):
                    args,env=study.compose_command(protocol,base|changes,directory)
                self.assertEqual(args[:2],['docker','compose'])
                self.assertEqual(args[5],str(study.ROOT/'evaluation/compose.accelerated-training-surfaces.yml'))
                self.assertEqual(args[7],str(directory/'compose.json'))
                override=study.read(directory/'compose.json')
                if branch=='curriculum':self.assertEqual(override['services']['privoke-fuzzer']['environment']['FUZZ_CURRICULUM_MANIFEST_PATH'],'/curriculum/manifest.json')
                if branch=='sparse':
                    fuzzer=override['services']['privoke-fuzzer']
                    self.assertEqual(fuzzer['environment']['FUZZ_PRESENCE_DATASET_PATH'],'/training/presence.jsonl')
                    self.assertTrue(fuzzer['volumes'][0]['read_only'])
                if branch=='minilm':self.assertEqual(override['services']['client-runtime']['environment']['PRIVOKE_PRETRAINED_CONTEXT_DIR'],'/assets')
                if branch in ('minilm','scratch'):
                    self.assertEqual(override['services']['model-streaming-service']['environment']['MODEL_LATEST_ID'],'privoke-balanced')
                    self.assertEqual(env['AS_MODEL_ID'],base['model_id'])

    def _configuration(self,surface,seed):
        return {'id':f'{surface}-{seed}','seed':seed,'kind':'offline','group':'offline-representation','surface':surface,'profile':'balanced','scope':'heads','sampling':'procedural','objective':'contextual','optimizer':'adam'}

    def test_minilm_and_random_control_are_distinct_three_seed_groups(self):
        manifest=[self._configuration(surface,seed) for surface in ('minilm','random_control') for seed in (42,43,44)]
        results={c['id']:{'qualification':{'passes':c['seed']==42,'veto':False,'eligible':True}} for c in manifest}
        decisions=report.configuration_decisions(manifest,results)
        self.assertEqual(len(decisions),2)
        self.assertTrue(all(d['passing_seeds']==1 and not d['qualifies'] for d in decisions.values()))

    def test_configuration_rejects_duplicated_nominal_seed(self):
        manifest=[self._configuration('minilm',seed) for seed in (42,43,43)]
        results={c['id']:{'qualification':{'passes':True,'veto':False,'eligible':True}} for c in manifest}
        with self.assertRaisesRegex(ValueError,'unique seeds'):report.configuration_decisions(manifest,results)

    def test_configuration_decision_does_not_require_third_seed_gain(self):
        manifest=[self._configuration('minilm',seed) for seed in (42,43,44)]
        results={c['id']:{'qualification':{'passes':c['seed']!=44,'veto':False,'eligible':True}} for c in manifest}
        self.assertTrue(next(iter(report.configuration_decisions(manifest,results).values()))['qualifies'])
        results['minilm-44']['qualification']['veto']=True
        self.assertFalse(next(iter(report.configuration_decisions(manifest,results).values()))['qualifies'])

    def test_third_seed_without_gain_headroom_does_not_veto_configuration(self):
        manifest=[self._configuration('minilm',seed) for seed in (42,43,44)]
        results={c['id']:{'qualification':{'passes':c['seed']!=44,'veto':False,'eligible':c['seed']!=44}} for c in manifest}
        decision=next(iter(report.configuration_decisions(manifest,results).values()))
        self.assertTrue(decision['eligible']);self.assertTrue(decision['qualifies'])
        self.assertEqual(decision['passing_seeds'],2)
        results['minilm-44']['qualification']['veto']=True
        self.assertFalse(next(iter(report.configuration_decisions(manifest,results).values()))['qualifies'])

    def test_context_secondary_recall_veto_is_historical502_only(self):
        before=[];after=[]
        for i in range(320):
            target={'sensitivity':'S0' if i<160 else 'S2' if i<280 else 'S1','visibility':'P0','categories':[]}
            row={'id':str(i),'group_id':str(i),'target':target,'classification':{'sensitivity':'S0','visibility':'P0','categories':[]},'action':'ALLOW','allowed_actions':['ALLOW'],'status':'ok'}
            before.append(copy.deepcopy(row));after.append(copy.deepcopy(row))
            if 160<=i<176:after[-1]['classification']=target
        decline={'error_observations':0,'new_or_worsened_case_harms':0,'changes':{'recall':-.5}}
        self.assertTrue(report.qualification_rule(before,after,'context',{'annotation_transfer':decline})['passes'])
        self.assertFalse(report.qualification_rule(before,after,'context',{'historical_annotation':decline})['passes'])

    def test_deterministic_sparse_repetitions_do_not_use_two_of_three_rule(self):
        manifest=[self._configuration('sparse_presence',seed) for seed in (42,43,44)]
        results={c['id']:{'qualification':{'passes':c['seed']!=44,'veto':False,'eligible':True}} for c in manifest}
        decision=next(iter(report.configuration_decisions(manifest,results).values()))
        self.assertFalse(decision['qualifies']);self.assertFalse(decision['stochastic_seed_corroboration'])

if __name__=='__main__':unittest.main()
