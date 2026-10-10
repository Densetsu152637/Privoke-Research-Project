"""Synthetic compatibility boundaries; no Docker, real catalogue or study inputs."""
from __future__ import annotations
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
for directory in (ROOT/'evaluation',ROOT/'shared/python',ROOT/'extension/client-runtime',ROOT/'extension/client-runtime/generated',ROOT/'models'):
    sys.path.insert(0,str(directory))
from privoke_eval import in_house_live_compatibility as p
from privoke_eval import in_house_study_controller as c
from privoke_eval import in_house_study_evidence as e
H='a'*64
REV='b'*40


def identity(mid):
    return {'model_id':mid,'version':'v1.0.0+epoch.1','artifact_sha256':e.digest(mid),
            'artifact_checksum':H,'parameter_fingerprint':H}


def commitments():
    return {'source_revision':REV,'images':{role:H for role in c.IMAGE_ROLES},
        'effective_configuration_sha256':H,'source_hashes':{role:H for role in e.SOURCE_ROLES},
        'source_files':{file:H for file in p.SOURCE_FILES},'protocol_sha256':dict(c.contract.PIN_ITEMS)['protocol'],
        'plan_sha256':dict(c.contract.PIN_ITEMS)['plan'],'trainer_contract_sha256':c.TRAINER_DIGEST,
        'synthetic_manifest_sha256':e.digest(p.synthetic_manifest()),
        'image_source_attestation':{'file':'synthetic-unused','sha256':H},
        'prior_catalog':{mid:identity(mid) for mid in c.LEGACY_IDS}}


class SyntheticBackend:
    def __init__(self,output,inputs,*,failure=None):
        self.root=ROOT;self.output=Path(output);self.inputs=inputs;self.failure=failure
        self.calls=[];self.jobs=[];self.unresolved=set();self.number=0;self.changed=False
        self.catalog=p.expected_catalog(inputs)

    def verify_source_observations(self):
        self.safe()

    def prepare(self):
        return self.controls()

    def safe(self):
        if self.unresolved:raise c.RemoteUnknown('synthetic unknown')

    def controls(self):
        self.safe();return {'frozen':'d'*64 if self.changed else H}

    def quiescent(self):
        self.safe();return True

    def verify_external_job(self,proof):
        self.safe()

    def perform(self,operation,*,model_id=None,expected_sha256=None,artifact_sha256=None):
        self.safe();self.calls.append((operation,model_id));self.number+=1
        if self.failure=='unknown' and operation=='install':
            self.unresolved.add('unknown');raise c.RemoteUnknown('synthetic unknown')
        if self.failure=='control-drift' and operation=='probe':
            self.changed=True;raise p.CompatibilityError('synthetic controls changed')
        if self.failure=='probe' and operation=='probe':raise p.CompatibilityError('synthetic terminal failure')
        if operation=='initialize':result={'status':'private_store_initialized'}
        elif operation=='backup':result={'status':'four_raw_backups_verified','catalog':p.expected_catalog(self.inputs)}
        elif operation=='generate':
            records={mid:{'identity':identity(mid),'file':{'file':mid+'.json','sha256':identity(mid)['artifact_sha256']},
                          'loss':1.0,'optimizer_steps':1,'seed':12102026,'rows':2} for mid in c.SCRATCH_IDS}
            result={'status':'synthetic_mechanics_only','manifest':p.synthetic_manifest(),
                    'manifest_sha256':self.inputs['synthetic_manifest_sha256'],'scratch':records}
        elif operation=='install':
            if self.catalog[model_id] is not None:p.fail()
            self.catalog[model_id]=identity(model_id)['artifact_sha256']
            result={'status':'installed','identity':identity(model_id)}
        elif operation=='probe':
            if self.failure=='cas':self.catalog[model_id]='f'*64
            ref={'file':model_id+'-probe.json','sha256':H}
            result={'status':'raw_probe_validated','evidence':ref,'result':{'streaming_identity':identity(model_id),
                'runtime_identity':identity(model_id),'contextual_identity':self.inputs['prior_catalog']['privoke-balanced'],
                'raw_sha256':H,'chunks':18}}
        elif operation=='remove':
            if self.catalog[model_id]!=expected_sha256:p.fail()
            self.catalog[model_id]=None;result={'status':'removed','model_id':model_id,'artifact_sha256':None}
        elif operation=='absence':
            if self.catalog[model_id] is not None:p.fail()
            result={'status':'raw_absence_validated','evidence':{'file':model_id+'-absence.json','sha256':H},
                    'result':{'absent_after_removal':True,'raw_sha256':H}}
        elif operation=='catalogue-final':
            if self.failure=='restoration':p.fail()
            if self.catalog!=p.expected_catalog(self.inputs):p.fail()
            result={'status':'exact_raw_baseline_restored','catalog':dict(self.catalog)}
        else:raise AssertionError(operation)
        name='synthetic-'+str(self.number)
        req=c.save(self.output/('request-'+str(self.number)+'.json'),{'operation':operation,'source_files':self.inputs['source_files']})
        log=c.save(self.output/('log-'+str(self.number)+'.json'),result)
        record={'name':name,'container_id':format(self.number,'064x'),'image_id':'sha256:'+H,
                'exit_code':0,'terminal':True,'request_sha256':req['sha256'],'logs_sha256':log['sha256']}
        receipt=c.save(self.output/('job-'+str(self.number)+'.json'),record)
        proof={k:record[k] for k in ('name','container_id','image_id','exit_code')}
        proof.update(operation=operation,request=req,receipt=receipt)
        self.jobs.append(record)
        return result,proof,log


class LifecycleTests(unittest.TestCase):
    def run_case(self,failure=None):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        root=Path(tmp.name);inputs=commitments();ref=c.save(root/'commitments.json',inputs)
        backend=SyntheticBackend(root,inputs,failure=failure)
        with patch.object(p,'validate_commitments',return_value=inputs):
            result=p.run_producer(inputs,backend,root,commitments_reference=ref)
        return c.json_reference(result),backend,result

    def test_complete_candidate_has_six_distinct_four_job_sets(self):
        value,backend,_=self.run_case()
        self.assertEqual(value['status'],'candidate')
        self.assertEqual(value['receipt']['kind'],p.CANDIDATE_KIND)
        jobs=[j for item in value['receipt']['scratch'].values() for j in item['jobs'].values()]
        self.assertEqual(len(jobs),24);self.assertEqual(len({j['container_id'] for j in jobs}),24)
        self.assertEqual(len(value['raw_inventory']),12)
        self.assertEqual(backend.catalog,p.expected_catalog(backend.inputs))
        self.assertTrue(value['restoration']['complete'])

    def test_unknown_install_blocks_even_rollback(self):
        value,backend,_=self.run_case('unknown')
        self.assertEqual(value['status'],'failed');self.assertFalse(value['restoration']['complete'])
        index=backend.calls.index(('install',c.SCRATCH_IDS[0]))
        self.assertEqual(backend.calls[index+1:],[])

    def test_terminal_probe_failure_removes_only_owned_scratch(self):
        value,backend,_=self.run_case('probe')
        self.assertEqual(value['status'],'failed');self.assertTrue(value['restoration']['complete'])
        self.assertIn(('remove',c.SCRATCH_IDS[0]),backend.calls)
        self.assertEqual(backend.catalog,p.expected_catalog(backend.inputs))

    def test_changed_controls_block_all_rollback_calls(self):
        value,backend,_=self.run_case('control-drift')
        self.assertEqual(value['status'],'failed')
        self.assertFalse(value['restoration']['complete'])
        index=backend.calls.index(('probe',c.SCRATCH_IDS[0]))
        self.assertEqual(backend.calls[index+1:],[])
        self.assertEqual(backend.catalog[c.SCRATCH_IDS[0]],identity(c.SCRATCH_IDS[0])['artifact_sha256'])

    def test_cas_drift_is_not_overwritten(self):
        value,backend,_=self.run_case('cas')
        self.assertEqual(value['status'],'failed');self.assertFalse(value['restoration']['complete'])
        self.assertEqual(backend.catalog[c.SCRATCH_IDS[0]],'f'*64)

    def test_restoration_failure_never_yields_candidate_success(self):
        value,_,_=self.run_case('restoration')
        self.assertEqual(value['status'],'failed');self.assertFalse(value['restoration']['complete'])

    def test_existing_output_is_never_replaced(self):
        value,backend,ref=self.run_case()
        with patch.object(p,'validate_commitments',return_value=backend.inputs):
            with self.assertRaises(FileExistsError):
                p.run_producer(backend.inputs,backend,backend.output,commitments_reference=value['commitments'])
        self.assertEqual(c.json_reference(ref),value)

    def test_external_acceptance_raw_hash_is_required(self):
        value,backend,ref=self.run_case()
        authority=c.save(backend.output/'authority.json',{'schema_version':1,'kind':'root-authenticated-scratch-compatibility-raw-v1',
            'candidate_sha256':'d'*64,'raw_inventory_sha256':e.digest(value['raw_inventory']),
            'image_source_attestation_sha256':H,'job_proofs_sha256':H})
        with patch.object(p,'validate_commitments',return_value=backend.inputs):
            with self.assertRaises(p.CompatibilityError):p.accept_candidate(ref,backend.inputs,backend,authority,backend.output)
        self.assertFalse((backend.output/'compatibility.json').exists())

    def test_raw_hash_before_any_typed_decode(self):
        with self.assertRaises(p.CompatibilityError):
            p.decode_frame({'raw_b64':base64.b64encode(b'private marker').decode(),'sha256':H},None)

    def test_duplicate_and_nonfinite_packet_json_rejected(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}'):
            with self.assertRaises(e.StudyEvidenceError):e.checked_json(raw,p.sha(raw))

    def test_nonposix_private_io_fails_before_open(self):
        path=Path('unavailable')
        with patch.object(p.os,'name','nt'),patch.object(p.os,'open',side_effect=AssertionError('must not open')):
            with self.assertRaises(p.CompatibilityError):p.PrivateDirectory(path)


class SourceScopeTests(unittest.TestCase):
    def fixture(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);directory=Path(tmp.name)
        inputs=commitments()
        att={k:inputs[k] for k in ('source_revision','images','effective_configuration_sha256','source_files')}
        att.update(schema_version=2,kind='root-authenticated-compatibility-image-source-v2',source_scopes=p.source_scopes(inputs['source_files']))
        request=c.save(directory/'request.json',{'schema_version':1,'kind':p.SOURCE_PREFLIGHT_KIND,'source_files':inputs['source_files']})
        bindings=[{'source':'/daemon/source/'+path,'host_source':str((ROOT/path).resolve()),'destination':'/workspace/'+path,'sha256':H,'readonly':True} for path in p.SOURCE_FILES]
        att['helper_bindings']={'request':request,'bindings':bindings,'proof':None}
        states={};att['image_source_receipts']={}
        for i,role in enumerate(('client-runtime','model-streaming-service','evaluator_helper'),1):
            helper=role=='evaluator_helper';scope=att['source_scopes']['evaluator_helper' if helper else {'client-runtime':'client_runtime_image','model-streaming-service':'model_streaming_image'}[role]]
            raw=e.canonical({'schema_version':1,'kind':p.SOURCE_PREFLIGHT_KIND,'source_files':inputs['source_files']}) if helper else ('\n'.join(digest+'  /workspace/'+path for path,digest in sorted(scope.items()))+'\n').encode('ascii')
            log=c.exclusive(directory/(role+'.log'),raw);name='source-'+str(i);cid=format(i,'064x');serving=format(i+10,'064x') if not helper else None
            request_hash=request['sha256'] if helper else e.digest({'role':role,'scope':scope})
            record={'name':name,'container_id':cid,'image_id':'sha256:'+H,'exit_code':0,'terminal':True,'logs_sha256':log['sha256'],'request_sha256':request_hash}
            receipt=c.save(directory/(role+'.receipt.json'),record)
            proof={k:record[k] for k in ('name','container_id','image_id','exit_code','request_sha256')};proof.update(receipt=receipt,log=log,serving_container_id=serving)
            if helper:att['helper_bindings']['proof']=proof
            else:att['image_source_receipts'][role]=proof
            mounts=[{'Type':'bind','Destination':b['destination'],'Source':b['source'],'RW':False} for b in bindings]+[{'Type':'bind','Destination':'/request.json','Source':'/daemon/request.json','RW':False}] if helper else []
            states[name]={'Id':cid,'Image':'sha256:'+H,'State':{'Running':False,'Status':'exited','ExitCode':0},'Config':{'User':'65534:65534','Cmd':p.source_job_command(role,scope,request if helper else None)},'HostConfig':{'ReadonlyRootfs':True,'NetworkMode':'none','CapDrop':['ALL'],'CapAdd':None,'SecurityOpt':['no-new-privileges:true'],'Memory':4*1024**3,'NanoCpus':4_000_000_000,'PidsLimit':128},'Mounts':mounts}
            if serving:states[serving]={'Id':serving,'Image':'sha256:'+H,'State':{'Running':True},'Mounts':[]}
        class Backend:
            root=ROOT
            def inspect(self,name):return states[name]
            def safe(self):pass
        return directory,inputs,att,states,Backend()

    def verify(self,directory,inputs,att,backend):
        ref=c.save(directory/('att-'+os.urandom(4).hex()+'.json'),att)
        p.verify_source_observations(dict(inputs,image_source_attestation=ref),backend)

    def test_exact_scopes_and_genuine_observation_join(self):
        directory,inputs,att,states,backend=self.fixture()
        p.validate_source_attestation(att,inputs);self.verify(directory,inputs,att,backend)
        self.assertNotIn('evaluation/check-in-house-live-compatibility.py',att['source_scopes']['client_runtime_image'])
        self.assertNotIn('evaluation/check-in-house-live-compatibility.py',att['source_scopes']['model_streaming_image'])

    def test_scope_extra_missing_substitution_and_helper_misassignment(self):
        _,inputs,att,_,_=self.fixture()
        cases=[]
        for role in p.SOURCE_SCOPES:
            changed=copy.deepcopy(att);changed['source_scopes'][role].pop(next(iter(changed['source_scopes'][role])));cases.append(changed)
        changed=copy.deepcopy(att);changed['source_scopes']['client_runtime_image']['evaluation/check-in-house-live-compatibility.py']=H;cases.append(changed)
        changed=copy.deepcopy(att);changed['source_scopes']['operator'][p.SOURCE_FILES[0]]='c'*64;cases.append(changed)
        changed=copy.deepcopy(att);changed['extra']='unknown';cases.append(changed)
        for changed in cases:
            with self.assertRaises((p.CompatibilityError,e.StudyEvidenceError)):p.validate_source_attestation(changed,inputs)

    def test_binding_duplicate_missing_or_writable_rejected(self):
        _,inputs,att,_,_=self.fixture()
        for change in ('duplicate','missing','write'):
            changed=copy.deepcopy(att)
            if change=='duplicate':changed['helper_bindings']['bindings'][1]=changed['helper_bindings']['bindings'][0]
            elif change=='missing':changed['helper_bindings']['bindings'].pop()
            else:changed['helper_bindings']['bindings'][0]['readonly']=False
            with self.assertRaises(p.CompatibilityError):p.validate_source_attestation(changed,inputs)

    def test_observed_handle_mount_or_command_substitution_rejected(self):
        for change in ('image','mount','command','extra-mount','source'):
            directory,inputs,att,states,backend=self.fixture();state=states[att['helper_bindings']['proof']['name']]
            if change=='image':state['Image']='sha256:'+'d'*64
            elif change=='mount':state['Mounts'][0]['RW']=True
            elif change=='command':state['Config']['Cmd']=['python','-c','print("claimed")']
            elif change=='source':state['Mounts'][0]['Source']='/foreign/path'
            else:state['Mounts'].append({'Type':'volume','Destination':'/models','RW':True,'Source':'foreign'})
            with self.assertRaises(p.CompatibilityError):self.verify(directory,inputs,att,backend)

    def test_original_log_raw_and_duplicate_job_identity_rejected(self):
        directory,inputs,att,states,backend=self.fixture()
        proof=att['image_source_receipts']['client-runtime'];Path(proof['log']['file']).write_bytes(b'claimed')
        with self.assertRaises(e.StudyEvidenceError):self.verify(directory,inputs,att,backend)
        directory,inputs,att,states,backend=self.fixture();att['image_source_receipts']['model-streaming-service']=att['image_source_receipts']['client-runtime']
        with self.assertRaises(p.CompatibilityError):self.verify(directory,inputs,att,backend)

    def test_source_preflight_does_not_require_catalogue_or_artifact_inputs(self):
        request={'schema_version':1,'kind':p.SOURCE_PREFLIGHT_KIND,'source_files':{name:H for name in p.SOURCE_FILES}}
        with patch.object(p.os,'name','posix'),patch.dict(p.os.environ,{'PRIVOKE_EVAL_IN_CONTAINER':'true'}),patch.object(p,'verify_source_closure') as check:
            self.assertEqual(p.source_helper(request)['source_files'],request['source_files']);check.assert_called_once()
            with self.assertRaises(e.StudyEvidenceError):p.source_helper(dict(request,prior_catalog={}))

    def test_source_observation_failure_precedes_prepare_and_catalogue(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);directory=Path(tmp.name)
        inputs=commitments();backend=SyntheticBackend(directory,inputs);reference=c.save(directory/'commitments.json',inputs)
        with patch.object(p,'validate_commitments',return_value=inputs),patch.object(backend,'verify_source_observations',side_effect=p.CompatibilityError('synthetic rejected')),patch.object(backend,'prepare',side_effect=AssertionError('must not prepare')):
            with self.assertRaises(p.CompatibilityError):p.run_producer(inputs,backend,directory,commitments_reference=reference)
        self.assertEqual(backend.calls,[])
        self.assertFalse((directory/'compatibility-candidate.json').exists())

    def test_nonterminal_or_false_receipt_is_not_observed_authority(self):
        for change in ('running','false-terminal','wrong-receipt-hash','source-bytes-missing'):
            directory,inputs,att,states,backend=self.fixture();proof=att['image_source_receipts']['model-streaming-service']
            if change=='running':states[proof['name']]['State']['Running']=True
            elif change=='false-terminal':
                record=c.json_reference(proof['receipt']);record['terminal']=False;proof['receipt']=c.save(directory/'false-receipt.json',record)
            elif change=='wrong-receipt-hash':proof['receipt']['sha256']='d'*64
            else:
                proof['log']=c.exclusive(directory/'missing-source.log',b'')
                record=c.json_reference(proof['receipt']);record['logs_sha256']=proof['log']['sha256'];proof['receipt']=c.save(directory/'missing-source.receipt.json',record)
            with self.assertRaises((p.CompatibilityError,e.StudyEvidenceError)):self.verify(directory,inputs,att,backend)

    def test_live_serving_source_overlays_refused_but_unrelated_mounts_allowed(self):
        for destination in ('/','/workspace','/workspace/extension/client-runtime',
                '/workspace/extension/client-runtime/src/model.py'):
            directory,inputs,att,states,backend=self.fixture()
            serving=states[att['image_source_receipts']['client-runtime']['serving_container_id']]
            serving['Mounts']=[{'Destination':destination,'Type':'bind','RW':False}]
            with self.assertRaises(p.CompatibilityError):self.verify(directory,inputs,att,backend)
        directory,inputs,att,states,backend=self.fixture()
        serving=states[att['image_source_receipts']['model-streaming-service']['serving_container_id']]
        serving['HostConfig']={'Tmpfs':{'/workspace/services/model-streaming-service/cmd/server':{}}}
        with self.assertRaises(p.CompatibilityError):self.verify(directory,inputs,att,backend)
        directory,inputs,att,states,backend=self.fixture()
        for proof in att['image_source_receipts'].values():
            states[proof['serving_container_id']]['Mounts']=[{'Destination':'/models','Type':'volume','RW':False},{'Destination':'/var/cache/privoke','Type':'volume','RW':True},{'Destination':'/workspace/extension/client-runtime/source-neighbor','Type':'bind','RW':False}]
        self.verify(directory,inputs,att,backend)

    def test_accept_rechecks_source_observation_before_reading_candidate(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);directory=Path(tmp.name)
        inputs=commitments();backend=SyntheticBackend(directory,inputs)
        with patch.object(p,'validate_commitments',return_value=inputs),patch.object(backend,'verify_source_observations',side_effect=p.CompatibilityError('synthetic source drift')),patch.object(c,'json_reference',side_effect=AssertionError('candidate must not be read')):
            with self.assertRaises(p.CompatibilityError):p.accept_candidate({'file':'unused','sha256':H},inputs,backend,{'file':'unused','sha256':H},directory)
        self.assertEqual(backend.calls,[])

    def test_windows_output_junction_ancestor_rejected_before_mkdir(self):
        import subprocess
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);directory=Path(tmp.name);target=directory/'target';target.mkdir();link=directory/'link'
        if os.name=='nt':
            command="New-Item -ItemType Junction -Path '"+str(link).replace("'","''")+"' -Target '"+str(target).replace("'","''")+"' | Out-Null"
            subprocess.run(['powershell','-NoProfile','-Command',command],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            self.assertTrue(getattr(link.lstat(),'st_file_attributes',0)&0x400)
        else:
            link.symlink_to(target,target_is_directory=True)
            self.assertTrue(link.is_symlink())
        with self.assertRaises(p.CompatibilityError):p.fresh_metadata_output(link/'new')
        self.assertFalse((target/'new').exists())
        original=Path.cwd()
        try:
            os.chdir(link)
            with self.assertRaises(p.CompatibilityError):p.fresh_metadata_output(Path('relative-new'))
            self.assertFalse((target/'relative-new').exists())
        finally:
            os.chdir(original)


class RealPerformTests(unittest.TestCase):
    def test_actual_perform_constructs_posix_container_target_in_native_argv(self):
        import subprocess
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);directory=Path(tmp.name);calls=[]
        def reject(argv,**kwargs):
            calls.append(list(argv));return subprocess.CompletedProcess(argv,99,b'',b'synthetic blocked')
        backend=p.CompatibilityBackend(directory,commitments(),root=ROOT,runner=reject)
        backend.volume='synthetic-private-volume';backend.model_volume='synthetic-model-volume';backend.cache_ttl=1.0
        with self.assertRaises(c.RemoteUnknown):backend.perform('initialize')
        launch=next(argv for argv in calls if 'run' in argv)
        volumes=[launch[i+1] for i,item in enumerate(launch[:-1]) if item=='--volume']
        self.assertIn('synthetic-private-volume:/compatibility',volumes)
        self.assertFalse(any('synthetic-private-volume:\\' in value for value in volumes))
        self.assertTrue(backend.unresolved)

    def test_capability_normalization_is_closed_and_rejects_duplicates(self):
        self.assertEqual(p.compatibility_caps(['CAP_CHOWN','CAP_DAC_OVERRIDE']),{'CHOWN','DAC_OVERRIDE'})
        self.assertEqual(p.compatibility_caps(['CHOWN','DAC_OVERRIDE']),{'CHOWN','DAC_OVERRIDE'})
        self.assertEqual(p.compatibility_caps(None),set())
        for value in (['CAP_CHOWN','CHOWN'],['CAP_CHOWN','CAP_CHOWN'],['CAP_CHOWN','SETUID'],['cap_chown'],['CAP_CAP_CHOWN'],'CAP_CHOWN'):
            with self.assertRaises(p.CompatibilityError):p.compatibility_caps(value)

    def test_actual_perform_validates_original_job_metadata_and_bounded_request(self):
        for raw in (e.canonical({'status':'private_store_initialized'}),b'{"status":"x","status":"y"}'):
            with self.subTest(valid=raw.startswith(b'{"status":"private')):
                tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);directory=Path(tmp.name)
                backend=p.CompatibilityBackend(directory,commitments(),root=ROOT,runner=lambda *a,**k: (_ for _ in ()).throw(AssertionError('Docker forbidden')))
                backend.volume='synthetic-private-volume';backend.model_volume='synthetic-model-volume';backend.cache_ttl=1.0
                def job(service,args,*,mounts,timeout,request_sha256):
                    self.assertEqual(service,'in-house-data-permissions');self.assertEqual(timeout,180)
                    self.assertEqual(len(mounts),len(p.SOURCE_FILES)+2)
                    self.assertEqual(mounts[1],('volume:synthetic-private-volume','/compatibility',False))
                    request=c.json_reference({'file':mounts[0][0],'sha256':request_sha256})
                    self.assertEqual(request['operation'],'initialize');self.assertEqual(request['source_files'],backend.commitments['source_files'])
                    self.assertEqual(args[-1],request_sha256)
                    backend.counter=1
                    log=c.exclusive(directory/'job-0001.log',raw)
                    record={'name':'synthetic-perform','container_id':'b'*64,'image_id':'sha256:'+H,'exit_code':0,'terminal':True,'request_sha256':request_sha256,'logs_sha256':log['sha256']}
                    receipt=c.save(directory/'job-0001.json',record);backend.jobs.append(record)
                    return raw,receipt['sha256']
                observed={'Config':{'User':'0:0'},'HostConfig':{'CapDrop':['ALL'],'CapAdd':['CAP_CHOWN','CAP_DAC_OVERRIDE'],'SecurityOpt':['no-new-privileges:true'],'PidsLimit':128},'Mounts':[]}
                with patch.object(backend,'job',side_effect=job),patch.object(backend,'inspect',return_value=observed):
                    if raw.startswith(b'{"status":"private'):
                        metadata,proof,log=backend.perform('initialize')
                        self.assertEqual(metadata,{'status':'private_store_initialized'})
                        self.assertEqual(c.json_reference(proof['receipt'])['logs_sha256'],log['sha256'])
                        self.assertEqual(c.read_reference(log),raw)
                    else:
                        with self.assertRaises(e.StudyEvidenceError):backend.perform('initialize')


class SyntheticMechanicsTests(unittest.TestCase):
    def test_export_requires_real_step_and_records_truthful_minibatch(self):
        from privoke_eval.in_house_presence_training import create_paired_trainers
        for trainer in create_paired_trainers('efficient'):
            args=dict(source_revision=REV,study_plan_sha256=H,prepared_manifest_sha256=e.digest(p.synthetic_manifest()),
                      trainer_contract_sha256=c.TRAINER_DIGEST,checkpoint_epoch=1,generated_at_unix=1)
            with self.assertRaises(ValueError):trainer.build_artifact(**args)
            metrics=trainer.step(('synthetic mechanics zero','synthetic mechanics one'),(False,True))
            artifact=trainer.build_artifact(**args)
            self.assertEqual(metrics.step,1);self.assertEqual(artifact['metadata']['training_steps'],'1')
            self.assertEqual(artifact['metadata']['prepared_manifest_sha256'],args['prepared_manifest_sha256'])
            self.assertEqual(artifact['metadata']['training_seed'],'12102026')
            self.assertEqual(c.artifact_identity(e.canonical(artifact))[0]['model_id'],trainer.model_id)


try:
    from privoke.v1 import parameters_pb2 as pb,runtime_pb2 as rb
    HAVE_PROTOBUF=True
except ImportError:
    HAVE_PROTOBUF=False


def scratch_fixture():
    from privoke_model.scratch_presence import scratch_presence_tensor_shapes,scratch_presence_trainable_names
    from privoke_eval.in_house_presence_training import presence_config
    from privoke_model.artifact import artifact_checksum
    config=presence_config('efficient','head_only');shapes=scratch_presence_tensor_shapes(config)
    trainable=set(scratch_presence_trainable_names(config))
    artifact={'schema_version':1,'model_id':c.SCRATCH_IDS[0],'version':'v1.0.0+epoch.1','generated_at_unix':1,
        'architecture':'privoke_scratch_presence_transformer_v1','config':config,
        'parameters':{name:{'shape':list(shape),'values':[0.0]*__import__('math').prod(shape),'trainable':name in trainable} for name,shape in shapes.items()},
        'metadata':{'training_route':'offline_release_fit_v1','source_revision':REV,'study_plan_sha256':H,
          'prepared_manifest_sha256':H,'initialization_sha256':H,'trainer_contract_sha256':H,'checkpoint_epoch':'1','training_steps':'1','training_seed':'12102026'}}
    artifact['checksum']=artifact_checksum(artifact)
    return artifact,e.canonical(artifact)


def contextual_fixture():
    import numpy as np
    from generate_baseline import initial_parameters,CATEGORIES,SENSITIVITIES,VISIBILITIES,TRAINABLE
    from src.model import ModelConfig
    from privoke_model.artifact import artifact_checksum
    config=ModelConfig(vocab_size=32,hidden_size=8,intermediate_size=16,max_tokens=8,
        sensitivity_labels=SENSITIVITIES,visibility_labels=VISIBILITIES,category_labels=CATEGORIES,category_threshold=0.5,num_layers=1,num_attention_heads=2)
    arrays=initial_parameters(config,np.random.default_rng(1))
    value={'schema_version':1,'model_id':'privoke-balanced','version':'v0.3.0','generated_at_unix':1,
        'architecture':'privoke_tiny_transformer_v1','config':{k:getattr(config,k) for k in ('vocab_size','hidden_size','intermediate_size','max_tokens','sensitivity_labels','visibility_labels','category_labels','category_threshold','num_layers','num_attention_heads')},
        'parameters':{n:{'shape':list(a.shape),'values':a.ravel().tolist(),'trainable':n in TRAINABLE} for n,a in arrays.items()},'metadata':{}}
    value['checksum']=artifact_checksum(value);return e.canonical(value)


def typed_packet():
    from privoke_model.scratch_presence import scratch_presence_trainable_names
    artifact,raw=scratch_fixture();context=contextual_fixture();i,_=c.artifact_identity(raw);ci,_=c.artifact_identity(context)
    config=artifact['config'];meta=dict(artifact['metadata']);meta.update(served_by='model-streaming-service',consumer_id=p.CONSUMER,
        architecture=artifact['architecture'],model_config=json.dumps(config,separators=(',',':')),
        artifact_checksum=i['artifact_checksum'],artifact_file_checksum=i['artifact_sha256'],
        trainable_parameters=','.join(scratch_presence_trainable_names(config)),task=config['task'],profile=config['profile'],
        training_mode=config['training_mode'],text_normalization=config['normalization'],tokenizer=config['tokenizer'],pooling=config['pooling'],arithmetic=config['arithmetic'])
    chunks=[]
    for name,tensor in sorted(artifact['parameters'].items()):
        for offset in range(0,len(tensor['values']),1024):
            chunks.append(pb.ModelParameterChunk(model_id=i['model_id'],version=i['version'],generated_at_unix=1,
                parameter=pb.ParameterChunk(name=name,shape=tensor['shape'],value_offset=offset,values=tensor['values'][offset:offset+1024])))
    for index,chunk in enumerate(chunks):chunk.chunk_index=index;chunk.total_chunks=len(chunks)
    chunks[0].metadata.update(meta)
    preq=rb.DetectAnnotationPresenceRequest(request_id=p.CONSUMER+'-presence',text=p.PROBE_TEXT,model_id=i['model_id'], layers=[rb.DETECTION_LAYER_SEMANTIC])
    pres=rb.DetectAnnotationPresenceResponse(request_id=preq.request_id,model_id=i['model_id'],model_version=i['version'],
        artifact_checksum=i['artifact_checksum'],parameter_fingerprint=i['parameter_fingerprint'],probability=0.5,threshold=0.5,predicted_label=rb.ANNOTATION_PRESENCE_PRESENT,executions=[rb.RuntimeLayerExecution(layer=4,status="ok")])
    req=rb.AnalyzePromptRequest(request_id=p.CONSUMER+'-gate',text=p.PROBE_TEXT,semantic_model_id='privoke-balanced',layers=[rb.DETECTION_LAYER_SEMANTIC])
    req.semantic_presence_gate.model_id=i['model_id'];req.semantic_presence_gate.threshold=0.0
    trace=rb.SemanticPresenceGateTrace(status=rb.SEMANTIC_PRESENCE_GATE_STATUS_APPLIED,model_id=i['model_id'],model_version=i['version'],
        artifact_checksum=i['artifact_checksum'],parameter_fingerprint=i['parameter_fingerprint'],probability=.5,model_threshold=.5,decision_threshold=0.0,
        predicted_label=rb.ANNOTATION_PRESENCE_PRESENT,contextual_model_id=ci['model_id'],contextual_model_version=ci['version'],
        contextual_artifact_checksum=ci['artifact_checksum'],contextual_parameter_fingerprint=ci['parameter_fingerprint'])
    response=rb.AnalyzePromptResponse(request_id=req.request_id,layers=[rb.RuntimeLayerExecution(layer=rb.DETECTION_LAYER_SEMANTIC,status='ok',semantic_presence_gate=trace)])
    packet={'schema_version':1,'kind':'scratch-compatibility-raw-probe-v1',
        'stream':{'request':p.frame(pb.ModelParametersRequest(model_id=i['model_id'],consumer_id=p.CONSUMER)),'chunks':[p.frame(x) for x in chunks]},
        'presence':{'request':p.frame(preq),'response':p.frame(pres)},'gate':{'request':p.frame(req),'response':p.frame(response)}}
    return packet,raw,context


@unittest.skipUnless(HAVE_PROTOBUF,'Host protobuf dependency unavailable; ROOT pinned evaluator must run these tests')
class TypedTests(unittest.TestCase):
    def verify(self,packet,raw,context):
        captured=e.canonical(packet);return p.verify_probe(captured,p.sha(captured),raw,context)

    def test_genuine_typed_stream_and_both_runtime_identities(self):
        packet,raw,context=typed_packet();result=self.verify(packet,raw,context)
        self.assertEqual(result['runtime_identity'],c.artifact_identity(raw)[0])
        self.assertEqual(result['contextual_identity'],c.artifact_identity(context)[0])

    def test_missing_raw_or_missing_chunk_fails(self):
        for mutation in ('missing','empty'):
            packet,raw,context=typed_packet()
            if mutation=='missing':packet['stream']['chunks'].pop()
            else:packet['presence']['response']['raw_b64']=''
            with self.assertRaises(Exception):self.verify(packet,raw,context)

    def test_mixed_version_and_discontinuous_chunks_fail(self):
        for mutation in ('version','offset','shape'):
            packet,raw,context=typed_packet();chunk=p.decode_frame(packet['stream']['chunks'][1],pb.ModelParameterChunk)
            if mutation=='version':chunk.version='v1.0.0+epoch.2'
            elif mutation=='offset':chunk.parameter.value_offset+=1
            else:chunk.parameter.shape[0]+=1
            packet['stream']['chunks'][1]=p.frame(chunk)
            with self.assertRaises(p.CompatibilityError):self.verify(packet,raw,context)

    def test_parameter_value_and_fingerprint_tampering_fail(self):
        packet,raw,context=typed_packet();chunk=p.decode_frame(packet['stream']['chunks'][0],pb.ModelParameterChunk)
        chunk.parameter.values[0]=.25;packet['stream']['chunks'][0]=p.frame(chunk)
        with self.assertRaises(p.CompatibilityError):self.verify(packet,raw,context)

    def test_scratch_gate_and_context_identity_both_checked(self):
        for field in ('parameter_fingerprint','contextual_parameter_fingerprint'):
            packet,raw,context=typed_packet();response=p.decode_frame(packet['gate']['response'],rb.AnalyzePromptResponse)
            setattr(response.layers[0].semantic_presence_gate,field,'d'*64);packet['gate']['response']=p.frame(response)
            with self.assertRaises(p.CompatibilityError):self.verify(packet,raw,context)

    def test_stale_success_cannot_be_absence(self):
        packet,_,_=typed_packet()
        absent={'schema_version':1,'kind':'scratch-compatibility-raw-absence-v1','stream_request':packet['stream']['request'],
                'stream_status':'NOT_FOUND','stream_chunks':[],'presence':packet['presence'],'gate':packet['gate']}
        raw=e.canonical(absent)
        with self.assertRaises(p.CompatibilityError):p.verify_absence(raw,p.sha(raw),c.SCRATCH_IDS[0])

    def test_actual_typed_errors_prove_absence(self):
        packet,_,_=typed_packet();preq=p.decode_frame(packet['presence']['request'],rb.DetectAnnotationPresenceRequest)
        greq=p.decode_frame(packet['gate']['request'],rb.AnalyzePromptRequest)
        pres=rb.DetectAnnotationPresenceResponse(request_id=preq.request_id,error='synthetic not found')
        trace=rb.SemanticPresenceGateTrace(status=rb.SEMANTIC_PRESENCE_GATE_STATUS_ERROR,error='synthetic not found')
        gres=rb.AnalyzePromptResponse(request_id=greq.request_id,layers=[rb.RuntimeLayerExecution(layer=rb.DETECTION_LAYER_SEMANTIC,status='error',error='synthetic not found',semantic_presence_gate=trace)])
        value={'schema_version':1,'kind':'scratch-compatibility-raw-absence-v1','stream_request':packet['stream']['request'],
               'stream_status':'NOT_FOUND','stream_chunks':[],'presence':{'request':packet['presence']['request'],'response':p.frame(pres)},
               'gate':{'request':packet['gate']['request'],'response':p.frame(gres)}}
        raw=e.canonical(value);self.assertTrue(p.verify_absence(raw,p.sha(raw),c.SCRATCH_IDS[0])['absent_after_removal'])


@unittest.skipUnless(os.name=='posix','POSIX private I/O requires ROOT Linux')
class PrivateTests(unittest.TestCase):
    def test_exclusive_private_bytes_and_mode_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);path.chmod(0o700);directory=p.PrivateDirectory(path)
            try:
                ref=directory.write('test.json',b'private synthetic marker')
                with self.assertRaises(FileExistsError):directory.write('test.json',b'different')
                (path/'test.json').chmod(0o644)
                with self.assertRaises(p.CompatibilityError):directory.read('test.json',ref['sha256'])
            finally:directory.close()

    def test_same_bytes_new_inode_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);path.chmod(0o700);directory=p.PrivateDirectory(path)
            real=p.os.fsync;done=False
            def replace(fd):
                nonlocal done
                real(fd)
                if not done and (path/'test.json').exists():
                    done=True;replacement=path/'replacement';replacement.write_bytes(b'private');replacement.chmod(0o600);replacement.replace(path/'test.json')
            try:
                with patch.object(p.os,'fsync',side_effect=replace):
                    with self.assertRaises(p.CompatibilityError):directory.write('test.json',b'private')
            finally:directory.close()


    def test_install_atomic_collision_preserves_foreign_and_failed_temp(self):
        import fcntl
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);path.chmod(0o700)
            directory=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            fcntl.flock(directory,fcntl.LOCK_EX)
            temp='.failed-artifact';fd=os.open(temp,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600,dir_fd=directory)
            os.write(fd,b'owned artifact');os.fsync(fd)
            real_link=p.os.link
            def collide(src,dst,**kwargs):
                foreign=path/dst;foreign.write_bytes(b'foreign artifact');foreign.chmod(0o600)
                return real_link(src,dst,**kwargs)
            try:
                with patch.object(p.os,'link',side_effect=collide):
                    with self.assertRaises(FileExistsError):p.publish_no_replace(directory,temp,'model.json',fd,b'owned artifact')
                self.assertEqual((path/'model.json').read_bytes(),b'foreign artifact')
                self.assertEqual((path/temp).read_bytes(),b'owned artifact')
            finally:os.close(fd);os.close(directory)

    def test_remove_interposed_same_byte_replacement_preserves_foreign_inode(self):
        import fcntl
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);path.chmod(0o700);named=path/'model.json';named.write_bytes(b'owned');named.chmod(0o600)
            directory=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fcntl.flock(directory,fcntl.LOCK_EX)
            original=p._read_held_file;replaced=False;foreign_inode=None
            def replace_after_capture(fd):
                nonlocal replaced,foreign_inode
                raw=original(fd)
                if not replaced:
                    replaced=True;foreign=path/'foreign';foreign.write_bytes(b'owned');foreign.chmod(0o600);foreign.replace(named);foreign_inode=named.stat().st_ino
                return raw
            try:
                with patch.object(p,'_read_held_file',side_effect=replace_after_capture):
                    with self.assertRaises(p.CompatibilityError):p.remove_committed(directory,'model.json',p.sha(b'owned'))
                self.assertEqual(named.read_bytes(),b'owned');self.assertEqual(named.stat().st_ino,foreign_inode)
            finally:os.close(directory)

    def test_owned_publication_and_removal_hold_original_inode(self):
        import fcntl
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);path.chmod(0o700);directory=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            fcntl.flock(directory,fcntl.LOCK_EX)
            fd=os.open('.temporary',os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600,dir_fd=directory)
            try:
                os.write(fd,b'owned');os.fsync(fd);inode=os.fstat(fd).st_ino
                p.publish_no_replace(directory,'.temporary','model.json',fd,b'owned')
                self.assertEqual((path/'model.json').stat().st_ino,inode)
                self.assertFalse((path/'.temporary').exists())
                p.remove_committed(directory,'model.json',p.sha(b'owned'))
                self.assertFalse((path/'model.json').exists())
            finally:os.close(fd);os.close(directory)


if __name__=='__main__':unittest.main()