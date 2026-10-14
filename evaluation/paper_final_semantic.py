"""Frozen sole-semantic host RPC probe and once-only final evaluator."""
from __future__ import annotations
import argparse
import base64
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import gc
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from paper_evidence_audit import canonical, sha, require, read_bound, retained, paired_bootstrap, scores

THREADS=('OMP_NUM_THREADS','MKL_NUM_THREADS','OPENBLAS_NUM_THREADS','NUMEXPR_NUM_THREADS','BLIS_NUM_THREADS')
for key in THREADS: os.environ[key]='4'
os.environ.update(MODEL_STREAMING_CACHE_TTL_SECONDS='604800',PRIVOKE_LLM_CHOICE='streamed',LLM_CHOICE='streamed',PRIVOKE_MODEL_DEVICE='cpu',HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1')
SYNTHETIC=('A fictional story describes a quiet meadow.', 'My diagnosis is cancer and this is private.', 'My name is Jane Example and I live in Exampletown.', 'This imaginary password is abc-def-123.')

def configure(root):
    root=Path(root)
    for relative in ('evaluation','shared/python','extension/client-runtime/generated','extension/client-runtime','services/pretrained-v3/src','services/privoke-fuzzer/src'):
        sys.path.insert(0,str(root/relative))
    import torch
    torch.set_num_threads(4);torch.use_deterministic_algorithms(True)
    return root

def verify(freeze, worktree):
    root=Path(freeze['evidence_root'])
    for relative,expected in freeze['runtime_source_files'].items():
        require(sha(root/relative)==expected,'Frozen runtime dependency changed: '+relative)
    for relative,expected in freeze['new_executable_sources'].items():
        require(sha(Path(worktree)/relative)==expected,'Frozen evaluation dependency changed: '+relative)
    for entry in freeze['packages'].values():
        for item in entry['assets'].values():require(sha(item['path'])==item['sha256'],'Frozen model asset changed')
    return root

def response_record(response,request,entry):
    require(response.request_id==request.request_id,'Response request identity mismatch')
    require([l.layer for l in response.layers]==[4],'Actual execution is not sole semantic')
    require(not response.error and response.layers[0].status=='ok' and not response.layers[0].error,'Semantic runtime/layer error')
    for key in ('model_id','model_version','artifact_checksum','parameter_fingerprint'):
        require(response.metadata.get('privoke.semantic.'+key)==entry['identity'][key],'Returned package identity differs')
    from privoke_contracts.classification import Classification
    value=Classification(response.classification.packed).to_dict()
    require(value=={'sensitivity':response.classification.sensitivity,'visibility':response.classification.visibility,'categories':list(response.classification.categories)},'Packed/named classification mismatch')
    return {'valid':True,'positive':value['sensitivity']!='S0' or bool(value['categories']),'classification':value,'action':response.action,'actual_layers':[4],'identity':entry['identity']}

def serve(freeze_path,name,ready,worktree):
    freeze=json.loads(Path(freeze_path).read_bytes());root=verify(freeze,worktree);configure(root)
    import grpc
    from privoke.v1 import runtime_pb2_grpc
    from privoke_eval.pipeline_v1_v3_serving import load_semantic
    from src.config import GLOBAL_CONFIG
    from src.LLM.privoke.parameter_stream import ModelParameterStreamer
    from src.LLM.privoke.streamed_model import GLOBAL_STREAMED_MODEL_CACHE, _CachedModel
    from src.hosting.grpc_server import PrivokeRuntimeService
    entry=freeze['packages'][name];entry={**entry,'assets':{k:v['sha256'] for k,v in entry['assets'].items()}}
    semantic=load_semantic(entry);GLOBAL_CONFIG.llm_choice='streamed'
    streamer=ModelParameterStreamer(model_id=entry['identity']['model_id']);cache_key=(streamer.target,streamer.model_id)
    GLOBAL_STREAMED_MODEL_CACHE.clear();GLOBAL_STREAMED_MODEL_CACHE._models[cache_key]=_CachedModel(entry['identity']['parameter_fingerprint'],semantic,time.monotonic())
    require(GLOBAL_STREAMED_MODEL_CACHE.refresh_interval_seconds==604800,'Cache TTL differs')
    class ReadOnlySemantic(PrivokeRuntimeService):
        def AnalyzePrompt(self,request,context):
            if list(request.layers)!=[4] or request.semantic_model_id!=entry['identity']['model_id'] or request.visibility_hint or request.HasField('semantic_presence_gate'):
                context.abort(grpc.StatusCode.INVALID_ARGUMENT,'Frozen sole-semantic model/no-hint/no-gate request required')
            cached=GLOBAL_STREAMED_MODEL_CACHE._models.get(cache_key)
            if cached is None or cached.model is not semantic or time.monotonic()-cached.refreshed_at>604680:
                context.abort(grpc.StatusCode.FAILED_PRECONDITION,'Pinned cache unavailable; remote fallback prohibited')
            return super().AnalyzePrompt(request,context)
        def deny(self,request,context):context.abort(grpc.StatusCode.UNIMPLEMENTED,'Frozen inference-only endpoint')
        ComputeSemanticGradients=deny;ComputeUnderlyingModelGradients=deny;ComputePresenceGradients=deny;DetectAnnotationPresence=deny
    server=grpc.server(ThreadPoolExecutor(max_workers=1));runtime_pb2_grpc.add_PrivokeRuntimeServiceServicer_to_server(ReadOnlySemantic(),server)
    token=sha(freeze_path).encode()
    def stop(request,context):
        if request!=token:context.abort(grpc.StatusCode.PERMISSION_DENIED,'Wrong run commitment')
        threading.Timer(.1,lambda:server.stop(2)).start();return b'stopping'
    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler('privoke.research.FrozenFinal',{'Stop':grpc.unary_unary_rpc_method_handler(stop)}),))
    require(server.add_insecure_port('127.0.0.1:'+str(freeze['inference']['port'])),'Private port unavailable')
    server.start();retained(ready,{'name':name,'pid':os.getpid(),'freeze_sha256':sha(freeze_path),'identity':entry['identity'],'actual_layer_contract':[4],'training_disabled':True,'remote_fallback_disabled':True})
    try:server.wait_for_termination()
    finally:server.stop(2).wait();retained(Path(ready).with_suffix('.stopped.json'),{'name':name,'pid':os.getpid(),'status':'stopped'})

def metric_with_f(truth,pred,valid):
    result=scores(truth,pred,valid);c=result['successful_confusion']
    positive_errors=sum(bool(t) and not v for t,v in zip(truth,valid));negative_errors=sum(not t and not v for t,v in zip(truth,valid))
    tp,fp,fn=c['tp'],c['fp']+negative_errors,c['fn']+positive_errors
    result.update(errors_by_truth={'positive':positive_errors,'negative':negative_errors},error_penalized_f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None,error_penalized_f2=5*tp/(5*tp+fp+4*fn) if 5*tp+fp+4*fn else None,
                  f_error_convention='positive errors add FN; negative errors add FP; successful confusion preserved separately')
    return result

def call_rpc(stub,request,entry):
    terminal={}
    try:
        response=stub.AnalyzePrompt(request,timeout=120);wire=response.SerializeToString(deterministic=True)
        terminal={'response_pb':base64.b64encode(wire).decode(),'response_sha256':hashlib.sha256(wire).hexdigest()}
        record=response_record(response,request,entry)
    except Exception as exc:
        terminal={**terminal,'error':type(exc).__name__+': '+str(exc)}
        record={'valid':False,'positive':False,'error':terminal['error']}
    return terminal,record

def collect_rpc(freeze_path,freeze,root,rows,output,worktree,probe):
    import grpc
    from privoke.v1 import runtime_pb2 as pb,runtime_pb2_grpc
    results={};port=freeze['inference']['port'];target='127.0.0.1:'+str(port)
    for name,entry in sorted(freeze['packages'].items()):
        arm=Path(output)/name;arm.mkdir();ready=arm/'ready.json';log=(arm/'server.log').open('xb')
        command=[sys.executable,'-u',str(Path(__file__)), 'serve','--freeze',str(freeze_path),'--name',name,'--output',str(ready),'--worktree',str(worktree)]
        proc=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT,cwd=root)
        channel=None;records=[];failure=None
        try:
            deadline=time.monotonic()+300
            while not ready.exists():
                require(proc.poll() is None,'Host model server failed; inspect retained log')
                require(time.monotonic()<deadline,'Host model load exceeded300s cap');time.sleep(.1)
            ready_value=json.loads(ready.read_bytes());require(ready_value['name']==name and ready_value['freeze_sha256']==sha(freeze_path),'Ready identity differs')
            channel=grpc.insecure_channel(target);grpc.channel_ready_future(channel).result(timeout=15);stub=runtime_pb2_grpc.PrivokeRuntimeServiceStub(channel)
            with (arm/'raw.jsonl').open('xb') as journal:
                for index,row in enumerate(rows):
                    request=pb.AnalyzePromptRequest(request_id='fn14-'+hashlib.sha256(canonical([sha(freeze_path),name,row['id']])).hexdigest()[:40],text=row['text'],source='paper-final-semantic' if not probe else 'paper-synthetic-probe',layers=[4],semantic_model_id=entry['identity']['model_id'])
                    request_bytes=request.SerializeToString(deterministic=True)
                    journal.write(canonical({'kind':'reserve','index':index,'id':row['id'],'request_pb':base64.b64encode(request_bytes).decode(),'request_sha256':hashlib.sha256(request_bytes).hexdigest()}));journal.flush()
                    start=time.perf_counter()
                    terminal,record=call_rpc(stub,request,entry)
                    record.update(id=row['id'],elapsed_ms=(time.perf_counter()-start)*1000)
                    journal.write(canonical({'kind':'terminal','index':index,'id':row['id'],**terminal,'record':record}));journal.flush();records.append(record)
            retained(arm/'complete.json',{'rows':len(records),'errors':sum(not r['valid'] for r in records),'raw_sha256':sha(arm/'raw.jsonl')})
            results[name]=records
        except BaseException as exc:failure=type(exc).__name__+': '+str(exc);raise
        finally:
            if channel is not None:
                try:channel.unary_unary('/privoke.research.FrozenFinal/Stop')(sha(freeze_path).encode(),timeout=5)
                except Exception:pass
                channel.close()
            try:proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.terminate();proc.wait(timeout=10)
            log.close();retained(arm/'terminal.json',{'pid':proc.pid,'exit_code':proc.returncode,'failure':failure,'rows_completed':len(records)})
        print(name+' completed '+str(len(records))+' rows; errors='+str(sum(not r['valid'] for r in records)),flush=True)
    return results

def evaluate(freeze_path,output,worktree,*,release=None,probe=False):
    freeze=json.loads(Path(freeze_path).read_bytes());root=verify(freeze,worktree);configure(root)
    require(not Path(output).exists(),'Existing output prohibited; unknown attempts are never replayed')
    if probe:
        rows=[{'id':'synthetic-'+str(i),'text':text,'expected_has_pii':False,'group_id':'synthetic-'+str(i)} for i,text in enumerate(SYNTHETIC)]
    else:
        require(release is not None,'Root/critic release required before final access')
        accepted=json.loads(Path(release).read_bytes())
        require(accepted.get('status')=='accepted_for_once_only_final' and accepted.get('freeze_sha256')==sha(freeze_path),'Release does not bind accepted freeze')
        probe_receipt=accepted.get('synthetic_probe',{})
        probe_evidence=read_bound(probe_receipt['path'],probe_receipt['sha256'])
        require(probe_evidence['status']=='passed' and probe_evidence['freeze_sha256']==sha(freeze_path) and probe_evidence['synthetic_only'] is True and probe_evidence['rows_per_arm']==4 and set(probe_evidence['arms'])==set(freeze['packages']),'Synthetic probe does not bind freeze')
        require(sha(freeze['gate_receipts']['training_protection']['path'])==freeze['gate_receipts']['training_protection']['sha256'],'Protection gate changed')
        require(sha(freeze['gate_receipts']['synthetic_tests']['path'])==freeze['gate_receipts']['synthetic_tests']['sha256'],'Synthetic gate changed')
        data=freeze['data'];path=Path(data['path']);require(sha(path)==data['expected_sha256'],'Protected final bytes differ')
        rows=[json.loads(l) for l in path.read_bytes().splitlines() if l]
        require(len(rows)==498 and all(type(r['expected_has_pii']) is bool for r in rows) and sum(r['expected_has_pii'] for r in rows)==236,'Final class/count/schema differs')
    require(len({r['id'] for r in rows})==len(rows),'Duplicate evaluation IDs')
    retained(Path(output)/'reservation.json',{'freeze_sha256':sha(freeze_path),'probe':probe,'rows':len(rows),'utc_seconds':time.time()})
    results=collect_rpc(freeze_path,freeze,root,rows,output,worktree,probe)
    if probe:
        require(all(all(r['valid'] for r in records) for records in results.values()),'Synthetic probe did not achieve sole-layer/identity success')
        result={'status':'passed','freeze_sha256':sha(freeze_path),'synthetic_only':True,'rows_per_arm':len(rows),'arms':list(results),'raw_commitments':{n:sha(Path(output)/n/'raw.jsonl') for n in results}}
    else:
        truth=[r['expected_has_pii'] for r in rows];pred={n:[r['positive'] for r in records] for n,records in results.items()};valid={n:[r['valid'] for r in records] for n,records in results.items()}
        raw_groups=[str(r.get('group_id') or r['id']) for r in rows]
        sources=[str(r.get('metadata',{}).get('source_dataset') or r.get('source_dataset') or 'namespace_unavailable') for r in rows]
        namespaces=[s+'\0'+g for s,g in zip(sources,raw_groups)]
        collisions=defaultdict(set)
        for group,source in zip(raw_groups,sources):collisions[group].add(source)
        result={'status':'complete','freeze_sha256':sha(freeze_path),'data_sha256':freeze['data']['expected_sha256'],'rows':len(rows),'metrics':{n:metric_with_f(truth,pred[n],valid[n]) for n in results},
                'group_audit':{'historical_raw_groups':len(set(raw_groups)),'namespaced_groups':len(set(namespaces)),'raw_groups_with_multiple_source_namespaces':sum(len(v)>1 for v in collisions.values()),'rows_without_namespace':sources.count('namespace_unavailable'),'source_rows':dict(Counter(sources)),
                               'raw_cluster_size_distribution':dict(Counter(Counter(raw_groups).values())),'namespaced_cluster_size_distribution':dict(Counter(Counter(namespaces).values()))},
                'uncertainty':{'historical_raw_group':paired_bootstrap(truth,pred,valid,raw_groups),'supplied_source_namespaced_group':paired_bootstrap(truth,pred,valid,namespaces)},
                'paired_within_tier':{tier:{'correctness_gained':sum(vb and b==t and (not va or a!=t) for t,a,b,va,vb in zip(truth,pred['v1-'+tier],pred['v3-'+tier],valid['v1-'+tier],valid['v3-'+tier])),
                                           'correctness_lost':sum(va and a==t and (not vb or b!=t) for t,a,b,va,vb in zip(truth,pred['v1-'+tier],pred['v3-'+tier],valid['v1-'+tier],valid['v3-'+tier]))} for tier in ('efficient','balanced','quality')},
                'limitations':['Official annotation-presence target, not contextual privacy/action ground truth.','All contrasts descriptive with unadjusted95% intervals; no familywise confirmatory claim.','Source metadata grouping is an observed key convention, not certified template/document independence.','No tuning, reselection or promotion follows final failures.']}
    retained(Path(output)/'analysis.json',result);return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('serve','probe','evaluate'));p.add_argument('--freeze',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--worktree',type=Path,default=Path(__file__).resolve().parents[1]);p.add_argument('--name');p.add_argument('--release',type=Path)
    a=p.parse_args()
    if a.action=='serve':serve(a.freeze,a.name,a.output,a.worktree)
    else:
        result=evaluate(a.freeze,a.output,a.worktree,release=a.release,probe=a.action=='probe');print(json.dumps({'output':str(a.output),'sha256':sha(a.output/'analysis.json'),'status':result['status']}))

if __name__=='__main__':main()
