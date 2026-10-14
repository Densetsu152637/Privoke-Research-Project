"""Authorized postcompletion read-only final audit; emits no prompts/original IDs."""
import argparse
import base64
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys
from paper_evidence_audit import read_bound,sha,retained,require,canonical

ANALYSIS_SHA='986715007d427ef9b11ebb265e21377eba1ccf24a482bfc1195849f40cae402f'

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--evidence-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--projection',type=Path,required=True);p.add_argument('--publish',type=Path,required=True)
    a=p.parse_args();root=a.evidence_root;results=root/'evaluation/results/paper_completion_20261014/final-semantic-01'
    analysis=read_bound(results/'analysis.json',ANALYSIS_SHA)
    freeze=read_bound(root/'evaluation/results/paper_completion_20261014/final-freeze-03.json',analysis['freeze_sha256'])
    data=Path(freeze['data']['path']);require(sha(data)==freeze['data']['expected_sha256'],'Released data digest changed')
    rows=[]
    for line in data.read_bytes().splitlines():
        if not line:continue
        source=json.loads(line)
        rows.append({'id':source['id'],'truth':source['expected_has_pii'],'group':str(source.get('group_id') or source['id']),
                     'source':str(source.get('metadata',{}).get('source_dataset') or source.get('source_dataset') or 'namespace_unavailable')})
    require(len(rows)==498 and sum(r['truth'] for r in rows)==236,'Released class/count mismatch')
    for relative in ('extension/client-runtime/generated','shared/python'):sys.path.insert(0,str(root/relative))
    from privoke.v1 import runtime_pb2 as pb
    from privoke_contracts.classification import Classification
    rawrank={g:'g'+str(i).zfill(6) for i,g in enumerate(sorted({r['group'] for r in rows}))}
    nsrank={g:'n'+str(i).zfill(6) for i,g in enumerate(sorted({r['source']+'\0'+r['group'] for r in rows}))}
    projected=[{'index':i,'opaque_id':hashlib.sha256(r['id'].encode()).hexdigest(),'truth':r['truth'],'historical_raw_group':rawrank[r['group']],
                'supplied_source_namespaced_group':nsrank[r['source']+'\0'+r['group']],'source':r['source'],'models':{}} for i,r in enumerate(rows)]
    receipts={};slices={}
    for name,entry in freeze['packages'].items():
        arm=results/name;events=[json.loads(l) for l in (arm/'raw.jsonl').read_bytes().splitlines() if l]
        require(len(events)==996,'Raw event denominator mismatch');counts=Counter();sourcecounts=defaultdict(Counter)
        for i,row in enumerate(rows):
            reserve,terminal=events[2*i:2*i+2]
            require(reserve['kind']=='reserve' and terminal['kind']=='terminal' and reserve['index']==terminal['index']==i and reserve['id']==terminal['id']==row['id'],'Raw case pairing differs')
            request_bytes=base64.b64decode(reserve['request_pb'],validate=True);response_bytes=base64.b64decode(terminal['response_pb'],validate=True)
            require(hashlib.sha256(request_bytes).hexdigest()==reserve['request_sha256'] and hashlib.sha256(response_bytes).hexdigest()==terminal['response_sha256'],'Raw wire digest differs')
            request=pb.AnalyzePromptRequest.FromString(request_bytes);response=pb.AnalyzePromptResponse.FromString(response_bytes)
            require(list(request.layers)==[4] and request.semantic_model_id==entry['identity']['model_id'] and not request.visibility_hint and not request.HasField('semantic_presence_gate'),'Request layer/model/no-hint contract differs')
            expected_request='fn14-'+hashlib.sha256(canonical([analysis['freeze_sha256'],name,row['id']])).hexdigest()[:40]
            require(request.request_id==response.request_id==expected_request,'Request/case identity differs')
            require([l.layer for l in response.layers]==[4] and response.layers[0].status=='ok' and not response.layers[0].error and not response.error,'Actual sole-semantic execution differs')
            require(all(response.metadata.get('privoke.semantic.'+k)==entry['identity'][k] for k in ('model_id','model_version','artifact_checksum','parameter_fingerprint')),'Returned package identity differs')
            value=Classification(response.classification.packed).to_dict()
            require(value=={'sensitivity':response.classification.sensitivity,'visibility':response.classification.visibility,'categories':list(response.classification.categories)},'Packed/named classification mismatch')
            positive=value['sensitivity']!='S0' or bool(value['categories'])
            require(terminal['record']['valid'] is True and terminal['record']['positive']==positive,'Saved parsed projection differs')
            category=('t' if positive==row['truth'] else 'f')+('p' if positive else 'n');counts[category]+=1;sourcecounts[row['source']][category]+=1
            projected[i]['models'][name]={'positive':positive,'valid':True}
        require(dict(counts)==analysis['metrics'][name]['successful_confusion'],'Independent confusion differs')
        complete=json.loads((arm/'complete.json').read_bytes());terminal=json.loads((arm/'terminal.json').read_bytes());stopped=json.loads((arm/'ready.stopped.json').read_bytes())
        require(complete['rows']==498 and complete['errors']==0 and complete['raw_sha256']==sha(arm/'raw.jsonl'),'Raw completion commitment differs')
        require(terminal['exit_code']==0 and terminal['failure'] is None and stopped['status']=='stopped','Model process cleanup differs')
        receipts[name]={'raw_sha256':sha(arm/'raw.jsonl'),'requested_semantic_only':498,'actual_successful_sole_semantic':498,'verified_identity':498,'errors':0,'confusion':dict(counts),'process_exit_code':0}
        slices[name]={source:{'rows':sum(c.values()),'positive':c['tp']+c['fn'],'negative':c['tn']+c['fp'],'successful_confusion':{k:c[k] for k in ('tp','tn','fp','fn')}} for source,c in sourcecounts.items()}
    a.projection.parent.mkdir(parents=True,exist_ok=True)
    with a.projection.open('xb') as f:
        for row in projected:f.write(canonical(row))
    groupclasses=defaultdict(set)
    for row in rows:groupclasses[row['group']].add(row['truth'])
    receipt={'schema':1,'status':'passed_independent_postcompletion_wire_decode_and_count_audit','analysis_sha256':ANALYSIS_SHA,'freeze_sha256':analysis['freeze_sha256'],'models':receipts,
             'projection_sha256':sha(a.projection),'projection_role':'restricted text-free truth/prediction/source and opaque-ID/group-rank projection; lexicographic ranks preserve original cluster draw ordering',
             'group_class_composition':dict(Counter('mixed' if len(v)>1 else ('positive_only' if True in v else 'negative_only') for v in groupclasses.values())),
             'source_slices':slices,'authorization':'Root explicitly extended postcompletion read-only raw-audit scope after automatic review rejection; no inference/rerun/tuning/promotion; no prompts/original IDs in outputs.'}
    retained(a.output,receipt);retained(a.publish,receipt)
    print({'audit_sha256':sha(a.output),'projection_sha256':sha(a.projection),'safe_audit_sha256':sha(a.publish)})

if __name__=='__main__':main()
