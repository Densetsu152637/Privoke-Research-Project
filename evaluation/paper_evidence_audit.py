"""Hash-bound descriptive analysis of opened PIPE3 evidence; never reads final data."""
from __future__ import annotations
import argparse
import base64
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import sys
import numpy as np

PIPE_PROTOCOL = '938f626bec9b5810a34e6e9f33d1d28f0070fbc10ac6a570e568b41c39346ed7'
RAW_INVENTORY = 'd68f9cb08b4d3f16db396a4f3fea4c5c8764803c3a387ff87719f637e7184da7'
DATA_MANIFEST = '41cfd9e476f3d0a17c2a4997efab2afbb6b044c5fbd55217b0614525a2571fe0'
PRESIDIO_RAW = 'ce72efabc79cf4f58edda618acc7bf05790f7ecd0d2b197c73593a0aca4984d3'

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)+'\n').encode()

def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def require(value, message):
    if not value:
        raise ValueError(message)

def read_bound(path, expected):
    require(sha(path) == expected, 'Input SHA256 differs: '+str(path))
    return json.loads(Path(path).read_bytes())

def retained(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as f:
        f.write(canonical(value))

def reliability(scores, correct):
    """Heuristic bins only: scores have no asserted probability interpretation."""
    require(len(scores) == len(correct), 'Confidence pairing differs')
    bins = []
    for lower in range(10):
        indices = [i for i, score in enumerate(scores) if min(int(score*10), 9) == lower]
        bins.append({'lower':lower/10, 'upper':(lower+1)/10, 'count':len(indices),
                     'mean_score':float(np.mean([scores[i] for i in indices])) if indices else None,
                     'correct_fraction':float(np.mean([correct[i] for i in indices])) if indices else None})
    return {'n':len(scores), 'bins':bins, 'meaning':'heuristic_score_vs_observed_correctness_not_probability_calibration',
            'ece':None, 'brier':None, 'probability_metrics_unavailable':'Wire confidence is a maximum of unrelated head probabilities, not P(presence) or P(full correctness).'}

def scores(truth, prediction, valid):
    truth, prediction, valid = (np.asarray(x, dtype=bool) for x in (truth, prediction, valid))
    tp = int(np.sum(truth & prediction & valid)); fn = int(np.sum(truth & ~prediction & valid))
    tn = int(np.sum(~truth & ~prediction & valid)); fp = int(np.sum(~truth & prediction & valid))
    pos = int(truth.sum()); neg = len(truth)-pos
    recall = tp/pos if pos else None; specificity = tn/neg if neg else None
    return {'rows':len(truth), 'positive':pos, 'negative':neg, 'errors':int((~valid).sum()),
            'successful_confusion':{'tp':tp,'fn':fn,'tn':tn,'fp':fp},
            'recall_full_denominator':recall,'specificity_full_denominator':specificity,
            'accuracy_errors_incorrect':(tp+tn)/len(truth) if len(truth) else None,
            'balanced_accuracy_errors_incorrect':(recall+specificity)/2 if pos and neg else None}

def paired_bootstrap(truth, predictions, valid, groups, *, iterations=2000, seed=42):
    """Whole clusters, common draws across every arm, row-weighted rates."""
    require(iterations > 0 and len(truth) == len(groups), 'Invalid bootstrap settings')
    names = sorted(predictions); keys = sorted(set(groups))
    require(len(keys) >= 2, 'At least two clusters required')
    truth = np.asarray(truth, dtype=bool)
    members = [np.flatnonzero(np.asarray(groups) == k) for k in keys]
    totals = np.zeros((len(keys), len(names), 5), dtype=np.int64)
    for c, idx in enumerate(members):
        for a, name in enumerate(names):
            p=np.asarray(predictions[name], dtype=bool)[idx]; v=np.asarray(valid[name],dtype=bool)[idx]; t=truth[idx]
            totals[c,a]=[int((t&p&v).sum()),int((~t&~p&v).sum()),int(t.sum()),int((~t).sum()),len(idx)]
    draws=np.random.default_rng(seed).integers(0,len(keys),size=(iterations,len(keys)))
    sampled=totals[draws].sum(axis=1)
    metrics={'recall':(0,2),'specificity':(1,3),'accuracy':(None,4)}
    output={}
    for metric,(numerator,denominator) in metrics.items():
        nums=sampled[:,:,0]+sampled[:,:,1] if numerator is None else sampled[:,:,numerator]
        den=sampled[:,:,denominator]; values=np.divide(nums,den,out=np.full(nums.shape,np.nan),where=den>0)
        output[metric]={}
        for a,name in enumerate(names):
            data=values[:,a]; supported=np.isfinite(data)
            output[metric][name]={'valid_replicates':int(supported.sum()),'undefined_replicates':int((~supported).sum()),
                                 'interval95':np.quantile(data[supported],[.025,.975],method='linear').tolist() if supported.any() else None}
        output[metric]['paired_differences']={}
        for a,b in ((i,j) for i in range(len(names)) for j in range(i+1,len(names))):
            delta=values[:,b]-values[:,a]; supported=np.isfinite(delta)
            output[metric]['paired_differences'][names[b]+' minus '+names[a]]={
                'valid_replicates':int(supported.sum()),'undefined_replicates':int((~supported).sum()),
                'interval95':np.quantile(delta[supported],[.025,.975],method='linear').tolist() if supported.any() else None}
    return {'clusters':len(keys),'cluster_sizes':dict(Counter(len(v) for v in members)), 'seed':seed,'iterations':iterations,
            'method':'paired_whole_cluster_row_weighted_percentile_linear', 'metrics':output}

def journal(path):
    calls={}; previous='0'*64
    for sequence,line in enumerate(Path(path).read_bytes().splitlines()):
        event=json.loads(line); claimed=event.pop('sha256')
        require(event['sequence']==sequence and event['previous']==previous and hashlib.sha256(canonical(event)).hexdigest()==claimed,'Journal chain differs')
        previous=claimed; key=event['request_id']
        if event['kind']=='reserve':
            require(key not in calls and all('terminal' in c for c in calls.values()),'Duplicate/unresolved reservation')
            wire=base64.b64decode(event['request_pb'],validate=True)
            require(hashlib.sha256(wire).hexdigest()==event['request_sha256'],'Request hash differs')
            calls[key]={'reserve':event}
        else:
            require(event['kind']=='terminal' and key in calls and 'terminal' not in calls[key],'Invalid terminal')
            require(('response_pb' in event)!=('transport_error' in event),'Missing/conflicting outcome')
            if 'response_pb' in event:
                wire=base64.b64decode(event['response_pb'],validate=True)
                require(hashlib.sha256(wire).hexdigest()==event['response_sha256'],'Response hash differs')
            calls[key]['terminal']=event
    require(all('terminal' in c for c in calls.values()),'Unresolved outcome')
    return calls

def opened_pipe3(root):
    root=Path(root); results=root/'evaluation/results/pipeline_v1_v3_20261014/runs/cpu-01'
    protocol=read_bound(results/'protocol.json',PIPE_PROTOCOL)
    inventory=read_bound(results/'raw-inventory.json',RAW_INVENTORY)
    manifest=read_bound(Path(protocol['data_manifest']),DATA_MANIFEST)
    item=manifest['files']['fresh_eval']; data=Path(protocol['data_manifest']).parent/item['path']
    require(sha(data)==item['sha256'],'Opened FRESH changed')
    rows=[json.loads(l) for l in data.read_bytes().splitlines() if l]
    require(len(rows)==1560 and len({r['id'] for r in rows})==1560,'FRESH ID/count mismatch')
    for relative in ('extension/client-runtime/generated','shared/python'):
        sys.path.insert(0,str(root/relative))
    from privoke.v1 import runtime_pb2 as pb
    from privoke_contracts.classification import Classification
    records={}; confidence={}; observed={}
    for entry in protocol['entries']:
        name=entry['name']; rel='models/'+name+'/raw.jsonl'; require(sha(results/rel)==inventory[rel],'Raw inventory differs')
        calls=journal(results/rel); require(len(calls)==3*1560+4,'Journal call count differs')
        selected=sorted((c for c in calls.values() if c['reserve']['repeat']==0 and not c['reserve']['warmup']),key=lambda c:c['reserve']['index'])
        require(len(selected)==1560,'First-pass count differs')
        values=[]; cs=[]; sensitivity_correct=[]; categories_correct=[]; layer_counts=Counter()
        for index,(row,call) in enumerate(zip(rows,selected)):
            reserve,terminal=call['reserve'],call['terminal']
            require((reserve['index'],reserve['case_id'],reserve['model'])==(index,row['id'],name),'Raw case binding differs')
            request=pb.AnalyzePromptRequest.FromString(base64.b64decode(reserve['request_pb']))
            require(request.text==row['text'] and list(request.layers)==[2,3,4] and request.semantic_model_id==entry['identity']['model_id'],'Product stimulus differs')
            require('response_pb' in terminal,'Archived transport error')
            response=pb.AnalyzePromptResponse.FromString(base64.b64decode(terminal['response_pb']))
            require(response.request_id==request.request_id and [l.layer for l in response.layers]==[2,3,4],'Response identity/layers differ')
            require(not response.error and all(l.status in ('ok','skipped') and (not l.error or l.status=='skipped') for l in response.layers),'Archived layer/runtime error')
            statuses=tuple(l.status for l in response.layers); require(statuses in (('ok','ok','ok'),('ok','skipped','skipped')),'Invalid cascade status')
            if statuses[1]=='skipped':
                require(any(r.action=='BLOCK' for r in response.layers[0].results) and all(not l.results and l.error=='Skipped after regex returned BLOCK.' for l in response.layers[1:]),'Invalid skip')
            else:
                for key,value in entry['identity'].items():
                    if key in ('model_id','model_version','artifact_checksum','parameter_fingerprint'):
                        require(response.metadata.get('privoke.semantic.'+key)==value,'Semantic identity differs')
            for l in response.layers: layer_counts[str(l.layer)+':'+l.status]+=1
            value=Classification(response.classification.packed).to_dict()
            require(value=={'sensitivity':response.classification.sensitivity,'visibility':response.classification.visibility,'categories':list(response.classification.categories)},'Packed/named mismatch')
            require(response.action in ('ALLOW','WARN','BLOCK'),'Invalid action')
            values.append({'id':row['id'],'classification':value,'action':response.action,'valid':True})
            if statuses[2]=='ok':
                if len(response.layers[2].results)!=1:
                    continue
                result=response.layers[2].results[0]
                if result.has_confidence:
                    require(math.isfinite(result.confidence) and 0<=result.confidence<=1,'Invalid confidence')
                    cs.append(result.confidence)
                    sensitivity_correct.append(result.classification.sensitivity==row['classification']['sensitivity'])
                    categories_correct.append(set(result.classification.categories)==set(row['classification']['categories']))
        records[name]=values; observed[name]=dict(layer_counts)
        confidence[name]={'sensitivity_exact':reliability(cs,sensitivity_correct),'category_set_exact':reliability(cs,categories_correct),
                          'conditional_scope':'semantic_executed_only; regex early-block skips have no semantic confidence'}
    return protocol,rows,records,confidence,observed

def provenance(root,protocol):
    root=Path(root); source=Counter(); differences=[]
    for relative,expected in protocol['source_files'].items():
        path=root/relative
        state='missing' if not path.is_file() else ('matches' if sha(path)==expected else 'changed')
        source[state]+=1
        if state!='matches': differences.append({'path':relative,'status':state,'expected':expected,'actual':sha(path) if path.is_file() else None})
    models={}
    for entry in protocol['entries']:
        models[entry['name']]={relative:('matches' if (Path(entry['directory'])/relative).is_file() and sha(Path(entry['directory'])/relative)==expected else 'missing_or_changed') for relative,expected in entry['assets'].items()}
    return {'source_closure':protocol['source_closure'],'source_status_counts':dict(source),'source_differences':differences,
            'model_assets':models,'clean_room_inference':'requires ignored pinned assets and actual historical source closure; Git HEAD alone is insufficient',
            'protected_final_access':False}

def analyze(root,output):
    protocol,rows,records,confidence,observed=opened_pipe3(root)
    truth=[r['classification']['sensitivity']!='S0' or bool(r['classification']['categories']) for r in rows]
    predictions={n:[r['classification']['sensitivity']!='S0' or bool(r['classification']['categories']) for r in values] for n,values in records.items()}
    valid={n:[r['valid'] for r in values] for n,values in records.items()}
    presidio_path=Path(root)/'evaluation/results/paper_revision_20261014/presidio-au3/raw.json'
    baseline=read_bound(presidio_path,PRESIDIO_RAW)['predictions']
    require([r['example_id'] for r in baseline]==[r['id'] for r in rows] and [r['expected_has_pii'] for r in baseline]==truth,'Presidio pairing differs')
    predictions['presidio-small']=[bool(r.get('detected_sensitive')) for r in baseline]; valid['presidio-small']=[r['status']=='ok' for r in baseline]
    result={'schema':1,'study_id':'paper-completion-saved-analysis-20261014','inputs':{'protocol':PIPE_PROTOCOL,'raw_inventory':RAW_INVENTORY,'data_manifest':DATA_MANIFEST,'presidio_small_raw':PRESIDIO_RAW},
            'scope':'opened reused assistant-provisional AU3 product cases; post-hoc descriptive', 'rows':len(rows),
            'metrics':{n:scores(truth,predictions[n],valid[n]) for n in predictions},'actual_layers':observed,'confidence_diagnostics':confidence,
            'uncertainty':{field:paired_bootstrap(truth,predictions,valid,[r['family_id'] if field=='family_id' else r['metadata'][field] for r in rows]) for field in ('family_id','audience_expression_group_id')},
            'provenance':provenance(root,protocol),'limitations':['No independent external or human-label validation.','Family/expression intervals separately assess dependence, not crossed independence.','Three passes are repeatability, not4680 independent cases.','Confidence bins are heuristics, no ECE/Brier/probability calibration claim.','All comparisons are descriptive post-hoc; no configuration selection.','Presidio native entity ontology differs from contextual-sensitive truth.']}
    retained(output,result)
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--evidence-root',type=Path,required=True); p.add_argument('--output',type=Path,required=True)
    a=p.parse_args(); result=analyze(a.evidence_root,a.output)
    print(json.dumps({'output':str(a.output),'sha256':sha(a.output),'rows':result['rows'],'protected_final_access':False}))

if __name__=='__main__': main()
