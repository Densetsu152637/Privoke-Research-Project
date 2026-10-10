"""Strict scope-aware reconciliation; failures and exposure remain separate."""
from __future__ import annotations
from collections import Counter
from pathlib import Path
import math
import hashlib
import json
import random
from collections import defaultdict
import sqlite3
from contextlib import closing
from privoke_eval.accelerated_training_surfaces_study import read,write,sha,digest,verify_protocol


def verify_trace(record, identity):
    executions=record.get('executions', record.get('layers',[]))
    if len(executions)!=1 or executions[0].get('layer') not in ('DETECTION_LAYER_SEMANTIC',4):
        raise ValueError('Exactly one actual semantic execution required')
    execution=executions[0]
    if execution.get('status')!='ok' or execution.get('error'):
        raise ValueError('Semantic execution failed')
    actual=record.get('identity',execution.get('identity'))
    if actual!=identity:
        raise ValueError('Actual semantic model identity differs')


def paired_metrics(before,after,*,task,iterations=2000):
    a={r['id']:r for r in before};b={r['id']:r for r in after}
    if len(a)!=len(before) or len(b)!=len(after) or set(a)!=set(b):
        raise ValueError('Paired fixed denominator mismatch')
    for key in a:
        if a[key].get('target')!=b[key].get('target') or a[key].get('group_id')!=b[key].get('group_id'):
            raise ValueError('Assessment targets/groups changed')
    errors=sum(r.get('status')!='ok' for r in before+after)
    if task=='presence':
        def metrics(rows):
            tp=tn=fp=fn=0
            for row in rows:
                if row.get('status')!='ok':continue
                truth=row['target'];pred=row['predicted_present']
                tp+=truth and pred;tn+=not truth and not pred;fp+=not truth and pred;fn+=truth and not pred
            positive=sum(r['target'] for r in rows);negative=len(rows)-positive
            return {'rows':len(rows),'recall':tp/positive if positive else None,'specificity':tn/negative if negative else None,
                    'accuracy':(tp+tn)/len(rows),'tp':tp,'tn':tn,'fp':fp,'fn':fn}
    else:
        def metrics(rows):
            selected=[row for row in rows if row.get('quantitative',True)]
            totals=Counter()
            for row in selected:
                if row.get('status')!='ok':continue
                truth,pred=row['target'],row['classification']
                bits=[truth['sensitivity']==pred['sensitivity'],truth['visibility']==pred['visibility'],set(truth['categories'])==set(pred.get('categories',[]))]
                for name,bit in zip(('sensitivity_accuracy','visibility_accuracy','category_accuracy'),bits):totals[name]+=bit
                totals['joint_accuracy']+=all(bits)
                totals['action_accuracy']+=row['action'] in row['allowed_actions']
            return {'rows':len(selected),'all_rows':len(rows),**{name:totals[name]/len(selected) if selected else None for name in ('sensitivity_accuracy','visibility_accuracy','category_accuracy','joint_accuracy','action_accuracy')}}
    first,last=metrics(before),metrics(after)
    changes={k:last[k]-first[k] for k in first if k!='rows' and type(first[k]) in (float,int) and type(last[k]) in (float,int)}
    changed=sum(a[k].get('classification',a[k].get('predicted_present'))!=b[k].get('classification',b[k].get('predicted_present')) or a[k].get('action')!=b[k].get('action') for k in a)
    harm=0
    if task=='context':
        ranks={'ALLOW':0,'WARN':1,'BLOCK':2}
        for key in a:
            left,right=a[key],b[key]
            if not left.get('quantitative',True) or left.get('status')!='ok' or right.get('status')!='ok':continue
            allowed=[ranks[v] for v in left['allowed_actions']]
            old,new=ranks[left['action']],ranks[right['action']]
            harm+=max(min(allowed)-new,0)>max(min(allowed)-old,0) or max(new-max(allowed),0)>max(old-max(allowed),0) or (left['action'] in left['allowed_actions'] and right['action'] not in right['allowed_actions'])
    primary='accuracy' if task=='presence' else 'joint_accuracy'
    qualifies=not errors and last[primary]>first[primary] and not harm and all(v>=0 for k,v in changes.items() if k.endswith('accuracy') or k in ('recall','specificity'))
    intervals=None
    if not errors and iterations:
        groups=defaultdict(list)
        for index,row in enumerate(before):groups[row['group_id']].append(index)
        draws=defaultdict(list);rng=random.Random(10102026);keys=sorted(groups)
        for _ in range(iterations):
            indexes=[i for group in rng.choices(keys,k=len(keys)) for i in groups[group]]
            left,right=metrics([before[i] for i in indexes]),metrics([after[i] for i in indexes])
            for name in changes:
                if name.endswith('accuracy') or name in ('recall','specificity'):
                    if left[name] is not None and right[name] is not None:draws[name].append(right[name]-left[name])
        intervals={name:[sorted(values)[int((len(values)-1)*p)] for p in (.025,.975)] for name,values in draws.items() if values}
    observed_before=metrics([r for r in before if r.get('status')=='ok']) if any(r.get('status')=='ok' for r in before) else None
    observed_after=metrics([r for r in after if r.get('status')=='ok']) if any(r.get('status')=='ok' for r in after) else None
    bounds={}
    for label,original,values in (('before',before,first),('after',after,last)):
        missing=sum(r.get('status')!='ok' for r in original)
        bounds[label]={k:[v,min(1.,v+missing/max(values['rows'],1))] for k,v in values.items() if k.endswith('accuracy') and v is not None}
        if task=='presence':
            for name,truth in (('recall',True),('specificity',False)):
                denominator=sum(r['target']==truth for r in original);unknown=sum(r['target']==truth and r.get('status')!='ok' for r in original)
                if denominator:bounds[label][name]=[values[name],values[name]+unknown/denominator]
    return {'error_inclusive_rate_bounds':bounds,'rate_semantics':'before/after use assigned-denominator lower bounds; success-only rates separately', 'coverage':{'before':sum(r.get('status')=='ok' for r in before)/len(before),'after':sum(r.get('status')=='ok' for r in after)/len(after)},'success_only':{'before':observed_before,'after':observed_after},'before':first,'after':last,'changes':changes,'uncertainty':{'method':'paired declared-family/source-group percentile bootstrap; descriptive scenario uncertainty','seed':10102026,'iterations':iterations,'intervals_95':intervals},'exact_prediction_change_count':changed,'new_or_worsened_case_harms':harm,
            'error_observations':errors,'qualifies':qualifies,'interpretation':'engineering per-cell criterion; no promotion or significance claim'}


def audit_cell(directory,cell,protocol):
    directory=Path(directory)
    if cell['kind']=='offline':
        fit=read(directory/'fit-receipt.json')
        dose=fit['dose'];accepted=rejected=skipped=0
        parity=read(directory/'serving-parity.json')
        if parity['status']!=('unsupported' if cell['surface']=='random_control' else 'passed') or parity['final_sha256']!=fit['final_artifact']['sha256']:raise ValueError('Required native serving parity missing')
    else:
        stages=[read(directory/f'stage-{slot:03d}.json') for slot in range(1,97)]
        accepted=sum(r['state']=='accepted' for r in stages);rejected=sum(r['state']=='rejected' for r in stages);skipped=sum(r['state']=='skipped_head_rejection' for r in stages)
        if accepted+rejected+skipped!=96:raise ValueError('Stage opportunities do not reconcile')
        if cell['surface']=='sparse_presence':
            requests={r['request_id']:r for r in stages}
        else:
            requests={r['cycle']['stages'][r['stage']]['request_id']:r for r in stages if r['state']!='skipped_head_rejection'}
        evidence=[read(p) for p in (directory/'fuzzer-state/training-cycles').glob('*/*.json')]
        by_request={r['request_id']:r for r in evidence}
        if len(by_request)!=len(evidence) or set(by_request)!=set(requests):raise ValueError('Missing or duplicated actual runtime evidence')
        physical_evidence=[read(p) for p in (directory/'fuzzer-state/training-cycles').glob('*/attempts/*.json')]
        for attempt in physical_evidence:
            canonical_record=by_request.get(attempt['request_id'])
            if canonical_record is None or any(attempt.get(k)!=canonical_record.get(k) for k in ('model_id','base_version','execution_evidence','request_protobuf_sha256')):
                raise ValueError('Physical presence attempt differs from canonical logical evidence')
        if cell['surface']=='sparse_presence' and {r['request_id'] for r in physical_evidence}!=set(requests):raise ValueError('Presence immutable physical evidence missing')
        diagnostics=([{'request_id':e['request_id'],'metrics':e['metrics'],'gate_passed':e['gate_passed'],
            'failed_predicates':([] if e['gate_passed'] else [{'predicate':'presence_guard','error':e['gate_diagnostics']['error']}])} for e in evidence]
            if cell['surface']=='sparse_presence' else [read(p) for p in (directory/'fuzzer-state/gate-diagnostics').glob('*.json')])
        if len(diagnostics)!=accepted+rejected:raise ValueError('Attempt-linked diagnostics missing')
        if {r['request_id'] for r in diagnostics}!=set(requests):raise ValueError('Diagnostic/request join mismatch')

        trained=guards=physical_optimizer_steps=0
        for record in diagnostics:
            stage=requests[record['request_id']]
            verify_gate_metrics(record,presence=cell['surface']=='sparse_presence')
            for value in record['metrics'].values():
                if type(value) not in (int,float) or not math.isfinite(value):raise ValueError('Invalid numeric gate metric')
            if record['gate_passed']!=(not record['failed_predicates']):raise ValueError('Gate predicate mismatch')
            if stage['state']=='accepted' and not record['gate_passed']:raise ValueError('Publication bypassed gate')
            pending=read(directory/f"pending-{stage['slot']:03d}.json")
            independent=audit_runtime_evidence(by_request[record['request_id']],stage,pending,presence=cell['surface']=='sparse_presence')
            trained+=independent['training_examples'];guards+=independent['guard_examples'];physical_optimizer_steps+=independent['optimizer_steps']
        updates=directory/'update-state/updates.jsonl'
        published=[json.loads(line) for line in updates.read_text().splitlines() if line.strip()] if updates.exists() else []
        if len(published)!=accepted:raise ValueError('Updater publication count differs')
        receipt_path=updates.with_name(updates.name+'.receipts.sqlite3')
        with closing(sqlite3.connect(receipt_path.resolve().as_uri()+'?mode=ro',uri=True)) as database:
            receipts=list(database.execute('SELECT key,receipt FROM update_receipts'))
        if len(receipts)!=accepted:raise ValueError('Durable updater receipt count differs')
        dose={'generated_prompts':(accepted+rejected)*32,'training_examples':trained,'guard_examples':guards,
              'stage_opportunities':96,'attempted_stages':accepted+rejected,'skipped_stages':skipped,'internal_optimizer_steps':physical_optimizer_steps,'physical_rpc_attempts':sum(r.get('physical_attempts',r.get('cycle',{}).get('stages',{}).get(r['stage'],{}).get('physical_attempts',0)) for r in stages if r['state']!='skipped_head_rejection')}
    baseline=read(directory/'assessment-000.json');final=read(directory/'assessment-096.json')
    for observation in (baseline,final):audit_saved_inference(observation,cell,directory)
    def predictions(record):
        return record['layers']['semantic']['predictions']
    measured=paired_metrics(predictions(baseline),predictions(final),task=baseline['task'])
    if set(baseline['endpoints'])!=set(final['endpoints']):raise ValueError('Endpoint ledger differs between before/final')
    endpoints={name:paired_metrics(baseline['endpoints'][name]['layers']['semantic']['predictions'],
        final['endpoints'][name]['layers']['semantic']['predictions'],task=baseline['endpoints'][name]['task']) for name in baseline['endpoints']}
    if baseline['task']=='context':
        disclosure_before=[r for r in predictions(baseline) if r['target']['sensitivity']!='S0']
        disclosure_after=[r for r in predictions(final) if r['target']['sensitivity']!='S0']
        disclosure=paired_metrics(disclosure_before,disclosure_after,task='context')
    else:disclosure=None
    measured['qualifies']=all(not r['error_observations'] and not r['new_or_worsened_case_harms'] and all(v>=0 for k,v in r['changes'].items() if k.endswith('accuracy') or k in ('recall','specificity')) for r in endpoints.values())
    if disclosure:measured['qualifies']=measured['qualifies'] and all(v>=0 for k,v in disclosure['changes'].items() if k.endswith('accuracy'))
    qualification=qualification_rule(predictions(baseline),predictions(final),baseline['task'],endpoints)
    measured['qualifies']=qualification['passes']
    inventory={p.relative_to(directory).as_posix():sha(p) for p in sorted(directory.rglob('*')) if p.is_file() and p.name not in ('complete.json','operations.log')}
    return {'schema_version':'accelerated-surfaces-cell-audit-v1','cell_id':cell['id'],'status':'complete','accepted':accepted,'rejected':rejected,'skipped':skipped,
            'dose':dose,'assessment':measured,'qualification':qualification,'endpoints':endpoints,'disclosure':disclosure,'evidence_files':inventory,'archive_sha256':digest(inventory)}


def report(output,*,summary=False):
    protocol,state=verify_protocol(output,execution=True)
    cells={}
    for cell in protocol['cells']:
        directory=Path(output)/'cells'/cell['id']
        receipt=read(directory/'complete.json')
        if audit_cell(directory,cell,protocol)!=receipt:raise ValueError('Stable cell receipt differs from raw audit')
        cells[cell['id']]=receipt
    controlled={}
    ledger=read(protocol['inputs']['endpoint_ledger']['path'])['routes']
    for cell in protocol['cells']:
        reference=ledger[cell['id']]['comparator']
        if reference=='own_baseline':continue
        if reference not in cells:raise ValueError('Declared comparator missing from complete matrix')
        own=cells[cell['id']]['assessment'];other=cells[reference]['assessment']
        own_initial=read(Path(output)/'cells'/cell['id']/'assessment-000.json')['identity']['parameter_fingerprint']
        other_initial=read(Path(output)/'cells'/reference/'assessment-000.json')['identity']['parameter_fingerprint']
        same_initial=own_initial==other_initial
        if ledger[cell['id']].get('expected_same_baseline') and not same_initial:raise ValueError('Matched baseline tensor identity differs')
        controlled[cell['id']]={'comparator':reference,'same_baseline_parameter_fingerprint':same_initial,'final_metric_difference':{k:own['after'][k]-other['after'][k] for k in own['after'] if k.endswith('accuracy') or k in ('recall','specificity')},
            'difference_in_changes':{k:own['changes'][k]-other['changes'][k] for k in own['changes'] if k.endswith('accuracy') or k in ('recall','specificity')}}
    identical={}
    for cell in protocol['cells']:
        if cell['kind']=='offline':
            final=read(Path(output)/'cells'/cell['id']/'assessment-096.json')['identity']['parameter_fingerprint']
            identical.setdefault(final,[]).append(cell['id'])
    group_decisions=configuration_decisions(protocol['cells'],cells)
    eligible=[r for r in group_decisions.values() if r['eligible']]
    result={'schema_version':'accelerated-surfaces-report-v1' ,'protocol_sha256':sha(Path(output)/'protocol.json'),'cells':cells,
            'controlled_contrasts':controlled,'group_decisions':group_decisions,'identical_offline_parameter_groups':[v for v in identical.values() if len(v)>1],
            'all_eligible_configurations_qualify':bool(eligible) and all(r['qualifies'] for r in eligible),
            'all_configurations_eligible_and_qualify':bool(group_decisions) and all(r['eligible'] and r['qualifies'] for r in group_decisions.values()),
            'interpretation':'Training interfaces and target ontologies differ; package contrasts are descriptive, no automatic promotion.'}
    write(Path(output)/('summary.json' if summary else 'audit.json'),result,immutable=True)
    return result

def audit_runtime_evidence(evidence, stage, pending, *, presence=False):
    import base64
    from privoke.v1 import runtime_pb2 as R
    from privoke_model.fingerprint import parameter_fingerprint
    from privoke_model.artifact import float32
    trace=evidence['execution_evidence']
    request_type=R.ComputePresenceGradientsRequest if presence else R.ComputeSemanticGradientsRequest
    response_type=R.ComputePresenceGradientsResponse if presence else R.ComputeSemanticGradientsResponse
    request=request_type.FromString(base64.b64decode(trace['request_protobuf_base64'],validate=True))
    response=response_type.FromString(base64.b64decode(trace['response_protobuf_base64'],validate=True))
    if list(request.layers)!=[R.DETECTION_LAYER_SEMANTIC] or response.request_id!=request.request_id or response.model_id!=request.model_id or response.error:
        raise ValueError('Serialized training request/response isolation differs')
    expected=[('training',len(request.examples)),('base_heldout',len(request.heldout_examples)),('candidate_heldout',len(request.heldout_examples))]
    actual=[(e.phase,e.examples) for e in response.executions]
    if actual!=expected or any(e.layer!=R.DETECTION_LAYER_SEMANTIC or e.status!='ok' or e.error for e in response.executions):
        raise ValueError('Actual serialized training executions/counts differ')
    before=pending['base'];shapes={n:t['shape'] for n,t in before['parameters'].items()}
    fingerprint=lambda values:parameter_fingerprint(values,shapes) if presence else parameter_fingerprint(values)
    base={n:t['values'] for n,t in before['parameters'].items()}
    if response.base_version!=before['identity']['model_version'] or response.model_id!=before['identity']['model_id']:
        raise ValueError('Gradient base differs from reserved serving base')
    if response.metadata.get('base_parameter_fingerprint')!=fingerprint(base):
        raise ValueError('Runtime base fingerprint differs from independently archived tensors')
    gradients={p.name:p for p in response.gradients}
    if len(gradients)!=len(response.gradients):raise ValueError('Duplicate transported gradient')
    candidate={n:list(v) for n,v in base.items()}
    for name,gradient in gradients.items():
        if name not in candidate or list(gradient.shape)!=before['parameters'][name]['shape'] or len(gradient.values)!=len(candidate[name]):
            raise ValueError('Transported gradient inventory differs')
        if any(not math.isfinite(v) or abs(v)>.05 for v in gradient.values):raise ValueError('Transported gradient violates frozen clamp')
        candidate[name]=[float32(float32(v)+float32(delta)) for v,delta in zip(candidate[name],gradient.values)]
    if response.metadata.get('updated_parameter_fingerprint')!=fingerprint(candidate):
        raise ValueError('Candidate commitment differs from reconstructed actual tensors')
    if stage['state']=='accepted':
        observed={n:t['values'] for n,t in stage['snapshot']['parameters'].items()}
        if observed!=candidate:raise ValueError('Published tensors differ from guarded candidate')
    optimizer=response.metadata.get('contextual_optimizer_trace')
    steps=json.loads(optimizer)['steps'] if optimizer else 1
    return {'training_examples':len(request.examples),'guard_examples':len(request.heldout_examples),'optimizer_steps':steps,
        'request_protobuf_sha256':hashlib.sha256(request.SerializeToString(deterministic=True)).hexdigest(),
        'candidate_parameter_fingerprint':fingerprint(candidate)}

def verify_gate_metrics(record,*,presence=False):
    metrics=record['metrics']
    recall='present_recall' if presence else 'sensitive_recall'
    specificity='absent_specificity' if presence else 'clean_specificity'
    names=['exact_match_rate','heldout_exact_match_rate','candidate_heldout_exact_match_rate',
        'heldout_'+recall,'candidate_heldout_'+recall,'heldout_'+specificity,'candidate_heldout_'+specificity]
    if not presence:names.append('candidate_heldout_safety_regression_rate')
    if any(type(metrics.get(n)) not in (int,float) or not math.isfinite(metrics[n]) or not 0<=metrics[n]<=1 for n in names):
        raise ValueError('Required finite gate rates missing or outside[0,1]')
    for name in (('heldout_present_examples','heldout_absent_examples') if presence else ('heldout_sensitive_examples','heldout_clean_examples')):
        if type(metrics.get(name)) not in (int,float) or metrics[name]<1 or int(metrics[name])!=metrics[name]:raise ValueError('Both guard strata must have positive integer counts')
    predicates={'training_exact_above_minimum':metrics['exact_match_rate']>0,
        'heldout_exact_no_decline':metrics['candidate_heldout_exact_match_rate']>=metrics['heldout_exact_match_rate'],
        'heldout_recall_no_decline':metrics['candidate_heldout_'+recall]>=metrics['heldout_'+recall],
        'heldout_specificity_no_decline':metrics['candidate_heldout_'+specificity]>=metrics['heldout_'+specificity]}
    if not presence:predicates['no_safety_regression']=metrics['candidate_heldout_safety_regression_rate']<=0
    if record['gate_passed']!=all(predicates.values()):raise ValueError('Independent gate predicates disagree with recorded gate')
    return predicates


def qualification_rule(before,after,task,endpoints):
    """Exact retained prospective gates, with integer primary numerators."""
    errors=any(r.get("status")!="ok" for r in before+after)
    veto=errors
    if task=="presence":
        m=paired_metrics(before,after,task=task,iterations=0);a,b=m["before"],m["after"]
        if (sum(r["target"] for r in before),sum(not r["target"] for r in before))!=(160,160):raise ValueError("Presence denominator differs")
        veto=veto or b["tp"]<144 or b["tp"]<a["tp"]
        for name,e in endpoints.items():
            if name=="primary":continue
            veto=veto or bool(e["error_observations"]) or e["after"]["recall"]<.9 or e["changes"]["recall"]<0 or e["changes"]["specificity"]<0
        return {"rule":"presence_specificity8of160_recall144of160_allseed_v1","eligible":a["tn"]<=152,"specificity_gain_count":b["tn"]-a["tn"],"recall_before_count":a["tp"],"recall_after_count":b["tp"],"passes":not veto and b["tn"]-a["tn"]>=8,"veto":veto}
    def union(row):return row.get("status")=="ok" and (row["classification"]["sensitivity"]!="S0" or bool(row["classification"]["categories"]))
    subsets={}
    for name,select,denominator,gain,tolerance in (("non_s0",lambda r:r["target"]["sensitivity"]!="S0",160,16,3),("serious",lambda r:r["target"]["sensitivity"] in ("S2","S3"),120,12,2),("s0",lambda r:r["target"]["sensitivity"]=="S0",160,None,3)):
        left=[r for r in before if select(r)];right=[r for r in after if select(r)]
        if len(left)!=denominator:raise ValueError("Context subgroup denominator differs")
        def joint(rows):return sum(r.get("status")=="ok" and r["classification"]["sensitivity"]==r["target"]["sensitivity"] and r["classification"]["visibility"]==r["target"]["visibility"] and set(r["classification"]["categories"])==set(r["target"]["categories"]) for r in rows)
        old,new=joint(left),joint(right)
        old_union=sum((not union(r)) if name=="s0" else union(r) for r in left)
        new_union=sum((not union(r)) if name=="s0" else union(r) for r in right)
        veto=veto or new_union<old_union-tolerance
        subsets[name]={"denominator":denominator,"before_joint_count":old,"after_joint_count":new,"gain_count":new-old,"required_gain_count":gain,"before_union_correct_count":old_union,"after_union_correct_count":new_union,"allowed_union_loss_count":tolerance,"eligible":gain is None or old<=denominator-gain,"passes":gain is None or new-old>=gain}
    ranks={"ALLOW":0,"WARN":1,"BLOCK":2}
    newly_incorrect=serious_underaction=0
    for a,b in zip(before,after):
        if a.get("status")!="ok" or b.get("status")!="ok":continue
        newly_incorrect+=a["action"] in a["allowed_actions"] and b["action"] not in b["allowed_actions"]
        if a["target"]["sensitivity"] in ("S2","S3"):
            minimum=min(ranks[x] for x in a["allowed_actions"])
            serious_underaction+=max(minimum-ranks[b["action"]],0)>max(minimum-ranks[a["action"]],0)
    veto=veto or bool(newly_incorrect or serious_underaction)
    for name,e in endpoints.items():
        if name=="primary":continue
        veto=veto or bool(e["error_observations"])
        if name=="historical_fixtures":veto=veto or bool(e["new_or_worsened_case_harms"])
        if name=="historical_annotation":veto=veto or e["changes"]["recall"] < -.02-1e-12
    return {"rule":"context_joint16of160_12of120_union_tolerances3_2_3_action_v1","subgroups":subsets,"eligible":all(x["eligible"] for x in subsets.values()),"newly_incorrect_actions":newly_incorrect,"serious_underaction_worsening":serious_underaction,"passes":not veto and all(x["passes"] for x in subsets.values()),"veto":bool(veto)}


def audit_saved_inference(observation,cell,directory):
    from privoke_eval.continual_fuzzer_study import require_semantic_execution
    from google.protobuf.json_format import ParseDict
    from privoke.v1 import runtime_pb2 as R
    from privoke_eval.accelerated_training_surfaces_presence import validate_presence_execution
    identity=observation["identity"]
    if cell["kind"]=="online":
        snapshot=read(Path(directory)/f"snapshot-{observation['slot']:03d}.json")
        if snapshot["identity"]!=identity:raise ValueError("Saved assessment differs from immutable snapshot")
    for endpoint in observation["endpoints"].values():
        for row in endpoint["layers"]["semantic"]["predictions"]:
            if row.get("status")!="ok":continue
            if observation["execution_mode"]=="offline_learned_forward_v1":
                trace=row.get("executions",[])
                if row.get("snapshot_sha256")!=observation["snapshot_sha256"] or row.get("executed_layers")!=["DETECTION_LAYER_SEMANTIC"] or len(trace)!=1 or trace[0].get("forward_count")!=1 or trace[0].get("status")!="complete" or trace[0].get("layer")!="DETECTION_LAYER_SEMANTIC":raise ValueError("Archived offline execution differs")
                actual={"model_id":row.get("used_model_id"),"model_version":row.get("used_version"),"artifact_checksum":row.get("snapshot_checksum") or row.get("snapshot_sha256"),"parameter_fingerprint":row.get("parameter_fingerprint")}
                if actual!=identity or row.get("requested_model_id")!=identity["model_id"] or row.get("requested_version")!=identity["model_version"]:raise ValueError("Archived offline identity differs")
            elif cell["surface"] in ("sparse_presence","scratch_presence"):
                response=ParseDict(row["raw"],R.DetectAnnotationPresenceResponse())
                validate_presence_execution(response,identity,R.DETECTION_LAYER_SEMANTIC)
                if row["predicted_present"]!=(response.predicted_label==R.ANNOTATION_PRESENCE_PRESENT):raise ValueError("Saved presence prediction differs")
            else:
                raw=row["raw"];require_semantic_execution(raw)
                actual=[{k:r.get("metadata",{}).get(k,"") for k in identity} for layer in raw.get("layers",[]) for r in layer.get("results",[])]
                if not actual or any(v!=identity for v in actual) or row.get("identities")!=actual:raise ValueError("Saved semantic execution identity differs")
                if "classification" in row and row["classification"]!=raw["classification"]:raise ValueError("Saved classification differs from trace")


def configuration_decisions(manifest,cells):
    """Aggregate exactly one complete three-seed configuration per surface."""
    groups=defaultdict(list)
    for cell in manifest:
        key=tuple(cell.get(k) for k in ('kind','group','surface','profile','scope','sampling','objective','optimizer'))
        groups[key].append(cell)
    decisions={}
    for key,members in groups.items():
        if len(members)!=3 or sorted(c['seed'] for c in members)!=[42,43,44] or len({c['id'] for c in members})!=3:
            raise ValueError('Configuration requires exactly unique seeds42/43/44')
        qualifications=[cells[c['id']]['qualification'] for c in members]
        passes=sum(q['passes'] for q in qualifications);veto=any(q['veto'] for q in qualifications)
        deterministic=members[0]['surface']=='sparse_presence' and members[0]['kind']=='offline'
        eligible=sum(q['eligible'] for q in qualifications)>=(3 if deterministic else 2)
        decisions['|'.join(str(v) for v in key)]={'cells':[c['id'] for c in sorted(members,key=lambda c:c['seed'])],
            'seeds':[42,43,44],'eligible':eligible,'passing_seeds':passes,'all_seed_veto':veto,
            'qualifies':eligible and not veto and (passes==3 if deterministic else passes>=2),
            'qualification_type':'deterministic_solver_repetition_all_runs' if deterministic else 'same_two_of_three_seed_gains_all_seed_vetoes',
            'stochastic_seed_corroboration':not deterministic}
    return decisions
