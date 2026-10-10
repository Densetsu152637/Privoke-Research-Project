"""Independent standard-library count check, run only after all fits finish."""
from collections import Counter, defaultdict
from pathlib import Path
import hashlib
import json
import sys

root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('evaluation/results/accelerated_all_surfaces_20261010/execution-study-v3')
def read(path):
    return json.loads(path.read_text(encoding='utf-8'))
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def metrics(rows, task):
    if task == 'presence':
        valid = [r for r in rows if r['status'] == 'ok']
        tp = sum(r['target'] and r['predicted_present'] for r in valid)
        tn = sum(not r['target'] and not r['predicted_present'] for r in valid)
        positives = sum(r['target'] for r in rows)
        negatives = len(rows) - positives
        return dict(rows=len(rows), tp=tp, tn=tn,
                    fp=sum(not r['target'] and r['predicted_present'] for r in valid),
                    fn=sum(r['target'] and not r['predicted_present'] for r in valid),
                    recall=tp/positives if positives else None,
                    specificity=tn/negatives if negatives else None, accuracy=(tp+tn)/len(rows))
    selected = [r for r in rows if r.get('quantitative', True)]
    valid = [r for r in selected if r['status'] == 'ok']
    count = Counter()
    for r in valid:
        truth, prediction = r['target'], r['classification']
        bits = (truth['sensitivity'] == prediction['sensitivity'],
                truth['visibility'] == prediction['visibility'],
                set(truth['categories']) == set(prediction.get('categories', [])))
        for field, hit in zip(('sensitivity', 'visibility', 'category'), bits):
            count[field + '_accuracy'] += hit
        count['joint_accuracy'] += all(bits)
        count['action_accuracy'] += r['action'] in r['allowed_actions']
    return dict(rows=len(selected), all_rows=len(rows), **{field: count[field]/len(selected)
                for field in ('sensitivity_accuracy', 'visibility_accuracy', 'category_accuracy',
                              'joint_accuracy', 'action_accuracy')})
def joint(row):
    if row['status'] != 'ok':
        return False
    a, b = row['target'], row['classification']
    return (a['sensitivity'], a['visibility'], set(a['categories'])) == (
        b['sensitivity'], b['visibility'], set(b.get('categories', [])))
def union(row):
    return row['status'] == 'ok' and (row['classification']['sensitivity'] != 'S0'
                                     or bool(row['classification'].get('categories', [])))
def harms(before, after, task):
    if task == 'presence':
        return 0
    ranks = {'ALLOW': 0, 'WARN': 1, 'BLOCK': 2}
    total = 0
    for a, b in zip(before, after):
        if not a.get('quantitative', True) or a['status'] != 'ok' or b['status'] != 'ok':
            continue
        allowed = [ranks[x] for x in a['allowed_actions']]
        old, new = ranks[a['action']], ranks[b['action']]
        total += (max(0, min(allowed)-new) > max(0, min(allowed)-old)
                  or max(0, new-max(allowed)) > max(0, old-max(allowed))
                  or (old in allowed and new not in allowed))
    return total

summary_path=Path(sys.argv[3]) if len(sys.argv)>3 else root/'summary.json'
protocol, summary = read(root/'protocol.json'), read(summary_path)
assert len(protocol['cells']) == len(summary['cells']) == 168
assert summary['protocol_sha256'] == sha(root/'protocol.json')
assert summary['protocol_sha256'] == 'aadcef30cd3fabb595cf076ce8beeb9c9bbc9159bfd44899dd0ede0fbc76e797'
assert Counter(c['kind'] for c in protocol['cells']) == {'online': 111, 'offline': 57}
independent = {}
endpoint_pairs = 0
for cell in protocol['cells']:
    name = cell['id']
    directory = root/'cells'/name
    receipt = read(directory/'complete.json')
    assert receipt == summary['cells'][name] and receipt['status'] == 'complete'
    if cell['kind'] == 'online':
        stages = [read(directory/f'stage-{i:03d}.json') for i in range(1,97)]
        counts = Counter(s['state'] for s in stages)
        assert (receipt['accepted'], receipt['rejected'], receipt['skipped']) == (
            counts['accepted'], counts['rejected'], counts['skipped_head_rejection'])
        assert sum(counts.values()) == receipt['accepted']+receipt['rejected']+receipt['skipped'] == 96
        assert receipt['dose']['generated_prompts'] == 32*(receipt['accepted']+receipt['rejected'])
    else:
        fit = read(directory/'fit-receipt.json')
        assert receipt['dose'] == fit['dose']
        if cell['surface'] != 'sparse_presence':
            assert fit['dose']['optimizer_steps'] == 96
            assert fit['dose']['presentations'] == 96*cell['batch_size']
    before, after = (read(directory/f'assessment-{slot:03d}.json') for slot in (0, 96))
    assert set(before['endpoints']) == set(after['endpoints']) == set(receipt['endpoints'])
    expected_endpoints = {'primary','historical_annotation'}
    if cell['surface'] not in ('sparse_presence','scratch_presence'):
        expected_endpoints |= {'annotation_transfer','historical_fixtures'}
    assert set(before['endpoints']) == expected_endpoints
    for endpoint in before['endpoints']:
        left = before['endpoints'][endpoint]
        right = after['endpoints'][endpoint]
        a, b = left['layers']['semantic']['predictions'], right['layers']['semantic']['predictions']
        assert left['task'] == right['task']
        assert len(a) == len(b) and len({r['id'] for r in a}) == len(a)
        assert [(r['id'], r['target'], r['group_id']) for r in a] == [(r['id'], r['target'], r['group_id']) for r in b]
        expected = receipt['endpoints'][endpoint]
        assert metrics(a, left['task']) == expected['before'], (name, endpoint, 'before')
        assert metrics(b, left['task']) == expected['after'], (name, endpoint, 'after')
        old, new = metrics(a, left['task']), metrics(b, left['task'])
        changes = {key: new[key]-value for key, value in old.items()
                   if key != 'rows' and type(value) in (int, float) and type(new[key]) in (int, float)}
        assert changes == expected['changes']
        assert sum(r['status'] != 'ok' for r in a+b) == expected['error_observations']
        assert harms(a, b, left['task']) == expected['new_or_worsened_case_harms']
        changed=sum(x.get('classification',x.get('predicted_present'))!=y.get('classification',y.get('predicted_present'))
                    or x.get('action')!=y.get('action') for x,y in zip(a,b))
        assert changed==expected['exact_prediction_change_count']
        for label,data in [('before',a),('after',b)]:
            valid=[r for r in data if r['status']=='ok']
            assert expected['coverage'][label]==len(valid)/len(data)
            assert expected['success_only'][label]==(metrics(valid,left['task']) if valid else None)
            bounds=expected['error_inclusive_rate_bounds'][label]
            values=expected[label];missing=len(data)-len(valid)
            expected_bounds={k:[v,min(1.,v+missing/max(values['rows'],1))]
                             for k,v in values.items() if k.endswith('accuracy') and v is not None}
            if left['task']=='presence':
                for rate,truth in [('recall',True),('specificity',False)]:
                    total=sum(r['target']==truth for r in data)
                    unknown=sum(r['target']==truth and r['status']!='ok' for r in data)
                    if total:expected_bounds[rate]=[values[rate],values[rate]+unknown/total]
            assert bounds==expected_bounds
        endpoint_pairs += 1
    a, b = before['layers']['semantic']['predictions'], after['layers']['semantic']['predictions']
    assert len(a) == len(b) == 320
    assert a == before['endpoints']['primary']['layers']['semantic']['predictions']
    assert b == after['endpoints']['primary']['layers']['semantic']['predictions']
    assert metrics(a, before['task']) == receipt['assessment']['before']
    assert metrics(b, after['task']) == receipt['assessment']['after']
    if before['task'] == 'context':
        assert metrics([r for r in a if r['target']['sensitivity'] != 'S0'], 'context') == receipt['disclosure']['before']
        assert metrics([r for r in b if r['target']['sensitivity'] != 'S0'], 'context') == receipt['disclosure']['after']
    veto = any(r['status'] != 'ok' for r in a+b)
    q = receipt['qualification']
    if before['task'] == 'presence':
        old, new = metrics(a, 'presence'), metrics(b, 'presence')
        assert sum(r['target'] for r in a) == 160
        eligible = old['tn'] <= 152
        gain = new['tn'] - old['tn'] >= 8
        veto |= new['tp'] < 144 or new['tp'] < old['tp']
        assert (q['specificity_gain_count'], q['recall_before_count'], q['recall_after_count']) == (
            new['tn']-old['tn'], old['tp'], new['tp'])
        for endpoint, e in receipt['endpoints'].items():
            if endpoint == 'primary':
                continue
            veto |= bool(e['error_observations']) or e['after']['recall'] < .9 or e['changes']['recall'] < 0 or e['changes']['specificity'] < 0
    else:
        eligible, gain = True, True
        selectors = (('non_s0', lambda r:r['target']['sensitivity'] != 'S0', 160, 16, 3),
                     ('serious', lambda r:r['target']['sensitivity'] in ('S2','S3'), 120, 12, 2),
                     ('s0', lambda r:r['target']['sensitivity'] == 'S0', 160, None, 3))
        for group, choose, total, required, tolerance in selectors:
            left, right = [r for r in a if choose(r)], [r for r in b if choose(r)]
            assert len(left) == len(right) == total
            old, new = sum(map(joint, left)), sum(map(joint, right))
            old_union = sum(not union(r) if group == 's0' else union(r) for r in left)
            new_union = sum(not union(r) if group == 's0' else union(r) for r in right)
            subgroup = q['subgroups'][group]
            assert (old, new, new-old, old_union, new_union) == tuple(subgroup[k] for k in (
                'before_joint_count','after_joint_count','gain_count','before_union_correct_count','after_union_correct_count'))
            if required is not None:
                eligible &= old <= total-required
                gain &= new-old >= required
            veto |= new_union < old_union-tolerance
        ranks = {'ALLOW': 0, 'WARN': 1, 'BLOCK': 2}
        incorrect = worsening = 0
        for left, right in zip(a, b):
            if left['status'] != 'ok' or right['status'] != 'ok':
                continue
            incorrect += left['action'] in left['allowed_actions'] and right['action'] not in right['allowed_actions']
            if left['target']['sensitivity'] in ('S2','S3'):
                floor = min(ranks[x] for x in left['allowed_actions'])
                worsening += max(0, floor-ranks[right['action']]) > max(0, floor-ranks[left['action']])
        assert (incorrect, worsening) == (q['newly_incorrect_actions'], q['serious_underaction_worsening'])
        veto |= bool(incorrect or worsening)
        for endpoint, e in receipt['endpoints'].items():
            if endpoint == 'primary':
                continue
            veto |= bool(e['error_observations'])
            if endpoint == 'historical_annotation':
                veto |= e['changes']['recall'] < -.02-1e-12
            if endpoint == 'historical_fixtures':
                veto |= bool(e['new_or_worsened_case_harms'])
    independent[name] = dict(eligible=bool(eligible), veto=bool(veto), passes=bool(gain and not veto))
    assert all(independent[name][k] == q[k] for k in independent[name]), name

groups = defaultdict(list)
for c in protocol['cells']:
    key = '|'.join(str(c.get(k)) for k in ('kind','group','surface','profile','scope','sampling','objective','optimizer'))
    groups[key].append(c)
assert len(groups) == len(summary['group_decisions']) == 56
for key, members in groups.items():
    assert sorted(c['seed'] for c in members) == [42,43,44]
    minimum = 3 if members[0]['kind'] == 'offline' and members[0]['surface'] == 'sparse_presence' else 2
    q = [independent[c['id']] for c in members]
    eligible = sum(x['eligible'] for x in q) >= minimum
    passes = sum(x['passes'] for x in q)
    veto = any(x['veto'] for x in q)
    expected = summary['group_decisions'][key]
    assert expected['cells'] == [c['id'] for c in sorted(members,key=lambda c:c['seed'])]
    assert expected['seeds'] == [42,43,44]
    assert expected['stochastic_seed_corroboration'] == (minimum == 2)
    assert expected['qualification_type'] == ('deterministic_solver_repetition_all_runs' if minimum == 3 else 'same_two_of_three_seed_gains_all_seed_vetoes')
    assert (eligible, passes, veto, eligible and not veto and passes >= minimum) == tuple(
        expected[k] for k in ('eligible','passing_seeds','all_seed_veto','qualifies')), key
decisions = list(summary['group_decisions'].values())
eligible = [x for x in decisions if x['eligible']]
assert summary['all_eligible_configurations_qualify'] == (bool(eligible) and all(x['qualifies'] for x in eligible))
assert summary['all_configurations_eligible_and_qualify'] == all(x['eligible'] and x['qualifies'] for x in decisions)
ledger = read(Path(protocol['inputs']['endpoint_ledger']['path']))['routes']
comparators = {}
manifest={c['id']:c for c in protocol['cells']}
for name,entry in ledger.items():
    comparator=entry['comparator']
    if isinstance(comparator,dict):
        cell=manifest[name]
        expected=('actual_streamed_snapshot_slot96' if cell['kind']=='online' else
                  'offline_fixed_LBFGS_final' if cell['surface']=='sparse_presence' else
                  'fixed_final_head_Adam_step96' if cell['surface'] in ('minilm','random_control') else
                  'offline_fixed_final_Adam_step96')
        assert comparator['kind']==expected and set(comparator)<=set('kind selection solver native_context causal_scope'.split())
        if 'native_context' in comparator:assert comparator['native_context']=={'efficient':64,'balanced':96,'quality':128}[cell['profile']]
    elif comparator!='own_baseline':
        assert isinstance(comparator,str) and comparator in manifest
        comparators[name]=comparator
assert set(comparators) == set(summary['controlled_contrasts'])
for name, reference in comparators.items():
    contrast = summary['controlled_contrasts'][name]
    assert contrast['comparator'] == reference
    own, other = summary['cells'][name]['assessment'], summary['cells'][reference]['assessment']
    rates = {key for key in own['after'] if key.endswith('accuracy') or key in ('recall','specificity')}
    assert contrast['final_metric_difference'] == {key:own['after'][key]-other['after'][key] for key in rates}
    assert contrast['difference_in_changes'] == {key:own['changes'][key]-other['changes'][key] for key in rates}
    own_before = read(root/'cells'/name/'assessment-000.json')['identity']['parameter_fingerprint']
    other_before = read(root/'cells'/reference/'assessment-000.json')['identity']['parameter_fingerprint']
    assert contrast['same_baseline_parameter_fingerprint'] == (own_before == other_before)
    assert not ledger[name].get('expected_same_baseline') or own_before == other_before
assert endpoint_pairs == 600
result = dict(status='passed', method='independent standard-library count arithmetic',
              checker_sha256=sha(Path(__file__)),
              protocol_sha256=sha(root/'protocol.json'), summary_sha256=sha(summary_path),
              checked_cells=168, checked_configurations=56, checked_endpoint_pairs=endpoint_pairs,
              checks='fixed doses, 600 primary/secondary endpoint pairs and disclosure subsets, rate numerators, stable pairs, casewise harms, subgroup gains, vetoes, configuration/global decisions, controlled contrasts')
output = Path(sys.argv[2]) if len(sys.argv) > 2 else root.parent/'linux-validation'/'independent-quality-reconciliation.json'
with output.open('x', encoding='utf-8', newline='\n') as stream:
    stream.write(json.dumps(result, indent=2)+'\n')
print(json.dumps(result))
