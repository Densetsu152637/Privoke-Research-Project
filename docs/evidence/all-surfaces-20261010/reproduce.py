"""Project accepted all-surface aggregates; no fitting, inference or network use.

Run only after root acceptance: python project-public-study.py RAW_BASE BINDINGS OUTPUT
Bindings fix the hashes of protocol, audit, summary, amendment and independent check.
"""
from pathlib import Path
import hashlib
import json
import math
import re
import sys

FITTING_SOURCE = '0b469c7a5972beee4f64544f5c0f33337923fc85'
AUDIT_SOURCE = 'f3650a3445ec26d17e8bba57da7cf7d7807b31ab'
ENVIRONMENT_SOURCE = '7be337e704ade2773dd8b533ad0be2a454b06c11'
SCORING_SOURCE = '236328d04a1673902375d91b0624265d2aa36f05'
REPORT_SOURCE = 'ad9241a86ba39e4d594b17eda67137807b7f632f'
PROTOCOL_SHA = 'aadcef30cd3fabb595cf076ce8beeb9c9bbc9159bfd44899dd0ede0fbc76e797'
CONTEXT = set('rows all_rows sensitivity_accuracy visibility_accuracy category_accuracy joint_accuracy action_accuracy'.split())
PRESENCE = set('rows recall specificity accuracy tp tn fp fn'.split())
RATES = {k for k in CONTEXT | PRESENCE if k.endswith('accuracy') or k in ('recall','specificity')}

def read(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key] = value
        return result
    return json.loads(path.read_bytes(), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def canonical(value):
    return (json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n').encode('utf-8')

def keys(value, names):
    if not isinstance(value, dict) or set(value) != set(names):
        raise ValueError('Unexpected aggregate schema')

def number(value, nullable=False):
    if nullable and value is None:
        return value
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError('Expected finite number')
    return value

def numeric_map(value, allowed, *, exact=False, nullable=False):
    if not isinstance(value, dict) or not set(value) <= allowed or exact and set(value) != allowed:
        raise ValueError('Unexpected numeric metric')
    for v in value.values():
        number(v, nullable)
    return value

def metric(value):
    allowed = PRESENCE if isinstance(value, dict) and 'tp' in value else CONTEXT
    return numeric_map(value, allowed, exact=True, nullable=True)

def intervals(value, allowed):
    if not isinstance(value, dict) or not set(value) <= allowed:
        raise ValueError('Unexpected interval metric')
    for bounds in value.values():
        if not isinstance(bounds, list) or len(bounds) != 2:
            raise ValueError('Expected two interval endpoints')
        for v in bounds:
            number(v)
    return value

def paired(value):
    keys(value, 'error_inclusive_rate_bounds rate_semantics coverage success_only before after changes uncertainty exact_prediction_change_count new_or_worsened_case_harms error_observations qualifies interpretation'.split())
    if value['rate_semantics'] != 'before/after use assigned-denominator lower bounds; success-only rates separately' or value['interpretation'] != 'engineering per-cell criterion; no promotion or significance claim':
        raise ValueError('Unexpected metric interpretation')
    keys(value['error_inclusive_rate_bounds'], ('before','after'))
    for v in value['error_inclusive_rate_bounds'].values():
        intervals(v, RATES)
    numeric_map(value['coverage'], {'before','after'}, exact=True)
    keys(value['success_only'], ('before','after'))
    for v in value['success_only'].values():
        if v is not None:
            metric(v)
    metric(value['before']); metric(value['after'])
    numeric_map(value['changes'], (CONTEXT | PRESENCE) - {'rows'})
    uncertainty = value['uncertainty']
    keys(uncertainty, ('method','seed','iterations','intervals_95'))
    if uncertainty['method'] != 'paired declared-family/source-group percentile bootstrap; descriptive scenario uncertainty' or uncertainty['seed'] != 10102026 or uncertainty['iterations'] != 2000:
        raise ValueError('Unexpected uncertainty method')
    if uncertainty['intervals_95'] is not None:
        intervals(uncertainty['intervals_95'], RATES)
    for field in ('exact_prediction_change_count','new_or_worsened_case_harms','error_observations'):
        number(value[field])
    if type(value['qualifies']) is not bool:
        raise ValueError('Expected qualification flag')
    return value

def qualification(value):
    if value.get('rule') == 'presence_specificity8of160_recall144of160_allseed_v1':
        keys(value, 'rule eligible specificity_gain_count recall_before_count recall_after_count passes veto'.split())
        for k in ('specificity_gain_count','recall_before_count','recall_after_count'):
            number(value[k])
    elif value.get('rule') == 'context_joint16of160_12of120_union_tolerances3_2_3_action_v1':
        keys(value, 'rule subgroups eligible newly_incorrect_actions serious_underaction_worsening passes veto'.split())
        keys(value['subgroups'], ('non_s0','serious','s0'))
        for subgroup in value['subgroups'].values():
            keys(subgroup, 'denominator before_joint_count after_joint_count gain_count required_gain_count before_union_correct_count after_union_correct_count allowed_union_loss_count eligible passes'.split())
            for k, v in subgroup.items():
                if k in ('eligible','passes'):
                    if type(v) is not bool:
                        raise ValueError('Invalid subgroup flag')
                else:
                    number(v, nullable=k=='required_gain_count')
        number(value['newly_incorrect_actions']); number(value['serious_underaction_worsening'])
    else:
        raise ValueError('Unknown qualification rule')
    for field in ('eligible','passes','veto'):
        if type(value[field]) is not bool:
            raise ValueError('Invalid qualification flag')
    return value

def dose(value):
    online = 'generated_prompts' in value
    keys(value, ('generated_prompts training_examples guard_examples stage_opportunities attempted_stages skipped_stages internal_optimizer_steps physical_rpc_attempts' if online else 'optimizer_steps presentations unique_rows solver_budget').split())
    for k, v in value.items():
        if k != 'solver_budget':
            number(v, nullable=not online)
        elif v is not None:
            keys(v, ('solver','max_iter','tol','C','class_weight'))
            if v['solver'] != 'lbfgs' or v['class_weight'] != 'balanced':
                raise ValueError('Unknown solver budget')
            for field in ('max_iter','tol','C'):
                number(v[field])
    return value

def hash_value(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        raise ValueError('Expected SHA256')
    return value

def cell_projection(value):
    keys(value, 'schema_version cell_id status accepted rejected skipped dose assessment qualification endpoints disclosure evidence_files archive_sha256'.split())
    if value['schema_version'] != 'accelerated-surfaces-cell-audit-v1' or value['status'] != 'complete':
        raise ValueError('Incomplete cell')
    for k in ('accepted','rejected','skipped'):
        number(value[k])
    dose(value['dose']); paired(value['assessment']); qualification(value['qualification'])
    if not set(value['endpoints']) <= {'primary','annotation_transfer','historical_annotation','historical_fixtures'} or 'primary' not in value['endpoints']:
        raise ValueError('Unknown endpoint')
    for v in value['endpoints'].values():
        paired(v)
    if value['disclosure'] is not None:
        paired(value['disclosure'])
    hash_value(value['archive_sha256'])
    return {**{k: v for k, v in value.items() if k != 'evidence_files'},
            'schema_version':'accelerated-surfaces-public-cell-v1'}

def summary_projection(value, identifiers):
    keys(value, 'schema_version protocol_sha256 cells controlled_contrasts group_decisions identical_offline_parameter_groups all_eligible_configurations_qualify all_configurations_eligible_and_qualify interpretation'.split())
    if value['schema_version'] != 'accelerated-surfaces-report-v1' or value['protocol_sha256'] != PROTOCOL_SHA:
        raise ValueError('Wrong study report')
    if set(value['cells']) != identifiers:
        raise ValueError('Incomplete matrix')
    projected = dict(value, cells={k: cell_projection(v) for k, v in value['cells'].items()})
    projected['schema_version'] = 'accelerated-surfaces-public-report-v1'
    for name, cell in projected['cells'].items():
        if cell['cell_id'] != name:
            raise ValueError('Mismatched cell identifier')
    if not set(value['controlled_contrasts']) <= identifiers:
        raise ValueError('Unknown controlled contrast')
    for contrast in value['controlled_contrasts'].values():
        keys(contrast, 'comparator same_baseline_parameter_fingerprint final_metric_difference difference_in_changes'.split())
        if contrast['comparator'] not in identifiers or type(contrast['same_baseline_parameter_fingerprint']) is not bool:
            raise ValueError('Invalid comparator')
        numeric_map(contrast['final_metric_difference'], RATES)
        numeric_map(contrast['difference_in_changes'], RATES)
    for decision in value['group_decisions'].values():
        keys(decision, 'cells seeds eligible passing_seeds all_seed_veto qualifies qualification_type stochastic_seed_corroboration'.split())
        if len(decision['cells']) != 3 or not set(decision['cells']) <= identifiers or decision['seeds'] != [42,43,44]:
            raise ValueError('Invalid seed group')
        if decision['qualification_type'] not in ('deterministic_solver_repetition_all_runs','same_two_of_three_seed_gains_all_seed_vetoes'):
            raise ValueError('Unknown configuration rule')
        for field in ('eligible','all_seed_veto','qualifies','stochastic_seed_corroboration'):
            if type(decision[field]) is not bool:
                raise ValueError('Invalid configuration flag')
        number(decision['passing_seeds'])
    for group in value['identical_offline_parameter_groups']:
        if not isinstance(group, list) or not set(group) <= identifiers:
            raise ValueError('Unknown repeated fit')
    for field in ('all_eligible_configurations_qualify','all_configurations_eligible_and_qualify'):
        if type(value[field]) is not bool:
            raise ValueError('Invalid global flag')
    if value['interpretation'] != 'Training interfaces and target ontologies differ; package contrasts are descriptive, no automatic promotion.':
        raise ValueError('Unknown report interpretation')
    return projected

def reference_hashes(value, prefix='inputs'):
    result = {}
    if isinstance(value, dict):
        if 'path' in value and 'sha256' in value:
            result[prefix] = hash_value(value['sha256'])
        for key, nested in value.items():
            result.update(reference_hashes(nested, prefix+'.'+key))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            result.update(reference_hashes(nested, prefix+'.'+str(index)))
    return result

def protocol_projection(value, amendment, environment, scoring, reporting):
    keys(value, 'analysis assessment_inventory cells checkpoint_slots concurrency image_attestation images inputs objective objective_attribution offline_worker_attestation offline_worker_image ports qualification_rules schema_version secondary_fixture_context settings source_files source_revision study_id training_cohort_policy'.split())
    if value['source_revision'] != FITTING_SOURCE or amendment['source_revision'] != AUDIT_SOURCE or amendment['frozen_source_revision'] != FITTING_SOURCE or amendment['protocol_sha256'] != PROTOCOL_SHA or amendment['status'] != 'accepted' or amendment['scope'] != 'audit_only':
        raise ValueError('Unexpected source provenance')
    if any(amendment[k] for k in ('qualification_rules_changed','training_images_changed','training_settings_changed','retry_allowance_reset')):
        raise ValueError('Audit amendment exceeded scope')
    pythonpath='/study/evaluation:/study/shared/python:/study/extension/client-runtime:/study/extension/client-runtime/generated'
    if (environment['status']!='accepted' or environment['scope']!='worker_environment_only'
            or environment['protocol_sha256']!=PROTOCOL_SHA
            or environment['audit_amendment_sha256']!=hashlib.sha256(canonical(amendment)).hexdigest()
            or environment['prior_source_revision']!=AUDIT_SOURCE or environment['prior_source_files']!=amendment['source_files']
            or environment['source_revision']!=ENVIRONMENT_SOURCE or environment['offline_worker_image']!=value['offline_worker_image']
            or environment['pythonpath_before']!=pythonpath or environment['pythonpath_after']!=pythonpath+':/study/models'
            or environment['qualification_rules_changed'] or environment['recovery_allowance_reset']
            or not environment['inputs_images_fitting_code_and_budgets_unchanged']):
        raise ValueError('Worker environment amendment exceeded scope')
    changes={p for p in environment['source_files'] if environment['source_files'][p]!=amendment['source_files'].get(p)}
    if set(environment['source_files'])!=set(amendment['source_files']) or changes!={'evaluation/privoke_eval/accelerated_training_surfaces_study.py','evaluation/Dockerfile.accelerated-training-surfaces-worker'}:
        raise ValueError('Unexpected environment source changes')
    keys(scoring,'status scope protocol_sha256 environment_amendment_sha256 prior_source_revision prior_source_files source_revision source_files offline_worker_image'.split())
    if (scoring['status']!='accepted' or scoring['scope']!='score_dependency_mount_only'
            or scoring['protocol_sha256']!=PROTOCOL_SHA
            or scoring['environment_amendment_sha256']!=hashlib.sha256(canonical(environment)).hexdigest()
            or scoring['prior_source_revision']!=ENVIRONMENT_SOURCE or scoring['prior_source_files']!=environment['source_files']
            or scoring['source_revision']!=SCORING_SOURCE or scoring['offline_worker_image']!=value['offline_worker_image']):
        raise ValueError('Score dependency amendment exceeded scope')
    changes={p for p in scoring['source_files'] if scoring['source_files'][p]!=environment['source_files'].get(p)}
    if set(scoring['source_files'])!=set(environment['source_files']) or changes!={'evaluation/privoke_eval/accelerated_training_surfaces_study.py'}:
        raise ValueError('Unexpected score dependency source changes')
    keys(reporting,'status scope protocol_sha256 scoring_amendment_sha256 prior_source_revision prior_source_files source_revision source_files offline_worker_image'.split())
    if (reporting['status']!='accepted' or reporting['scope']!='report_comparator_schema_only'
            or reporting['protocol_sha256']!=PROTOCOL_SHA
            or reporting['scoring_amendment_sha256']!=hashlib.sha256(canonical(scoring)).hexdigest()
            or reporting['prior_source_revision']!=SCORING_SOURCE or reporting['prior_source_files']!=scoring['source_files']
            or reporting['source_revision']!=REPORT_SOURCE or reporting['offline_worker_image']!=value['offline_worker_image']):
        raise ValueError('Report ledger amendment exceeded scope')
    changes={p for p in reporting['source_files'] if reporting['source_files'][p]!=scoring['source_files'].get(p)}
    if set(reporting['source_files'])!=set(scoring['source_files']) or changes!={'evaluation/privoke_eval/accelerated_training_surfaces_study.py','evaluation/privoke_eval/accelerated_training_surfaces_report.py'}:
        raise ValueError('Unexpected report ledger source changes')
    for path, digest in value['source_files'].items():
        if path.startswith(('/', '\\')) or ':' in path or '..' in path.split('/'):
            raise ValueError('Expected repository-relative source inventory')
        hash_value(digest)
    cells = []
    for cell in value['cells']:
        expected = set('batch_size cycles group id kind model_id objective optimizer optimizer_steps profile project sampling scope seed seed_role solver_budget stage_slots surface'.split())
        if cell['kind'] == 'online':
            expected.add('stage_seed_plan_sha256')
        keys(cell, expected)
        cells.append({k: v for k, v in cell.items() if k != 'project'})
    fields = 'schema_version study_id source_revision source_files settings offline_worker_image images checkpoint_slots concurrency training_cohort_policy secondary_fixture_context qualification_rules objective objective_attribution analysis'.split()
    result = {k: value[k] for k in fields}
    result.update(schema_version='accelerated-surfaces-public-protocol-v1',raw_schema_version=value['schema_version'],
                  cells=cells, protocol_sha256=PROTOCOL_SHA, audit_source_revision=AUDIT_SOURCE,
                  audit_source_files=amendment['source_files'],
                  environment_source_revision=ENVIRONMENT_SOURCE,environment_source_files=environment['source_files'],
                  scoring_source_revision=SCORING_SOURCE,scoring_source_files=scoring['source_files'],
                  report_source_revision=REPORT_SOURCE,report_source_files=reporting['source_files'],
                  worker_pythonpath=environment['pythonpath_after'],
                  input_commitments=reference_hashes(value['inputs']),
                  image_attestation_commitments=reference_hashes(value['image_attestation'],'image_attestation'),
                  offline_worker_attestation_commitments=reference_hashes(value['offline_worker_attestation'],'offline_worker_attestation'),
                  offline_worker_recipe_sha256=hash_value(value['offline_worker_attestation']['recipe_sha256']),
                  offline_worker_requirements_sha256=hash_value(value['offline_worker_attestation']['requirements_sha256']),
                  offline_worker_pip_freeze_sha256=hash_value(value['offline_worker_attestation']['pip_freeze_sha256']))
    return result

def main(argv):
    base, binding_path, output = map(Path, argv)
    base = base.resolve(strict=True)
    binding = read(binding_path)
    keys(binding, ('schema_version','status','files'))
    if binding['schema_version'] != 'all-surfaces-publication-bindings-v1' or binding['status'] != 'accepted':
        raise ValueError('Publication requires exact accepted input bindings')
    names = {'protocol.json','audit.json','summary.json','audit-source-amendment.json','worker-environment-amendment.json','score-dependency-amendment.json','report-ledger-amendment.json'}
    expected_paths = {'execution-study-v3/'+name for name in names} | {'linux-validation/independent-quality-reconciliation.json'}
    keys(binding['files'], expected_paths)
    for name, digest in binding['files'].items():
        if sha(base/name) != hash_value(digest):
            raise ValueError('Accepted publication input changed')
    if binding['files']['execution-study-v3/protocol.json'] != PROTOCOL_SHA:
        raise ValueError('Wrong frozen protocol')
    documents = {name: read(base/'execution-study-v3'/name) for name in names}
    if documents['audit.json'] != documents['summary.json']:
        raise ValueError('Audit and report disagree')
    independent = read(base/'linux-validation/independent-quality-reconciliation.json')
    keys(independent, 'status method checker_sha256 protocol_sha256 summary_sha256 checked_cells checked_configurations checked_endpoint_pairs checks'.split())
    if independent['status'] != 'passed' or independent['protocol_sha256'] != PROTOCOL_SHA or independent['summary_sha256'] != binding['files']['execution-study-v3/summary.json'] or independent['checked_cells'] != 168 or independent['checked_configurations'] != 56 or independent['checked_endpoint_pairs'] != 600:
        raise ValueError('Independent count check missing')
    if independent['method'] != 'independent standard-library count arithmetic' or independent['checks'] != 'fixed doses, 600 primary/secondary endpoint pairs and disclosure subsets, rate numerators, stable pairs, casewise harms, subgroup gains, vetoes, configuration/global decisions, controlled contrasts':
        raise ValueError('Unexpected independent check scope')
    checker_candidates = [Path(__file__).with_name(name) for name in ('reconcile-study-quality.py','independent-check.py')]
    checker = next((p for p in checker_candidates if p.is_file() and sha(p) == hash_value(independent['checker_sha256'])), None)
    if checker is None:
        raise ValueError('Exact independent checker source unavailable')
    protocol = documents['protocol.json']
    identifiers = {cell['id'] for cell in protocol['cells']}
    if len(identifiers) != 168 or sum(c['kind']=='online' for c in protocol['cells']) != 111:
        raise ValueError('Incomplete study matrix')
    summary = summary_projection(documents['summary.json'], identifiers)
    if len(summary['group_decisions']) != 56:
        raise ValueError('Incomplete configuration decisions')
    artifacts = {
        'summary.json': summary,
        'protocol.json': protocol_projection(protocol, documents['audit-source-amendment.json'],documents['worker-environment-amendment.json'],documents['score-dependency-amendment.json'],documents['report-ledger-amendment.json']),
        'audit.json': {'schema_version':'all-surfaces-public-audit-projection-v1',
                      'raw_audit_sha256':binding['files']['execution-study-v3/audit.json'],
                      'raw_summary_sha256':binding['files']['execution-study-v3/summary.json'],
                      'protocol_sha256':PROTOCOL_SHA,
                      'cell_archive_sha256':{k:v['archive_sha256'] for k,v in summary['cells'].items()},
                      'independent_check_sha256':binding['files']['linux-validation/independent-quality-reconciliation.json']},
        'independent-check.json':independent,
        'bindings.json':binding,
    }
    destination = output.resolve()
    if destination == base or base in destination.parents or destination in base.parents:
        raise ValueError('Publication output must be separate from raw evidence')
    output.mkdir(parents=True, exist_ok=False)
    for name, value in artifacts.items():
        if name == 'bindings.json':
            (output/name).write_bytes(binding_path.read_bytes())
        else:
            (output/name).write_bytes(canonical(value))
    (output/'reproduce.py').write_bytes(Path(__file__).read_bytes())
    (output/'independent-check.py').write_bytes(checker.read_bytes())
    manifest = {'schema_version':'all-surfaces-publication-manifest-v1', 'accepted_bindings_sha256':sha(binding_path),
                'raw_inputs':binding['files'], 'public_files':{name:sha(output/name) for name in (*artifacts,'reproduce.py','independent-check.py')},
                'fitting_source_revision':FITTING_SOURCE, 'audit_source_revision':AUDIT_SOURCE,
                'environment_source_revision':ENVIRONMENT_SOURCE,
                'scoring_source_revision':SCORING_SOURCE,
                'report_source_revision':REPORT_SOURCE,
                'omissions':['raw archive inventories','host paths','ports','temporary project names','raw prompts','per-example predictions','model tensors','SQLite state','operational logs'],
                'scope':'Aggregate projection only; full archive audit requires retained local raw evidence and frozen computation sources.'}
    for name, digest in binding['files'].items():
        if sha(base/name) != digest:
            raise ValueError('Accepted input changed during publication')
    (output/'publication-hashes.json').write_bytes(canonical(manifest))
    print(json.dumps({'status':'passed','cells':168,'configurations':56,'published_files':len(artifacts)+3}))

if __name__ == '__main__':
    main(sys.argv[1:])
