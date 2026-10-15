"""Build hash-only prospective final release; never open final bytes."""
from __future__ import annotations
import argparse
import importlib.metadata
import json
from pathlib import Path
import subprocess
import sys
from paper_evidence_audit import PIPE_PROTOCOL, canonical, read_bound, retained, sha, require

FINAL_SHA='613a78b9e5fa677904125b4c056fb8d57d15fb6ebd9c443a75f406ae3ac05515'

def freeze(root, output):
    root=Path(root); worktree=Path(__file__).resolve().parents[1]
    protocol_path=root/'evaluation/results/pipeline_v1_v3_20261014/runs/cpu-01/protocol.json'
    protocol=read_bound(protocol_path,PIPE_PROTOCOL)
    source={}
    for relative in protocol['source_files']:
        path=root/relative; require(path.is_file(),'Source dependency unavailable: '+relative)
        source[relative]=sha(path)
    required_sources=('evaluation/grpc_runtime_client.py','evaluation/host_environment.py',
                      'evaluation/privoke_eval/runners.py','evaluation/privoke_eval/datasets.py',
                      'evaluation/privoke_eval/pipeline_v1_v3_serving.py')
    for relative in required_sources: source[relative]=sha(root/relative)
    assets={}
    for entry in protocol['entries']:
        verified={}
        for relative,expected in entry['assets'].items():
            path=Path(entry['directory'])/relative; require(path.is_file() and sha(path)==expected,'Pinned package asset unavailable/changed')
            verified[relative]={'path':str(path),'sha256':expected}
        assets[entry['name']]={'identity':entry['identity'],'family':entry['family'],'native_cap':entry['native_cap'],'assets':verified,'directory':entry['directory']}
    bootstrap_path=root/'models/generate_baseline.py'
    new_sources={relative:sha(worktree/relative) for relative in ('evaluation/paper_evidence_audit.py','evaluation/freeze_paper_final.py','evaluation/paper_final_semantic.py','evaluation/audit_paper_training_protection.py','evaluation/tests/test_paper_evidence_audit.py')}
    receipts={name:{'path':str(root/'evaluation/results/paper_completion_20261014'/file),'sha256':sha(root/'evaluation/results/paper_completion_20261014'/file)} for name,file in (('training_protection','training-protection-01.json'),('synthetic_tests','synthetic-tests-03.log'))}
    result={'schema':1,'evidence_root':str(root),'worktree_root':str(worktree),'new_executable_sources':new_sources,'gate_receipts':receipts,'study_id':'FN14-final-semantic-20261014','status':'prospective_frozen_pending_root_and_critic_release',
            'exact_user_request':'Can you now get data and rewrite the sections of the paper for all the unfinished work that you can get yourself? First plan out an implementation that utilises the workflows effectively and then act on that implementation.',
            'protected_final_opened':False,'data':{'path':str(root/'evaluation/results/locked-public/final.jsonl'),'expected_sha256':FINAL_SHA,'expected_rows':498,'positive':236,'negative':262,'digest_origin':'existing protocol metadata; final contents not hashed/read during freeze'},
            'packages':assets,'package_selection':'fixed original V1 and existing AU3 selected V3 for every E/B/Q tier; no new selection',
            'protocol_source':{'path':str(protocol_path),'sha256':PIPE_PROTOCOL},'runtime_source_files':source,
            'source_closure_policy':'actual current dependency bytes frozen, all differences from PIPE3 explicitly reportable; source HEAD alone insufficient',
            'host':{'executable':sys.executable,'python':sys.version,'packages':{n:importlib.metadata.version(n) for n in ('numpy','torch','transformers','tokenizers','safetensors','grpcio','protobuf','spacy','presidio-analyzer','en-core-web-sm','en-core-web-lg')}},
            'inference':{'requested_layers':[4],'assert_actual_layers':[4],'successful_sole_layer_required':True,'identity_fields':['model_id','model_version','artifact_checksum','parameter_fingerprint'],'device':'cpu','threads':4,'port':50181,'repeats':1,'timeout_seconds_per_rpc':120,'empty_visibility_hint':True,'training_disabled':True,'remote_fallback_disabled':True,'native_thresholds_and_windows_unchanged':True},
            'analysis':{'binary_projection':'sensitivity != S0 OR bool(categories)','primary_contrasts':['v3-efficient minus v1-efficient','v3-balanced minus v1-balanced','v3-quality minus v1-quality'],'other_pairwise':'exploratory_descriptive','counts':['successful_tp','successful_tn','successful_fp','successful_fn','runtime_errors_by_truth'],'denominators':'all498; errors incorrect; successful-only confusion shown separately','metrics':['recall','specificity','accuracy','balanced_accuracy','F1','F2'],'bootstrap':{'iterations':2000,'seed':42,'quantile':'linear','joint_draws_all_six':True,'grouping':'raw historical group_id primary; namespaced (source_dataset,group_id) sensitivity if source metadata exists; collisions and group-size/source/class composition disclosed; no reconstructed document lineage','undefined_class_resamples':'count and exclude; report valid denominator; no silent zero'},'f_error_convention':'successful confusion preserved; positive errors add FN and negative errors add FP for explicitly error-penalized F1/F2; no error becomes success','interval_inference':'all three planned within-tier contrasts and other comparisons descriptive, unadjusted95%, no familywise confirmatory inference','failure_audit':'descriptive once after scoring, no tuning, threshold/model/policy change or promotion'},
            'prospective_protocol_amendment':'Current user goal authorizes final annotation-presence scoring after freeze. Supersedes historical no-final-failure-inspection solely for descriptive audit after all fixed six arms score. It never authorizes test-driven tuning or promotion. Human contextual safety remains unverified.',
            'preopen_gates':['root and independent critic acceptance of exact manifest/hash and executable source','final runner/model readiness on synthetic-only probes','known task-training versus opaque protected1000 index overlap audit including IDs/groups/normalized texts; namespace ambiguity disclosed','protected final contents inaccessible until release'],
            'training_overlap_scope':'Compare known V1 bootstrap and AU3/PH3/EN3 task-training/validation texts to existing opaque protected selection keys; unknown upstream pretrained-BERT data overlap cannot be excluded.',
            'outputs_root':str(root/'evaluation/results/paper_completion_20261014/final-semantic-01'),
            'limitations':['PIIMB official annotation presence is not contextual severity/audience/action truth.','PIIMB-test-derived historical sparse fitting is within-corpus, not independent benchmark training. These six contextual packages use separately audited task supervision.','Raw source group identifiers lack dataset namespace; grouping collision audit is mandatory before interpreting source-cluster intervals.','No safety/promotion/superiority inference from six fixed package comparisons.']}
    retained(output,result); return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--evidence-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();freeze(a.evidence_root,a.output);print(json.dumps({'freeze':str(a.output),'sha256':sha(a.output),'protected_final_opened':False}))

if __name__=='__main__':main()
