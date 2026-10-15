"""Publish safe aggregate-only projections from independently bound raw analyses."""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path
from paper_evidence_audit import read_bound, retained, sha, require

SAVED='4f1bbe75efe293aa1640cda75860e452bc271461de9e5425a2176b07717ab6d7'
LARGE='247553c43d530751872e99c7e87ec6e5ab6edc24de67e7e0ba8fa6aa0c0df738'

def publish(root,output):
    root=Path(root);evidence=root/'evaluation/results/paper_completion_20261014'
    saved=read_bound(evidence/'saved-analysis-01.json',SAVED)
    large=read_bound(evidence/'presidio-large-01/analysis.json',LARGE)
    raw=read_bound(evidence/'presidio-large-01/raw.json',large['raw_sha256'])['predictions']
    confusion=Counter()
    for row in raw:
        require(row['status']=='ok','Larger reference has error')
        confusion[('t' if row['expected_has_pii']==row['detected_sensitive'] else 'f')+('p' if row['detected_sensitive'] else 'n')]+=1
    require(dict(confusion)==large['metrics']['presidio-large']['successful_confusion'],'Independent larger raw-count check differs')
    small=read_bound(root/'evaluation/results/paper_revision_20261014/presidio-au3/raw.json',saved['inputs']['presidio_small_raw'])['predictions']
    require([r['example_id'] for r in raw]==[r['example_id'] for r in small],'Larger/small IDs differ')
    gained=sum(a['detected_sensitive']==a['expected_has_pii'] and b['detected_sensitive']!=b['expected_has_pii'] for a,b in zip(raw,small))
    lost=sum(a['detected_sensitive']!=a['expected_has_pii'] and b['detected_sensitive']==b['expected_has_pii'] for a,b in zip(raw,small))
    require({'gained':gained,'lost':lost}==large['paired_large_vs_small'],'Independent paired-count check differs')
    confidence=saved['confidence_diagnostics']
    for values in confidence.values():
        values['conditional_scope']='only rows where semantic executed AND exactly one native finding exposed confidence; outcome-selected emission subset; not all semantic executions'
    result={'schema':1,'study_id':'paper-completion-obtainable-evidence-20261014','evidence_hashes':{'saved_analysis':SAVED,'large_analysis':LARGE,'large_raw':large['raw_sha256'],'large_protocol':large['protocol_sha256']},
            'scope':'descriptive reused assistant-provisional AU3; no protected final cases in this projection','rows':1560,
            'saved':{'metrics':saved['metrics'],'actual_layers':saved['actual_layers'],'confidence_diagnostics':confidence,'uncertainty':saved['uncertainty'],'limitations':saved['limitations']},
            'recognizer_large':{'metrics':large['metrics']['presidio-large'],'paired_large_vs_small':large['paired_large_vs_small'],'uncertainty':large['uncertainty'],'limitations':large['limitations']},
            'provenance':{'actual_source_closure':saved['provenance']['source_closure'],'source_status_counts':saved['provenance']['source_status_counts'],'model_asset_status':saved['provenance']['model_assets'],'protected_final_access':False,
                          'clean_room_boundary':'Every154 current runtime dependency matched accepted historical source hashes and every declared model asset matched. Assets remain ignored/local; inference reproducibility requires those exact dirty source bytes and assets, whereas aggregate reproduction needs no weights/prompts.',
                          'larger_protocol_limitation':'Initial BL14 protocol binds its main wrapper, model package/assets/dependencies and input, but omits the imported saved-analysis helper hash. Raw recognizer counts and192/192 transitions were independently recomputed here; no claim that this omission was prospectively repaired.'},
            'independent_checks':{'larger_raw_confusion':dict(confusion),'larger_paired_correctness_gained':gained,'larger_paired_correctness_lost':lost}}
    retained(output,result);return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--evidence-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();publish(a.evidence_root,a.output);print(json.dumps({'output':str(a.output),'sha256':sha(a.output)}))

if __name__=='__main__':main()
