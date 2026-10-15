"""Audit known task-training/validation overlap against opaque protected1000 keys."""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from paper_evidence_audit import sha, require, read_bound, retained

INDEX_SHA='c0700613a965e26b85a2511c8a721b2f808536f215b8fe6f18f0d3890634fc2d'

def audit(root,output):
    root=Path(root)
    for relative in ('shared/python','evaluation','extension/client-runtime'):
        sys.path.insert(0,str(root/relative))
    from privoke_model.training_data import training_text_key
    from privoke_eval.clean_augmentation_grouping import opaque_exclusion_key
    from privoke_eval.clean_augmentation_protection import _canonical_group, _identity_aliases
    index_path=root/'evaluation/results/external_pii_20261004_prepared_v3/exclusion-index.json'
    index=read_bound(index_path,INDEX_SHA)
    require(index['aggregate']['selected']==1000 and index['reproduced_twice'] is True,'Protected index provenance differs')
    keys={k:set(v) for k,v in index['key_sets'].items()}
    exact={r['text_sha256'] for r in index['records']}
    commitments={'protected_index':INDEX_SHA}; rows={}
    for study,release in (('privacy_heads_v3_20261013','release-03'),('audience_v3_20261013','release-07')):
        manifest_path=root/'evaluation/results'/study/'data'/release/'manifest.json'
        manifest=json.loads(manifest_path.read_bytes());commitments[study+'_manifest']=sha(manifest_path)
        for role in ('train','validation'):
            item=manifest['files'][role]; path=manifest_path.parent/item['path']
            require(sha(path)==item['sha256'],'Known task-supervision bytes differ')
            batch=[json.loads(l) for l in path.read_bytes().splitlines() if l]
            require(len(batch)==item['rows'],'Known task-supervision count differs')
            rows[study+'/'+role]=batch;commitments[study+'/'+role]=item['sha256']
    module_path=root/'models/generate_baseline.py';commitments['v1_bootstrap_source']=sha(module_path)
    spec=importlib.util.spec_from_file_location('frozen_known_v1_bootstrap',module_path)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    rows['v1_bootstrap']=[{'text':x[0]} for x in module.training_samples()]
    counts={}
    for name,batch in rows.items():
        collisions=Counter(); namespace=Counter()
        for row in batch:
            text=row['text'];norm=training_text_key(text)
            collisions['normalized_text']+=opaque_exclusion_key('text_key',norm) in keys['texts']
            collisions['exact_text']+=hashlib.sha256(text.encode()).hexdigest() in exact
            if 'id' in row and 'group_id' in row:
                collisions['id_alias']+=bool({opaque_exclusion_key('id',v) for v in _identity_aliases(row['id'],row['group_id'])}&keys['ids'])
                collisions['canonical_raw_group']+=opaque_exclusion_key('group',_canonical_group(row['group_id'])) in keys['groups']
                namespace[str(row.get('source') or row.get('metadata',{}).get('source_dataset') or 'not_supplied')]+=1
        counts[name]={'rows':len(batch),'collisions':dict(collisions),'source_namespace_available':dict(namespace)}
        require(not any(collisions.values()),'Known task-supervision collides with protected selection')
    result={'schema':1,'status':'passed_known_task_supervision_disjoint','commitments':commitments,'counts':counts,'protected_final_opened':False,
            'scope':'No final/development rows opened. Compare known original V1 bootstrap and PH3/AU3 TRAIN/VAL to full opaque1000 protection, including final subset. EN3 reuses PH3 supervision.',
            'limitations':['Unknown upstream linguistic-pretraining overlap cannot be excluded.','Known task-training disjointness is not a full literature model-contamination certificate.','Raw PIIMB parent/group keys historically lack source namespace; final analysis must audit raw-group versus supplied source-dataset namespace collisions and report grouping limitations.']}
    retained(output,result);return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--evidence-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();r=audit(a.evidence_root,a.output);print(json.dumps({'status':r['status'],'sha256':sha(a.output),'counts':r['counts']}))

if __name__=='__main__':main()
