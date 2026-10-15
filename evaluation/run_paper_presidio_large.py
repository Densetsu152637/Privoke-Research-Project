"""One prospectively frozen native Presidio-lg run on already-open AU3 cases."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import sys
import time
from paper_evidence_audit import canonical, sha, retained, require, read_bound, opened_pipe3, paired_bootstrap, scores

WHEEL_SHA='ab70aeb6172cde82508f7739f35ebc9918a3d07debeed637403c8f794ba3d3dc'
INPUT_SHA='64c69e5526a83b4d536655f2a3a19422bb5eec3bad0991855f8f0799918c2e5a'
RAW_SMALL='ce72efabc79cf4f58edda618acc7bf05790f7ecd0d2b197c73593a0aca4984d3'
CONFIG={'nlp_engine_name':'spacy','models':[{'lang_code':'en','model_name':'en_core_web_lg'}]}

def execute(root,output):
    root,output=Path(root),Path(output)
    require(not output.exists(),'Refusing existing run directory; ambiguous outcomes are not replayed')
    versions={n:importlib.metadata.version(n) for n in ('presidio-analyzer','spacy','en-core-web-lg','numpy')}
    require(versions['presidio-analyzer']=='2.2.363' and versions['spacy']=='3.7.5' and versions['en-core-web-lg']=='3.7.1','Pinned host packages differ')
    wheel=root/'models/experiments/paper_completion_20261014/vendor/en_core_web_lg-3.7.1-py3-none-any.whl'
    require(sha(wheel)==WHEEL_SHA,'Official model wheel differs')
    source=root/'evaluation/results/paper_revision_20261014/presidio-au3/projected-input.jsonl'
    require(sha(source)==INPUT_SHA,'Already-open projected input changed')
    rows=[json.loads(l) for l in source.read_bytes().splitlines() if l]
    require(len(rows)==1560 and sum(r['expected_has_pii'] for r in rows)==810,'Projected workload differs')
    spec=importlib.util.find_spec('en_core_web_lg'); require(spec and spec.origin,'Large model missing')
    package_root=Path(spec.origin).parent
    model_assets={p.relative_to(package_root).as_posix():sha(p) for p in sorted(package_root.rglob('*')) if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc'}
    protocol={'schema':1,'study_id':'BL14-presidio-large-20261014','status':'frozen_before_inference','data_sha256':INPUT_SHA,'rows':1560,'positive':810,'negative':750,
              'configuration':CONFIG,'threshold':0.5,'versions':versions,'official_wheel_sha256':WHEEL_SHA,
              'official_release_url':'https://github.com/explosion/spacy-models/releases/tag/en_core_web_lg-3.7.1',
              'official_wheel_url':'https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.7.1/en_core_web_lg-3.7.1-py3-none-any.whl',
              'model_assets':model_assets,'script_sha256':sha(__file__),'executable':sys.executable,
              'settings':'native recognizers; English; text only; no hints, custom rules, tuning or target ontology adaptation',
              'execution':'one invocation, reserve before model load, retain terminal/error outcomes, no retry after ambiguous outcome',
              'analysis':{'binary':'any native entity above0.5','truth':'existing contextual-sensitive projection; deliberate entity/contextual mismatch','bootstrap':'2000 paired common draws seed42; separate family/expression dependence sensitivities','unsupported':['sensitivity_severity','audience','category_exact','policy_action','joint'],'timing':'direct analyzer only; never rank against product RPC times'},
              'limitations':['Larger default native model configuration, not strongest/SOTA certification.','Reused assistant-provisional synthetic data, no independent human or external generalization.']}
    retained(output/'protocol.json',protocol)
    retained(output/'reservation.json',{'utc':datetime.now(timezone.utc).isoformat(),'protocol_sha256':sha(output/'protocol.json'),'status':'reserved_before_model_load'})
    predictions=[]; failure=None
    try:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        engine=NlpEngineProvider(nlp_configuration=CONFIG).create_engine()
        analyzer=AnalyzerEngine(nlp_engine=engine,supported_languages=['en'])
        retained(output/'recognizers.json',{'supported_entities':sorted(analyzer.get_supported_entities(language='en')),
                 'recognizers':[{'class':type(r).__module__+'.'+type(r).__qualname__,'name':r.name,'supported_entities':r.supported_entities,'version':r.version} for r in analyzer.registry.recognizers]})
        raw_path=output/'raw.jsonl'
        with raw_path.open('xb') as journal:
            for row in rows:
                start=time.perf_counter()
                try:
                    findings=analyzer.analyze(text=row['text'],language='en',score_threshold=0.5)
                    result={'status':'ok','detected_sensitive':bool(findings),'entities':sorted({r.entity_type for r in findings}),
                            'findings':[{'entity_type':r.entity_type,'start':r.start,'end':r.end,'score':r.score} for r in findings],
                            'elapsed_ms':(time.perf_counter()-start)*1000}
                except Exception as exc:
                    result={'status':'error','error':type(exc).__name__+': '+str(exc)}
                record={'example_id':row['id'],'group_id':row['group_id'],'expected_has_pii':row['expected_has_pii'],**result}
                journal.write(canonical(record)); journal.flush(); predictions.append(record)
        retained(output/'raw.json',{'baseline':'presidio-large-english','dataset_sha256':INPUT_SHA,'configuration':CONFIG,'threshold':0.5,'versions':versions,'predictions':predictions})
        _,cases,product,_,_=opened_pipe3(root)
        require([r['example_id'] for r in predictions]==[r['id'] for r in cases],'Product pairing differs')
        truth=[r['expected_has_pii'] for r in predictions]
        pred={n:[r['classification']['sensitivity']!='S0' or bool(r['classification']['categories']) for r in values] for n,values in product.items()}
        valid={n:[r['valid'] for r in values] for n,values in product.items()}
        small=read_bound(root/'evaluation/results/paper_revision_20261014/presidio-au3/raw.json',RAW_SMALL)['predictions']
        for name,values in (('presidio-small',small),('presidio-large',predictions)):
            require([r['example_id'] for r in values]==[r['id'] for r in cases],'Reference pairing differs')
            pred[name]=[bool(r.get('detected_sensitive')) for r in values];valid[name]=[r['status']=='ok' for r in values]
        analysis={'schema':1,'protocol_sha256':sha(output/'protocol.json'),'raw_sha256':sha(output/'raw.json'),
                  'metrics':{n:scores(truth,pred[n],valid[n]) for n in pred},
                  'uncertainty':{field:paired_bootstrap(truth,pred,valid,[r['family_id'] if field=='family_id' else r['metadata'][field] for r in cases]) for field in ('family_id','audience_expression_group_id')},
                  'paired_large_vs_small':{'gained':sum(v and a==t and b!=t for t,a,b,v in zip(truth,pred['presidio-large'],pred['presidio-small'],valid['presidio-large'])),
                                          'lost':sum(v and a!=t and b==t for t,a,b,v in zip(truth,pred['presidio-large'],pred['presidio-small'],valid['presidio-large']))},
                  'direct_analyzer_elapsed_ms':{'total':sum(r.get('elapsed_ms',0) for r in predictions)},'limitations':protocol['limitations']+['Entity detection and contextual truth deliberately differ; unsupported tasks remain NA.','Post-hoc descriptive paired intervals; family/expression sensitivities do not establish crossed independence.']}
        retained(output/'analysis.json',analysis)
    except BaseException as exc:
        failure=type(exc).__name__+': '+str(exc)
        raise
    finally:
        retained(output/'terminal.json',{'utc':datetime.now(timezone.utc).isoformat(),'rows_completed':len(predictions),'errors':sum(r['status']!='ok' for r in predictions),'failure':failure,'status':'complete' if failure is None and len(predictions)==1560 else 'failed'})
    return analysis

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--evidence-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();r=execute(a.evidence_root,a.output);print(json.dumps({'output':str(a.output),'analysis_sha256':sha(a.output/'analysis.json'),'large':r['metrics']['presidio-large']}))

if __name__=='__main__':main()
