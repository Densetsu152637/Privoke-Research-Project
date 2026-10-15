"""Host PH3 controller. Root acceptance gates precede cache and physical fits."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
import traceback
import uuid
from privoke_eval import privacy_heads_v3 as core

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",choices=("probe","prepare","cache","fit","resume","export",
        "audit-training","freeze-eval-registry","evaluate","audit"))
    parser.add_argument("--repository",type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument("--results",type=Path)
    parser.add_argument("--models",type=Path)
    parser.add_argument("--data-manifest",type=Path)
    parser.add_argument("--tier",choices=core.TIERS)
    parser.add_argument("--feature-batch",type=int,default=16)
    parser.add_argument("--threads",type=int,default=4)
    parser.add_argument("--model",choices=[f"{family}-{tier}" for family in ("v1","v3") for tier in core.TIERS])
    parser.add_argument("--target",default="127.0.0.1:50371")
    parser.add_argument("--ready-file",type=Path)
    args = parser.parse_args(argv)
    root = core.configure_repository(args.repository)
    results = args.results or root/"evaluation/results"/core.STUDY_ID
    models = args.models or root/"models/experiments"/core.STUDY_ID
    manifest = args.data_manifest or results/"data/manifest.json"
    if args.action in ("cache","fit","resume","export","audit-training") and not args.tier:
        parser.error("--tier is required")
    if args.action=="evaluate" and (not args.model or not args.ready_file):
        parser.error("--model and --ready-file are required")
    try:
        if args.action=="prepare":
            value = core.prepare(root,results,models,manifest,feature_batch=args.feature_batch,threads=args.threads)
        elif args.action=="probe":
            value = core.resource_probe(root,results,manifest,threads=args.threads)
        elif args.action=="cache":
            value = core.cache(results,args.tier)
        elif args.action in ("fit","resume"):
            value = core.fit(results,args.tier,resume=args.action=="resume")
        elif args.action=="export":
            value = core.export(results,args.tier)
        elif args.action=="audit-training":
            value = core.audit_training(results,args.tier)
        else:
            from privoke_eval import privacy_heads_v3_comparison as comparison
            if args.action=="freeze-eval-registry":
                value = comparison.freeze_registry(results)
            elif args.action=="evaluate":
                value = comparison.evaluate(results,args.model,args.target,ready_file=args.ready_file)
            else:
                value = comparison.audit_comparison(results)
    except Exception as error:
        core.retain(results/"failures"/(args.action+"-"+uuid.uuid4().hex+".json"),
                    {"action":args.action,"tier":args.tier,"type":type(error).__name__,
                     "error":str(error),"traceback":traceback.format_exc(),"fresh_eval_policy":"sealed_until_registry"})
        raise
    print(core.canonical(value).decode(),end="")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
