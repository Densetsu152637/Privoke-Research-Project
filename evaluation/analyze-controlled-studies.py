"""Independent descriptive group reconciliation for AB14/AD14 saved raw outputs."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys


def main(args):
    root=args.repository.resolve()
    sys.path.insert(0,str(root / "evaluation"))
    from privoke_eval import pipeline_v1_v3 as c
    c.configure(root)
    spec=importlib.util.spec_from_file_location("frozen_ablation",Path(__file__).with_name("run-controlled-product-ablation.py"))
    helper=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.CORE=c
    output=args.output
    p=c.read(output / "protocol.json")
    source_rows=c.rows_for(p,"validation" if args.kind=="adaptation" else "fresh_eval")
    if args.kind=="adaptation":
        selected=set(c.read(output / "assessment-ids.json"))
        source_rows=[r for r in source_rows if r["id"] in selected]
    indexed={r["id"]:r for r in source_rows}
    names=(["original"]+[f"steps64-{scope}-{seed}" for seed in (42,43,44) for scope in ("heads","full_encoder")]) if args.kind=="adaptation" else list(helper.CONFIGS)
    records={}
    for name in names:
        directory=output / "assessment" / name if args.kind=="adaptation" else output / name
        values=c.read(directory / "records.json")
        c.require([r["id"] for r in values]==[r["id"] for r in source_rows],"Ordered case reconciliation failed")
        # Frozen runners stored group_id=family_id. This post-hoc correction reads
        # actual saved audience-expression identities, without changing inference.
        records[name]=[dict(r,group_id=indexed[r["id"]]["metadata"]["audience_expression_group_id"]) for r in values]
    result={"protocol_sha256":c.file_hash(output / "protocol.json"),"kind":args.kind,"rows":len(source_rows),
        "group_reconciliation":{"original_group_id_equals_family_id":all(r["group_id"]==r["family_id"] for r in source_rows),
            "family_groups":len({r["family_id"] for r in source_rows}),"actual_expression_groups":len({r["metadata"]["audience_expression_group_id"] for r in source_rows}),
            "interpretation":"Post-hoc correction of duplicate family interval field; separate family/expression dependence sensitivities, not crossed independence"},
        "analysis_source_sha256":c.file_hash(__file__),"record_hashes":{name:c.file_hash((output / "assessment" / name if args.kind=="adaptation" else output / name) / "records.json") for name in names}}
    if args.kind=="adaptation":
        result["candidate_minus_original"]={name:helper.contrast(records["original"],values) for name,values in records.items() if name!="original"}
        result["full_minus_heads"]={str(seed):helper.contrast(records[f"steps64-heads-{seed}"],records[f"steps64-full_encoder-{seed}"]) for seed in (42,43,44)}
        effective={}
        for name in names[1:]:
            directory=Path(p["models"]) / name
            evidence=c.read(directory / "evidence.json")
            passes=evidence["action_harms"]==0 and evidence["candidate_guard"]["joint_correct"]>evidence["base_guard"]["joint_correct"]
            selected=name if passes else "original"
            selected_directory=directory if passes else Path(p["original"])
            manifest=c.read(selected_directory / "manifest.json")
            catalog={"kind":"hypothetical existing guard mapping; no publication or promotion", "guard_pass":passes,
                "evidence_sha256":c.file_hash(directory / "evidence.json"),"effective_source":selected,
                "manifest_path":str(selected_directory / "manifest.json"),"manifest_sha256":c.file_hash(selected_directory / "manifest.json"),"blob_sha256":manifest["blob"],
                "raw_candidate_preserved":True,"independent_original_preserved":True}
            c.retain(directory / "effective-catalog.json",catalog)
            effective[name]={"guard_mapping":catalog,"correct":{m:sum(helper.metric(r,m) for r in records[selected]) for m in ("binary","action","joint")},
                "raw_fit_seconds":evidence["seconds"],"raw_cuda_peak_allocated_bytes":evidence["cuda_peak_bytes"],"train_counts":evidence["counts"],"encoder_changes":evidence["changes"]["encoder"]}
        result["effective_outcomes"]=effective
    else:
        result["contrasts_to_product"]={name:helper.contrast(records["product"],values) for name,values in records.items() if name!="product"}
        parent=c.read(p["parent_protocol"])
        historical={}
        historical_hashes={}
        for tier in ("efficient","balanced","quality"):
            name="v3-"+tier
            entry=next(e for e in parent["entries"] if e["name"]==name)
            path=Path(p["parent_protocol"]).parent / "models" / name / "raw.jsonl"
            journal=c.Journal(path)
            historical_hashes[name]=c.file_hash(path)
            values=[]
            for row in source_rows:
                key=c.request_id(c.file_hash(p["parent_protocol"]),name,0,row["id"])
                req=c.request_for(entry,row,key)
                values.append(c.record_for(journal.calls[key],entry,row,req))
            historical[tier]=values
        cohorts=[{r["id"] for r in values if helper.distance(r) is not None and helper.distance(r)[1]>0} for values in historical.values()]
        shared=set.intersection(*cohorts)
        c.require(len(shared)==139,"Historical shared over-enforcement cohort differs")
        result["historical_shared139"]={"rows":len(shared),"ids_sha256":c.digest(c.canonical(sorted(shared))),"historical_journal_hashes":historical_hashes,
            "current_configuration_counts":{name:{"allowed_action":sum(helper.metric(r,"action") for r in values if r["id"] in shared),
                "over_enforced":sum(helper.distance(r)[1]>0 for r in values if r["id"] in shared and helper.distance(r) is not None),
                "under_enforced":sum(helper.distance(r)[0]>0 for r in values if r["id"] in shared and helper.distance(r) is not None),
                "errors":sum(r["status"]!="ok" for r in values if r["id"] in shared)} for name,values in records.items()}}
        old={r["id"]:r for r in historical["balanced"]}
        result["historical_balanced_repeatability"]={key:sum(r[key]!=old[r["id"]][key] for r in records["product"]) for key in ("classification","action","status")}
    c.retain(output / "group-reconciled-analysis.json",result)
    print(c.canonical(result).decode())


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("kind",choices=("ablation","adaptation"))
    p.add_argument("--repository",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    main(p.parse_args())
