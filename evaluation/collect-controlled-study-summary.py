"""Export prompt-free AB14/AD14 aggregates from immutable local study evidence."""
import argparse
import hashlib
import json
from pathlib import Path


def read(path):
    return json.loads(Path(path).read_bytes())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def compact(value):
    if isinstance(value,dict):
        return {key:(len(item) if key in ("lost_correct_actions","gained_correct_actions") else compact(item)) for key,item in value.items()}
    if isinstance(value,list):
        return [compact(item) for item in value]
    return value


def main(args):
    base=args.repository / "evaluation/results/controlled_studies_20261014"
    ab=base / "ablation-02"
    ad=base / "adaptation-02"
    abp,abraw,abgroup=read(ab / "protocol.json"),read(ab / "analysis.json"),read(ab / "group-reconciled-analysis.json")
    adp,adraw,adgroup=read(ad / "protocol.json"),read(ad / "analysis.json"),read(ad / "group-reconciled-analysis.json")
    result={"schema":1,"study_id":"controlled_studies_20261014","ablation":{"scope":abp["scope"],"execution_mode":"host gRPC over dedicated loopback server","package_identity":abp["entry"]["identity"],"source_closure":abp["source_closure"],"requests":abraw["requests"],"rows":abraw["rows"],
        "configs":abp["configs"],"configurations":abraw["configurations"],"group_reconciliation":abgroup["group_reconciliation"],"contrasts_to_product":compact(abgroup["contrasts_to_product"]),
        "historical_shared139":abgroup["historical_shared139"],"historical_balanced_repeatability":abgroup["historical_balanced_repeatability"],"hashes":{f:sha(ab / f) for f in ("protocol.json","analysis.json","group-reconciled-analysis.json","server-cessation.json")}},
        "adaptation":{"scope":"semantic-only fixed-base matched adaptation; raw terminal candidates plus unchanged control", "fit_execution_mode":"direct host Torch semantic training primitive", "assessment_execution_mode":"in-process host CUDA native protobuf handler; serialized request/response audit; no gRPC transport", "source_closure":adp["source_closure"],"base_manifest_sha256":adp["base_manifest_sha256"],"base_blob":adp["base_blob"],
        "assessment_rows":adraw["rows"],"assessment_exclusion":adp["assessment_exclusion"],"main":adp["main"],"policy":adp["fit_policy"],"summaries":adraw["summaries"],"group_reconciliation":adgroup["group_reconciliation"],
        "candidate_minus_original":compact(adgroup["candidate_minus_original"]),"full_minus_heads":compact(adgroup["full_minus_heads"]),"effective_outcomes":adgroup["effective_outcomes"],
        "hashes":{f:sha(ad / f) for f in ("protocol.json","pilot-results.json","pilot-accepted.json","main-results.json","analysis.json","group-reconciled-analysis.json")}},
        "limitations":["Reused assistant-provisional synthetic labels; no protected final access or promotion", "Separate family/expression dependence sensitivities are not crossed independent intervals", "Group-label correction is explicitly post-hoc; original frozen scorer repeated family identities", "Unchanged zero-head ORIGINAL is a weak task baseline", "Seed realizations reuse assessment identities; no pooled independent sample claim", "Fixed host/order/resource observations do not establish deployment or pretraining causality"]}
    args.destination.parent.mkdir(parents=True,exist_ok=True)
    args.destination.write_text(json.dumps(result,indent=2,sort_keys=True,allow_nan=False)+"\n",encoding="utf8")
    print(sha(args.destination))


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository",type=Path,required=True)
    parser.add_argument("--destination",type=Path,required=True)
    main(parser.parse_args())
