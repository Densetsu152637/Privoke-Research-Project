"""Authenticate already-produced ORIGINAL task logits; no teacher/model execution."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"shared/python"))
from privoke_model import window_training as contract, sensitive_retention as legacy


def prepare(bank_payload,logit_payload,teacher_path,teacher_sha256,profile):
    bank=legacy.validate_bank(bank_payload)
    teacher=contract.teacher_identity(teacher_path,profile,teacher_sha256)
    supplied=json.loads(logit_payload)
    if set(supplied)!={"schema","teacher","bank_sha256","rows"} or supplied["schema"]!=2 or supplied["teacher"]!=teacher or supplied["bank_sha256"]!=legacy.BANK_SHA256:
        raise ValueError("Supplied full task-logit evidence must already bind authenticated ORIGINAL and fixed TRAIN bank.")
    rows=[]
    if len(supplied["rows"])!=len(bank):
        raise ValueError("Full ORIGINAL task logits require every approved bank row in order.")
    for source,row in zip(bank,supplied["rows"]):
        if set(row)!={"id","gold","original","confidence","logits"} or row["id"]!=source["id"] or row["gold"]!=source["packed_classification"]:
            raise ValueError("Supplied ORIGINAL logit membership/targets differ.")
        rows.append({**row,"components":contract.component_specs(row["gold"],row["original"],row["logits"],teacher["config"])})
    references=contract.canonical_bytes({**supplied,"rows":rows})
    manifest=contract.canonical_bytes({"schema":2,"kind":"original_train_component_retention_v2","teacher":teacher,
        "bank_sha256":legacy.BANK_SHA256,"references_sha256":contract.sha256(references),
        "epsilon":contract.EPSILON,"margin_cap":1.0,"normalization":contract.CONFIG["normalization"],"coefficient":1,"fit_release":False})
    release=contract.ComponentRelease(bank_payload,references,manifest,str(teacher_path),teacher_sha256)
    contract.validate_component_release(release)
    return references,manifest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("bank","task-logits","teacher","output-references","output-manifest"):
        parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--teacher-sha256",required=True,help="Independently accepted ORIGINAL raw-file SHA; preparation does not approve this pin")
    parser.add_argument("--profile",choices=("quality","balanced","efficient"),required=True)
    args=parser.parse_args()
    if args.output_references.resolve()==args.output_manifest.resolve() or args.output_references.exists() or args.output_manifest.exists():
        parser.error("Preparation requires two distinct new outputs.")
    references,manifest=prepare(args.bank.read_bytes(),args.task_logits.read_bytes(),args.teacher,args.teacher_sha256,args.profile)
    for path,payload in ((args.output_references,references),(args.output_manifest,manifest)):
        path.parent.mkdir(parents=True,exist_ok=True)
        with path.open("xb") as stream:
            stream.write(payload)
    print(contract.canonical({"manifest_sha256":contract.sha256(manifest),"teacher_sha256":args.teacher_sha256,"model_calls":0,"fit_release":False}))


if __name__=="__main__":
    main()
