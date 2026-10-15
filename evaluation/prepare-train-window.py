"""Freeze authenticated BC01 TRAIN sources without executing a model or fitting."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
for path in (ROOT/"shared/python",ROOT/"services/privoke-fuzzer/src",ROOT/"services/privoke-fuzzer/generated"):
    sys.path.insert(0,str(path))
from privoke_model import window_training as contract
from prompt_generation.taxonomy_coverage import load_dataset
from prompt_generation.benign_coverage import load_release
from prompt_generation.train_window import prepare_window


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("dataset","benign-pool","benign-manifest","benign-proof","output"):
        parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--seed",type=int,required=True)
    args=parser.parse_args()
    dataset=load_dataset(args.dataset)
    release=load_release(args.benign_pool,args.benign_manifest,args.benign_proof,dataset)
    value=prepare_window(dataset,release,args.seed)
    payload=contract.canonical_bytes(value)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open("xb") as stream:
        stream.write(payload)
    print(contract.canonical({"manifest_sha256":contract.sha256(payload),"model_calls":0,"fit_release":False,
                              "provenance":value["provenance"]}))


if __name__=="__main__":
    main()
