"""Freeze positively admitted TRAIN inputs; teacher model execution is a separate release."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared" / "python"))
from privoke_model import sensitive_retention as contract


def prepare_bank(dataset_path, label_review_path):
    raw = Path(dataset_path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != contract.DATASET_SHA256:
        raise ValueError("Permanent TRAIN source bytes differ.")
    review_raw = Path(label_review_path).read_bytes()
    review = json.loads(review_raw)
    if (hashlib.sha256(review_raw).hexdigest() != contract.LABEL_REVIEW_SHA256
            or review["status"] != "accepted" or review["approved_rows"] != 200 or review["rejected_ids"]):
        raise ValueError("Independent positive TRAIN label receipt differs.")
    source = json.loads(raw)
    # Metadata first: access text/targets only for positively admitted TRAIN rows.
    selected = []
    for row in source["rows"]:
        metadata = row.get("metadata", {})
        if metadata.get("taxonomy_partition") != "train":
            continue
        if row["classification"]["sensitivity"] == "S0":
            continue
        if metadata.get("split") != "train":
            raise ValueError("Approved retention membership is not permanent TRAIN.")
        selected.append(row)
    payload = contract.canonical_bytes(sorted(selected, key=lambda row: row["id"]))
    contract.validate_bank(payload)
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--label-review", required=True)
    parser.add_argument("--output-bank", required=True)
    args = parser.parse_args()
    payload = prepare_bank(args.dataset, args.label_review)
    path = Path(args.output_bank)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(payload)
    print(json.dumps({"bank_sha256": contract.sha256(payload), "rows": 200, "groups": 20,
                      "model_calls": 0, "fit_release": False}))


if __name__ == "__main__":
    main()
