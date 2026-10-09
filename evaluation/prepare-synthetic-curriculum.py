"""Prepare fact-preserving synthetic contextual prompts for controlled fuzzer runs."""
import argparse
import json
from pathlib import Path

from host_environment import ROOT, configure_imports

configure_imports()
from privoke_eval.synthetic_curriculum import prepare


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--teacher-templates", type=Path, default=ROOT / "evaluation/datasets/synthetic-teacher-templates.json")
    parser.add_argument("--exclusion-index", type=Path, required=True)
    parser.add_argument("--evaluation-file", type=Path, help="Pinned development JSONL only; final paths are rejected.")
    parser.add_argument("--evaluation-sha256")
    parser.add_argument("--seed", type=int, default=9102026)
    args = parser.parse_args()
    try:
        manifest = prepare(args.output, args.teacher_templates, args.exclusion_index,
                           args.evaluation_file, args.evaluation_sha256, args.seed)
    except (ValueError, OSError) as error:
        parser.exit(1, f"Preparation failed: {error}\n")
    print(json.dumps({"output": str(args.output), "curriculum_id": manifest["curriculum_id"],
                      "counts": {name: split["count"] for name, split in manifest["splits"].items()},
                      "label_status": manifest["label_status"]}))


if __name__ == "__main__":
    main()
