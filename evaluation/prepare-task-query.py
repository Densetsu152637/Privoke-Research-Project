"""Prepare a separate Tiny v2 zero-query release; never install or fit it."""
from pathlib import Path
import argparse
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared/python"))
from privoke_model.artifact import load_artifact
from privoke_model.contextual_training import prepare_task_query_artifact, LAST_BLOCK_STRATEGY, FULL_ENCODER_STRATEGY


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--generated-at-unix", type=int, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--scope", choices=("heads", "last_block", "full_encoder"), required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Preparation requires a new output file.")
    strategy = {"heads": None, "last_block": LAST_BLOCK_STRATEGY, "full_encoder": FULL_ENCODER_STRATEGY}[args.scope]
    result = prepare_task_query_artifact(load_artifact(args.source), version=args.version,
        generated_at_unix=args.generated_at_unix, source_revision=args.source_revision, strategy=strategy)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, sort_keys=True, separators=(",", ":"), allow_nan=False)
        stream.write("\n")


if __name__ == "__main__":
    main()
