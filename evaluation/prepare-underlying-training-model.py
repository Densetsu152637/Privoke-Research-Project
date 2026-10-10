"""Prepare a separate full-Tiny training release; never install or fit weights."""
from pathlib import Path
import argparse
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared/python"))
from privoke_model.artifact import load_artifact
from privoke_model.contextual_training import prepare_full_encoder_artifact


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Validated Tiny source artifact; retained unchanged.")
    parser.add_argument("--output", type=Path, required=True, help="New artifact path; existing files are refused.")
    parser.add_argument("--version", required=True, help="Distinct release version for the full-training capability.")
    parser.add_argument("--generated-at-unix", type=int, required=True)
    parser.add_argument("--source-revision", required=True, help="Exact 40-character source commit binding this preparation.")
    parser.add_argument("--max-tokens", type=int, default=256,
                        help="Total context including one start token; default 256 allows 255 content tokens. Full-training releases reject overlength inputs.")
    args = parser.parse_args()
    source = load_artifact(args.input)
    if "last_update_receipt" in source.get("metadata", {}):
        parser.error("Source has a recovery receipt; its owner must checkpoint/clear it before preparing a new release.")
    result = prepare_full_encoder_artifact(source, version=args.version,
        generated_at_unix=args.generated_at_unix, source_revision=args.source_revision, max_tokens=args.max_tokens)
    raw = (json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
    with args.output.open("xb") as handle:
        handle.write(raw)
    print(json.dumps({"output": str(args.output.resolve()), "checksum": result["checksum"],
                      "version": result["version"], "existing_weights_changed": False,
                      "max_tokens": result["config"]["max_tokens"],
                      "new_position_rows": result["config"]["max_tokens"] - source["config"]["max_tokens"]}))


if __name__ == "__main__":
    main()
