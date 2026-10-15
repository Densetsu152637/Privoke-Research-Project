"""Prepare a new immutable AU3 TRAIN/validation/sealed-fresh release on the host."""
import argparse
import json
from pathlib import Path
from host_environment import configure_imports
configure_imports()
from privoke_eval.audience_v3_data import prepare

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    manifest = prepare(args.output)
    print(json.dumps({"study_id": manifest["study_id"], "files": manifest["files"], "audit": manifest["audit"]}))
