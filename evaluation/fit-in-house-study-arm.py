"""Run exactly one isolated, train-only in-house study arm."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

# Set bounded CPU math pools before NumPy, Torch or scikit-learn are imported.
for _name in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS"):
    os.environ[_name] = "4"

EVALUATION = Path(__file__).resolve().parent
ROOT = EVALUATION.parent
for _path in (EVALUATION, ROOT / "shared/python", ROOT / "extension/client-runtime", ROOT / "models"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from privoke_eval.in_house_study_fit import StudyFitError, run_fit
from privoke_eval.in_house_study_contract import ARM_KEYS


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm", required=True, choices=tuple(key for key in ARM_KEYS if key != "S0"))
    parser.add_argument("--train-file", required=True, type=Path)
    parser.add_argument("--training-manifest", required=True, type=Path)
    parser.add_argument("--expected-inputs", required=True, type=Path)
    parser.add_argument("--expected-inputs-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    try:
        result = run_fit(
            arm_key=args.arm,
            train_file=args.train_file,
            training_manifest=args.training_manifest,
            expected_inputs_file=args.expected_inputs,
            expected_inputs_sha256=args.expected_inputs_sha256,
            output=args.output,
            source_revision=args.source_revision,
        )
    except StudyFitError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({
        "status": result["status"],
        "arm_key": result["arm_key"],
        "checkpoint_count": result.get("checkpoint_count", 0),
        "test_scored": False,
        "validation_read": False,
    }, sort_keys=True))
    return 0 if result["status"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
