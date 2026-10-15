"""Host PIPE3 fixed product pipeline comparison and immutable evidence audit."""
import argparse
import os
from pathlib import Path

from privoke_eval import pipeline_v1_v3 as core


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "preflight", "evaluate", "audit"))
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--results", type=Path)
    parser.add_argument("--models", type=Path)
    parser.add_argument("--name", choices=core.NAMES)
    parser.add_argument("--target", default="127.0.0.1:53771")
    parser.add_argument("--ready-file", type=Path)
    args = parser.parse_args(argv)
    for key, value in core.PRODUCT_ENV.items():
        os.environ[key] = value
    core.configure(args.repository)
    root = args.repository.resolve()
    results = args.results or root / "evaluation/results" / core.STUDY_ID / "runs/cpu-01"
    models = args.models or root / "models/experiments" / core.STUDY_ID / "runs/cpu-01"
    if args.action in ("preflight", "evaluate") and (not args.name or not args.ready_file):
        parser.error("--name and --ready-file required")
    if args.action == "prepare":
        result = core.prepare(root, results, models)
    elif args.action == "audit":
        result = core.audit(results)
    else:
        result = getattr(core, args.action)(results, args.name, args.target, args.ready_file)
    print(core.canonical(result).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
