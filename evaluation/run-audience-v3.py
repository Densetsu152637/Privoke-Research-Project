"""Host AU3 controller; root-bound gates precede probes, fits and FRESH access."""
import argparse
from pathlib import Path
import traceback
import uuid

from privoke_eval import audience_v3 as core


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "probe", "fit", "resume", "export", "capture-native", "verify-native",
                                           "audit-training", "freeze-test", "evaluate-test", "audit-test"))
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--results", type=Path)
    parser.add_argument("--models", type=Path)
    parser.add_argument("--data-manifest", type=Path)
    parser.add_argument("--admission", type=Path)
    parser.add_argument("--tier", choices=core.TIERS)
    parser.add_argument("--name", choices=[p + "-" + t for p in ("before", "after") for t in core.TIERS])
    parser.add_argument("--target", default="127.0.0.1:50381")
    parser.add_argument("--ready-file", type=Path)
    args = parser.parse_args(argv)
    root = args.repository.resolve()
    results = args.results or root / "evaluation/results" / core.STUDY_ID / "runs/cpu-01"
    models = args.models or root / "models/experiments" / core.STUDY_ID / "runs/cpu-01"
    data_manifest = args.data_manifest or root / "evaluation/results" / core.STUDY_ID / "data/release-07/manifest.json"
    if args.action == "prepare" and not args.admission:
        parser.error("--admission required with accepted data review and actual normal/v3 pilots")
    if args.action not in ("prepare", "freeze-test", "evaluate-test", "audit-test") and not args.tier:
        parser.error("--tier required")
    if args.action == "evaluate-test" and (not args.name or not args.ready_file):
        parser.error("--name and --ready-file required")
    try:
        if args.action == "prepare":
            result = core.prepare(root, results, models, data_manifest, args.admission)
        elif args.action in ("fit", "resume"):
            result = core.fit(results, args.tier, resume=args.action == "resume")
        elif args.action in ("probe", "export", "capture-native", "verify-native", "audit-training"):
            result = getattr(core, args.action.replace("-", "_"))(results, args.tier)
        else:
            from privoke_eval import audience_v3_comparison as comparison
            if args.action == "freeze-test":
                result = comparison.freeze_registry(results)
            elif args.action == "evaluate-test":
                result = comparison.evaluate(results, args.name, args.target, args.ready_file)
            else:
                result = comparison.audit(results)
    except Exception as error:
        possible = args.action in ("evaluate-test", "audit-test")
        core.retain(results / "failures" / (args.action + "-" + uuid.uuid4().hex + ".json"),
                    {"action": args.action, "tier": args.tier, "name": args.name, "error": str(error),
                     "traceback": traceback.format_exc(), "fresh_access": None if possible else False,
                     "fresh_access_status": "unknown_may_have_accessed" if possible else "not_accessed"})
        raise
    print(core.canonical(result).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
