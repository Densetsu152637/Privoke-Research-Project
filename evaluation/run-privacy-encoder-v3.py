"""Host EN3 full-encoder continuation. Root-bound gates precede real probes/fits."""
from __future__ import annotations
import argparse
from pathlib import Path
import traceback
import uuid
from privoke_eval import privacy_encoder_v3 as core


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "probe", "fit", "resume", "export", "audit-training", "verify-export",
                                           "freeze-development", "evaluate-development", "audit-development"))
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--results", type=Path)
    parser.add_argument("--models", type=Path)
    parser.add_argument("--data-manifest", type=Path)
    parser.add_argument("--tier", choices=core.TIERS)
    parser.add_argument("--device", choices=("cpu", "cuda"), default="cpu")
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--target", default="127.0.0.1:50371")
    parser.add_argument("--ready-file", type=Path)
    args = parser.parse_args(argv)
    root = args.repository.resolve()
    results = args.results or root/"evaluation/results"/core.STUDY_ID
    models = args.models or root/"models/experiments"/core.STUDY_ID
    manifest = args.data_manifest or root/"evaluation/results/privacy_heads_v3_20261013/data/release-03/manifest.json"
    if args.action not in ("prepare", "freeze-development", "audit-development") and not args.tier:
        parser.error("--tier required")
    try:
        if args.action == "prepare":
            value = core.prepare(root, results, models, manifest, device=args.device, threads=args.threads)
        elif args.action == "probe":
            value = core.probe(results, args.tier)
        elif args.action in ("fit", "resume"):
            value = core.fit(results, args.tier, resume=args.action == "resume")
        elif args.action == "export":
            value = core.export(results, args.tier)
        elif args.action == "verify-export":
            value = core.verify_export(results, args.tier)
        elif args.action == "audit-training":
            value = core.audit_training(results, args.tier)
        else:
            from privoke_eval import privacy_encoder_v3_comparison as comparison
            if args.action == "freeze-development":
                value = comparison.freeze_registry(results)
            elif args.action == "evaluate-development":
                if not args.ready_file:
                    parser.error("--ready-file required")
                value = comparison.evaluate(results, args.tier, args.target, args.ready_file)
            else:
                value = comparison.audit(results)
    except Exception as error:
        development_possible = args.action in ("evaluate-development", "audit-development")
        core.retain(results/"failures"/(args.action+"-"+uuid.uuid4().hex+".json"),
                    {"action": args.action, "tier": args.tier, "error": str(error),
                     "traceback": traceback.format_exc(),
                     "development_access": None if development_possible else False,
                     "development_access_status": "unknown_may_have_accessed" if development_possible else "not_accessed"})
        raise
    print(core.canonical(value).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
