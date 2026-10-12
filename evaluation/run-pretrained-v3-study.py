"""Host controller. Physical phases run only after the root milestone review."""
from pathlib import Path
import argparse
import json
from privoke_eval.pretrained_v3_study import init_cell, bind_cell, start, cycle, reconcile, health, compose
from privoke_eval.pretrained_v3_plan import freeze_plan, validate_plan, run_plan, score_plan, analyze_plan, export_fixed_models, create_audit_amendment
parser = argparse.ArgumentParser()
parser.add_argument("phase", choices=("init-cell", "bind-cell", "start", "cycle", "reconcile", "health", "stop", "freeze-plan", "validate-plan", "run-plan", "score-plan", "analyze-plan", "export", "create-audit-amendment"))
parser.add_argument("--cell", type=Path)
parser.add_argument("--plan", type=Path)
parser.add_argument("--image-id")
parser.add_argument("--audit-amendment", type=Path)
parser.add_argument("--amendment-output", type=Path)
parser.add_argument("--expected-protocol-sha256")
parser.add_argument("--prior-evidence", type=Path)
parser.add_argument("--pilot-cells", nargs=3, type=Path)
parser.add_argument("--max-total-seconds", type=float)
parser.add_argument("--vram-capacity-bytes", type=int)
parser.add_argument("--tier", choices=("efficient", "balanced", "quality"), default="efficient")
parser.add_argument("--scope", choices=("heads", "full_encoder"), default="heads")
parser.add_argument("--seed", type=int, default=42)
parser.add_argument("--steps", type=int, choices=(2, 64, 256, 512), default=2)
args = parser.parse_args(); cell = args.cell.resolve() if args.cell else None
if args.audit_amendment is not None and args.phase not in ("score-plan", "analyze-plan", "export"):
    parser.error("--audit-amendment is restricted to post-fit score-plan, analyze-plan and export")
if (args.amendment_output is not None or args.expected_protocol_sha256 is not None or args.prior_evidence is not None) and args.phase != "create-audit-amendment":
    parser.error("amendment creation arguments require create-audit-amendment")
if args.phase in ("freeze-plan", "validate-plan", "run-plan", "score-plan", "analyze-plan", "export", "create-audit-amendment"):
    if args.plan is None: parser.error("--plan is required for plan phases")
    if args.phase == "freeze-plan":
        if not args.pilot_cells or not args.image_id or args.max_total_seconds is None or args.vram_capacity_bytes is None:
            parser.error("freeze-plan requires --pilot-cells, --image-id, --max-total-seconds and --vram-capacity-bytes")
        value = freeze_plan(args.plan, args.pilot_cells, args.image_id, max_total_seconds=args.max_total_seconds, vram_capacity_bytes=args.vram_capacity_bytes)
    elif args.phase == "create-audit-amendment":
        if args.amendment_output is None or args.expected_protocol_sha256 is None or args.prior_evidence is None:
            parser.error("create-audit-amendment requires --amendment-output, --expected-protocol-sha256 and --prior-evidence")
        value = create_audit_amendment(args.plan, args.amendment_output, expected_protocol_sha256=args.expected_protocol_sha256, prior_evidence=args.prior_evidence)
    elif args.phase in ("score-plan", "analyze-plan", "export"):
        value = {"score-plan": score_plan, "analyze-plan": analyze_plan, "export": export_fixed_models}[args.phase](args.plan, audit_amendment=args.audit_amendment)
    else:
        value = {"validate-plan": validate_plan, "run-plan": run_plan, "score-plan": score_plan, "analyze-plan": analyze_plan, "export": export_fixed_models}[args.phase](args.plan)
elif cell is None: parser.error("--cell is required for cell phases")
elif args.phase == "init-cell": value = init_cell(cell, args.tier, args.scope, args.seed, steps=args.steps)
elif args.phase == "bind-cell":
    if not args.image_id: parser.error("bind-cell requires --image-id")
    value = bind_cell(cell, args.image_id)
elif args.phase == "start": value = start(cell)
elif args.phase == "cycle": value = cycle(cell)
elif args.phase == "reconcile": value = reconcile(cell)
elif args.phase == "health": value = {role: health(role) for role in ("checkpoint", "runtime", "fuzzer")}
else:
    result = compose(cell, "stop", "fuzzer", "runtime", "checkpoint")
    print(result.stdout + result.stderr); raise SystemExit(result.returncode)
print(json.dumps(value, sort_keys=True))
