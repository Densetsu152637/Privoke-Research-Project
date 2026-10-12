"""Host controller. Full-study dispatch requires the separate root milestone."""
from pathlib import Path
import argparse
import json
from privoke_eval.pretrained_v3_study import init_cell, start, cycle, health, compose
parser = argparse.ArgumentParser()
parser.add_argument("phase", choices=("init-cell", "start", "cycle", "health", "stop"))
parser.add_argument("--cell", type=Path, required=True)
parser.add_argument("--tier", choices=("efficient", "balanced", "quality"), default="efficient")
parser.add_argument("--scope", choices=("heads", "full_encoder"), default="heads")
parser.add_argument("--seed", type=int, default=42)
parser.add_argument("--steps", type=int, choices=(2, 64, 256, 512), default=2)
args = parser.parse_args(); cell = args.cell.resolve()
if args.phase == "init-cell": value = init_cell(cell, args.tier, args.scope, args.seed, steps=args.steps)
elif args.phase == "start": value = start(cell)
elif args.phase == "cycle": value = cycle(cell)
elif args.phase == "health": value = {role: health(role) for role in ("checkpoint", "runtime", "fuzzer")}
else:
    result = compose(cell, "stop", "fuzzer", "runtime", "checkpoint")
    print(result.stdout + result.stderr); raise SystemExit(result.returncode)
print(json.dumps(value, sort_keys=True))
