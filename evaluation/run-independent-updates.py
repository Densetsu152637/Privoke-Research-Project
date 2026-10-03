"""Host orchestration of independent synthetic update experiments in Docker.

The actual training cycle remains implemented by the fuzzer service. Run only
after the frozen baseline batch completes. All writes target research volumes.
"""
import argparse
import json
import re
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose", "-f", "docker-compose.yml", "-f", "evaluation/compose.tests.yml"]
MODEL_PATH = "/models/privoke-balanced.json"


def call(arguments, *, input=None, capture=False, log=None):
    result = subprocess.run(COMPOSE + arguments, cwd=ROOT, input=input, text=True,
                            stdout=subprocess.PIPE if capture else log,
                            stderr=subprocess.PIPE if capture else log, check=True)
    return result.stdout if capture else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--seeds", nargs="+", type=int, default=[42, 1337, 2026])
    parser.add_argument("--compose-override", type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", args.experiment_id):
        parser.error("Use a run identifier of 1-64 letters, digits, dots, underscores or hyphens, starting with a letter or digit.")
    if args.compose_override:
        COMPOSE.extend(["-f", str(args.compose_override)])
    experiment = ROOT / "evaluation/results" / args.experiment_id
    if experiment.exists():
        raise SystemExit("Refusing to overwrite an experiment directory or reuse its update IDs.")
    experiment.mkdir(parents=True)
    original = (ROOT / "models/privoke-balanced.json").read_text()
    assert json.loads(original)["version"] == "v0.3.0"
    manual = call(["exec", "-T", "param-update-service", "python", "-c",
                   "import os; print(os.environ['FUZZER_PROMPT_COUNT'])"], capture=True).strip()
    if manual != "0":
        raise SystemExit("Disable automatic training in the research override first.")
    for seed in args.seeds:
        name = f"{args.experiment_id}_seed{seed}_cycle1"
        with (experiment / f"seed{seed}.log").open("w", encoding="utf-8") as log:
            call(["exec", "-T", "param-update-service", "python", "-c",
                  "import json,sys; from pathlib import Path; from privoke_model.artifact import write_artifact_atomic; "
                  f"write_artifact_atomic(Path('{MODEL_PATH}'),json.load(sys.stdin))"], input=original, log=log)
            call(["up", "-d", "--no-deps", "--force-recreate", "--wait", "model-streaming-service", "client-runtime"], log=log)
            response = call(["exec", "-T", "privoke-fuzzer", "python", "src/cli.py", "train",
                             "--model-id", "privoke-balanced", "--prompt-count", "256", "--seed", str(seed),
                             "--request-id", name, "--source-id", "research-development", "--timeout", "120"], capture=True)
            outcome = json.loads(response)
            (experiment / f"seed{seed}-update.json").write_text(response)
            if outcome["base_version"] != "v0.3.0":
                raise SystemExit("Independent cycle did not use the original baseline.")
            snapshot = call(["exec", "-T", "param-update-service", "python", "-c",
                             f"from pathlib import Path; print(Path('{MODEL_PATH}').read_text())"], capture=True)
            artifact_path = experiment / f"seed{seed}-model.json"
            artifact_path.write_text(snapshot)
            call(["up", "-d", "--no-deps", "--force-recreate", "--wait", "client-runtime"], log=log)
            call(["run", "--rm", "--no-deps", "evaluation-tests", "python", "run-ablations.py",
                  "--dataset-file", "results/locked-public/development.jsonl", "--run-name", name,
                  "--layers", "semantic", "pipeline", "--model-artifact",
                  f"results/{args.experiment_id}/{artifact_path.name}"], log=log)
        print(json.dumps({"seed": seed, "accepted": outcome["accepted"], "version": outcome["applied_version"],
                          "run": name}), flush=True)

if __name__ == "__main__":
    main()
