"""Call bounded additional fuzzer cycles; training implementation stays in its service."""
import argparse
from study_scope import add_product_pipeline_argument, require_product_pipeline
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose", "-f", "docker-compose.yml", "-f", "evaluation/compose.tests.yml",
           "-f", "evaluation/compose.original-runtime.yml", "-f", "evaluation/compose.fuzzer-calibration-anchors.yml",
           "-f", "evaluation/compose.learning-rate-0003.yml"]
MODEL = "/models/privoke-balanced.json"


def call(arguments, *, capture=False, input=None, log=None):
    return subprocess.run(COMPOSE + arguments, cwd=ROOT, input=input, text=True,
                          stdout=subprocess.PIPE if capture else log,
                          stderr=subprocess.PIPE if capture else log, check=True).stdout


def restore(content, log):
    call(["exec", "-T", "param-update-service", "python", "-c",
          "import json,sys; from pathlib import Path; from privoke_model.artifact import write_artifact_atomic; "
          f"write_artifact_atomic(Path('{MODEL}'),json.load(sys.stdin))"], input=content, log=log)
    call(["up", "-d", "--no-deps", "--force-recreate", "--wait", "model-streaming-service", "client-runtime"], log=log)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--experiment-id", required=True)
    add_product_pipeline_argument(parser)
    args = parser.parse_args()
    require_product_pipeline(args, parser)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", args.experiment_id):
        parser.error("Use a 1-64 character experiment identifier starting with a letter or digit.")
    output = ROOT / "evaluation/results" / args.experiment_id
    if output.exists():
        raise SystemExit("Refusing to overwrite a training curve or reuse its request IDs.")
    original = ROOT / "evaluation/results/original_public_development_frozen"
    thresholds = {layer: json.loads(next(original.glob(f"local-jsonl_{layer}_*_results.json"))
                                   .read_text(encoding="utf-8"))["metrics"]
                  for layer in ("semantic", "pipeline")}
    selected = ROOT / "evaluation/results/calibration0003_20261003/seed42-model.json"
    selected_content = selected.read_text(encoding="utf-8")
    selected_cycle = 1
    initial = ROOT / "evaluation/results/calibration0003_20261003_seed42_cycle1"
    initial_report = json.loads(next(initial.glob("local-jsonl_pipeline_*_results.json"))
                                .read_text(encoding="utf-8"))
    best_score = initial_report["metrics"]["balanced_accuracy"]
    if call(["exec", "-T", "param-update-service", "python", "-c",
             "import os; print(os.environ['FUZZER_PROMPT_COUNT'])"], capture=True).strip() != "0":
        raise SystemExit("Automatic startup training must be disabled.")
    settings = json.loads(call(["exec", "-T", "privoke-fuzzer", "python", "-c",
                               "import json,os; print(json.dumps({k:os.environ.get(k) for k in "
                               "['FUZZ_TRAINING_LEARNING_RATE','FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE','FUZZ_PROMPT_DATASET_PATH']}))"], capture=True))
    if settings["FUZZ_TRAINING_LEARNING_RATE"] != "0.003" or settings["FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE"] != "0":
        raise SystemExit("This curve requires the exact approved smaller-step curriculum settings.")
    output.mkdir()
    checkpoints = []
    with (output / "curve.log").open("w", encoding="utf-8") as log:
        restore(selected_content, log)
        try:
            for cycle in (2, 3):
                name = f"{args.experiment_id}_seed42_cycle{cycle}"
                try:
                    response = call(["exec", "-T", "privoke-fuzzer", "python", "src/cli.py", "train",
                                     "--model-id", "privoke-balanced", "--prompt-count", "256", "--seed", "42",
                                     "--request-id", name, "--source-id", "research-development", "--timeout", "120"], capture=True)
                except subprocess.CalledProcessError as exc:
                    (output / f"cycle{cycle}-failure.json").write_text(
                        json.dumps({"exit_code": exc.returncode, "stdout": exc.stdout, "stderr": exc.stderr}, indent=2), encoding="utf-8")
                    checkpoints.append({"cycle": cycle, "accepted": False})
                    break
                outcome = json.loads(response)
                (output / f"cycle{cycle}-update.json").write_text(response, encoding="utf-8")
                if not outcome["accepted"]:
                    checkpoints.append({"cycle": cycle, "accepted": False})
                    break
                snapshot = call(["exec", "-T", "param-update-service", "python", "-c",
                                 f"from pathlib import Path; print(Path('{MODEL}').read_text())"], capture=True)
                artifact = output / f"cycle{cycle}-model.json"
                artifact.write_text(snapshot, encoding="utf-8")
                call(["up", "-d", "--no-deps", "--force-recreate", "--wait", "client-runtime"], log=log)
                call(["run", "--rm", "--no-deps", "evaluation-tests", "python", "run-ablations.py",
                      "--dataset-file", "results/locked-public/development.jsonl", "--run-name", name,
                      "--layers", "semantic", "pipeline", "--model-artifact",
                      f"results/{args.experiment_id}/{artifact.name}"], log=log)
                measured = ROOT / "evaluation/results" / name
                metrics = {layer: json.loads(next(measured.glob(f"local-jsonl_{layer}_*_results.json"))
                                            .read_text(encoding="utf-8"))["metrics"]
                           for layer in thresholds}
                eligible = all(metrics[layer][metric] >= thresholds[layer][metric]
                               for layer in thresholds for metric in ("recall", "specificity"))
                checkpoints.append({"cycle": cycle, "accepted": True, "eligible": eligible,
                                    "metrics": metrics, "artifact": str(artifact.relative_to(ROOT))})
                print(json.dumps({"cycle": cycle, "eligible": eligible,
                                  "pipeline_recall": metrics["pipeline"]["recall"],
                                  "pipeline_specificity": metrics["pipeline"]["specificity"]}), flush=True)
                if not eligible:
                    break
                if metrics["pipeline"]["balanced_accuracy"] > best_score:
                    selected, selected_content, selected_cycle = artifact, snapshot, cycle
                    best_score = metrics["pipeline"]["balanced_accuracy"]
        finally:
            restore(selected_content, log)
    manifest = {"settings": settings, "seed": 42, "source_prompt_count_per_cycle": 256,
                "selection": "No recall/specificity loss in semantic or pipeline versus original; maximize pipeline balanced accuracy; ties prefer fewer cycles",
                "selected_cycle": selected_cycle, "selected_artifact": str(selected.relative_to(ROOT)),
                "selected_sha256": hashlib.sha256(selected.read_bytes()).hexdigest(), "checkpoints": checkpoints}
    (output / "selection.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"selected_cycle": selected_cycle, "selected_artifact": manifest["selected_artifact"]}), flush=True)


if __name__ == "__main__":
    main()
