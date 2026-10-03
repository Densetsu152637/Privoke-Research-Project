"""Call the existing fuzzer and evaluator for the prospective negative-coverage study."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MODEL = "/models/privoke-balanced.json"
COMPOSE = ["docker", "compose", "-f", "docker-compose.yml", "-f", "evaluation/compose.tests.yml",
           "-f", "evaluation/compose.public-negatives.yml"]
PRIOR = ROOT / "evaluation/results/calibration0003_20261003/seed42-model.json"
LAYERS = ("semantic", "pipeline")


def call(arguments, *, input=None, capture=False, log=None, compose=COMPOSE):
    return subprocess.run(compose + arguments, cwd=ROOT, input=input, text=True,
                          stdout=subprocess.PIPE if capture else log,
                          stderr=subprocess.PIPE if capture else log, check=True).stdout


def restore(content, log, compose=COMPOSE):
    call(["exec", "-T", "param-update-service", "python", "-c",
          "import json,sys; from pathlib import Path; from privoke_model.artifact import write_artifact_atomic; "
          f"write_artifact_atomic(Path('{MODEL}'),json.load(sys.stdin))"], input=content, log=log, compose=compose)
    call(["up", "-d", "--no-deps", "--force-recreate", "--wait", "model-streaming-service", "client-runtime"],
         log=log, compose=compose)


def measurements(directory):
    result = {}
    for layer in LAYERS:
        reports = list(directory.glob(f"local-jsonl_{layer}_*_results.json"))
        if len(reports) != 1:
            raise ValueError(f"Expected one {layer} report in {directory}.")
        report = json.loads(reports[0].read_text(encoding="utf-8"))
        if report["errors"] or report["metrics"]["evaluated_samples"] != 502:
            raise ValueError("Only complete zero-error matched development runs are eligible.")
        result[layer] = report["metrics"]
    return result


def candidate_key(metrics, cycle, rate, seed):
    pipeline = metrics["pipeline"]
    if pipeline["true_positives"] / 264 < .9 or pipeline["true_negatives"] < 54:
        return None
    return (pipeline["true_negatives"], pipeline["true_positives"], -cycle, -rate, -seed)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--experiment-prefix", default="public_negative_20261003")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,39}", args.experiment_prefix):
        parser.error("Use a 1-40 character prefix starting with a letter or digit.")
    args.output = args.output or ROOT / "evaluation/results" / args.experiment_prefix
    if args.output.exists():
        raise SystemExit("Refusing to overwrite study evidence or reuse request IDs.")
    dataset_path = ROOT / "evaluation/results/public-negative-curriculum/prompts.jsonl"
    data_manifest = json.loads(dataset_path.with_name("manifest.json").read_text(encoding="utf-8"))
    if hashlib.sha256(dataset_path.read_bytes()).hexdigest() != data_manifest["curriculum_sha256"]:
        raise SystemExit("Curriculum differs from its recorded digest.")
    prior = PRIOR.read_text(encoding="utf-8")
    selected = PRIOR
    best = (54, 247, -1, -.003, -42)
    records = []
    source_revision = subprocess.check_output(
        ["git", "-c", f"safe.directory={ROOT.as_posix()}", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    completed = False
    extend = False
    active_compose = COMPOSE
    args.output.mkdir(parents=True)
    with (args.output / "study.log").open("w", encoding="utf-8") as log:
        if call(["exec", "-T", "param-update-service", "python", "-c",
                 "import os; print(os.environ['FUZZER_PROMPT_COUNT'])"], capture=True).strip() != "0":
            raise SystemExit("Disable automatic startup training before this study.")
        try:
            restore((ROOT / "models/privoke-balanced.json").read_text(encoding="utf-8"), log)
            original_snapshot = call(["exec", "-T", "param-update-service", "python", "-c",
                                      f"from pathlib import Path; print(Path('{MODEL}').read_text())"], capture=True)
            baseline_artifact = args.output / "original-model.json"
            baseline_artifact.write_text(original_snapshot, encoding="utf-8")
            call(["run", "--rm", "--no-deps", "evaluation-tests", "python", "run-ablations.py",
                  "--dataset-file", "results/locked-public/development.jsonl", "--run-name", args.experiment_prefix + "_baseline",
                  "--layers", *LAYERS, "--model-artifact", baseline_artifact.relative_to(ROOT / "evaluation").as_posix()], log=log)
            for slug, rate, overlay in (("003", .03, None), ("01", .1, "evaluation/compose.learning-rate-01.yml"),
                                        ("03", .3, "evaluation/compose.learning-rate-03.yml")):
                compose = COMPOSE + (["-f", overlay] if overlay else [])
                active_compose = compose
                experiment_id = f"{args.experiment_prefix}_lr{slug}"
                call(["up", "-d", "--no-deps", "--force-recreate", "--wait", "privoke-fuzzer"], log=log, compose=compose)
                command = [sys.executable, "evaluation/run-independent-updates.py", "--experiment-id", experiment_id,
                           "--compose-override", "evaluation/compose.public-negatives.yml"]
                if overlay:
                    command += ["--compose-override", overlay]
                subprocess.run(command, cwd=ROOT, stdout=log, stderr=log, check=True)
                for seed in (42, 1337, 2026):
                    measured = ROOT / "evaluation/results" / f"{experiment_id}_seed{seed}_cycle1"
                    if not measured.exists():
                        records.append({"rate": rate, "seed": seed, "cycle": 1, "scored": False})
                        continue
                    metrics = measurements(measured)
                    key = candidate_key(metrics, 1, rate, seed)
                    artifact = ROOT / "evaluation/results" / experiment_id / f"seed{seed}-model.json"
                    records.append({"rate": rate, "seed": seed, "cycle": 1, "scored": True,
                                    "eligible": key is not None, "metrics": metrics,
                                    "artifact": artifact.relative_to(ROOT).as_posix()})
                    if key is not None and key > best:
                        best, selected = key, artifact
                    print(json.dumps({"rate": rate, "seed": seed, "eligible": key is not None,
                                      "pipeline_recall": metrics["pipeline"]["recall"],
                                      "pipeline_specificity": metrics["pipeline"]["specificity"]}), flush=True)
            # Additional cycles are a separate bounded action only if the prospective
            # five-percentage-point trigger is actually satisfied by exact counts.
            extend = (best[0] - 54) / 238 >= .05
            completed = True
        finally:
            selected_content = selected.read_text(encoding="utf-8") if selected.exists() else prior
            restored = False
            try:
                restore(selected_content, log, compose=active_compose)
                restored = True
            finally:
                manifest = {"completed": completed, "selected_restored": restored, "source_revision": source_revision,
                "curriculum_sha256": data_manifest["curriculum_sha256"],
                "selection": "Maximize specificity subject to pipeline recall>=0.9 and specificity>=54/238; ties prefer recall, fewer cycles, lower rate and seed",
                "records": records, "selected_artifact": selected.relative_to(ROOT).as_posix(),
                "selected_file_sha256": hashlib.sha256(selected.read_bytes()).hexdigest(),
                "additional_cycle_trigger_met": extend,
                "selected_exact_counts": {"true_negatives": best[0], "true_positives": best[1]}}
                (args.output / "selection.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({key: manifest[key] for key in
                     ("selected_artifact", "selected_exact_counts", "additional_cycle_trigger_met")}))


if __name__ == "__main__":
    main()
