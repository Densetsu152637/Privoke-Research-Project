"""Call at most two further cycles under the public-negative study protocol."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

SPEC = importlib.util.spec_from_file_location(
    "negative_study", Path(__file__).with_name("run-public-negative-study.py"))
STUDY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STUDY)
ROOT = STUDY.ROOT
RATE_SLUGS = {.03: "003", .1: "01", .3: "03"}


def curve_candidate_improves(metrics, selected_metrics):
    """Require the declared recall floor and a strict specificity improvement."""
    candidate = metrics["pipeline"]
    return (candidate["true_positives"] >= 238
            and candidate["true_negatives"] > selected_metrics["pipeline"]["true_negatives"])


def checked_selection(path):
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not manifest["completed"] or not manifest["selected_restored"]:
        raise ValueError("The independent study must complete and restore its selection first.")
    records = manifest["records"]
    if {(row["rate"], row["seed"]) for row in records} != {
            (rate, seed) for rate in (.03, .1, .3) for seed in (42, 1337, 2026)} or len(records) != 9:
        raise ValueError("The independent study must retain all nine attempts.")
    best = (54, 247, -1, -.003, -42)
    selected_record = None
    expected = STUDY.locked_prediction_keys()
    prefix = path.parent.name
    for row in records:
        if row["cycle"] != 1:
            raise ValueError("Independent attempts must be first-cycle restarts.")
        if not row["scored"]:
            continue
        run = f"{prefix}_lr{RATE_SLUGS[row['rate']]}_seed{row['seed']}_cycle1"
        metrics = STUDY.measurements(ROOT / "evaluation/results" / run, expected)
        if metrics != row["metrics"]:
            raise ValueError("Independent manifest metrics differ from checked raw reports.")
        key = STUDY.candidate_key(metrics, 1, row["rate"], row["seed"])
        if row["eligible"] != (key is not None):
            raise ValueError("Independent eligibility differs from the prospective criterion.")
        if key is not None and key > best:
            best, selected_record = key, row
    if selected_record is None or (best[0] - 54) / 238 < .05:
        raise ValueError("No independently selected candidate meets the five-point extension trigger.")
    if selected_record["artifact"] != manifest["selected_artifact"]:
        raise ValueError("Recorded selection differs from the checked prospective ranking.")
    if (manifest["selected_exact_counts"] != {"true_negatives": best[0], "true_positives": best[1]}
            or not manifest["additional_cycle_trigger_met"]):
        raise ValueError("Recorded selected counts or extension trigger are inconsistent.")
    artifact = ROOT / manifest["selected_artifact"]
    if hashlib.sha256(artifact.read_bytes()).hexdigest() != manifest["selected_file_sha256"]:
        raise ValueError("Selected artifact differs from its recorded digest.")
    return manifest, selected_record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--study-manifest", type=Path, required=True)
    parser.add_argument("--experiment-id", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,49}", args.experiment_id):
        parser.error("Use a 1-50 character experiment identifier starting with a letter or digit.")
    output = ROOT / "evaluation/results" / args.experiment_id
    if output.exists():
        raise SystemExit("Refusing to overwrite evidence or reuse update request IDs.")
    manifest, selected_record = checked_selection(args.study_manifest)
    selected = ROOT / selected_record["artifact"]
    selected_content = selected.read_text(encoding="utf-8")
    selected_metrics = selected_record["metrics"]
    selected_cycle = 1
    seed, rate = selected_record["seed"], selected_record["rate"]
    compose = STUDY.COMPOSE + ({.03: [], .1: ["-f", "evaluation/compose.learning-rate-01.yml"],
                               .3: ["-f", "evaluation/compose.learning-rate-03.yml"]}[rate])
    dataset = ROOT / "evaluation/results/public-negative-curriculum/prompts.jsonl"
    if hashlib.sha256(dataset.read_bytes()).hexdigest() != manifest["curriculum_sha256"]:
        raise SystemExit("Curriculum differs from the independent study.")
    if STUDY.call(["exec", "-T", "param-update-service", "python", "-c",
                   "import os; print(os.environ['FUZZER_PROMPT_COUNT'])"], capture=True, compose=compose).strip() != "0":
        raise SystemExit("Automatic startup training must remain disabled.")
    output.mkdir()
    records = []
    completed = False
    error = None
    with (output / "curve.log").open("w", encoding="utf-8") as log:
        try:
            STUDY.call(["up", "-d", "--no-deps", "--force-recreate", "--wait", "privoke-fuzzer"], log=log, compose=compose)
            settings = json.loads(STUDY.call(["exec", "-T", "privoke-fuzzer", "python", "-c",
                "import json,os; print(json.dumps({k:os.environ.get(k) for k in "
                "['FUZZ_TRAINING_LEARNING_RATE','FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE','FUZZ_PROMPT_DATASET_PATH']}))"],
                capture=True, compose=compose))
            if (float(settings["FUZZ_TRAINING_LEARNING_RATE"]) != rate
                    or settings["FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE"] != "0"
                    or settings["FUZZ_PROMPT_DATASET_PATH"] != "/workspace/evaluation/results/public-negative-curriculum/prompts.jsonl"):
                raise ValueError("Fuzzer configuration differs from the selected study profile.")
            (output / "configuration.json").write_text(json.dumps(settings, indent=2), encoding="utf-8")
            STUDY.restore(selected_content, log, compose)
            for cycle in (2, 3):
                run = f"{args.experiment_id}_seed{seed}_cycle{cycle}"
                try:
                    response = STUDY.call(["exec", "-T", "privoke-fuzzer", "python", "src/cli.py", "train",
                        "--model-id", "privoke-balanced", "--prompt-count", "256", "--seed", str(seed),
                        "--request-id", run, "--source-id", "research-development", "--timeout", "120"],
                        capture=True, compose=compose)
                except subprocess.CalledProcessError as exc:
                    (output / f"cycle{cycle}-failure.json").write_text(json.dumps({
                        "exit_code": exc.returncode, "stdout": exc.stdout, "stderr": exc.stderr}, indent=2), encoding="utf-8")
                    records.append({"cycle": cycle, "accepted": False, "scored": False})
                    break
                outcome = json.loads(response)
                (output / f"cycle{cycle}-update.json").write_text(response, encoding="utf-8")
                if not outcome["accepted"]:
                    records.append({"cycle": cycle, "accepted": False, "scored": False})
                    break
                checkpoint = {"cycle": cycle, "accepted": True, "scored": False}
                records.append(checkpoint)
                if outcome["base_version"] != json.loads(selected_content)["version"]:
                    raise ValueError("Additional cycle did not start from the selected checkpoint.")
                snapshot = STUDY.call(["exec", "-T", "param-update-service", "python", "-c",
                    f"from pathlib import Path; print(Path('{STUDY.MODEL}').read_text())"], capture=True, compose=compose)
                artifact = output / f"cycle{cycle}-model.json"
                artifact.write_text(snapshot, encoding="utf-8")
                STUDY.call(["up", "-d", "--no-deps", "--force-recreate", "--wait", "client-runtime"], log=log, compose=compose)
                STUDY.call(["run", "--rm", "--no-deps", "evaluation-tests", "python", "run-ablations.py",
                    "--dataset-file", "results/locked-public/development.jsonl", "--run-name", run,
                    "--layers", "semantic", "pipeline", "--model-artifact",
                    artifact.relative_to(ROOT / "evaluation").as_posix()], log=log, compose=compose)
                metrics = STUDY.measurements(ROOT / "evaluation/results" / run)
                improves = curve_candidate_improves(metrics, selected_metrics)
                checkpoint.update(scored=True, improves=improves,
                    metrics=metrics, artifact=artifact.relative_to(ROOT).as_posix())
                print(json.dumps({"cycle": cycle, "improves": improves, "pipeline": metrics["pipeline"]}), flush=True)
                if not improves:
                    break
                selected, selected_content, selected_metrics, selected_cycle = artifact, snapshot, metrics, cycle
            completed = True
        except Exception as exc:
            error = {"type": type(exc).__name__, "message": str(exc)}
            if records and not records[-1]["scored"]:
                records[-1]["error"] = error
            (output / "execution-failure.json").write_text(json.dumps(error, indent=2), encoding="utf-8")
            raise
        finally:
            restored = False
            try:
                STUDY.restore(selected_content, log, compose)
                restored = True
            finally:
                record = {"completed": completed, "selected_restored": restored, "seed": seed, "rate": rate,
                    "source_revision": subprocess.check_output(["git", "-c", f"safe.directory={ROOT.as_posix()}",
                        "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                    "study_manifest_sha256": hashlib.sha256(args.study_manifest.read_bytes()).hexdigest(),
                    "curriculum_sha256": manifest["curriculum_sha256"], "records": records, "error": error,
                    "selected_artifact": selected.relative_to(ROOT).as_posix(), "selected_cycle": selected_cycle,
                    "selected_file_sha256": hashlib.sha256(selected.read_bytes()).hexdigest(),
                    "selected_metrics": selected_metrics,
                    "selection": "Strictly improve pipeline specificity with TP>=238/264; stop at rejection, recall below90% or no improvement; at most cycles2 and3"}
                (output / "selection.json").write_text(json.dumps(record, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
