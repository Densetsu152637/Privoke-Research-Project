"""Measure released model profiles through the existing Docker evaluator."""
import argparse
from study_scope import add_product_pipeline_argument, require_product_pipeline
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import subprocess

SPEC = importlib.util.spec_from_file_location("study", Path(__file__).with_name("run-public-negative-study.py"))
STUDY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STUDY)
ROOT = STUDY.ROOT
COMPOSE = STUDY.COMPOSE
PROFILES = ("privoke-efficient", "privoke-balanced", "privoke-quality")


def runtime_cost(report):
    values = [row["elapsed_ms"] for row in report["metadata"]["predictions"]]
    if not values or any(not isinstance(value, (float, int)) or not math.isfinite(value) or value < 0 for value in values):
        raise ValueError("Runtime durations must be complete, finite and nonnegative.")
    ordered = sorted(values)
    def percentile(fraction):
        location = (len(ordered) - 1) * fraction
        low, high = math.floor(location), math.ceil(location)
        return ordered[low] + (ordered[high] - ordered[low]) * (location - low)
    return {"scope": "returned runtime elapsed_ms; excludes browser/bridge overhead",
            "samples": len(values), "first_request_ms": values[0], "median_ms": percentile(.5),
            "p95_ms": percentile(.95), "mean_ms": sum(values) / len(values), "max_ms": max(values)}


def live_artifact(model_id):
    return STUDY.call(["exec", "-T", "param-update-service", "python", "-c",
        f"from pathlib import Path; print(Path('/models/{model_id}.json').read_text())"], capture=True)


def image_ids():
    rows = json.loads(STUDY.call(["images", "--format", "json"], capture=True))
    return {row["Repository"]: row["ID"] for row in rows
            if row["Repository"] != "privoke-research-project-evaluation-tests"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-prefix", default="model_profiles_20261003")
    add_product_pipeline_argument(parser)
    args = parser.parse_args()
    require_product_pipeline(args, parser)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,39}", args.run_prefix):
        parser.error("Use a 1-40 character run prefix starting with a letter or digit.")
    output = ROOT / "evaluation/results" / args.run_prefix
    if output.exists() or any((output.parent / f"{args.run_prefix}_{model_id}").exists() for model_id in PROFILES):
        raise SystemExit("Refusing to overwrite profile evidence or reuse run IDs.")
    STUDY.locked_prediction_keys()
    if STUDY.call(["exec", "-T", "param-update-service", "python", "-c",
                  "import os; print(os.environ['FUZZER_PROMPT_COUNT'])"], capture=True).strip() != "0":
        raise SystemExit("Automatic startup training must remain disabled.")
    prior = live_artifact("privoke-balanced")
    prior_payload = json.loads(prior)
    snapshots = {model_id: (ROOT / "models" / f"{model_id}.json").read_text(encoding="utf-8") for model_id in PROFILES}
    for model_id in ("privoke-efficient", "privoke-quality"):
        if json.loads(live_artifact(model_id)) != json.loads(snapshots[model_id]):
            raise SystemExit(f"Catalog {model_id} differs from the checked-in original.")
    before_images = image_ids()
    output.mkdir()
    (output / "prior-selected-model.json").write_text(prior, encoding="utf-8")
    records = []
    completed, restored, error = False, False, None
    with (output / "study.log").open("w", encoding="utf-8") as log:
        try:
            STUDY.restore(snapshots["privoke-balanced"], log)
            hardware = STUDY.call(["exec", "-T", "client-runtime", "python", "-c",
                "import json,os,platform;from pathlib import Path; "
                "print(json.dumps({'machine':platform.machine(),'python':platform.python_version(),'cpu_count':os.cpu_count(),"
                "'cpu_model':next((x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() "
                "if x.startswith('model name')),None),'limits':{x:Path('/sys/fs/cgroup/'+x).read_text().strip() "
                "for x in ['cpu.max','memory.max','cpuset.cpus.effective'] if Path('/sys/fs/cgroup/'+x).exists()}}))"], capture=True)
            (output / "hardware.json").write_text(hardware, encoding="utf-8")
            for model_id in PROFILES:
                artifact = output / f"{model_id}.json"
                artifact.write_text(live_artifact(model_id), encoding="utf-8")
                payload = json.loads(artifact.read_text(encoding="utf-8"))
                if payload != json.loads(snapshots[model_id]) or payload["version"] != "v0.3.0":
                    raise ValueError("Each profile must use its exact original v0.3.0 payload.")
                STUDY.call(["up", "-d", "--no-deps", "--force-recreate", "--wait", "client-runtime"], log=log)
                run = f"{args.run_prefix}_{model_id}"
                STUDY.call(["run", "--rm", "--no-deps", "evaluation-tests", "python", "run-ablations.py",
                    "--dataset-file", "results/locked-public/development.jsonl", "--run-name", run,
                    "--layers", "semantic", "pipeline", "--model-artifact",
                    artifact.relative_to(ROOT / "evaluation").as_posix()], log=log)
                directory = output.parent / run
                metrics = STUDY.measurements(directory)
                cost = {layer: runtime_cost(json.loads(next(directory.glob(f"local-jsonl_{layer}_*_results.json"))
                        .read_text(encoding="utf-8"))) for layer in STUDY.LAYERS}
                record = {"model_id": model_id, "artifact": artifact.relative_to(ROOT).as_posix(),
                    "artifact_file_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    "checksum": payload["checksum"], "config": payload["config"], "metadata": payload["metadata"],
                    "parameter_count": sum(len(tensor["values"]) for tensor in payload["parameters"].values()),
                    "json_bytes": len(artifact.read_bytes()), "metrics": metrics, "runtime_cost": cost}
                records.append(record)
                print(json.dumps({"model_id": model_id, "counts": {layer: {key: value[key]
                    for key in ("true_positives", "true_negatives", "false_positives", "false_negatives")}
                    for layer, value in metrics.items()}, "runtime_cost": cost}), flush=True)
            completed = True
        except Exception as exc:
            error = {"type": type(exc).__name__, "message": str(exc)}
            raise
        finally:
            try:
                STUDY.restore(prior, log)
                restored = json.loads(live_artifact("privoke-balanced")) == prior_payload
                if not restored:
                    raise ValueError("Restored model payload differs from the prior selection.")
            finally:
                after_images = image_ids()
                unchanged_images = before_images == after_images
                if not unchanged_images:
                    completed = False
                    error = error or {"type": "ImageMismatch", "message": "Serving images changed during the matched comparison."}
                result = {"completed": completed, "selected_restored": restored, "error": error,
                    "source_revision": subprocess.check_output(["git", "-c", f"safe.directory={ROOT.as_posix()}",
                        "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(), "records": records,
                    "prior_checksum": prior_payload["checksum"], "image_ids_before": before_images,
                    "image_ids_after": after_images, "serving_images_unchanged": unchanged_images}
                (output / "summary.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
                if not unchanged_images:
                    raise ValueError("Serving images changed; the profile comparison is incomplete.")


if __name__ == "__main__":
    main()
