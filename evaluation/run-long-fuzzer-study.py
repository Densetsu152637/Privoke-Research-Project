"""Run a prospective six-hour study in isolated Compose storage, then audit it.

Uses the installed evaluation Python environment and existing tested service
images. Does not read final examples, select models, or alter source artifacts.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

from privoke_eval.continual_fuzzer_study import DEVELOPMENT_SHA, PROFILES, sha, write_json

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ["model-streaming-service", "param-update-service", "client-runtime", "privoke-fuzzer", "telemetry-service"]


def now():
    return datetime.now(timezone.utc).isoformat()


def execute(command, env=None):
    print("Executing: " + " ".join(map(str, command)), flush=True)
    subprocess.run(list(map(str, command)), cwd=ROOT, env=env, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--study-id", required=True)
    parser.add_argument("--hours-per-profile", type=float, default=2)
    args = parser.parse_args()
    if args.hours_per_profile <= 0 or not args.hours_per_profile < 24:
        parser.error("hours per profile must be positive and below 24")
    if not args.study_id.startswith("privoke-long-") or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in args.study_id):
        parser.error("study ID must be a unique lowercase privoke-long- name")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    state = {"status": "preparing", "pid": os.getpid(), "started_at": now(), "study_id": args.study_id, "profiles": {}}
    write_json(output / "supervisor.json", state)
    compose = ["docker", "compose", "--project-name", args.study_id, "-f", ROOT / "docker-compose.yml",
               "-f", ROOT / "evaluation/compose.tests.yml", "-f", ROOT / "evaluation/compose.continual-fuzzer-study.yml"]
    env = dict(os.environ, CONTINUAL_STUDY_ID=args.study_id, CONTINUAL_STUDY_CURRICULUM=str(output / "curriculum"))
    try:
        execute([sys.executable, ROOT / "evaluation/prepare-synthetic-curriculum.py", "--output", output / "curriculum",
                 "--exclusion-index", ROOT / "evaluation/results/external_pii_20261004_prepared_v3/exclusion-index.json",
                 "--evaluation-file", ROOT / "evaluation/results/locked-public/development.jsonl", "--evaluation-sha256", DEVELOPMENT_SHA])
        duration = args.hours_per_profile * 3600
        protocol = {"schema_version": 2, "question": "What happens during repeated synthetic fuzzer training over two hours per model profile?",
                    "created_at": now(), "profiles": list(PROFILES), "duration_seconds_per_profile": duration,
                    "cycles_per_profile": 100000, "prompt_count": 256, "new_rows": 192, "replay_rows": 64,
                    "checkpoint_interval_seconds": 1200, "round_pause_seconds": 15, "seed_start": 1337,
                    "bootstrap_iterations": 2000, "learning_rate": .003, "replay_weight": .35, "transforms": 0,
                    "heldout_count": 16, "dataset_sha256": DEVELOPMENT_SHA,
                    "curriculum_manifest_sha256": sha(output / "curriculum/manifest.json"),
                    "source_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                    "source_files": {str(p.relative_to(ROOT)): sha(p) for p in [Path(__file__), ROOT / "evaluation/privoke_eval/continual_fuzzer_study.py",
                        ROOT / "services/privoke-fuzzer/src/prompt_generation/curriculum.py", ROOT / "services/privoke-fuzzer/src/fuzzer_service.py",
                        ROOT / "services/privoke-fuzzer/src/config.py", ROOT / "services/privoke-fuzzer/src/training/trainer.py",
                        ROOT / "services/privoke-fuzzer/src/training/transforms.py", ROOT / "evaluation/compose.continual-fuzzer-study.yml"]},
                    "limitations": ["Exploratory development comparisons; no old-sampler control or model promotion.",
                        "Contextual synthetic labels are provisional and differ from annotation-presence endpoint targets.",
                        "Repeated rounds reuse a finite synthetic pool; exposures are correlated."]}
        write_json(output / "protocol.json", protocol)
        (output / "state").mkdir()
        for model_id in PROFILES:
            short = model_id.removeprefix("privoke-")
            env["CONTINUAL_STUDY_MODEL_ID"] = model_id
            state.update(status="running", current_profile=model_id)
            state["profiles"][model_id] = {"status": "starting", "started_at": now()}
            write_json(output / "supervisor.json", state)
            execute(compose + ["config", "--services"], env)
            execute(compose + ["up", "-d", "--wait", "--wait-timeout", "180", *SERVICES], env)
            names = [args.study_id + "-" + suffix for suffix in ("fuzzer", "updater", "runtime", "model", "telemetry")]
            inspected = json.loads(subprocess.check_output(["docker", "inspect", *names], text=True))
            operations = {"schema_version": 1, "recorded_at": now(), "containers": {}}
            prefixes = ("FUZZ", "PARAM_", "MODEL_", "PRIVOKE_", "TELEMETRY_", "OMP_", "MKL_", "PYTHONPATH")
            for row in inspected:
                operations["containers"][row["Name"].lstrip("/")] = {"image_id": row["Image"], "environment":
                    {k: v for k, v in (entry.split("=", 1) for entry in row["Config"]["Env"] if "=" in entry) if k.startswith(prefixes)}}
            operations_path = output / f"operations-{short}.json"
            write_json(operations_path, operations)
            state["profiles"][model_id]["status"] = "training"
            write_json(output / "supervisor.json", state)
            execute([sys.executable, ROOT / "evaluation/run-continual-fuzzer-study.py", "--model-id", model_id,
                     "--cycles", "100000", "--checkpoints", "0", "--duration-seconds", duration,
                     "--checkpoint-interval-seconds", "1200", "--round-pause-seconds", "15", "--checkpoint-only-snapshots",
                     "--dataset-file", ROOT / "evaluation/results/locked-public/development.jsonl",
                     "--curriculum-manifest", output / "curriculum/manifest.json", "--output", output / short,
                     "--operational-manifest", operations_path], env)
            execute(["docker", "cp", f"{args.study_id}-updater:/models/{model_id}.json", output / short / "published-artifact.json"])
            execute(["docker", "cp", f"{args.study_id}-fuzzer:/workspace/dumps/privoke-fuzzer/curriculum.sqlite3", output / "state" / f"after-{short}.sqlite3"])
            state["profiles"][model_id].update(status="complete", finished_at=now())
            write_json(output / "supervisor.json", state)
        execute(["docker", "cp", f"{args.study_id}-updater:/data", output / "state/parameter-update-data"])
        execute([sys.executable, ROOT / "evaluation/summarize-continual-fuzzer-study.py", "--study-root", output])
        summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
        lines = ["# Sustained synthetic fuzzer study", "", "Exploratory development results; no model promotion. Contextual training targets and annotation-presence evaluation are distinct tasks.", "",
                 "| Profile | Training hours | Attempts | Accepted | Layer | Recall before → after | Specificity before → after |", "|---|---:|---:|---:|---|---|---|"]
        for short, profile in summary["profiles"].items():
            final = profile["checkpoints"][str(profile["final_cycle"])]
            for layer in ("semantic", "pipeline"):
                before = profile["checkpoints"]["0"][layer]["metrics"]
                after = final[layer]["metrics"]
                lines.append(f"| {short} | {profile['timed_training_seconds']/3600:.3f} | {profile['attempts']} | {profile['accepted_updates']} | {layer} | {before['recall']:.2%} → {after['recall']:.2%} | {before['specificity']:.2%} → {after['specificity']:.2%} |")
        lines += ["", "All rejected attempts and deterioration remain in summary.json. Its checkpoint records include paired group bootstrap intervals. Repeated checkpoints reuse 502 endpoint rows in 465 source groups; they do not increase the independent sample size.", "", *protocol["limitations"]]
        (output / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        state.update(status="complete", finished_at=now(), summary_sha256=sha(output / "summary.json"))
    except BaseException as exc:
        state.update(status="interrupted", error=str(exc), interrupted_at=now())
        raise
    finally:
        write_json(output / "supervisor.json", state)
        execute(compose + ["stop", *SERVICES], env)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
