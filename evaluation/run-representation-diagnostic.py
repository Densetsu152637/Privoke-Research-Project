"""Orchestrate fresh, auditable offline pooled-feature export and probe fitting."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "evaluation/results"
LOCKED = RESULTS / "locked-public"
COMPOSE = ["docker", "compose", "-f", "docker-compose.yml", "-f", "evaluation/compose.tests.yml",
           "-f", "evaluation/compose.public-negatives.yml"]
EXPORT_PROGRAM = r'''
import json,sys
from src.model import TinyTransformerModel
from src.detection.preprocessing import normalize_text
payload=json.load(sys.stdin)
model=TinyTransformerModel.from_artifact(payload['artifact'])
result={}
for name,rows in payload['partitions'].items():
    features=[]
    for start in range(0,len(rows),32):
        batch=rows[start:start+32]
        predictions=model.predict_many([normalize_text(row['text']) for row in batch])
        for row,pred in zip(batch,predictions):
            features.append({'id':row['id'],'group_id':row['group_id'],
                'expected_has_pii':row['expected_has_pii'],'pooled':list(pred.pooled),
                'original_binary':pred.sensitivity!='S0' or bool(pred.categories)})
    result[name]=features
print(json.dumps({'config':payload['artifact']['config'],'partitions':result}))
'''


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def artifact_fingerprint(artifact):
    parameters = artifact["parameters"]
    tensors = [[name, list(parameters[name]["shape"]),
                [float(value) for value in parameters[name]["values"]]] for name in sorted(parameters)]
    packed = json.dumps(tensors, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(packed.encode("utf-8")).hexdigest()


def git_revision():
    result = subprocess.run(["git", "-c", f"safe.directory={ROOT.as_posix()}", "rev-parse", "HEAD"],
                            cwd=ROOT, capture_output=True, text=True, check=True)
    return result.stdout.strip()


def output_container_path(path):
    relative = path.resolve().relative_to(RESULTS.resolve()).as_posix()
    return f"/workspace/evaluation/results/{relative}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, help="Fresh directory under evaluation/results for this run")
    args = parser.parse_args()
    default_name = "frozen-representation-study-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output = args.output or (RESULTS / default_name)
    if not output.is_absolute():
        output = RESULTS / output
    output = output.resolve()
    if RESULTS.resolve() not in output.parents:
        parser.error("--output must be a new directory inside evaluation/results.")
    output.mkdir(parents=True, exist_ok=False)
    container_output = output_container_path(output)
    run_manifest = {"status": "running", "started_at_utc": datetime.now(timezone.utc).isoformat(),
                    "source_revision": None, "compose_files": COMPOSE[3::2], "phases": {},
                    "output": output.relative_to(RESULTS).as_posix()}
    manifest_path = output / "run-manifest.json"

    def persist():
        manifest_path.write_text(json.dumps(run_manifest, indent=2), encoding="utf-8")

    persist()

    def phase(name, command, *, input_text=None):
        result = subprocess.run(command, cwd=ROOT, input=input_text, capture_output=True, text=True)
        (output / f"{name}.stdout.log").write_text(result.stdout, encoding="utf-8")
        (output / f"{name}.stderr.log").write_text(result.stderr, encoding="utf-8")
        run_manifest["phases"][name] = {"returncode": result.returncode,
            "command": command,
            "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
            "stderr_sha256": hashlib.sha256(result.stderr.encode()).hexdigest()}
        persist()
        if result.returncode:
            raise RuntimeError(f"Phase {name} failed with exit code {result.returncode}; see its stdout/stderr logs.")
        return result.stdout

    try:
        run_manifest["source_revision"] = git_revision()
        persist()
        locked_manifest_path = LOCKED / "manifest.json"
        locked_manifest = json.loads(locked_manifest_path.read_text(encoding="utf-8"))
        for split in ("development", "final"):
            if sha256_file(LOCKED / f"{split}.jsonl") != locked_manifest["partitions"][split]["sha256"]:
                raise ValueError(f"Locked {split} input digest mismatch.")
        prep_command = COMPOSE + ["run", "--rm", "--no-deps", "-T", "evaluation-tests", "python",
                                  "prepare-representation-study.py", "--output", container_output]
        phase("prepare", prep_command)
        prep_manifest_path = output / "manifest.json"
        prep_manifest = json.loads(prep_manifest_path.read_text(encoding="utf-8"))
        partitions = {}
        for name in ("train", "validation", "development"):
            path = output / f"{name}.jsonl"
            if sha256_file(path) != prep_manifest["partition_sha256"][name]:
                raise ValueError(f"Prepared {name} partition digest mismatch.")
            partitions[name] = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        artifact_path = RESULTS / "original-v0.3.0-model.json"
        artifact_bytes = artifact_path.read_bytes()
        artifact = json.loads(artifact_bytes)
        run_manifest["model"] = {"model_id": artifact.get("model_id"), "version": artifact.get("version"),
            "checksum": artifact.get("checksum"), "artifact_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
            "parameter_fingerprint": artifact_fingerprint(artifact), "config": artifact.get("config")}
        run_manifest["protected_sha256"] = prep_manifest["locked_sha256"]
        run_manifest["study_manifest_sha256"] = sha256_file(prep_manifest_path)
        bootstrap_path = ROOT / "models/generate_baseline.py"
        if sha256_file(bootstrap_path) != prep_manifest["bootstrap_source_sha256"]:
            raise ValueError("Bootstrap source changed since preparation.")
        run_manifest["bootstrap_source_sha256"] = prep_manifest["bootstrap_source_sha256"]
        reference_files = list((RESULTS / "original_public_development_frozen").glob("local-jsonl_semantic_*_results.json"))
        if len(reference_files) != 1:
            raise ValueError("Expected exactly one archived original semantic development report.")
        original_report = reference_files[0]
        rule_union = RESULTS / "context-rules-v2-development.json"
        rule_report = json.loads(rule_union.read_text(encoding="utf-8"))
        rule_hashes = {}
        if not isinstance(rule_report.get("source_sha256"), dict) or not rule_report["source_sha256"]:
            raise ValueError("Revised rule report has no source hashes.")
        for source_name, expected_digest in rule_report["source_sha256"].items():
            normalized = source_name.replace("\\", "/")
            source_path = (ROOT / normalized).resolve()
            if ROOT.resolve() not in source_path.parents:
                raise ValueError("Rule source path escapes the repository root.")
            actual_digest = sha256_file(source_path)
            if actual_digest != expected_digest:
                raise ValueError(f"Revised rule source hash mismatch for {normalized}.")
            rule_hashes[normalized] = actual_digest
        run_manifest["rule_source_sha256"] = rule_hashes
        run_manifest["baseline_reference_sha256"] = sha256_file(original_report)
        run_manifest["reused_rule_report_sha256"] = sha256_file(rule_union)
        run_manifest["prepared_partition_sha256"] = prep_manifest["partition_sha256"]
        persist()
        export_input = json.dumps({"artifact": artifact, "partitions": partitions}, ensure_ascii=False)
        export_stdout = phase("feature-export", COMPOSE + ["exec", "-T", "client-runtime", "python", "-c", EXPORT_PROGRAM],
                              input_text=export_input)
        (output / "runtime-export.json").write_text(export_stdout, encoding="utf-8")
        exported = json.loads(export_stdout)
        if set(exported["partitions"]) != set(partitions):
            raise ValueError("Runtime export did not return every partition.")
        payload = {"partitions": {name: {"rows": rows, "features": exported["partitions"][name]}
                                  for name, rows in partitions.items()},
                   "partition_paths": {name: f"{container_output}/{name}.jsonl" for name in partitions},
                   "partition_sha256": prep_manifest["partition_sha256"],
                   "study_manifest_path": f"{container_output}/manifest.json",
                   "study_manifest_sha256": run_manifest["study_manifest_sha256"],
                   "locked_directory": "/workspace/evaluation/results/locked-public",
                   "original_semantic_reference": f"/workspace/evaluation/results/original_public_development_frozen/{original_report.name}",
                   "rule_union": "/workspace/evaluation/results/context-rules-v2-development.json",
                   "rule_source_sha256": rule_hashes, "artifact_sha256": run_manifest["model"]["artifact_sha256"],
                   "runtime_config": exported["config"]}
        for part in payload["partitions"].values():
            for row in part["rows"]:
                del row["text"]
        features_path = output / "features.json"
        features_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        run_manifest["features_sha256"] = sha256_file(features_path)
        persist()
        phase("fit", COMPOSE + ["run", "--rm", "--no-deps", "-T", "evaluation-tests", "python",
              "fit-representation-probe.py", "--input", f"{container_output}/features.json",
              "--output", f"{container_output}/fit-report.json"])
        run_manifest["image_identity"] = {}
        for service in ("client-runtime", "evaluation-tests"):
            names = subprocess.run(COMPOSE + ["config", "--images", service], cwd=ROOT,
                                   capture_output=True, text=True)
            references = [line.strip() for line in names.stdout.splitlines() if line.strip()]
            identities = []
            for reference in references:
                inspected = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", reference],
                                           cwd=ROOT, capture_output=True, text=True)
                identities.append({"reference": reference, "image_id": inspected.stdout.strip(),
                                   "returncode": inspected.returncode, "stderr": inspected.stderr})
            run_manifest["image_identity"][service] = {"references": references,
                "inspect_returncode": names.returncode, "inspect_stderr": names.stderr, "images": identities}
            if names.returncode or not identities or any(item["returncode"] or not item["image_id"] for item in identities):
                raise RuntimeError(f"Could not resolve immutable image identity for {service}.")
        persist()
        fit_path = output / "fit-report.json"
        selection_path = output / "fit-report-selection.json"
        if not fit_path.is_file():
            raise RuntimeError("Fit phase completed without its report artifact.")
        run_manifest["fit_report_sha256"] = sha256_file(fit_path)
        if not selection_path.is_file():
            raise RuntimeError("Fit phase completed without its frozen validation selection artifact.")
        run_manifest["selection_artifact_sha256"] = sha256_file(selection_path)
        fit_summary = json.loads(fit_path.read_text(encoding="utf-8"))
        run_manifest["fit_status"] = fit_summary.get("status")
        if fit_summary.get("status") != "complete":
            raise RuntimeError("Fit report is not complete.")
        run_manifest["status"] = "complete"
        run_manifest["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        persist()
        print(json.dumps({"status": run_manifest["status"], "output": output.as_posix(),
                          "features_sha256": run_manifest["features_sha256"]}))
        return 0
    except Exception as exc:
        run_manifest["status"] = "failed"
        run_manifest["failure"] = f"{type(exc).__name__}: {exc}"
        run_manifest["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        persist()
        raise


if __name__ == "__main__":
    raise SystemExit(main())
