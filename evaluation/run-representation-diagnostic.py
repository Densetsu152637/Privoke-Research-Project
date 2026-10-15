"""Orchestrate fresh, auditable offline pooled-feature export and probe fitting."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import struct

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "evaluation/results"
LOCKED = RESULTS / "locked-public"
COMPOSE = ["docker", "compose", "-f", "docker-compose.yml", "-f", "evaluation/compose.tests.yml",
           "-f", "evaluation/compose.public-negatives.yml"]
EXPORT_PROGRAM = r'''
import json,sys
from src.model import TinyTransformerModel
from src.detection.preprocessing import normalize_text
from privoke_model.fingerprint import parameter_fingerprint
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
fingerprint=parameter_fingerprint({name:value.ravel() for name,value in model.parameters.items()},
                                 {name:list(value.shape) for name,value in model.parameters.items()})
print(json.dumps({'config':payload['artifact']['config'],'partitions':result,'parameter_fingerprint':fingerprint}))
'''


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def artifact_fingerprint(artifact):
    parameters = artifact["parameters"]
    def as_runtime_float32(value):
        return struct.unpack("!f", struct.pack("!f", float(value)))[0]
    tensors = [[name, list(parameters[name]["shape"]),
                [as_runtime_float32(value) for value in parameters[name]["values"]]]
               for name in sorted(parameters)]
    packed = json.dumps(tensors, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(packed.encode("utf-8")).hexdigest()


def git_revision():
    result = subprocess.run(["git", "-c", f"safe.directory={ROOT.as_posix()}", "rev-parse", "HEAD"],
                            cwd=ROOT, capture_output=True, text=True, encoding="utf-8", check=True)
    return result.stdout.strip()


def run_text_process(command, *, cwd, input_text=None):
    """Run a text process with deterministic UTF-8 stdin/stdout/stderr transport."""
    return subprocess.run(command, cwd=cwd, input=input_text, capture_output=True,
                          text=True, encoding="utf-8")


def run_phase(name, command, *, output, run_manifest, persist, input_text=None):
    """Run and persist one phase, including failures raised before a process result exists."""
    try:
        result = run_text_process(command, cwd=ROOT, input_text=input_text)
    except Exception as exc:
        failure = f"{type(exc).__name__}: {exc}"
        stderr = failure + "\n"
        (output / f"{name}.stdout.log").write_text("", encoding="utf-8")
        (output / f"{name}.stderr.log").write_text(stderr, encoding="utf-8")
        run_manifest["phases"][name] = {"returncode": None, "command": command,
            "transport_exception": failure,
            "stdout_sha256": hashlib.sha256(b"").hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr.encode("utf-8")).hexdigest()}
        persist()
        raise RuntimeError(f"Phase {name} transport failed; see its stdout/stderr logs: {failure}") from exc
    (output / f"{name}.stdout.log").write_text(result.stdout, encoding="utf-8")
    (output / f"{name}.stderr.log").write_text(result.stderr, encoding="utf-8")
    run_manifest["phases"][name] = {"returncode": result.returncode,
        "command": command,
        "stdout_sha256": hashlib.sha256(result.stdout.encode("utf-8")).hexdigest(),
        "stderr_sha256": hashlib.sha256(result.stderr.encode("utf-8")).hexdigest()}
    persist()
    if result.returncode:
        raise RuntimeError(f"Phase {name} failed with exit code {result.returncode}; see its stdout/stderr logs.")
    return result.stdout


def output_container_path(path):
    relative = path.resolve().relative_to(RESULTS.resolve()).as_posix()
    return f"/workspace/evaluation/results/{relative}"


def preparation_target(output):
    """Return the fresh prepared-data subdirectory and its container path."""
    target = output / "prepared"
    if target.exists():
        raise FileExistsError(f"Refusing to replace prepared data: {target}")
    return target, output_container_path(target)


def prepared_partition_container_path(output, name):
    return f"{output_container_path(output / 'prepared')}/{name}"


def preparation_invocation(output):
    target, container_target = preparation_target(output)
    command = COMPOSE + ["run", "--pull", "never", "--rm", "--no-deps", "-T", "evaluation-tests", "python",
                         "prepare-representation-study.py", "--output", container_target]
    return target, container_target, command


def original_artifact_identity(artifact):
    checked_in = json.loads((ROOT / "models/privoke-balanced.json").read_text(encoding="utf-8"))
    if artifact != checked_in:
        raise ValueError("Original snapshot differs from checked-in balanced model artifact.")
    if (artifact.get("model_id") != "privoke-balanced" or artifact.get("version") != "v0.3.0"
            or artifact.get("config", {}).get("hidden_size") != 32):
        raise ValueError("Frozen probe requires the original privoke-balanced v0.3.0 32D artifact.")


def capture_image_identity(service, label, phase):
    if service == "client-runtime":
        result = phase(f"{label}-runtime-container", COMPOSE + ["ps", "-q", service])
        container_ids = [line.strip() for line in result.splitlines() if line.strip()]
        if len(container_ids) != 1:
            raise RuntimeError("Expected exactly one running client-runtime container.")
        image_id = phase(f"{label}-runtime-image", ["docker", "inspect", "--format", "{{.Image}}", container_ids[0]]).strip()
        if not image_id:
            raise RuntimeError("Could not resolve running client-runtime image ID.")
        return {"container_id": container_ids[0], "image_id": image_id}
    result = phase(f"{label}-evaluation-image-reference", COMPOSE + ["config", "--images", service])
    references = [line.strip() for line in result.splitlines() if line.strip()]
    if len(references) != 1:
        raise RuntimeError("Expected one configured evaluation-tests image reference.")
    image_id = phase(f"{label}-evaluation-image", ["docker", "image", "inspect", "--format", "{{.Id}}", references[0]]).strip()
    if not image_id:
        raise RuntimeError("Could not resolve configured evaluation-tests image ID.")
    return {"reference": references[0], "image_id": image_id}


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
        return run_phase(name, command, output=output, run_manifest=run_manifest,
                         persist=persist, input_text=input_text)

    try:
        run_manifest["source_revision"] = git_revision()
        run_manifest["images_before"] = {
            service: capture_image_identity(service, "before", phase)
            for service in ("client-runtime", "evaluation-tests")}
        persist()
        locked_manifest_path = LOCKED / "manifest.json"
        locked_manifest = json.loads(locked_manifest_path.read_text(encoding="utf-8"))
        for split in ("development", "final"):
            if sha256_file(LOCKED / f"{split}.jsonl") != locked_manifest["partitions"][split]["sha256"]:
                raise ValueError(f"Locked {split} input digest mismatch.")
        prepared, prepared_container, prep_command = preparation_invocation(output)
        phase("prepare", prep_command)
        prep_manifest_path = prepared / "manifest.json"
        prep_manifest = json.loads(prep_manifest_path.read_text(encoding="utf-8"))
        partitions = {}
        for name in ("train", "validation", "development"):
            path = prepared / f"{name}.jsonl"
            if sha256_file(path) != prep_manifest["partition_sha256"][name]:
                raise ValueError(f"Prepared {name} partition digest mismatch.")
            partitions[name] = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        artifact_path = RESULTS / "original-v0.3.0-model.json"
        artifact_bytes = artifact_path.read_bytes()
        artifact = json.loads(artifact_bytes)
        original_artifact_identity(artifact)
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
        if exported.get("parameter_fingerprint") != run_manifest["model"]["parameter_fingerprint"]:
            raise ValueError("Client-runtime parameter fingerprint differs from frozen artifact.")
        payload = {"partitions": {name: {"rows": rows, "features": exported["partitions"][name]}
                                  for name, rows in partitions.items()},
                   "partition_paths": {name: prepared_partition_container_path(output, f"{name}.jsonl")
                                       for name in partitions},
                   "partition_sha256": prep_manifest["partition_sha256"],
                   "study_manifest_path": prepared_partition_container_path(output, "manifest.json"),
                   "study_manifest_sha256": run_manifest["study_manifest_sha256"],
                   "locked_directory": "/workspace/evaluation/results/locked-public",
                   "original_semantic_reference": f"/workspace/evaluation/results/original_public_development_frozen/{original_report.name}",
                   "original_semantic_reference_sha256": run_manifest["baseline_reference_sha256"],
                   "rule_union": "/workspace/evaluation/results/context-rules-v2-development.json",
                   "rule_union_sha256": run_manifest["reused_rule_report_sha256"],
                   "rule_source_sha256": rule_hashes, "artifact_sha256": run_manifest["model"]["artifact_sha256"],
                   "runtime_config": exported["config"]}
        for part in payload["partitions"].values():
            for row in part["rows"]:
                del row["text"]
        features_path = output / "features.json"
        features_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        run_manifest["features_sha256"] = sha256_file(features_path)
        persist()
        phase("fit", COMPOSE + ["run", "--pull", "never", "--rm", "--no-deps", "-T", "evaluation-tests", "python",
              "fit-representation-probe.py", "--input", f"{container_output}/features.json",
              "--output", f"{container_output}/fit-report.json"])
        run_manifest["images_after"] = {
            service: capture_image_identity(service, "after", phase)
            for service in ("client-runtime", "evaluation-tests")}
        for service in ("client-runtime", "evaluation-tests"):
            if run_manifest["images_before"][service] != run_manifest["images_after"][service]:
                raise RuntimeError(f"Container image identity drifted for {service} during the study.")
        persist()
        fit_path = output / "fit-report.json"
        selection_path = output / "fit-report-selection.json"
        if not fit_path.is_file():
            raise RuntimeError("Fit phase completed without its report artifact.")
        run_manifest["fit_report_sha256"] = sha256_file(fit_path)
        if not selection_path.is_file():
            raise RuntimeError("Fit phase completed without its frozen validation selection artifact.")
        run_manifest["selection_artifact_sha256"] = sha256_file(selection_path)
        persist()
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
