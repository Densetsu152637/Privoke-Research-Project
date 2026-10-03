"""Run the fixed external-PII profile comparison through the research Compose stack."""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
RESULTS = (ROOT / "evaluation/results").resolve()
sys.path.insert(0, str(ROOT / "shared/python"))
COMPOSE = ["docker", "compose", "-f", "docker-compose.yml", "-f", "evaluation/compose.tests.yml",
           "-f", "evaluation/compose.public-negatives.yml", "-f", "evaluation/compose.presence.yml"]
PROFILES = ("efficient", "balanced", "quality")
CONTROLS = ("baseline", "expanded")
PARTITIONS = ("validation", "nemotron_heldout", "meddies_heldout")
MODEL_IDS = {profile: f"privoke-presence-{profile}" for profile in PROFILES}
CATALOG_IDS = ("privoke-balanced", *MODEL_IDS.values())
BALANCED_CHECKSUM = "8c139431ba8605a3d6817d24d233cce78fc22a086fdeb3ee99702ada86c80015"

ADMIN_READ = """import base64,json,sys
from pathlib import Path
model_id=sys.argv[1]
assert model_id in ('privoke-balanced','privoke-presence-efficient','privoke-presence-balanced','privoke-presence-quality')
p=Path('/models')/(model_id+'.json')
print(json.dumps({'exists':p.is_file(),'raw_b64':base64.b64encode(p.read_bytes()).decode('ascii') if p.is_file() else None}))
"""
ADMIN_INSTALL = """import json,sys
from pathlib import Path
from privoke_model.artifact import validate_artifact,write_artifact_atomic
model_id=sys.argv[1]
assert model_id in ('privoke-presence-efficient','privoke-presence-balanced','privoke-presence-quality')
raw=sys.stdin.buffer.read();payload=json.loads(raw.decode('utf-8'))
assert payload.get('model_id')==model_id
validate_artifact(payload)
write_artifact_atomic(Path('/models')/(model_id+'.json'),payload)
"""
ADMIN_RESTORE = """import json,os,sys
from pathlib import Path
from privoke_model.artifact import validate_artifact
model_id=sys.argv[1]
assert model_id in ('privoke-balanced','privoke-presence-efficient','privoke-presence-balanced','privoke-presence-quality')
raw=sys.stdin.buffer.read();payload=json.loads(raw.decode('utf-8'))
assert payload.get('model_id')==model_id
validate_artifact(payload)
path=Path('/models')/(model_id+'.json');tmp=path.with_name(path.name+'.restore-'+str(os.getpid()))
with tmp.open('xb') as stream:
 stream.write(raw);stream.flush();os.fsync(stream.fileno())
os.replace(tmp,path)
fd=os.open(str(path.parent),os.O_RDONLY)
try: os.fsync(fd)
finally: os.close(fd)
"""
IDENTITY_PROBE = """import json,sys,grpc
sys.path.insert(0,'/workspace/extension/client-runtime/generated')
from privoke.v1 import runtime_pb2 as pb,runtime_pb2_grpc as stubs
expected=json.load(sys.stdin)
with grpc.insecure_channel('client-runtime:50054') as channel:
 response=stubs.PrivokeRuntimeServiceStub(channel).DetectAnnotationPresence(
  pb.DetectAnnotationPresenceRequest(request_id='external-pii-readiness',text='Presence runtime readiness probe.',model_id=expected['model_id']),timeout=10)
print(json.dumps({'model_id':response.model_id,'model_version':response.model_version,
 'artifact_checksum':response.artifact_checksum,'parameter_fingerprint':response.parameter_fingerprint,
 'threshold':response.threshold,'error':response.error},sort_keys=True))
"""


def sha_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha_file(path: Path) -> str:
    return sha_bytes(path.read_bytes())


def save_json(path: Path, record: dict, *, exclusive: bool = False) -> None:
    raw = (json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    if exclusive:
        with path.open("xb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        return
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("xb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)


def result_path(value: Path, *, fresh: bool = False) -> Path:
    path = Path(value).resolve()
    if RESULTS not in path.parents:
        raise ValueError("Study, fit and prepared paths must be children under evaluation/results.")
    if fresh and path.exists():
        raise FileExistsError("Refusing a reused study-output path.")
    if fresh and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,39}", path.name):
        raise ValueError("Use a fresh 1-40 character output name.")
    return path


def current_revision() -> str:
    result = subprocess.run(["git", "-c", f"safe.directory={ROOT.as_posix()}",
                             "rev-parse", "HEAD"], cwd=ROOT,
                            capture_output=True, text=True, check=True)
    value = result.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", value):
        raise ValueError("Git HEAD is not a full lowercase object ID.")
    return value


def load_scorer():
    path = ROOT / "evaluation/evaluate-external-pii.py"
    spec = importlib.util.spec_from_file_location("evaluate_external_pii_for_runner", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load the fixed external-PII scorer.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def container_results_path(path: Path) -> str:
    resolved = Path(path).resolve()
    relative = resolved.relative_to(RESULTS)
    return "/workspace/evaluation/results/" + relative.as_posix()


def validate_catalog_artifact(raw: bytes, model_id: str, *, balanced: bool = False) -> dict:
    from privoke_model.artifact import validate_artifact
    try:
        artifact = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Catalog artifact is not valid UTF-8 JSON.") from exc
    if not isinstance(artifact, dict) or artifact.get("model_id") != model_id:
        raise ValueError("Catalog artifact model ID differs from the fixed whitelist.")
    validate_artifact(artifact)
    if balanced and artifact.get("checksum") != BALANCED_CHECKSUM:
        raise ValueError("Prior contextual balanced artifact differs from its pinned checksum.")
    return artifact


class DockerBackend:
    def __init__(self, output: Path, *, env: dict[str, str] | None = None):
        self.output = output
        self.env = dict(os.environ if env is None else env)
        self.calls: list[dict] = []
        self.evaluator_images: set[str] = set()
        self.score_containers: list[dict] = []
        self.admin_mutation_outcome_unknown = False

    def call(self, args: list[str], *, data: bytes | None = None, direct: bool = False,
             timeout: int = 180, admin_mutation: bool = False) -> str:
        argv = list(args) if direct else COMPOSE + list(args)
        try:
            result = subprocess.run(argv, cwd=ROOT, env=self.env, input=data,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            if admin_mutation:
                self.admin_mutation_outcome_unknown = True
            stdout = exc.output or b""
            stderr = exc.stderr or b""
            if isinstance(stdout, str):
                stdout = stdout.encode("utf-8", errors="replace")
            if isinstance(stderr, str):
                stderr = stderr.encode("utf-8", errors="replace")
            self.calls.append({"argv": argv, "returncode": None, "timed_out": True,
                               "stdout_sha256": sha_bytes(stdout), "stderr_sha256": sha_bytes(stderr),
                               "admin_mutation": admin_mutation})
            raise
        stdout = result.stdout or b""
        stderr = result.stderr or b""
        self.calls.append({"argv": argv, "returncode": result.returncode,
                           "stdout_sha256": sha_bytes(stdout), "stderr_sha256": sha_bytes(stderr)})
        if result.returncode != 0:
            raise RuntimeError(f"Command failed with exit {result.returncode}; stderr sha256={sha_bytes(stderr)}")
        return stdout.decode("utf-8").strip()

    def ensure_services(self) -> None:
        self.call(["up", "-d", "--wait", "--wait-timeout", "180",
                   "client-runtime", "model-streaming-service", "param-update-service"], timeout=240)

    def images(self) -> dict:
        observed = {}
        for service in ("client-runtime", "model-streaming-service", "param-update-service"):
            containers = self.call(["ps", "--all", "--quiet", service]).splitlines()
            if len(containers) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", containers[0]):
                raise ValueError("Compose must expose exactly one container for each required service.")
            image = self.call(["docker", "inspect", "--format", "{{.Image}}", containers[0]], direct=True)
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
                raise ValueError("Required service did not expose its actual immutable image ID.")
            observed[service] = image
        return observed

    def read_raw(self, model_id: str) -> bytes:
        if model_id not in CATALOG_IDS:
            raise ValueError("Model ID is outside the fixed catalog whitelist.")
        record = json.loads(self.call(["exec", "-T", "param-update-service", "python", "-c", ADMIN_READ, model_id]))
        if record.get("exists") is not True or not isinstance(record.get("raw_b64"), str):
            raise ValueError("Required prior catalog artifact is missing.")
        return base64.b64decode(record["raw_b64"], validate=True)

    @staticmethod
    def identity(artifact: dict) -> dict:
        return load_scorer().identity_for_artifact(artifact)

    def install(self, artifact: dict) -> None:
        model_id = artifact.get("model_id")
        if model_id not in MODEL_IDS.values():
            raise ValueError("Only the three fixed presence profile IDs can be installed.")
        payload = (json.dumps(artifact, ensure_ascii=False, sort_keys=True,
                              separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
        self.call(["exec", "-T", "param-update-service", "python", "-c", ADMIN_INSTALL, model_id],
                  data=payload, admin_mutation=True)
        observed = validate_catalog_artifact(self.read_raw(model_id), model_id)
        if observed != artifact:
            raise ValueError("Installed catalog artifact differs from the selected frozen artifact.")

    def restore_exact(self, model_id: str, raw: bytes) -> None:
        if model_id not in CATALOG_IDS:
            raise ValueError("Model ID is outside the fixed catalog whitelist.")
        validate_catalog_artifact(raw, model_id, balanced=model_id == "privoke-balanced")
        self.call(["exec", "-T", "param-update-service", "python", "-c", ADMIN_RESTORE, model_id],
                  data=raw, admin_mutation=True)

    def wait_identity(self, expected: dict, *, timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        last = None
        payload = json.dumps(expected, sort_keys=True).encode("utf-8")
        while time.monotonic() < deadline:
            try:
                last = json.loads(self.call(["exec", "-T", "client-runtime", "python", "-c", IDENTITY_PROBE], data=payload, timeout=15))
                observed = dict(last); error = observed.pop("error", "")
                if not error and observed == expected:
                    return
            except Exception:
                pass
            time.sleep(.25)
        raise ValueError(f"Runtime did not expose the expected frozen identity within {timeout:g}s; last response type={type(last).__name__}.")

    def score(self, *, profile: str, control: str, partition: str, artifact: dict,
              prepared: Path, fit_root: Path, baseline_fit_root: Path, study_output: Path,
              protocol_copy: Path, protocol_sha256: str, execution_revision: str,
              fit_source_revision: str, runtime_image_id: str, ordinal: int) -> dict:
        score_output = study_output / profile / control / partition
        if score_output.exists():
            raise FileExistsError("A fixed scorer output path already exists.")
        score_output.parent.mkdir(parents=True, exist_ok=True)
        container_name = f"external-pii-{study_output.name}-{ordinal:02d}-{uuid.uuid4().hex[:8]}"
        args = ["run", "-d", "--no-deps", "--name", container_name, "evaluation-tests", "python",
                "/workspace/evaluation/evaluate-external-pii.py",
                "--fit-root", container_results_path(fit_root),
                "--prepared", container_results_path(prepared),
                "--baseline-fit-root", container_results_path(baseline_fit_root),
                "--profile", profile, "--control", control, "--partition", partition,
                "--output", container_results_path(score_output),
                "--source-revision", execution_revision,
                "--fit-source-revision", fit_source_revision,
                "--protocol-file", container_results_path(protocol_copy),
                "--protocol-sha256", protocol_sha256,
                "--runtime-image-id", runtime_image_id,
                "--evaluator-image-id", "pending", "--target", "client-runtime:50054"]
        container = self.call(args)
        if not re.fullmatch(r"[0-9a-f]{12,64}", container):
            raise ValueError("Compose did not return the scorer container ID.")
        record = {"container_id": container, "name": container_name,
                  "evaluator_image_id": None, "exit_code": None, "logs_sha256": None}
        failure = None
        try:
            record["evaluator_image_id"] = self.call(["docker", "inspect", "--format", "{{.Image}}", container], direct=True)
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", record["evaluator_image_id"]):
                raise ValueError("Scorer did not expose its actual Docker image ID.")
            self.evaluator_images.add(record["evaluator_image_id"])
            record["exit_code"] = int(self.call(["docker", "wait", container], direct=True, timeout=1200))
            logs = self.call(["docker", "logs", container], direct=True)
            record["logs_sha256"] = sha_bytes(logs.encode("utf-8"))
            if record["exit_code"] != 0:
                failure = RuntimeError("Scorer container returned a nonzero exit code.")
        except Exception as exc:
            failure = exc
        finally:
            if record["exit_code"] is None:
                try:
                    self.call(["docker", "stop", "--time", "5", container], direct=True, timeout=30)
                except Exception:
                    pass
            try:
                self.call(["docker", "rm", container], direct=True, timeout=30)
            except Exception as exc:
                if failure is None:
                    failure = exc
            self.score_containers.append(record)
        run_path = score_output / "run-manifest.json"
        if run_path.exists() and record["evaluator_image_id"]:
            run_record = json.loads(run_path.read_text(encoding="utf-8"))
            run_record["evaluator_image_id"] = record["evaluator_image_id"]
            save_json(run_path, run_record)
        if failure is not None:
            raise failure
        if not run_path.is_file():
            raise ValueError("Scorer container completed without writing its run manifest.")
        run_record = json.loads(run_path.read_text(encoding="utf-8"))
        if run_record.get("status") not in ("complete", "not_scored"):
            raise ValueError("Scorer did not produce a complete or explicitly zero-row result.")
        return {"status": run_record["status"], "rows": run_record.get("rows"),
                "successful_rows": run_record.get("successful_rows"),
                "metrics": run_record.get("metrics"), "failure_reason": run_record.get("failure_reason"),
                "run_manifest_sha256": sha_file(run_path),
                "predictions_sha256": run_record.get("predictions_sha256"),
                "evaluator_image_id": record["evaluator_image_id"],
                "container_exit_code": record["exit_code"], "container_logs_sha256": record["logs_sha256"]}


@contextmanager
def protected_catalog(backend, output: Path, manifest: dict):
    """Keep byte-exact private backups and restore all catalog state on every exit."""
    backup_dir = output / "private-backups"
    backup_dir.mkdir(parents=True, exist_ok=False)
    prior = {model_id: backend.read_raw(model_id) for model_id in CATALOG_IDS}
    artifacts = {model_id: validate_catalog_artifact(raw, model_id,
                 balanced=model_id == "privoke-balanced") for model_id, raw in prior.items()}
    backup_records = {}
    for model_id, raw in prior.items():
        path = backup_dir / (model_id + ".json.base64")
        encoded = base64.b64encode(raw)
        with path.open("xb") as stream:
            stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
        backup_records[model_id] = {"file": path.relative_to(output).as_posix(),
                                    "raw_sha256": sha_bytes(raw), "backup_sha256": sha_bytes(encoded)}
    manifest["prior_catalog_backups"] = backup_records
    manifest["prior_contextual_checksum"] = artifacts["privoke-balanced"]["checksum"]
    manifest["contextual_bytes_sha256_before"] = backup_records["privoke-balanced"]["raw_sha256"]
    save_json(output / "run-manifest.json", manifest)
    active_error = None
    try:
        yield prior, artifacts
    except BaseException as exc:
        active_error = exc
        raise
    finally:
        failures = []
        restored = {}
        for model_id in MODEL_IDS.values():
            try:
                backend.restore_exact(model_id, prior[model_id])
                after = backend.read_raw(model_id)
                if sha_bytes(after) != backup_records[model_id]["raw_sha256"]:
                    raise ValueError("Exact presence artifact bytes differ after restoration.")
                backend.wait_identity(backend.identity(artifacts[model_id]))
                restored[model_id] = sha_bytes(after)
            except Exception as exc:
                failures.append({"model_id": model_id, "error_type": type(exc).__name__,
                                 "error_sha256": sha_bytes(str(exc).encode("utf-8"))})
        try:
            contextual_after = backend.read_raw("privoke-balanced")
            if sha_bytes(contextual_after) != backup_records["privoke-balanced"]["raw_sha256"]:
                backend.restore_exact("privoke-balanced", prior["privoke-balanced"])
                contextual_after = backend.read_raw("privoke-balanced")
            validate_catalog_artifact(contextual_after, "privoke-balanced", balanced=True)
            if sha_bytes(contextual_after) != backup_records["privoke-balanced"]["raw_sha256"]:
                raise ValueError("Contextual model bytes changed and could not be restored exactly.")
            manifest["contextual_bytes_sha256_after"] = sha_bytes(contextual_after)
            manifest["contextual_unchanged_or_restored"] = True
        except Exception as exc:
            failures.append({"model_id": "privoke-balanced", "error_type": type(exc).__name__,
                             "error_sha256": sha_bytes(str(exc).encode("utf-8"))})
            manifest["contextual_unchanged_or_restored"] = False
        manifest["restored_presence_sha256"] = restored
        mutation_unknown = getattr(backend, "admin_mutation_outcome_unknown", False)
        if mutation_unknown:
            failures.append({"model_id": "presence-catalog", "error_type": "AdminMutationOutcomeUnknown",
                             "reason": "A catalog write timed out before its remote terminal state was established."})
        manifest["admin_mutation_outcome_unknown"] = mutation_unknown
        manifest["restoration_failures"] = failures
        manifest["restoration_verified"] = (not failures and not mutation_unknown
                                              and len(restored) == len(PROFILES))
        save_json(output / "run-manifest.json", manifest)
        if failures and active_error is None:
            raise RuntimeError("Exact catalog restoration failed; inspect restoration_failures.")


def fixed_plan() -> list[tuple[str, str, str]]:
    return [(profile, control, partition) for profile in PROFILES
            for control in CONTROLS for partition in PARTITIONS]


def run_study(*, fit_root: Path, prepared: Path, baseline_fit_root: Path,
              protocol_file: Path, protocol_sha256: str,
              execution_revision: str, fit_source_revision: str,
              output: Path, backend=None) -> dict:
    output = result_path(output, fresh=True)
    fit_root, prepared, baseline_fit_root = (result_path(item) for item in
                                             (fit_root, prepared, baseline_fit_root))
    if not re.fullmatch(r"[0-9a-f]{64}", protocol_sha256):
        raise ValueError("Protocol SHA-256 must be 64 lowercase hexadecimal characters.")
    protocol_file = Path(protocol_file).resolve()
    if ROOT not in protocol_file.parents or sha_file(protocol_file) != protocol_sha256:
        raise ValueError("Protocol file must be in the repository and match its frozen digest.")
    if current_revision() != execution_revision:
        raise ValueError("Executing Git HEAD differs from --source-revision.")
    scorer = load_scorer()
    candidate_bundle = scorer.load_external_fit(fit_root, prepared, source_revision=fit_source_revision,
                                                protocol_sha256=protocol_sha256)
    prepared = scorer.validate_prepared(prepared,
                    prepared_source_revision=candidate_bundle["manifest"].get("prepared_source_revision"),
                    protocol_sha256=protocol_sha256)
    prepared_revision = scorer.bind_prepared_to_fit(prepared, candidate_bundle["manifest"])
    baseline_bundle = scorer.load_baseline_fit(baseline_fit_root, "balanced")
    scorer.bind_baseline_reference(baseline_bundle, prepared)
    profiles = {}
    for profile in PROFILES:
        baseline = baseline_bundle["profiles"][profile]
        candidate = scorer.verify_profile_bundle(candidate_bundle, profile=profile,
                    fit_root=fit_root, source_revision=fit_source_revision,
                    protocol_sha256=protocol_sha256, prepared=prepared)
        expected_id = MODEL_IDS[profile]
        for item in (baseline, candidate):
            if item["artifact"].get("model_id") != expected_id:
                raise ValueError("Frozen artifacts do not match the exact profile/model-ID allowlist.")
        profiles[profile] = {"baseline": baseline, "expanded": candidate}

    output.mkdir(parents=True, exist_ok=False)
    protocol_copy = output / "dataset-expansion-protocol.md"
    with protocol_copy.open("xb") as stream:
        stream.write(protocol_file.read_bytes()); stream.flush(); os.fsync(stream.fileno())
    if sha_file(protocol_copy) != protocol_sha256:
        raise ValueError("Copied protocol bytes differ from the frozen protocol digest.")
    manifest = {"schema_version": 1, "status": "running", "phase": "preflight",
                "execution_source_revision": execution_revision,
                "fit_source_revision": fit_source_revision,
                "prepared_source_revision": prepared_revision,
                "protocol_sha256": protocol_sha256,
                "prepared_manifest_sha256": prepared["manifest_sha256"],
                "partition_sha256": prepared["manifest"]["partition_sha256"],
                "fit_manifest_sha256": candidate_bundle["manifest_sha256"],
                "baseline_fit_manifest_sha256": baseline_bundle["manifest_sha256"],
                "plan": [dict(zip(("profile", "control", "partition"), item)) for item in fixed_plan()],
                "images_before": None, "images_after": None, "scores": [], "errors": []}
    save_json(output / "run-manifest.json", manifest, exclusive=True)
    backend = backend or DockerBackend(output, env=dict(os.environ,
        PRIVOKE_RESEARCH_PRESENCE_MODEL_ID="privoke-presence-balanced",
        PRIVOKE_RESEARCH_PRESENCE_CURRICULUM_DIR=str(fit_root / "curriculum")))
    stage = "service_readiness"
    try:
        backend.ensure_services()
        images_before = backend.images()
        manifest.update({"phase": "catalog_snapshot", "images_before": images_before})
        save_json(output / "run-manifest.json", manifest)
        with protected_catalog(backend, output, manifest) as (_prior, _artifacts):
            ordinal = 0
            for profile, control, partition in fixed_plan():
                ordinal += 1
                stage = f"install:{profile}:{control}"
                selected = profiles[profile][control]
                backend.install(selected["artifact"])
                backend.wait_identity(backend.identity(selected["artifact"]))
                if partition != "validation" and prepared["manifest"]["rows"][partition] == 0:
                    manifest["scores"].append({"profile": profile, "control": control,
                        "partition": partition, "status": "not_scored", "rows": 0,
                        "reason": "zero_partition_rows_no_external_coverage"})
                    save_json(output / "run-manifest.json", manifest)
                    continue
                stage = f"score:{profile}:{control}:{partition}"
                record = backend.score(profile=profile, control=control, partition=partition,
                    artifact=selected["artifact"], prepared=prepared["root"], fit_root=fit_root,
                    baseline_fit_root=baseline_fit_root, study_output=output,
                    protocol_copy=protocol_copy, protocol_sha256=protocol_sha256,
                    execution_revision=execution_revision, fit_source_revision=fit_source_revision,
                    runtime_image_id=images_before["client-runtime"], ordinal=ordinal)
                manifest["scores"].append({"profile": profile, "control": control,
                                           "partition": partition, **record})
                save_json(output / "run-manifest.json", manifest)
        stage = "image_postcheck"
        images_after = backend.images()
        manifest["images_after"] = images_after
        if images_after != manifest["images_before"]:
            raise ValueError("A persistent service image changed during the fixed study.")
        if len(backend.evaluator_images) != 1:
            raise ValueError("Study did not use exactly one unchanged evaluator image digest.")
        manifest["evaluator_image_id"] = next(iter(backend.evaluator_images))
        if len(manifest["scores"]) != len(fixed_plan()):
            raise ValueError("The full fixed profile/control/partition plan did not complete.")
        manifest["status"] = "complete"
        manifest["phase"] = "complete"
    except Exception as exc:
        manifest["status"] = "failed"
        manifest["failure_stage"] = stage
        manifest["errors"].append({"error_type": type(exc).__name__,
                                   "error_sha256": sha_bytes(str(exc).encode("utf-8"))})
    finally:
        manifest["docker_calls"] = getattr(backend, "calls", [])
        manifest["score_containers"] = getattr(backend, "score_containers", [])
        manifest["evaluator_image_ids"] = sorted(getattr(backend, "evaluator_images", set()))
        save_json(output / "run-manifest.json", manifest)
    return manifest


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--fit-root", type=Path, required=True)
    result.add_argument("--prepared", type=Path, required=True)
    result.add_argument("--baseline-fit-root", type=Path, required=True)
    result.add_argument("--protocol-file", type=Path, required=True)
    result.add_argument("--protocol-sha256", required=True)
    result.add_argument("--source-revision", required=True)
    result.add_argument("--fit-source-revision", required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    manifest = run_study(fit_root=args.fit_root, prepared=args.prepared,
                         baseline_fit_root=args.baseline_fit_root,
                         protocol_file=args.protocol_file, protocol_sha256=args.protocol_sha256,
                         execution_revision=args.source_revision,
                         fit_source_revision=args.fit_source_revision, output=args.output)
    print(json.dumps({"status": manifest["status"], "phase": manifest.get("phase"),
                      "scores": len(manifest.get("scores", [])),
                      "restoration_verified": manifest.get("restoration_verified", False)}, sort_keys=True))
    return 0 if manifest["status"] == "complete" and manifest.get("restoration_verified") else 1


if __name__ == "__main__":
    raise SystemExit(main())
