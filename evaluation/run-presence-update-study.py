"""Call genuine presence fuzzer updates under the frozen nine-attempt protocol.

Run from the host after the four ordered research Compose files are built and
ready. This caller never fits a model, loads detector code, or scores final data.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared/python"))
from privoke_model.artifact import load_artifact, validate_artifact
from privoke_model.fingerprint import parameter_fingerprint
from privoke_model.presence import SparsePresenceModel

PROFILES = ("efficient", "balanced", "quality")
SEEDS = (42, 43, 44)
SOURCE_ID = "presence-research-evaluation"
UPDATER_SOURCE = "presence-research-fuzzer"
BALANCED_CHECKSUM = "8c139431ba8605a3d6817d24d233cce78fc22a086fdeb3ee99702ada86c80015"
COMPOSE = ["docker", "compose", "-f", "docker-compose.yml", "-f", "evaluation/compose.tests.yml",
           "-f", "evaluation/compose.public-negatives.yml", "-f", "evaluation/compose.presence.yml"]
PINNED_PARTITIONS = {
    "train": (3832, "da9a1b095587264714c5ae99c8a0f92329a04f6fc237a8ace7d71e837ede429d"),
    "validation": (968, "d2d0c538e49f5bbc7a8f85887b9b8cfddb188a5ab9aae55c69ce26ae932be6d1"),
    "development": (502, "45f91e320482dde4d0724cdf42a341649d52e33aeae326f059c714edc97cc706"),
}
LOCKED_DEV_SHA = "65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095"
LOCKED_FINAL_SHA = "613a78b9e5fa677904125b4c056fb8d57d15fb6ebd9c443a75f406ae3ac05515"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def json_read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_exclusive(path, value=None, *, raw=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = raw if raw is not None else (json.dumps(value, ensure_ascii=False, sort_keys=True,
                                               indent=2, allow_nan=False) + "\n").encode("utf-8")
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return sha(path)


def save_manifest(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                                    allow_nan=False) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def identity(artifact):
    model = SparsePresenceModel.from_artifact(artifact)
    return {"model_id": artifact["model_id"], "model_version": artifact["version"],
            "artifact_checksum": artifact["checksum"], "threshold": model.threshold,
            "parameter_fingerprint": parameter_fingerprint(model.parameters, model.shapes)}


def result_path(path, *, fresh=False):
    path = Path(path).resolve()
    if (ROOT / "evaluation/results").resolve() not in path.parents:
        raise ValueError("Study and fit paths must be children under evaluation/results.")
    if fresh and path.exists():
        raise FileExistsError("Refusing reused study evidence and request IDs.")
    if fresh and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,39}", path.name):
        raise ValueError("Use a fresh 1-40 character study name for bounded request IDs.")
    return path


def load_fit(fit_root, protocol_sha256, fit_source_revision=None):
    """Bind all completed profile selections and train-only curriculum before Docker."""
    fit_root = result_path(fit_root)
    manifest = json_read(fit_root / "run-manifest.json")
    if (manifest.get("status") != "complete" or manifest.get("errors")
            or manifest.get("selections_frozen_before_development_scoring") is not True
            or set(manifest.get("profiles", {})) != set(PROFILES)):
        raise ValueError("Fit must contain all three completed frozen profiles.")
    fit_source_revision = fit_source_revision or manifest.get("source_revision")
    if (not isinstance(fit_source_revision, str) or not re.fullmatch(r"[0-9a-f]{40,64}", fit_source_revision)
            or manifest.get("source_revision") != fit_source_revision
            or manifest.get("protocol_sha256") != protocol_sha256):
        raise ValueError("Fit source/protocol identity mismatch.")
    inputs = manifest.get("input_validation", {})
    if inputs.get("partition_sha256") != {name: item[1] for name, item in PINNED_PARTITIONS.items()}:
        raise ValueError("Fit partitions differ from pinned prepared inputs.")
    if inputs.get("locked_sha256") != {"development": LOCKED_DEV_SHA, "final": LOCKED_FINAL_SHA}:
        raise ValueError("Fit locked dataset digests differ.")
    curriculum_path = fit_root / "curriculum/prompts.jsonl"
    curriculum = manifest.get("training_curriculum", {})
    if curriculum.get("rows") != 3832 or sha(curriculum_path) != curriculum.get("sha256"):
        raise ValueError("Train-only curriculum is missing, changed or incomplete.")
    profiles = {}
    for profile in PROFILES:
        selection_path = fit_root / "profiles" / profile / "selection.json"
        selection = json_read(selection_path)
        artifact_path = fit_root / "profiles" / profile / "artifact.json"
        artifact = load_artifact(artifact_path)
        if (selection != manifest["profiles"][profile] or selection.get("status") != "selected"
                or selection.get("profile") != profile or artifact["config"]["profile"] != profile
                or selection.get("source_revision") != fit_source_revision
                or selection.get("protocol_sha256") != protocol_sha256
                or sha(artifact_path) != selection.get("selected_artifact_sha256")
                or identity(artifact) != selection.get("artifact_identity")):
            raise ValueError("Frozen fit profile selection/artifact identity mismatch.")
        if artifact.get("metadata", {}).get("source_revision") != fit_source_revision:
            raise ValueError("Artifact fit provenance mismatch.")
        profiles[profile] = {"artifact": artifact, "artifact_path": artifact_path,
                             "selection_path": selection_path, "selection": selection}
    return manifest, profiles, fit_source_revision


def dataset_keys(path, expected_sha, expected_count):
    if sha(path) != expected_sha:
        raise ValueError("Scoring dataset differs from its pinned digest.")
    rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line]
    keys = {}
    for row in rows:
        if (not isinstance(row.get("id"), str) or not row["id"] or row["id"] in keys
                or type(row.get("expected_has_pii")) is not bool
                or not isinstance(row.get("group_id"), str) or not row["group_id"]):
            raise ValueError("Scoring row has invalid ID/truth/group.")
        keys[row["id"]] = (row["expected_has_pii"], row["group_id"])
    if len(keys) != expected_count:
        raise ValueError("Scoring input has incorrect row count.")
    return keys


def verified_metrics(report_dir, expected_keys, expected_identity):
    report = json_read(report_dir / "report.json")
    rows = json_read(report_dir / "predictions.json")["rows"]
    if (report.get("status") != "complete" or report.get("errors") or len(rows) != len(expected_keys)
            or report.get("returned_identity") != expected_identity):
        raise ValueError("Only complete zero-error identity-matched scores are eligible.")
    seen, counts = set(), {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    for row in rows:
        if (row.get("id") in seen or expected_keys.get(row.get("id")) != (row.get("expected_has_pii"), row.get("group_id"))
                or type(row.get("expected_has_pii")) is not bool or type(row.get("predicted_present")) is not bool
                or row.get("error") or any(row.get(key) != value for key, value in expected_identity.items())):
            raise ValueError("Scoring predictions differ in IDs/truth/groups or model identity.")
        probability = row.get("probability")
        if (type(probability) not in (int, float) or not math.isfinite(probability) or not 0 <= probability <= 1
                or row["predicted_present"] != (probability >= expected_identity["threshold"])):
            raise ValueError("Scoring probability/enum differs from frozen threshold.")
        seen.add(row["id"])
        key = "tp" if row["expected_has_pii"] and row["predicted_present"] else "fn" if row["expected_has_pii"] else "fp" if row["predicted_present"] else "tn"
        counts[key] += 1
    if seen != set(expected_keys) or any(report["metrics"].get(key) != value for key, value in counts.items()):
        raise ValueError("Report confusion counts differ from matched raw predictions.")
    metrics = {**counts, "recall": counts["tp"] / (counts["tp"] + counts["fn"]),
               "specificity": counts["tn"] / (counts["tn"] + counts["fp"]),
               "positive_examples": counts["tp"] + counts["fn"],
               "absent_examples": counts["tn"] + counts["fp"]}
    metrics["balanced_accuracy"] = (metrics["recall"] + metrics["specificity"]) / 2
    if any(report["metrics"].get(key) != value for key, value in metrics.items()):
        raise ValueError("Report rates differ from recomputed confusion counts.")
    return metrics


def _varint(value):
    output = bytearray()
    while value >= 128:
        output.append((value & 127) | 128)
        value >>= 7
    return bytes(output) + bytes([value])


def request_bytes(request):
    """Deterministic serialization of the fixed request with no metadata fields."""
    output = b""
    for number, name in ((1, "request_id"), (2, "source_id"), (3, "model_id")):
        value = request[name].encode("utf-8")
        output += _varint(number * 8 + 2) + _varint(len(value)) + value
    return output + b"\x20" + _varint(request["prompt_count"]) + b"\x28" + _varint(request["seed"])


def request_fingerprint(request):
    return hashlib.sha256(b"RunPresenceTrainingCycle:annotation_presence:v1\0" + request_bytes(request)).hexdigest()


def validate_evidence(request, response, receipt, base, candidate):
    before, after = identity(base), identity(candidate)
    expected = {"model_id": base["model_id"], "base_version": base["version"],
                "applied_version": candidate["version"]}
    if (response.get("accepted") is not True or response.get("prompts_generated") != 256
            or receipt.get("found") is not True or receipt.get("accepted") is not True
            or receipt.get("request_fingerprint") != request_fingerprint(request)
            or any(response.get(key) != value or receipt.get(key) != value for key, value in expected.items())):
        raise ValueError("Accepted response, exact request and durable receipt do not agree.")
    if (base["config"] != candidate["config"] or set(base["parameters"]) != set(candidate["parameters"])
            or candidate["version"] != base["version"] + "+train.1"):
        raise ValueError("Update changed release config/manifest or did not advance version.")
    for name, tensor in base["parameters"].items():
        changed = candidate["parameters"][name]
        if tensor["shape"] != changed["shape"] or tensor["trainable"] != changed["trainable"]:
            raise ValueError("Update changed a tensor shape/trainability flag.")
        if not tensor["trainable"] and tensor != changed:
            raise ValueError("Update changed frozen IDF values.")
    metadata = response.get("metadata", {})
    if (metadata.get("base_parameter_fingerprint") != before["parameter_fingerprint"]
            or metadata.get("candidate_parameter_fingerprint") != after["parameter_fingerprint"]):
        raise ValueError("Runtime candidate/base fingerprint differs from committed artifact.")
    for field, expected_count in (("examples", 256), ("heldout_examples", 32)):
        value = float(metadata.get(field, "nan"))
        if value != expected_count:
            raise ValueError("Training response count differs from fixed protocol batch.")
    present = float(metadata.get("heldout_present_examples", "nan"))
    absent = float(metadata.get("heldout_absent_examples", "nan"))
    if not (present >= 1 and absent >= 1 and present == int(present) and absent == int(absent) and present + absent == 32):
        raise ValueError("Training response lacks valid held-out strata.")
    for field in ("exact_match_rate", "heldout_present_recall", "heldout_absent_specificity", "heldout_exact_match_rate"):
        value = float(metadata.get(field, "nan"))
        if not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError("Training response rate is invalid.")
        if field.startswith("heldout_"):
            candidate_value = float(metadata.get("candidate_" + field, "nan"))
            if not math.isfinite(candidate_value) or not value <= candidate_value <= 1:
                raise ValueError("Training response reports a held-out binary regression.")
    return after


def terminal_receipt(lookup, request, base):
    receipt = lookup.get("receipt", {})
    return (lookup.get("status") == "receipt" and receipt.get("found") is True
            and receipt.get("accepted") is True and receipt.get("request_fingerprint") == request_fingerprint(request)
            and receipt.get("model_id") == base["model_id"] and receipt.get("base_version") == base["version"]
            and receipt.get("applied_version") == base["version"] + "+train.1" and receipt.get("prompts_generated") == 256)


def rejected_receipt(lookup, request, base):
    receipt = lookup.get("receipt", {})
    return (lookup.get("status") == "receipt" and receipt.get("found") is True
            and receipt.get("accepted") is False and receipt.get("request_fingerprint") == request_fingerprint(request)
            and receipt.get("model_id", "") in ("", base["model_id"])
            and receipt.get("base_version", "") in ("", base["version"])
            and receipt.get("applied_version", "") in ("", base["version"]))


def choose_attempt(attempts, base_metrics):
    if (len(attempts) != 3 or {item["seed"] for item in attempts} != set(SEEDS)
            or any(item["status"] not in ("accepted", "rejected", "failed", "accepted_unscored") for item in attempts)):
        raise ValueError("Selection requires all three terminal attempt records.")
    eligible = [item for item in attempts if item["status"] == "accepted"
                and item["validation_metrics"]["recall"] >= .9
                and item["validation_metrics"]["specificity"] > base_metrics["specificity"]]
    return max(eligible, key=lambda item: (item["validation_metrics"]["specificity"],
                                         item["validation_metrics"]["recall"], -item["seed"])) if eligible else None


ADMIN_READ = """import json,sys;from pathlib import Path
model_id=sys.argv[1]
assert model_id in ('privoke-balanced','privoke-presence-efficient','privoke-presence-balanced','privoke-presence-quality')
p=Path('/models')/(model_id+'.json')
print(json.dumps({'exists':p.exists(),'raw':p.read_text(encoding='utf-8') if p.exists() else None}))
"""
ADMIN_INSTALL = """import json,sys;from pathlib import Path
from privoke_model.artifact import write_artifact_atomic
model_id=sys.argv[1]
assert model_id in ('privoke-balanced','privoke-presence-efficient','privoke-presence-balanced','privoke-presence-quality')
payload=json.load(sys.stdin);assert payload['model_id']==model_id
write_artifact_atomic(Path('/models')/(model_id+'.json'),payload)
"""
RPC_CLIENT = """import hashlib,json,sys,grpc
sys.path.insert(0,'/workspace/extension/client-runtime/generated')
from privoke.v1 import parameters_pb2 as pb,parameters_pb2_grpc as stubs
data=json.load(sys.stdin);r=pb.FuzzerTrainingRequest(**data['request'])
raw=r.SerializeToString(deterministic=True)
fingerprint=hashlib.sha256(b'RunPresenceTrainingCycle:annotation_presence:v1\\0'+raw).hexdigest()
out={'request_fingerprint':fingerprint,'request_binary_sha256':hashlib.sha256(raw).hexdigest()}
try:
 if data['operation']=='cycle':
  with grpc.insecure_channel('presence-fuzzer:50053') as ch:
   v=stubs.FuzzerServiceStub(ch).RunPresenceTrainingCycle(r,timeout=120)
  out.update(status='response',response={'accepted':v.accepted,'model_id':v.model_id,'base_version':v.base_version,'applied_version':v.applied_version,'prompts_generated':v.prompts_generated,'message':v.message,'metadata':dict(v.metadata)})
 else:
  with grpc.insecure_channel('presence-update-service:50052') as ch:
   q=pb.ParameterUpdateStatusRequest(source_id='presence-research-fuzzer',request_id=r.request_id,request_source_id=r.source_id,model_id=r.model_id,request_fingerprint=fingerprint)
   v=stubs.ParamUpdateServiceStub(ch).GetParameterUpdateStatus(q,timeout=15)
  out.update(status='receipt',receipt={'found':v.found,'accepted':v.ack.accepted,'model_id':v.ack.model_id,'base_version':v.base_version,'applied_version':v.ack.applied_version,'prompts_generated':v.prompts_generated,'request_fingerprint':fingerprint})
except grpc.RpcError as exc:
 out.update(status='rpc_error',code=exc.code().name,error=exc.details())
print(json.dumps(out,sort_keys=True))
"""


class DockerBackend:
    def __init__(self, fit_root, output, source_revision, fit_source_revision, protocol_sha256):
        self.env = dict(os.environ, PRIVOKE_RESEARCH_PRESENCE_CURRICULUM_DIR=str(fit_root / "curriculum"))
        self.output, self.source_revision, self.fit_source_revision = output, source_revision, fit_source_revision
        self.protocol_sha256 = protocol_sha256
        self.fit_manifest = fit_root / "run-manifest.json"
        self.evaluator_image_id = None
        self.log = (output / "study.log").open("x", encoding="utf-8")

    def call(self, args, *, data=None, direct=False, timeout=180):
        command = args if direct else COMPOSE + args
        result = subprocess.run(command, cwd=ROOT, env=self.env, input=data, encoding="utf-8",
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        self.log.write(json.dumps({"argv": command, "returncode": result.returncode}) + "\n")
        self.log.write(result.stderr + "\n")
        self.log.flush()
        if result.returncode:
            raise RuntimeError(f"Command failed ({result.returncode}): {command[0:6]}: {result.stderr[-2000:]}")
        return result.stdout

    def read(self, model_id):
        result = json.loads(self.call(["exec", "-T", "param-update-service", "python", "-c", ADMIN_READ, model_id]))
        return result["raw"] if result["exists"] else None

    def install(self, artifact):
        self.call(["exec", "-T", "param-update-service", "python", "-c", ADMIN_INSTALL, artifact["model_id"]], data=json.dumps(artifact, ensure_ascii=False))
        if json.loads(self.read(artifact["model_id"])) != artifact:
            raise ValueError("Installed catalog artifact differs from exact payload.")
        if artifact["model_id"].startswith("privoke-presence-"):
            self.wait_identity(artifact)

    def wait_identity(self, artifact):
        expected = identity(artifact)
        code = """import json,sys,grpc
sys.path.insert(0,'/workspace/extension/client-runtime/generated')
from privoke.v1 import runtime_pb2 as pb,runtime_pb2_grpc as stubs
expected=json.load(sys.stdin)
with grpc.insecure_channel('client-runtime:50054') as ch:
 r=stubs.PrivokeRuntimeServiceStub(ch).DetectAnnotationPresence(pb.DetectAnnotationPresenceRequest(request_id='presence-readiness',text='Presence runtime readiness probe.',model_id=expected['model_id']),timeout=10)
print(json.dumps({'model_id':r.model_id,'model_version':r.model_version,'artifact_checksum':r.artifact_checksum,'parameter_fingerprint':r.parameter_fingerprint,'threshold':r.threshold,'error':r.error}))
"""
        deadline, last = time.monotonic() + 30, None
        while time.monotonic() < deadline:
            observed = json.loads(self.call(["exec", "-T", "client-runtime", "python", "-c", code], data=json.dumps(expected), timeout=15))
            last = observed
            if not observed.pop("error", None) and observed == expected:
                return
            time.sleep(.25)
        raise ValueError(f"Runtime cache did not expose exact installed identity: {last}")

    def configure(self, model_id):
        self.env["PRIVOKE_RESEARCH_PRESENCE_MODEL_ID"] = model_id
        self.call(["up", "-d", "--no-deps", "--force-recreate", "--wait", "--wait-timeout", "120", "presence-fuzzer", "presence-update-service"])
        startup = self.call(["exec", "-T", "presence-update-service", "python", "-c", "import os;print(os.environ['FUZZER_PROMPT_COUNT'])"]).strip()
        if startup != "0":
            raise ValueError("Presence automatic startup training must be disabled.")

    def images(self):
        images = {}
        for service in ("client-runtime", "model-streaming-service", "param-update-service", "presence-fuzzer", "presence-update-service"):
            container = self.call(["ps", "--all", "--quiet", service]).strip()
            if not container or "\n" in container:
                raise ValueError("Expected one actual container per service.")
            images[service] = self.call(["docker", "inspect", "--format", "{{.Image}}", container], direct=True).strip()
        return images

    def hardware(self):
        code = "import json,os,platform;from pathlib import Path;print(json.dumps({'machine':platform.machine(),'python':platform.python_version(),'cpu_count':os.cpu_count(),'cpu_model':next((x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')),None),'limits':{x:Path('/sys/fs/cgroup/'+x).read_text().strip() for x in ['cpu.max','memory.max','cpuset.cpus.effective'] if Path('/sys/fs/cgroup/'+x).exists()}}))"
        return json.loads(self.call(["exec", "-T", "client-runtime", "python", "-c", code]))

    def rpc(self, operation, request):
        result = json.loads(self.call(["run", "--rm", "--no-deps", "-T", "evaluation-tests", "python", "-c", RPC_CLIENT],
                                      data=json.dumps({"operation": operation, "request": request}), timeout=150))
        if (result.get("request_fingerprint") != request_fingerprint(request)
                or result.get("request_binary_sha256") != hashlib.sha256(request_bytes(request)).hexdigest()):
            raise ValueError("Protobuf serialization/request fingerprint differs from caller.")
        return result

    def quiesce(self, request):
        self.call(["stop", "--timeout", "120", "presence-fuzzer"], timeout=150)
        # A stopped fuzzer can leave a submitted updater RPC in progress. Stop the
        # writer too, then let its receipt recovery reconcile the latest marker.
        self.call(["stop", "--timeout", "120", "presence-update-service"], timeout=150)
        self.call(["up", "-d", "--no-deps", "--wait", "--wait-timeout", "120", "presence-update-service"])
        return self.rpc("receipt", request)

    def score(self, artifact_path, fit_selection, dataset, output, *, phase, evidence=None, retention=None):
        def container_path(path):
            return "/workspace/evaluation/" + Path(path).resolve().relative_to(ROOT / "evaluation").as_posix()
        suffix = "-".join(output.relative_to(self.output).parts)
        name = f"presence-score-{self.output.name}-{suffix}"
        args = ["run", "-d", "--no-deps", "--name", name, "evaluation-tests", "python",
                "evaluate-presence.py" if phase == "base-development" else "evaluate-presence-update.py",
                "--selection", container_path(fit_selection), "--fit-manifest", container_path(self.fit_manifest),
                "--dataset-file", container_path(dataset), "--output", container_path(output),
                "--source-revision", self.source_revision, "--fit-source-revision", self.fit_source_revision,
                "--protocol-sha256", self.protocol_sha256]
        if phase == "base-development":
            args += ["--artifact", container_path(artifact_path)]
        else:
            base_artifact = fit_selection.with_name("artifact.json")
            args += ["--base-artifact", container_path(base_artifact), "--candidate-artifact", container_path(artifact_path),
                     "--partition", "development" if phase == "selected-development" else "validation"]
        if evidence:
            args += ["--update-evidence", container_path(evidence)]
        if retention:
            args += ["--retention-selection", container_path(retention)]
        container = self.call(args).strip()
        if not re.fullmatch(r"[0-9a-f]{12,64}", container):
            raise ValueError("Compose did not return the named evaluator container identity.")
        # Use a named Compose one-off so its actual Image ID can be inspected
        # while it exists, rather than inferring it from a tag or image listing.
        evidence_path = output.parent / f"{output.name}-container.json"
        container_record = {"container_id": container, "name": name, "actual_image_id": None, "exit_code": None}
        try:
            container_record["actual_image_id"] = self.call(["docker", "inspect", "--format", "{{.Image}}", container], direct=True).strip()
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", container_record["actual_image_id"]):
                raise ValueError("Evaluator did not expose an actual Docker image digest.")
            if self.evaluator_image_id is None:
                self.evaluator_image_id = container_record["actual_image_id"]
            elif self.evaluator_image_id != container_record["actual_image_id"]:
                raise ValueError("Evaluator image changed during the fixed study.")
            exited = self.call(["docker", "wait", container], direct=True, timeout=1200).strip()
            container_record["exit_code"] = int(exited)
            write_exclusive(output.parent / f"{output.name}-container.log", raw=self.call(["docker", "logs", container], direct=True).encode("utf-8"))
            if container_record["exit_code"] != 0:
                raise RuntimeError("Presence scoring container failed; retained its logs and output.")
        finally:
            write_exclusive(evidence_path, container_record)
            if container_record["exit_code"] is None:
                self.call(["docker", "stop", "--time", "5", container], direct=True)
            self.call(["docker", "rm", container], direct=True)

    def close(self):
        self.log.close()


class PublicationUncertain(RuntimeError):
    pass


@contextmanager
def protected_catalog(backend, manifest, output):
    """Restore only after publication is known terminal; never overwrite uncertainty."""
    prior = {}
    balanced_raw = backend.read("privoke-balanced")
    balanced = json.loads(balanced_raw)
    validate_artifact(balanced)
    if balanced["checksum"] != BALANCED_CHECKSUM:
        raise ValueError("Prior contextual selection differs from the recorded selected model.")
    write_exclusive(output / "prior-contextual-model.json", raw=balanced_raw.encode("utf-8"))
    manifest["prior_contextual_checksum"] = balanced["checksum"]
    manifest["prior_contextual_file_sha256"] = hashlib.sha256(balanced_raw.encode("utf-8")).hexdigest()
    manifest["restoration_blocked"] = False
    try:
        for profile in PROFILES:
            model_id = f"privoke-presence-{profile}"
            raw = backend.read(model_id)
            prior[model_id] = json.loads(raw) if raw else None
            if raw:
                validate_artifact(prior[model_id])
                write_exclusive(output / "prior-presence" / f"{model_id}.json", raw=raw.encode("utf-8"))
        try:
            yield prior
        except Exception as exc:
            manifest["operation_error"] = {"type": type(exc).__name__, "error": str(exc)}
            raise
    finally:
        failures = []
        if not manifest["restoration_blocked"] and not manifest.get("publication_pending"):
            for model_id, artifact in prior.items():
                desired = artifact or manifest.get("retained_artifacts", {}).get(model_id)
                if desired is not None:
                    try:
                        backend.install(desired)
                    except Exception as exc:
                        failures.append({"model_id": model_id, "error": str(exc)})
        else:
            manifest["restoration_blocked"] = True
            failures.append({"model_id": "presence", "error": "Unknown publication preserved; restoration blocked."})
        try:
            current_raw = backend.read("privoke-balanced")
            current = json.loads(current_raw)
            if current != balanced:
                backend.install(balanced)
                if json.loads(backend.read("privoke-balanced")) != balanced:
                    raise ValueError("Contextual artifact restoration mismatch.")
            manifest["contextual_unchanged_or_restored"] = True
            manifest["after_contextual_file_sha256"] = hashlib.sha256(backend.read("privoke-balanced").encode("utf-8")).hexdigest()
        except Exception as exc:
            failures.append({"model_id": "privoke-balanced", "error": str(exc)})
        manifest["restoration_failures"] = failures
        manifest["restoration_verified"] = not failures
        if failures:
            raise RuntimeError("Study restoration failed or is blocked: " + json.dumps(failures))


def execute_attempt(backend, details, seed, output, manifest, expected_validation, validation_path):
    base = details["artifact"]
    profile, model_id = base["config"]["profile"], base["model_id"]
    request = {"request_id": f"{output.name}-{profile}-{seed}", "source_id": SOURCE_ID,
               "model_id": model_id, "prompt_count": 256, "seed": seed}
    attempt = {"seed": seed, "request": request, "status": "started", "accepted": False}
    manifest["profiles"][profile]["attempts"].append(attempt)
    attempt_dir = output / profile / f"seed{seed}"
    attempt_dir.mkdir()
    write_exclusive(attempt_dir / "request.json", request)
    write_exclusive(attempt_dir / "request.pb", raw=request_bytes(request))
    manifest["publication_pending"] = request
    save_manifest(output / "run-manifest.json", manifest)
    try:
        try:
            outcome = backend.rpc("cycle", request)
        except Exception as exc:
            outcome = {"status": "rpc_error", "code": "UNKNOWN", "error": str(exc)}
        write_exclusive(attempt_dir / "rpc-outcome.json", outcome)
        try:
            lookup = backend.rpc("receipt", request)
        except Exception as exc:
            lookup = {"status": "rpc_error", "error": str(exc)}
        write_exclusive(attempt_dir / "receipt-initial.json", lookup)
        known_rejection = ((outcome.get("status") != "response" and outcome.get("code") in ("FAILED_PRECONDITION", "INVALID_ARGUMENT", "RESOURCE_EXHAUSTED"))
                           or (outcome.get("status") == "response" and outcome["response"].get("accepted") is False))
        if rejected_receipt(lookup, request, base) and json.loads(backend.read(model_id)) == base:
            manifest.pop("publication_pending", None)
            attempt.update(status="rejected", error="Durable terminal rejection; base unchanged.")
            return attempt
        if known_rejection and lookup.get("status") == "receipt" and not lookup["receipt"]["found"] and json.loads(backend.read(model_id)) == base:
            manifest.pop("publication_pending", None)
            attempt.update(status="rejected", error=outcome.get("error"))
            return attempt
        if not terminal_receipt(lookup, request, base):
            lookup = backend.quiesce(request)
            attempt["quiesced"] = True
            write_exclusive(attempt_dir / "receipt-after-quiescence.json", lookup)
            raw = backend.read(model_id)
            write_exclusive(attempt_dir / "uncertain-artifact.json", raw=raw.encode("utf-8"))
            if rejected_receipt(lookup, request, base) and json.loads(raw) == base:
                manifest.pop("publication_pending", None)
                attempt.update(status="rejected", error="Recovered durable terminal rejection; base unchanged.")
                return attempt
            if lookup.get("status") == "receipt" and not lookup["receipt"]["found"] and json.loads(raw) == base:
                # Both processes were stopped; recovered receipt lookup and exact
                # unchanged base prove there is no submitted writer left to finish.
                manifest.pop("publication_pending", None)
                attempt.update(status="failed", error="RPC failed without a committed publication.")
                return attempt
            if not terminal_receipt(lookup, request, base):
                manifest["restoration_blocked"] = True
                raise PublicationUncertain("Cannot prove publication terminal; preserve current artifact.")
        attempt["accepted"] = True
        raw = backend.read(model_id)
        candidate_path = attempt_dir / "artifact.json"
        write_exclusive(candidate_path, raw=raw.encode("utf-8"))
        # The committed checkpoint remains protected until its exact bytes are
        # durably archived. A read/write failure must never permit base restore.
        attempt["committed_artifact_archived"] = True
        manifest.pop("publication_pending", None)
        candidate = load_artifact(candidate_path)
        attempt.update(artifact_path=str(candidate_path), artifact_sha256=sha(candidate_path),
                       artifact_checksum=candidate["checksum"],
                       parameter_fingerprint=identity(candidate)["parameter_fingerprint"])
        if outcome.get("status") != "response" or outcome["response"].get("accepted") is not True:
            attempt.update(status="accepted_unscored", error="Durable commit recovered without complete successful response evidence.")
            return attempt
        response = outcome["response"]
        candidate_identity = validate_evidence(request, response, lookup["receipt"], base, candidate)
        evidence = {"request": request, "response": response, "request_fingerprint": request_fingerprint(request),
                    "request_binary_sha256": hashlib.sha256(request_bytes(request)).hexdigest(),
                    "candidate_artifact_sha256": sha(candidate_path),
                    "candidate_artifact_checksum": candidate["checksum"], "receipt": lookup["receipt"]}
        evidence_path = attempt_dir / "update-evidence.json"
        write_exclusive(evidence_path, evidence)
        backend.score(candidate_path, details["selection_path"], validation_path, attempt_dir / "validation", phase="candidate-validation", evidence=evidence_path)
        metrics = verified_metrics(attempt_dir / "validation", expected_validation, candidate_identity)
        attempt.update(status="accepted", validation_metrics=metrics,
                       validation_report_sha256=sha(attempt_dir / "validation/report.json"), evidence_path=str(evidence_path))
        return attempt
    except PublicationUncertain as exc:
        attempt.update(status="accepted_unscored" if attempt["accepted"] else "failed", error=str(exc))
        raise
    except Exception as exc:
        attempt.update(status="accepted_unscored" if attempt["accepted"] else "failed", error=str(exc))
        if manifest.get("publication_pending"):
            manifest["restoration_blocked"] = True
            raise PublicationUncertain("Failure before publication quiescence was proved.") from exc
        return attempt
    finally:
        write_exclusive(attempt_dir / "attempt.json", attempt)
        save_manifest(output / "run-manifest.json", manifest)


def execute_profiles(backend, profiles, output, manifest, expected_validation, expected_dev, validation_path, dev_path,
                     base_development_root=None):
    for profile in PROFILES:
        details = profiles[profile]
        base, model_id = details["artifact"], details["artifact"]["model_id"]
        directory = output / profile
        directory.mkdir()
        manifest["retained_artifacts"][model_id] = base
        backend.install(base)
        backend.configure(model_id)
        before_images = backend.images()
        backend.score(details["artifact_path"], details["selection_path"], validation_path, directory / "base-validation", phase="base-validation")
        base_metrics = verified_metrics(directory / "base-validation", expected_validation, identity(base))
        base_dev = (Path(base_development_root) / profile) if base_development_root else directory / "base-development"
        if base_development_root:
            report = json_read(base_dev / "report.json")
            if (report.get("dataset_sha256") != sha(dev_path)
                    or report.get("protocol_sha256") != manifest["protocol_sha256"]
                    or report.get("fit_source_revision") != manifest["fit_source_revision"]
                    or not re.fullmatch(r"[0-9a-f]{40,64}", report.get("source_revision", ""))):
                raise ValueError("Existing base development report has incompatible data/provenance.")
            write_exclusive(directory / "base-development-reuse.json", {
                "reused_verified_base": True, "report_path": str(base_dev / "report.json"),
                "report_sha256": sha(base_dev / "report.json"),
                "original_execution_source_revision": report["source_revision"]})
        else:
            backend.score(details["artifact_path"], details["selection_path"], dev_path, base_dev, phase="base-development")
        verified_metrics(base_dev, expected_dev, identity(base))
        attempts = []
        manifest["profiles"][profile] = {"attempts": attempts, "base_validation_metrics": base_metrics}
        for seed in SEEDS:
            backend.install(base)
            attempt = execute_attempt(backend, details, seed, output, manifest, expected_validation, validation_path)
            backend.install(base)
            attempt["restoration_verified"] = True
            write_exclusive(directory / f"seed{seed}" / "base-restoration.json", {
                "restoration_verified": True, "base_identity": identity(base),
                "base_artifact_sha256": sha(details["artifact_path"])})
            if attempt.get("quiesced"):
                backend.configure(model_id)
        chosen = choose_attempt(attempts, base_metrics)
        selected_path = Path(chosen["artifact_path"]) if chosen else details["artifact_path"]
        selected = load_artifact(selected_path)
        selected_identity = identity(selected)
        selection = {"status": "selected", "profile": profile,
                     "chosen_candidate_artifact_sha256": sha(selected_path),
                     "chosen_artifact_checksum": selected["checksum"],
                     "chosen_parameter_fingerprint": selected_identity["parameter_fingerprint"],
                     "fit_manifest_sha256": manifest["fit_manifest_sha256"],
                     "source_revision": manifest["source_revision"], "fit_source_revision": manifest["fit_source_revision"],
                     "protocol_sha256": manifest["protocol_sha256"], "base_artifact_sha256": sha(details["artifact_path"]),
                     "validation_metrics": chosen["validation_metrics"] if chosen else base_metrics,
                     "chosen_seed": chosen["seed"] if chosen else None, "attempts": attempts,
                     "restoration_verified": True, "base_validation_metrics": base_metrics,
                     "validation_dataset_sha256": sha(validation_path),
                     "base_validation_report_sha256": sha(directory / "base-validation/report.json"),
                     "chosen_validation_report_sha256": chosen["validation_report_sha256"] if chosen else sha(directory / "base-validation/report.json")}
        selection_path = directory / "retention-selection.json"
        write_exclusive(selection_path, selection)
        backend.install(selected)
        if chosen:
            backend.score(selected_path, details["selection_path"], dev_path, directory / "selected-development",
                          phase="selected-development", evidence=Path(chosen["evidence_path"]), retention=selection_path)
            verified_metrics(directory / "selected-development", expected_dev, selected_identity)
        else:
            write_exclusive(directory / "selected-development-reuse.json", {"reused_verified_base": True,
                                                                           "report_path": str(base_dev / "report.json"),
                                                                           "report_sha256": sha(base_dev / "report.json")})
        after_images = backend.images()
        if before_images != after_images:
            raise ValueError("Actual Docker container image IDs changed within a profile comparison.")
        manifest["profiles"][profile].update(selection=selection, image_ids_before=before_images, image_ids_after=after_images)
        manifest["retained_artifacts"][model_id] = selected
        save_manifest(output / "run-manifest.json", manifest)


def run_study(fit_root, output, source_revision, protocol_sha256, *, fit_source_revision=None,
              prepared=None, locked_root=None, base_development_root=None, backend_factory=DockerBackend):
    output = result_path(output, fresh=True)
    fit_manifest, profiles, fit_source_revision = load_fit(fit_root, protocol_sha256, fit_source_revision)
    default_base_root = Path(fit_root) / "runtime-base"
    base_development_root = base_development_root or (default_base_root if default_base_root.exists() else None)
    if base_development_root:
        base_development_root = result_path(base_development_root)
        if any(not (base_development_root / profile / "report.json").is_file() for profile in PROFILES):
            raise ValueError("Existing base development evidence must cover all three profiles; no partial rerun.")
    prepared = prepared or ROOT / "evaluation/results/representation_20261004_v3/prepared"
    locked_root = locked_root or ROOT / "evaluation/results/locked-public"
    validation_path, dev_path = Path(prepared) / "validation.jsonl", Path(locked_root) / "development.jsonl"
    validation_keys = dataset_keys(validation_path, PINNED_PARTITIONS["validation"][1], 968)
    dev_keys = dataset_keys(dev_path, LOCKED_DEV_SHA, 502)
    if sha(Path(locked_root) / "final.jsonl") != LOCKED_FINAL_SHA:
        raise ValueError("Locked final digest differs; final is never parsed.")
    output.mkdir(parents=True, exist_ok=False)
    manifest = {"status": "running", "source_revision": source_revision, "fit_source_revision": fit_source_revision,
                "protocol_sha256": protocol_sha256, "fit_manifest_sha256": sha(Path(fit_root) / "run-manifest.json"),
                "profiles": {}, "retained_artifacts": {}, "started_at_unix": time.time(),
                "input_sha256_before": {"validation": sha(validation_path), "development": sha(dev_path),
                                         "final": sha(Path(locked_root) / "final.jsonl")}}
    save_manifest(output / "run-manifest.json", manifest)
    backend = None
    try:
        backend = backend_factory(Path(fit_root).resolve(), output, source_revision, fit_source_revision, protocol_sha256)
        write_exclusive(output / "hardware.json", backend.hardware())
        with protected_catalog(backend, manifest, output):
            execute_profiles(backend, profiles, output, manifest, validation_keys, dev_keys, validation_path, dev_path,
                             base_development_root=base_development_root)
        manifest["status"] = "complete"
        return manifest
    except Exception as exc:
        manifest.update(status="failed", error={"type": type(exc).__name__, "error": str(exc), "traceback": traceback.format_exc()})
        raise
    finally:
        manifest["input_sha256_after"] = {"validation": sha(validation_path), "development": sha(dev_path),
                                           "final": sha(Path(locked_root) / "final.jsonl")}
        manifest["finished_at_unix"] = time.time()
        if manifest["input_sha256_after"] != manifest["input_sha256_before"]:
            manifest["status"] = "failed"
            manifest["input_changed"] = True
        save_manifest(output / "run-manifest.json", manifest)
        if backend is not None:
            backend.close()
        if manifest.get("input_changed"):
            raise ValueError("Protected input files changed during study.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fit-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--fit-source-revision")
    parser.add_argument("--protocol-sha256", required=True)
    parser.add_argument("--base-development-root", type=Path,
                        help="Reuse verified profile reports; defaults to fit-root/runtime-base when present.")
    args = parser.parse_args(argv)
    actual = subprocess.check_output(["git", "-c", f"safe.directory={ROOT.as_posix()}", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if actual != args.source_revision:
        parser.error("Execution source revision must match the current committed checkout.")
    if sha(ROOT / "paper/research/model-refactor-protocol.md") != args.protocol_sha256:
        parser.error("Prospective protocol digest differs from the current file.")
    manifest = run_study(args.fit_root, args.output, args.source_revision, args.protocol_sha256,
                         fit_source_revision=args.fit_source_revision, base_development_root=args.base_development_root)
    print(json.dumps({"status": manifest["status"], "output": str(args.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
