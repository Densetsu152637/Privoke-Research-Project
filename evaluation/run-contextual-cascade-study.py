"""Run the frozen contextual-presence cascade through staged Compose jobs."""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import math
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
sys.path.insert(0, str(ROOT / "evaluation"))
COMPOSE = ["docker", "compose", "-f", "docker-compose.yml", "-f", "evaluation/compose.tests.yml",
           "-f", "evaluation/compose.public-negatives.yml", "-f", "evaluation/compose.presence.yml"]
PROFILES = ("efficient", "balanced", "quality")
CONTROLS = ("original", "current")
PAIRS = tuple(f"{control}-{profile}" for control in CONTROLS for profile in PROFILES)
CASCADE_PROTOCOL_SHA256 = "2030fd53264bd5000775c1ddfbfd1e7dccc7267f395f89e66410b76e057ce720"
CONTEXT_CHECKSUMS = {"original": "8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c",
                     "current": "8c139431ba8605a3d6817d24d233cce78fc22a086fdeb3ee99702ada86c80015"}
PRESENCE_IDS = {p: f"privoke-presence-{p}" for p in PROFILES}
CATALOG_IDS = ("privoke-balanced", *PRESENCE_IDS.values())

ADMIN_READ = """import base64,json,sys
from pathlib import Path
ids=('privoke-balanced','privoke-presence-efficient','privoke-presence-balanced','privoke-presence-quality')
mid=sys.argv[1]; assert mid in ids; p=Path('/models')/(mid+'.json')
print(json.dumps({'exists':p.is_file(),'raw_b64':base64.b64encode(p.read_bytes()).decode('ascii') if p.is_file() else None}))
"""
ADMIN_INSTALL = """import json,sys
from pathlib import Path
from privoke_model.artifact import validate_artifact,write_artifact_atomic
mid,expected=sys.argv[1:3]
ids=('privoke-balanced','privoke-presence-efficient','privoke-presence-balanced','privoke-presence-quality')
assert mid in ids; raw=sys.stdin.buffer.read(); obj=json.loads(raw.decode('utf-8')); validate_artifact(obj)
assert obj.get('model_id')==mid and obj.get('checksum')==expected
if mid=='privoke-balanced': assert expected in ('8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c','8c139431ba8605a3d6817d24d233cce78fc22a086fdeb3ee99702ada86c80015')
write_artifact_atomic(Path('/models')/(mid+'.json'),obj)
"""
ADMIN_RESTORE = """import json,os,sys
from pathlib import Path
from privoke_model.artifact import validate_artifact
ids=('privoke-balanced','privoke-presence-efficient','privoke-presence-balanced','privoke-presence-quality')
mid=sys.argv[1]; assert mid in ids; raw=sys.stdin.buffer.read(); obj=json.loads(raw.decode('utf-8')); validate_artifact(obj); assert obj.get('model_id')==mid
p=Path('/models')/(mid+'.json'); t=p.with_name(p.name+'.restore-'+str(os.getpid()))
with t.open('xb') as f: f.write(raw); f.flush(); os.fsync(f.fileno())
os.replace(t,p); fd=os.open(str(p.parent),os.O_RDONLY)
try: os.fsync(fd)
finally: os.close(fd)
"""
IDENTITY_PROBE = """import json,sys,grpc,time
sys.path.insert(0,'/workspace/extension/client-runtime/generated')
from privoke.v1 import runtime_pb2 as pb,runtime_pb2_grpc as stubs
e=json.load(sys.stdin); q=pb.AnalyzePromptRequest(request_id='cascade-identity-probe',text='A public example sentence.',source='contextual-cascade-probe',semantic_model_id=e['context']['model_id'],semantic_presence_gate=pb.SemanticPresenceGate(model_id=e['presence']['model_id'],threshold=0.0),regex_execution_order=pb.REGEX_EXECUTION_ORDER_FIRST)
deadline=time.monotonic()+e.pop('_probe_retry_seconds',10.0); last=None; success=False
with grpc.insecure_channel('client-runtime:50054') as ch:
 s=stubs.PrivokeRuntimeServiceStub(ch)
 while time.monotonic()<deadline:
  try:
   r=s.AnalyzePrompt(q,timeout=3)
   x=next((z for z in r.layers if z.layer==pb.DETECTION_LAYER_SEMANTIC),None)
   if not r.error and x is not None and x.status!=pb.DETECTION_LAYER_STATUS_ERROR and not x.error and x.HasField('semantic_presence_gate'):
    t=x.semantic_presence_gate
    got={'context':{'model_id':t.contextual_model_id,'model_version':t.contextual_model_version,'artifact_checksum':t.contextual_artifact_checksum,'parameter_fingerprint':t.contextual_parameter_fingerprint},'presence':{'model_id':t.model_id,'model_version':t.model_version,'artifact_checksum':t.artifact_checksum,'parameter_fingerprint':t.parameter_fingerprint,'threshold':t.model_threshold},'status':int(t.status),'error':t.error,'decision_threshold':t.decision_threshold}
    if got['context']==e['context'] and {k:got['presence'][k] for k in e['presence']}==e['presence'] and got['status']==pb.SEMANTIC_PRESENCE_GATE_STATUS_APPLIED and not got['error'] and got['decision_threshold']==0.0:
     print(json.dumps({'context':got['context'],'presence':got['presence']},sort_keys=True)); success=True; break
    last='identity_or_gate_mismatch'
   else: last='runtime_error_or_missing_gate_trace'
  except grpc.RpcError: last='runtime_rpc_error'
  time.sleep(min(0.5,max(0.0,deadline-time.monotonic())))
if not success: raise RuntimeError('typed runtime probe did not converge: '+str(last))
"""
FIT_PREFLIGHT = """import argparse,importlib.util,json,sys
sys.path.insert(0,'/workspace/shared/python'); sys.path.insert(0,'/workspace/evaluation')
p='/workspace/evaluation/evaluate-contextual-cascade.py'; s=importlib.util.spec_from_file_location('cascade_fit_preflight',p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)
a=argparse.Namespace(fit_root=sys.argv[1],fit_source_revision=sys.argv[2],original_artifact=sys.argv[3],current_artifact=sys.argv[4],source_revision=sys.argv[5],protocol_sha256=sys.argv[6],runtime_image_id=sys.argv[7],evaluator_image_id=sys.argv[8],target='client-runtime:50054')
v=m.bind_inputs(a); open(sys.argv[9],'x',encoding='utf-8').write(json.dumps(v,sort_keys=True,allow_nan=False))
"""


def sha_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha_file(path: Path) -> str:
    return sha_bytes(Path(path).read_bytes())


def read_json(path: Path) -> dict:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Expected JSON object.")
    return value


def save_json(path: Path, value: dict, *, exclusive: bool = False) -> None:
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()
    if exclusive:
        with path.open("xb") as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
    else:
        temporary = path.with_name(path.name + ".tmp")
        with temporary.open("xb") as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)


def inside_results(path: Path, *, fresh: bool = False) -> Path:
    path = Path(path).resolve()
    if RESULTS not in path.parents:
        raise ValueError("Study inputs and outputs must be children of evaluation/results.")
    if fresh and path.exists():
        raise FileExistsError("Refusing to reuse an existing study path.")
    return path


def current_revision() -> str:
    result = subprocess.run(["git", "-c", f"safe.directory={ROOT.as_posix()}", "rev-parse", "HEAD"],
                            cwd=ROOT, check=True, capture_output=True, text=True)
    value = result.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", value):
        raise ValueError("Git HEAD is not a full object ID.")
    return value


def load_caller():
    path = ROOT / "evaluation/evaluate-contextual-cascade.py"
    spec = importlib.util.spec_from_file_location("contextual_cascade_caller", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot import the frozen contextual cascade caller.")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def container_path(path: Path) -> str:
    return "/workspace/evaluation/results/" + Path(path).resolve().relative_to(RESULTS).as_posix()


def safe_error(exc: Exception) -> dict:
    return {"error_type": type(exc).__name__, "error_sha256": sha_bytes(str(exc).encode("utf-8"))}


def validate_frozen_inputs(*, fit_root: Path, fit_source_revision: str,
                           original_artifact: Path, current_artifact: Path,
                           validation_file: Path, development_file: Path,
                           protocol_file: Path, protocol_sha256: str,
                           source_revision: str) -> dict:
    caller = load_caller()
    if current_revision() != source_revision:
        raise ValueError("Current source revision differs from the requested execution revision.")
    if protocol_sha256 != CASCADE_PROTOCOL_SHA256 or sha_file(protocol_file) != protocol_sha256:
        raise ValueError("Cascade protocol differs from its frozen SHA-256.")
    fit_root = inside_results(fit_root)
    for path in (original_artifact, current_artifact, validation_file, development_file, protocol_file):
        inside_results(path)
    # Validate fit bytes and selected artifact identities without host-side float replay.
    from privoke_model.artifact import load_artifact
    from privoke_eval.presence_evidence import artifact_identity
    from privoke_model.fingerprint import parameter_fingerprint
    fit_manifest_path = fit_root / "run-manifest.json"
    fit = read_json(fit_manifest_path)
    if (fit.get("status") != "complete" or fit.get("source_revision") != fit_source_revision
            or fit.get("protocol_sha256") != caller.FIT_PROTOCOL
            or fit.get("selections_frozen_before_development_scoring") is not True
            or fit.get("errors") not in (None, [])
            or set(fit.get("profiles", {})) != set(PROFILES)):
        raise ValueError("Presence fit is incomplete or has a wrong source/protocol/profile set.")
    presence = {}
    for profile in PROFILES:
        selection_path = fit_root / "profiles" / profile / "selection.json"
        selection = read_json(selection_path)
        if selection != fit["profiles"][profile] or selection.get("status") != "selected":
            raise ValueError("Frozen profile selection differs from its fit manifest.")
        artifact_path = (fit_root / selection["selected_artifact_file"]).resolve()
        if fit_root.resolve() not in artifact_path.parents or sha_file(artifact_path) != selection.get("selected_artifact_sha256"):
            raise ValueError("Frozen profile artifact path/hash mismatch.")
        artifact = load_artifact(artifact_path)
        identity = artifact_identity(artifact)
        if (artifact.get("model_id") != f"privoke-presence-{profile}"
                or artifact.get("config", {}).get("profile") != profile
                or artifact.get("metadata", {}).get("source_revision") != fit_source_revision
                or artifact.get("metadata", {}).get("protocol_sha256") != caller.FIT_PROTOCOL
                or selection.get("source_revision") != fit_source_revision
                or selection.get("protocol_sha256") != caller.FIT_PROTOCOL
                or selection.get("artifact_identity") != identity):
            raise ValueError("Frozen presence artifact identity/profile mismatch.")
        presence[profile] = {"identity": identity, "file_sha256": sha_file(artifact_path),
            "artifact_bytes": artifact_path.stat().st_size,
            "parameter_count": sum(len(v["values"]) for v in artifact["parameters"].values()),
            "word_features": len(artifact["config"]["branches"]["word"]["features"]),
            "char_features": len(artifact["config"]["branches"]["char"]["features"]),
            "artifact_path": str(artifact_path), "artifact": artifact}
    controls = {}
    for name, path in (("original", original_artifact), ("current", current_artifact)):
        artifact = load_artifact(path)
        if (artifact.get("checksum") != caller.CHECKSUMS[name]
                or artifact.get("model_id") != "privoke-balanced"
                or artifact.get("architecture") != "privoke_tiny_transformer_v1"):
            raise ValueError("Contextual control artifact identity mismatch.")
        controls[name] = {"path": str(Path(path).resolve()), "file_sha256": sha_file(path),
                          "identity": caller.contextual_identity(artifact), "artifact": artifact}
    validation = caller.dataset(validation_file, "validation")
    development = caller.dataset(development_file, "development")
    return {"caller": caller, "fit_root": fit_root, "fit_manifest_sha256": sha_file(fit_manifest_path),
        "fit": fit, "presence": presence, "controls": controls,
        "datasets": {"validation": validation, "development": development},
        "dataset_hashes": {"validation": sha_file(validation_file), "development": sha_file(development_file)},
        "paths": {"validation": str(Path(validation_file).resolve()),
                  "development": str(Path(development_file).resolve())},
        "source_revision": source_revision, "fit_source_revision": fit_source_revision,
        "protocol_sha256": protocol_sha256, "protocol_file": str(protocol_file.resolve())}


class DockerBackend:
    """Fixed Compose and model-admin boundary; callers never construct shell commands."""
    def __init__(self, output: Path, *, env: dict[str, str] | None = None):
        self.output = output
        self.env = dict(os.environ if env is None else env)
        self.calls: list[dict] = []
        self.job_images: set[str] = set()
        self.jobs: list[dict] = []
        self.admin_mutation_outcome_unknown = False
        self.evaluator_job_outcome_unknown = False
        self.runtime_cache_ttl_seconds = 1.0

    def call(self, args: list[str], *, data: bytes | None = None, direct: bool = False,
             timeout: int = 180, admin_mutation: bool = False) -> str:
        argv = list(args) if direct else COMPOSE + list(args)
        try:
            result = subprocess.run(argv, cwd=ROOT, env=self.env, input=data,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            if admin_mutation:
                self.admin_mutation_outcome_unknown = True
            self.calls.append({"argv": argv, "returncode": None, "timed_out": True,
                "stdout_sha256": sha_bytes(exc.output or b""), "stderr_sha256": sha_bytes(exc.stderr or b""),
                "admin_mutation": admin_mutation})
            raise
        out, err = result.stdout or b"", result.stderr or b""
        self.calls.append({"argv": argv, "returncode": result.returncode,
                           "stdout_sha256": sha_bytes(out), "stderr_sha256": sha_bytes(err),
                           "admin_mutation": admin_mutation})
        if result.returncode:
            if admin_mutation:
                self.admin_mutation_outcome_unknown = True
            raise RuntimeError(f"Command failed with exit {result.returncode}; stderr sha256={sha_bytes(err)}")
        return out.decode("utf-8").strip()

    def _assert_mutations_safe(self) -> None:
        if self.admin_mutation_outcome_unknown or self.evaluator_job_outcome_unknown:
            raise RuntimeError("A prior remote operation is unresolved; model writes are stopped.")

    def _quiesce_named_job(self, name: str) -> bool:
        """Remove only this invocation's named one-off and verify it is absent."""
        try:
            ids = self.call(["docker", "ps", "--all", "--quiet", "--filter", f"name=^{name}$"], direct=True).splitlines()
            if any(not re.fullmatch(r"[0-9a-f]{12,64}", item) for item in ids):
                return False
            for item in ids:
                self.call(["docker", "rm", "-f", item], direct=True, timeout=30)
            remaining = self.call(["docker", "ps", "--all", "--quiet", "--filter", f"name=^{name}$"], direct=True).splitlines()
            return not remaining
        except Exception:
            return False

    def ensure_services(self) -> None:
        for service in ("client-runtime", "model-streaming-service", "param-update-service"):
            ids = self.call(["ps", "--status", "running", "--quiet", service]).splitlines()
            if len(ids) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", ids[0]):
                raise ValueError("Required existing Compose service is not running exactly once.")
            state = json.loads(self.call(["docker", "inspect", "--format", "{{json .State}}", ids[0]], direct=True))
            if state.get("Running") is not True or state.get("Status") != "running":
                raise ValueError("Required existing Compose service is not running.")
            if state.get("Health") and state["Health"].get("Status") != "healthy":
                raise ValueError("Required existing Compose service is not healthy.")
        runtime_ids = self.call(["ps", "--all", "--quiet", "client-runtime"]).splitlines()
        runtime_env = json.loads(self.call(["docker", "inspect", "--format", "{{json .Config.Env}}", runtime_ids[0]], direct=True))
        ttl_text = next((item.split("=", 1)[1] for item in runtime_env
                         if isinstance(item, str) and item.startswith("MODEL_STREAMING_CACHE_TTL_SECONDS=")), "1.0")
        try:
            ttl = float(ttl_text)
        except (TypeError, ValueError) as exc:
            raise ValueError("Runtime cache TTL is invalid.") from exc
        if not math.isfinite(ttl) or ttl < 0 or ttl > 60:
            raise ValueError("Runtime cache TTL is outside the bounded probe window.")
        self.runtime_cache_ttl_seconds = ttl
        updater = self.call(["ps", "--all", "--quiet", "param-update-service"]).splitlines()
        env = json.loads(self.call(["docker", "inspect", "--format", "{{json .Config.Env}}", updater[0]], direct=True)) if len(updater) == 1 else []
        if "FUZZER_PROMPT_COUNT=0" not in env:
            raise ValueError("Existing parameter updater is not configured with startup training disabled.")
        for writer in ("presence-fuzzer", "presence-update-service"):
            if self.call(["ps", "--status", "running", "--quiet", writer]).splitlines():
                raise ValueError("A presence training/update writer is running during the cascade study.")

    def images(self) -> dict:
        result = {}
        for service in ("client-runtime", "model-streaming-service", "param-update-service"):
            ids = self.call(["ps", "--all", "--quiet", service]).splitlines()
            if len(ids) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", ids[0]):
                raise ValueError("Compose must expose exactly one container for each fixed service.")
            image = self.call(["docker", "inspect", "--format", "{{.Image}}", ids[0]], direct=True)
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
                raise ValueError("Service did not expose an immutable image ID.")
            result[service] = image
        return result

    def evaluator_image(self) -> str:
        config = json.loads(self.call(["config", "--format", "json"]))
        service = config.get("services", {}).get("evaluation-tests")
        project = config.get("name")
        if not isinstance(service, dict) or not isinstance(project, str) or not project:
            raise ValueError("Compose did not resolve the fixed evaluation service image.")
        image_ref = service.get("image") or f"{project}-evaluation-tests"
        if not isinstance(image_ref, str) or not image_ref:
            raise ValueError("Compose evaluation image reference is invalid.")
        image_id = self.call(["docker", "image", "inspect", "--format", "{{.Id}}", image_ref], direct=True)
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise ValueError("Prebuilt evaluation image is unavailable or did not expose an immutable ID.")
        return image_id

    def read_raw(self, model_id: str) -> bytes:
        if model_id not in CATALOG_IDS:
            raise ValueError("Model ID is outside the fixed four-file catalog allowlist.")
        record = json.loads(self.call(["exec", "-T", "param-update-service", "python", "-c", ADMIN_READ, model_id]))
        if record.get("exists") is not True:
            raise FileNotFoundError("A required frozen catalog artifact is missing.")
        return base64.b64decode(record["raw_b64"], validate=True)

    def write_artifact(self, artifact: dict, *, expected_checksum: str) -> None:
        self._assert_mutations_safe()
        model_id = artifact.get("model_id")
        if model_id not in CATALOG_IDS or artifact.get("checksum") != expected_checksum:
            raise ValueError("Artifact is outside the fixed model/checksum allowlist.")
        payload = (json.dumps(artifact, sort_keys=True, ensure_ascii=False,
                              separators=(",", ":"), allow_nan=False) + "\n").encode()
        self.call(["exec", "-T", "param-update-service", "python", "-c", ADMIN_INSTALL,
                   model_id, expected_checksum], data=payload, admin_mutation=True)
        current = self.read_raw(model_id)
        if json.loads(current) != artifact:
            raise ValueError("Installed model differs from the selected frozen artifact.")

    def restore_exact(self, model_id: str, raw: bytes) -> None:
        self._assert_mutations_safe()
        if model_id not in CATALOG_IDS:
            raise ValueError("Model ID is outside the fixed four-file catalog allowlist.")
        self.call(["exec", "-T", "param-update-service", "python", "-c", ADMIN_RESTORE, model_id],
                  data=raw, admin_mutation=True)

    def probe(self, expected: dict) -> None:
        payload = json.dumps({**expected, "_probe_retry_seconds": max(10.0, self.runtime_cache_ttl_seconds + 2.0)}, sort_keys=True).encode()
        observed = json.loads(self.call(["exec", "-T", "client-runtime", "python", "-c", IDENTITY_PROBE], data=payload, timeout=90))
        if observed != expected:
            raise ValueError("Runtime identity probe differs from the frozen model pair.")

    def preflight_fit(self, *, inputs: dict, binding: dict, output: Path) -> dict:
        receipt = output / "linux-fit-preflight.json"
        args = ["run", "--rm", "--no-deps", "-T", "evaluation-tests", "python", "-c", FIT_PREFLIGHT,
            container_path(inputs["fit_root"]), binding["fit_source_revision"],
            container_path(Path(inputs["controls"]["original"]["path"])),
            container_path(Path(inputs["controls"]["current"]["path"])),
            binding["source_revision"], binding["protocol_sha256"], binding["runtime_image_id"],
            binding["evaluator_image_id"], container_path(receipt)]
        self.call(args, timeout=600)
        value = read_json(receipt)
        expected = {"source_revision": binding["source_revision"],
            "fit_source_revision": binding["fit_source_revision"],
            "protocol_sha256": binding["protocol_sha256"],
            "fit_protocol_sha256": binding["fit_protocol_sha256"],
            "fit_manifest_sha256": binding["fit_manifest_sha256"],
            "runtime_image_id": binding["runtime_image_id"],
            "evaluator_image_id": binding["evaluator_image_id"], "target": binding["target"],
            "caller_sha256": binding["caller_sha256"],
            "controls": binding["controls"], "presence": binding["presence"],
            "datasets": binding["datasets"]}
        # The evaluator sees mounted /workspace paths; compare every identity/hash field,
        # while the host binding retains its native absolute locators.
        observed = dict(value)
        for name in CONTROLS:
            if name in observed.get("controls", {}):
                observed["controls"][name].pop("path", None)
        expected["controls"] = {k: {kk: vv for kk, vv in v.items() if kk != "path"}
                                 for k, v in expected["controls"].items()}
        if observed != expected:
            raise ValueError("Linux strict fit preflight differs from host hash-bound identity.")
        return {"sha256": sha_file(receipt), "binding": observed}

    def run_stage(self, *, stage: str, pair: str | None, study_root: Path,
                  inputs: dict, binding: dict, output: Path) -> dict:
        name = f"cascade-{output.name}-{uuid.uuid4().hex[:8]}"
        args = ["run", "-d", "--no-deps", "-T", "--name", name,
                "evaluation-tests", "python", "/workspace/evaluation/evaluate-contextual-cascade.py",
                "--phase", stage, "--study-root", container_path(study_root),
                "--fit-root", container_path(inputs["fit_root"]),
                "--original-artifact", container_path(Path(inputs["controls"]["original"]["path"])),
                "--current-artifact", container_path(Path(inputs["controls"]["current"]["path"])),
                "--validation-file", container_path(Path(inputs["paths"]["validation"])),
                "--development-file", container_path(Path(inputs["paths"]["development"])),
                "--source-revision", binding["source_revision"],
                "--fit-source-revision", binding["fit_source_revision"],
                "--protocol-sha256", binding["protocol_sha256"],
                "--runtime-image-id", binding["runtime_image_id"],
                "--evaluator-image-id", binding["evaluator_image_id"],
                "--target", "client-runtime:50054", "--protocol-file", container_path(Path(inputs["protocol_file"]))]
        if pair:
            control, profile = pair.split("-", 1)
            args += ["--control", control, "--profile", profile]
        return self._job(args, name=name, stage=stage, pair=pair, study_root=study_root, output=output)

    def _job(self, args: list[str], *, name: str, stage: str, pair: str | None,
             study_root: Path, output: Path) -> dict:
        try:
            container = self.call(args, timeout=120)
        except Exception:
            if not self._quiesce_named_job(name):
                self.evaluator_job_outcome_unknown = True
            raise
        if not re.fullmatch(r"[0-9a-f]{12,64}", container):
            if not self._quiesce_named_job(name):
                self.evaluator_job_outcome_unknown = True
            raise ValueError("Compose did not return the one-off evaluator container ID.")
        record = {"container_id": container, "stage": stage, "pair": pair,
                  "image_id": None, "exit_code": None, "logs_sha256": None}
        active_error = None
        try:
            record["image_id"] = self.call(["docker", "inspect", "--format", "{{.Image}}", container], direct=True)
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", record["image_id"]):
                raise ValueError("Evaluator job did not expose an immutable image ID.")
            expected_image = self.env.get("CASCADE_EXPECTED_EVALUATOR_IMAGE_ID")
            if expected_image and record["image_id"] != expected_image:
                raise ValueError("Evaluator job image differs from the frozen preflight image.")
            self.job_images.add(record["image_id"])
            record["exit_code"] = int(self.call(["docker", "wait", container], direct=True, timeout=1400))
            logs = self.call(["docker", "logs", container], direct=True, timeout=30)
            record["logs_sha256"] = sha_bytes(logs.encode())
            if record["exit_code"]:
                raise RuntimeError("Evaluator stage exited unsuccessfully.")
        except Exception as exc:
            active_error = exc
        finally:
            if not self._quiesce_named_job(name):
                self.evaluator_job_outcome_unknown = True
                if active_error is None:
                    active_error = RuntimeError("Named evaluator container could not be proven quiescent.")
            self.jobs.append(record)
        if active_error:
            raise active_error
        if stage == "calibrate":
            selection = read_json(study_root / "calibration/selection.json")
            return {"status": selection.get("status"), "choices": selection.get("choices"), **record}
        assert pair is not None
        pair_dir = study_root / stage / pair
        skipped = pair_dir / "skipped.json"
        if skipped.is_file():
            return {"status": read_json(skipped).get("status"), **record}
        report = read_json(pair_dir / "report.json")
        if report.get("status") != "complete" or report.get("pair") != pair or report.get("stage") != stage:
            raise ValueError("Evaluator stage report is incomplete or mismatched.")
        return {"status": report["status"], "report_sha256": sha_file(pair_dir / "report.json"), **record}


def make_binding(inputs: dict, runtime_image_id: str, evaluator_image_id: str) -> dict:
    return {"source_revision": inputs["source_revision"],
        "fit_source_revision": inputs["fit_source_revision"],
        "protocol_sha256": inputs["protocol_sha256"],
        "fit_protocol_sha256": inputs["caller"].FIT_PROTOCOL,
        "fit_manifest_sha256": inputs["fit_manifest_sha256"],
        "controls": {name: {key: value[key] for key in ("path", "file_sha256", "identity")}
                     for name, value in inputs["controls"].items()},
        "presence": {name: {key: value[key] for key in
                            ("identity", "file_sha256", "artifact_bytes", "parameter_count", "word_features", "char_features")}
                     for name, value in inputs["presence"].items()},
        "runtime_image_id": runtime_image_id, "evaluator_image_id": evaluator_image_id,
        "caller_sha256": sha_file(ROOT / "evaluation/evaluate-contextual-cascade.py"),
        "target": "client-runtime:50054",
        "datasets": {name: list(value) for name, value in inputs["caller"].DATA.items()}}


def check_prior_catalog(raws: dict[str, bytes], inputs: dict) -> dict[str, dict]:
    from privoke_model.artifact import validate_artifact
    from privoke_eval.presence_evidence import artifact_identity
    decoded = {}
    for model_id, raw in raws.items():
        artifact = json.loads(raw.decode("utf-8"))
        if not isinstance(artifact, dict) or artifact.get("model_id") != model_id:
            raise ValueError("Existing catalog bytes have a mismatched model ID.")
        validate_artifact(artifact)
        decoded[model_id] = artifact
    contextual = decoded["privoke-balanced"]
    if contextual.get("checksum") != CONTEXT_CHECKSUMS["current"]:
        raise ValueError("Runtime does not begin at the exact selected current contextual checksum.")
    for profile in PROFILES:
        model_id = PRESENCE_IDS[profile]
        if artifact_identity(decoded[model_id]) != inputs["presence"][profile]["identity"]:
            raise ValueError("Installed presence artifact differs from its frozen fit profile.")
    return decoded


def write_backups(output: Path, raws: dict[str, bytes]) -> dict:
    folder = output / "private-backups"
    folder.mkdir(parents=True, exist_ok=False)
    records = {}
    for model_id in CATALOG_IDS:
        raw = raws[model_id]
        path = folder / f"{model_id}.json.b64"
        payload = base64.b64encode(raw) + b"\n"
        with path.open("xb") as stream:
            stream.write(payload); stream.flush(); os.fsync(stream.fileno())
        records[model_id] = {"relative_path": path.relative_to(output).as_posix(),
                             "raw_sha256": sha_bytes(raw), "backup_sha256": sha_bytes(payload),
                             "bytes": len(raw)}
    return records


def _persist(output: Path, state: dict) -> None:
    save_json(output / "study-run-manifest.json", state)


def _record_job(output: Path, state: dict, stage: str, pair: str | None, result: dict) -> None:
    state["phase_jobs"].append({"stage": stage, "pair": pair, **{k: result[k] for k in
        ("status", "report_sha256", "container_id", "image_id", "exit_code", "logs_sha256") if k in result}})
    _persist(output, state)


def _run_group(*, backend, output: Path, study_root: Path, inputs: dict,
               binding: dict, state: dict, stage: str, control: str,
               prior_raw: dict[str, bytes], choices: dict | None = None) -> None:
    target_context = inputs["controls"][control]
    current_identity = inputs["controls"]["current"]["identity"]
    backend.write_artifact(target_context["artifact"], expected_checksum=target_context["artifact"]["checksum"])
    try:
        for profile in PROFILES:
            pair = f"{control}-{profile}"
            choice = (choices or {}).get(pair)
            ineligible = stage in ("evaluate-validation", "evaluate-development") and choice and choice.get("status") == "ineligible"
            presence = inputs["presence"][profile]
            if not ineligible:
                backend.write_artifact(presence["artifact"], expected_checksum=presence["identity"]["artifact_checksum"])
                backend.probe({"context": target_context["identity"], "presence": presence["identity"]})
            result = backend.run_stage(stage=stage, pair=pair, study_root=study_root,
                                       inputs=inputs, binding=binding, output=output)
            if stage == "collect-validation" and result.get("status") != "complete":
                raise ValueError("A validation collection did not complete successfully.")
            if stage in ("evaluate-validation", "evaluate-development"):
                expected = "skipped_ineligible" if ineligible else "complete"
                if result.get("status") != expected:
                    raise ValueError("A selected endpoint differs from frozen eligibility.")
            _record_job(output, state, stage, pair, result)
    finally:
        if not backend.admin_mutation_outcome_unknown and not getattr(backend, "evaluator_job_outcome_unknown", False):
            backend.restore_exact("privoke-balanced", prior_raw["privoke-balanced"])
            if not backend.admin_mutation_outcome_unknown:
                if sha_bytes(backend.read_raw("privoke-balanced")) != state["prior_sha256"]["privoke-balanced"]:
                    raise ValueError("Contextual control bytes did not restore at checkpoint.")
                backend.probe({"context": current_identity,
                               "presence": inputs["presence"][PROFILES[-1]]["identity"]})


def run_sequence(*, backend, output: Path, study_root: Path,
                 inputs: dict, binding: dict) -> dict:
    """Run staged requests and always restore byte-exact prior catalog state."""
    state = {"schema_version": 1, "status": "running", "phase": "preflight",
        "binding": binding, "phase_jobs": [], "errors": [], "restoration_verified": False,
        "admin_mutation_outcome_unknown": False, "images_before": None, "images_after": None}
    _persist(output, state)
    backups_written = False
    try:
        backend.ensure_services()
        images = backend.images()
        evaluator_image = backend.evaluator_image()
        if evaluator_image != binding["evaluator_image_id"]:
            raise ValueError("Prebuilt evaluator image changed after input binding.")
        if images["client-runtime"] != binding["runtime_image_id"]:
            raise ValueError("Runtime image differs from the frozen preflight identity.")
        state["linux_fit_preflight"] = backend.preflight_fit(inputs=inputs, binding=binding, output=output)
        _persist(output, state)
        state["images_before"] = images
        prior_raw = {model_id: backend.read_raw(model_id) for model_id in CATALOG_IDS}
        check_prior_catalog(prior_raw, inputs)
        state["prior_sha256"] = {key: sha_bytes(value) for key, value in prior_raw.items()}
        state["private_backups"] = write_backups(output, prior_raw)
        backups_written = True
        _persist(output, state)
        for control in CONTROLS:
            state["phase"] = f"collect-validation:{control}"; _persist(output, state)
            _run_group(backend=backend, output=output, study_root=study_root, inputs=inputs,
                       binding=binding, state=state, stage="collect-validation", control=control,
                       prior_raw=prior_raw)
        state["phase"] = "calibrate"; _persist(output, state)
        calibration = backend.run_stage(stage="calibrate", pair=None, study_root=study_root,
                                        inputs=inputs, binding=binding, output=output)
        if calibration.get("status") != "frozen" or set(calibration.get("choices", {})) != set(PAIRS):
            raise ValueError("Calibration did not freeze exactly six choices.")
        choices = calibration["choices"]
        for pair in PAIRS:
            choice = choices[pair]
            status = choice.get("status")
            if status not in ("eligible", "ineligible"):
                raise ValueError("Frozen choice has an unsupported eligibility state.")
            if status == "eligible":
                selected = choice.get("chosen")
                threshold = selected.get("threshold") if isinstance(selected, dict) else None
                if type(threshold) not in (int, float) or not math.isfinite(threshold) or not 0 <= threshold <= 1:
                    raise ValueError("Eligible frozen choice lacks a finite calibrated threshold.")
            elif choice.get("chosen") is not None:
                raise ValueError("Ineligible frozen choice must not contain a selected threshold.")
        state["calibration_sha256"] = sha_file(study_root / "calibration/selection.json")
        state["eligibility"] = {pair: choices[pair].get("status") for pair in PAIRS}
        _record_job(output, state, "calibrate", None, calibration)
        for control in CONTROLS:
            state["phase"] = f"evaluate-validation:{control}"; _persist(output, state)
            _run_group(backend=backend, output=output, study_root=study_root, inputs=inputs,
                       binding=binding, state=state, stage="evaluate-validation", control=control,
                       prior_raw=prior_raw, choices=choices)
        validation_status = {f"{job['stage']}:{job['pair']}": job["status"] for job in state["phase_jobs"]
                             if job["stage"] == "evaluate-validation"}
        if set(validation_status) != {f"evaluate-validation:{pair}" for pair in PAIRS}:
            raise ValueError("Development cannot begin until all six validation outcomes are recorded.")
        for pair in PAIRS:
            expected = "skipped_ineligible" if choices[pair].get("status") == "ineligible" else "complete"
            if validation_status[f"evaluate-validation:{pair}"] != expected:
                raise ValueError("Validation endpoint status does not match frozen eligibility.")
        for control in CONTROLS:
            state["phase"] = f"evaluate-development:{control}"; _persist(output, state)
            _run_group(backend=backend, output=output, study_root=study_root, inputs=inputs,
                       binding=binding, state=state, stage="evaluate-development", control=control,
                       prior_raw=prior_raw, choices=choices)
        state["images_after"] = backend.images()
        if state["images_after"] != state["images_before"] or backend.job_images != {binding["evaluator_image_id"]}:
            raise ValueError("Runtime/evaluator image identity changed during fixed study.")
        state["status"] = "complete"; state["phase"] = "complete"
    except Exception as exc:
        state["status"] = "failed"; state["failure_stage"] = state.get("phase")
        state["errors"].append(safe_error(exc))
    finally:
        unknown = (backend.admin_mutation_outcome_unknown
                   or getattr(backend, "evaluator_job_outcome_unknown", False))
        state["admin_mutation_outcome_unknown"] = unknown
        if backups_written and not unknown:
            restoration_errors = []
            for model_id in CATALOG_IDS:
                if backend.admin_mutation_outcome_unknown:
                    restoration_errors.append({"model_id": model_id,
                        "error_type": "RemoteOperationOutcomeUnknown",
                        "reason": "A timed-out restore may still be active; subsequent writes were stopped."})
                    break
                try:
                    backend.restore_exact(model_id, prior_raw[model_id])
                    if backend.admin_mutation_outcome_unknown:
                        restoration_errors.append({"model_id": model_id,
                            "error_type": "RemoteOperationOutcomeUnknown",
                            "reason": "A timed-out restore may still be active; subsequent writes were stopped."})
                        break
                    if sha_bytes(backend.read_raw(model_id)) != state["prior_sha256"][model_id]:
                        raise ValueError("Restored bytes differ from exact prior artifact.")
                except Exception as exc:
                    restoration_errors.append({"model_id": model_id, **safe_error(exc)})
            if not backend.admin_mutation_outcome_unknown and not restoration_errors:
                try:
                    for profile in PROFILES:
                        backend.probe({"context": inputs["controls"]["current"]["identity"],
                                       "presence": inputs["presence"][profile]["identity"]})
                except Exception as exc:
                    restoration_errors.append({"model_id": "runtime-probe", **safe_error(exc)})
            state["restoration_failures"] = restoration_errors
            state["restoration_verified"] = not backend.admin_mutation_outcome_unknown and not restoration_errors
        else:
            state["restoration_failures"] = ([{"error_type": "RemoteOperationOutcomeUnknown",
                "reason": "A timed-out writer or evaluator job may still be active; restoration is not claimed."}] if unknown else [])
            state["restoration_verified"] = False
        if not state["restoration_verified"]:
            state["status"] = "failed"
        state["admin_mutation_outcome_unknown"] = backend.admin_mutation_outcome_unknown
        state["evaluator_job_outcome_unknown"] = getattr(backend, "evaluator_job_outcome_unknown", False)
        state["docker_calls"] = getattr(backend, "calls", [])
        state["jobs"] = getattr(backend, "jobs", [])
        state["finished_unix"] = time.time()
        _persist(output, state)
    return state


def run_study(*, fit_root: Path, fit_source_revision: str,
              original_artifact: Path, current_artifact: Path,
              validation_file: Path, development_file: Path,
              protocol_file: Path, protocol_sha256: str, source_revision: str,
              output: Path, backend=None) -> dict:
    output = inside_results(output, fresh=True)
    inputs = validate_frozen_inputs(fit_root=fit_root, fit_source_revision=fit_source_revision,
        original_artifact=original_artifact, current_artifact=current_artifact,
        validation_file=validation_file, development_file=development_file,
        protocol_file=protocol_file, protocol_sha256=protocol_sha256, source_revision=source_revision)
    backend = backend or DockerBackend(output)
    backend.ensure_services()
    images = backend.images()
    evaluator_image = backend.evaluator_image()
    binding = make_binding(inputs, images["client-runtime"], evaluator_image)
    protocol_copy = output / "contextual-cascade-protocol.md"
    save_json(output / "input-binding.json", binding, exclusive=True)
    protocol_copy.parent.mkdir(parents=True, exist_ok=True)
    with protocol_copy.open("xb") as stream:
        stream.write(Path(protocol_file).read_bytes()); stream.flush(); os.fsync(stream.fileno())
    if sha_file(protocol_copy) != protocol_sha256:
        raise ValueError("Private protocol copy differs from its frozen SHA-256.")
    inputs["protocol_file"] = str(protocol_copy)
    if isinstance(backend, DockerBackend):
        backend.env["CASCADE_EXPECTED_EVALUATOR_IMAGE_ID"] = evaluator_image
    return run_sequence(backend=backend, output=output, study_root=output / "cascade-evidence",
                        inputs=inputs, binding=binding)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--fit-root", type=Path, required=True)
    result.add_argument("--fit-source-revision", required=True)
    result.add_argument("--original-artifact", type=Path, required=True)
    result.add_argument("--current-artifact", type=Path, required=True)
    result.add_argument("--validation-file", type=Path, required=True)
    result.add_argument("--development-file", type=Path, required=True)
    result.add_argument("--protocol-file", type=Path, required=True)
    result.add_argument("--protocol-sha256", required=True)
    result.add_argument("--source-revision", required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{64}", args.protocol_sha256):
        raise SystemExit("--protocol-sha256 must be lowercase SHA-256.")
    state = run_study(fit_root=args.fit_root, fit_source_revision=args.fit_source_revision,
        original_artifact=args.original_artifact, current_artifact=args.current_artifact,
        validation_file=args.validation_file, development_file=args.development_file,
        protocol_file=args.protocol_file, protocol_sha256=args.protocol_sha256,
        source_revision=args.source_revision, output=args.output)
    print(json.dumps({"status": state["status"], "restoration_verified": state["restoration_verified"],
                      "admin_mutation_outcome_unknown": state["admin_mutation_outcome_unknown"],
                      "phase_jobs": len(state["phase_jobs"]),
                      "failure_stage": state.get("failure_stage")}, sort_keys=True))
    return 0 if state["status"] == "complete" and state["restoration_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
