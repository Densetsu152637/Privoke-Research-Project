"""Host-only controller; the isolated runtime owns every physical fit."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import time
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services/pretrained-v3/src"))
from common import (pb, rpc, runtime_pb2, runtime_pb2_grpc, parameters_pb2, channel,
                    fetch, canonical, digest, source_inventory, source_identity)
from privoke_model.v3_contract import POLICY, TIERS, parse, validate_manifest, validate_execution, validate_policy
from fuzzer_training import schedule, validate_source_evidence

def exclusive(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(payload); handle.flush(); os.fsync(handle.fileno())


def retain(path, payload):
    """Reconciliation may reuse byte-identical evidence, never replace it."""
    if path.exists():
        if path.read_bytes() != payload: raise ValueError("Retained evidence differs: " + str(path))
    else: exclusive(path, payload)


def host_environment():
    import importlib.metadata
    return {"executable": sys.executable, "python": sys.version,
            "packages": {d.metadata["Name"]: d.version for d in sorted(importlib.metadata.distributions(), key=lambda d: d.metadata["Name"].lower())}}

def init_cell(cell, tier, scope, seed, *, steps=2):
    if tier not in TIERS or scope not in ("heads", "full_encoder") or seed not in (42, 43, 44):
        raise ValueError("Frozen tier/scope/seed required.")
    if steps == 2 and (tier, scope, seed) not in (("efficient", "heads", 42), ("efficient", "full_encoder", 42), ("quality", "full_encoder", 42)):
        raise ValueError("Only the three predeclared pilot coordinates are admitted.")
    cell = Path(cell).resolve()
    if cell.exists() and any(cell.iterdir()): raise ValueError("Refusing to reuse nonempty cell.")
    cell.mkdir(parents=True, exist_ok=True)
    initial = ROOT / "models/experiments/pretrained_v3_20261012/initials" / tier
    manifest_bytes = (initial / "manifest.json").read_bytes(); manifest = validate_manifest(parse(manifest_bytes))
    for name, key in (("model.safetensors", "blob"), ("config.json", "config"), ("vocab.txt", "vocab")):
        if digest((initial / name).read_bytes()) != manifest[key]: raise ValueError("ORIGINAL asset bytes changed.")
    policy = dict(POLICY, steps=steps, epochs=steps // 8)
    if steps == 2: policy.update(window_batches=1, epochs=2)
    validate_policy(policy, pilot=steps == 2)
    exclusive(cell / "policy.json", canonical(policy))
    binding = {"schema": 1, "tier": tier, "model_id": manifest["model_id"], "scope": scope, "seed": seed,
        "original_manifest": digest(manifest_bytes), "original_blob": manifest["blob"], "initial_directory": str(initial),
        "policy_sha256": digest(canonical(policy)), "terminal_candidate_is_scientific_endpoint_even_if_rejected": True,
        "endpoint_scoring_authorized": steps != 2}
    exclusive(cell / "cell.json", canonical(binding))
    return binding


def bind_cell(cell, image_id):
    """Pin current source bytes, environment and schedule before any dispatch."""
    import re
    if re.fullmatch("sha256:[0-9a-f]{64}", image_id) is None:
        raise ValueError("Exact Docker image ID required.")
    cell = Path(cell)
    binding = parse((cell / "cell.json").read_bytes())
    policy = parse((cell / "policy.json").read_bytes())
    _, _, source = schedule(binding["seed"], policy)
    value = {"image_id": image_id, "server_source_closure": source_identity(), "server_source_files": source_inventory(),
             "host_environment": host_environment(), "source_commitment": digest(canonical(source)),
             "train_wire_sha256": source["train_wire_sha256"], "guard_wire_sha256": source["guard_wire_sha256"]}
    retain(cell / "frozen-source.json", canonical(source))
    retain(cell / "execution-binding.json", canonical(value))
    return value


def check_binding(cell):
    value = parse((cell / "execution-binding.json").read_bytes(), 80 * 1024 * 1024)
    if value["server_source_closure"] != source_identity() or value["server_source_files"] != source_inventory():
        raise ValueError("Copied server source bytes changed since binding.")
    if value["host_environment"] != host_environment(): raise ValueError("Host environment changed since binding.")
    if digest((cell / "frozen-source.json").read_bytes()) != value["source_commitment"]:
        raise ValueError("Frozen source changed since binding.")
    return value

def compose(cell, *args):
    binding = parse((cell / "cell.json").read_bytes())
    env = dict(os.environ, V3_CELL=str(cell), V3_INITIAL=binding["initial_directory"],
               V3_INPUTS=str(ROOT / "evaluation/results/iterative_fuzzer_20261011"))
    command = ["docker", "compose", "-p", "privoke-v3-study", "-f", str(ROOT / "evaluation/compose.pretrained-v3-study.yml"), *args]
    return subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)

def health(role, timeout=60):
    port, stub_type = {"checkpoint": (50173, rpc.CheckpointServiceStub), "runtime": (50171, rpc.TrainingServiceStub), "fuzzer": (50172, rpc.V3FuzzerServiceStub)}[role]
    deadline = time.monotonic() + timeout; last = None
    with channel(f"127.0.0.1:{port}") as connection:
        stub = stub_type(connection)
        while time.monotonic() < deadline:
            try:
                result = stub.Health(pb.HealthRequest(), timeout=3)
                if result.ready and result.role == role: return {"role": result.role, "capabilities": dict(result.capabilities)}
            except Exception as error: last = error
            time.sleep(.5)
    raise RuntimeError("Server readiness failed: " + role + ": " + str(last))


def check_live_binding(cell):
    """Verify live source, policy and exact image before the fit reservation."""
    execution = check_binding(cell)
    binding = parse((cell / "cell.json").read_bytes())
    for role in ("checkpoint", "runtime", "fuzzer"):
        capabilities = health(role)["capabilities"]
        if capabilities.get("source_closure") != execution["server_source_closure"]:
            raise ValueError("Live source differs before dispatch.")
        if role == "fuzzer" and capabilities.get("policy_sha256") != binding["policy_sha256"]:
            raise ValueError("Live fuzzer policy differs before dispatch.")
        ids = compose(cell, "ps", "-q", role)
        if ids.returncode or len(ids.stdout.split()) != 1: raise ValueError("Cannot identify live v3 container.")
        result = subprocess.run(["docker", "inspect", ids.stdout.strip()], text=True, capture_output=True, check=True)
        containers = json.loads(result.stdout)
        if len(containers) != 1 or containers[0]["Image"] != execution["image_id"]:
            raise ValueError("Live image differs before dispatch.")
    return execution

def start(cell, *, output=None, roles=("checkpoint", "runtime", "fuzzer"), readiness_timeout=60):
    # Sequential server admission; raw readiness clients execute only on the host.
    cell = Path(cell); output = Path(output) if output else cell / "startup"
    output.mkdir(parents=True, exist_ok=True)
    attempt = len(list(output.glob("attempt-*"))) + 1
    output = output / f"attempt-{attempt:04d}"
    output.mkdir(exist_ok=False)
    binding = check_binding(cell)
    resolved = compose(cell, "config", "--services")
    if resolved.returncode or set(resolved.stdout.split()) != {"checkpoint", "runtime", "fuzzer"}:
        raise ValueError("Resolved v3 services differ from the dedicated stack.")
    before = compose(cell, "ps", "--all", "--format", "json")
    exclusive(output / "before-start.json", before.stdout.encode())
    if before.returncode: raise RuntimeError("Cannot inspect existing v3 services before startup.")
    results = {}
    for role in roles:
        result = compose(cell, "up", "-d", "--no-build", "--no-deps", role)
        exclusive(output / (role + ".log"), (result.stdout + result.stderr).encode())
        if result.returncode: raise RuntimeError("Compose startup failed: " + role)
        results[role] = health(role, timeout=readiness_timeout)
        if results[role]["capabilities"].get("source_closure") != binding["server_source_closure"]:
            raise ValueError("Running server source bytes differ from frozen host source.")
        ids = compose(cell, "ps", "-q", role)
        if ids.returncode or len(ids.stdout.split()) != 1: raise ValueError("Cannot establish serving container identity.")
        inspected = subprocess.run(["docker", "inspect", ids.stdout.strip()], text=True, capture_output=True, check=True)
        record = json.loads(inspected.stdout)
        if len(record) != 1 or record[0]["Image"] != binding["image_id"]:
            raise ValueError("Running service image differs from frozen exact image ID.")
        exclusive(output / (role + "-container.json"), canonical(record))
    exclusive(output / "readiness.json", canonical(results))
    return results

def assert_semantic(response, model, snapshot, manifest=None, *, allow_error=False):
    if len(response.layers) != 1 or response.layers[0].layer != 4:
        raise ValueError("Actual sole successful semantic execution required.")
    layer = response.layers[0]
    failed = bool(response.error or layer.error or layer.status != "ok")
    if failed and (not allow_error or layer.status != "error" or not (response.error or layer.error)):
        raise ValueError("Actual successful semantic execution required; error execution is inconsistent.")
    expected_fields = {"model_id": model, "model_version": snapshot, "artifact_checksum": snapshot}
    if manifest is not None:
        expected_fields.update(parameter_fingerprint=manifest["blob"], parameter_count=str(manifest["parameter_count"]),
            backbone_sha256=manifest["source"]["weights_sha256"], tokenizer_sha256=manifest["vocab"], architecture=manifest["architecture"])
    for key, expected in expected_fields.items():
        if response.metadata.get("privoke.semantic." + key) != expected: raise ValueError("Actual semantic identity mismatch: " + key)

def cycle(cell):
    cell = Path(cell)
    binding = parse((cell / "cell.json").read_bytes()); policy = parse((cell / "policy.json").read_bytes())
    execution = check_binding(cell)
    if (cell / "host-dispatch.pb").exists():
        raise ValueError("This cell has a reserved physical attempt; use reconcile without refitting.")
    check_live_binding(cell)
    request_id = "v3-" + binding["tier"] + "-" + binding["scope"] + "-" + str(binding["seed"]) + "-" + cell.name
    request = parameters_pb2.FuzzerTrainingRequest(request_id=request_id, source_id="host-v3-frozen-study",
        model_id=binding["model_id"], seed=binding["seed"], prompt_count=policy["window_batches"] * 32,
        metadata={"expected_base": binding["original_manifest"], "policy_sha256": binding["policy_sha256"],
                  "source_commitment": execution["source_commitment"]})
    exclusive(cell / "host-dispatch.pb", request.SerializeToString(deterministic=True))
    try:
        with channel("127.0.0.1:50172") as connection:
            stub = rpc.V3FuzzerServiceStub(connection)
            method = stub.RunTrainingCycle if binding["scope"] == "heads" else stub.RunUnderlyingTrainingCycle
            response = method(request, timeout=7200)
    except Exception as error:
        exclusive(cell / "dispatch-error.json", canonical({"error": type(error).__name__ + ": " + str(error), "retry_permitted": False}))
        raise RuntimeError("Fit outcome uncertain; reconcile this attempt without a replacement fit.") from error
    exclusive(cell / "host-response.pb", response.SerializeToString(deterministic=True))
    if response.metadata.get("publication_status") not in ("applied", "rejected"):
        raise ValueError("Unknown publication outcome; stop without another fit.")
    return reconcile(cell)


def reconcile(cell):
    """Only status/fetch/inference RPCs; this function never dispatches a fit."""
    cell = Path(cell); binding = parse((cell / "cell.json").read_bytes())
    execution = check_binding(cell)
    request = parameters_pb2.FuzzerTrainingRequest.FromString((cell / "host-dispatch.pb").read_bytes())
    request_id = request.request_id
    with channel("127.0.0.1:50173") as connection:
        checkpoint = rpc.CheckpointServiceStub(connection)
        receipt = checkpoint.GetCommitStatus(pb.StatusRequest(request_id=request_id), timeout=15)
        receipt_bytes = receipt.SerializeToString(deterministic=True)
        receipt_path = cell / "host-receipt.pb" if receipt.status in ("applied", "rejected") else cell / "status-observations" / "publication" / (digest(receipt_bytes) + ".pb")
        retain(receipt_path, receipt_bytes)
        if receipt.status not in ("applied", "rejected"):
            with channel("127.0.0.1:50171") as runtime_connection:
                status = rpc.TrainingServiceStub(runtime_connection).GetFitStatus(pb.StatusRequest(request_id=request_id), timeout=15)
            status_bytes = status.SerializeToString(deterministic=True)
            retain(cell / "status-observations" / "fit" / (digest(status_bytes) + ".pb"), status_bytes)
            raise RuntimeError("Publication outcome unknown; retain attempt and stop without replay. Fit status=" + status.status)
        candidate_sha = receipt.candidate
        if (receipt.request_id != request_id or receipt.model_id != binding["model_id"] or receipt.base != binding["original_manifest"]):
            raise ValueError("Terminal receipt differs from cell ORIGINAL/request.")
        manifest_bytes = fetch(checkpoint, candidate_sha); manifest = validate_manifest(parse(manifest_bytes))
        evidence_bytes = fetch(checkpoint, manifest["evidence"]); evidence = validate_execution(parse(evidence_bytes, 80 * 1024 * 1024))
        validate_source_evidence(evidence)
        if (manifest["parent"] != binding["original_manifest"] or manifest["original"] != binding["original_manifest"]
                or manifest["scope"] != binding["scope"] or manifest["model_id"] != binding["model_id"]
                or evidence["request_id"] != request_id or evidence["policy"] != parse((cell / "policy.json").read_bytes())
                or evidence["candidate_blob"] != manifest["blob"] or evidence["source_commitment"] != execution["source_commitment"]
                or evidence["capabilities"]["source_closure"] != execution["server_source_closure"]):
            raise ValueError("Terminal model/evidence/source differs from predeclared cell.")
        retain(cell / "terminal-manifest.json", manifest_bytes); retain(cell / "terminal-evidence.json", evidence_bytes)
        retain(cell / "terminal-candidate.safetensors", fetch(checkpoint, manifest["blob"]))
        published = checkpoint.ResolveCurrent(pb.Model(model_id=binding["model_id"]), timeout=15).sha256
        if published != (candidate_sha if receipt.status == "applied" else binding["original_manifest"]):
            raise ValueError("Publication pointer differs from terminal receipt.")
        retain(cell / "effective-manifest.json", fetch(checkpoint, published))
    # One actual serialized-candidate request on a TRAIN row, not an endpoint dataset.
    fit_request = pb.FitRequest.FromString((cell / "fuzzer" / digest(request_id.encode()) / "fit-request.pb").read_bytes())
    with channel("127.0.0.1:50171") as connection:
        result = runtime_pb2_grpc.PrivokeRuntimeServiceStub(connection).AnalyzePrompt(runtime_pb2.AnalyzePromptRequest(
            text=fit_request.train[0].text, semantic_model_id=binding["model_id"], layers=[4], metadata={"v3_checkpoint": candidate_sha}), timeout=120)
    assert_semantic(result, binding["model_id"], candidate_sha, manifest)
    # elapsed_ms changes across read-only reconciliation, so retain the first probe.
    if not (cell / "candidate-inference.pb").exists():
        exclusive(cell / "candidate-inference.pb", result.SerializeToString(deterministic=True))
    summary = {"request_id": request_id, "status": receipt.status, "reason": receipt.reason,
        "candidate": candidate_sha, "published": published, "encoder_changes": evidence["changes"],
        "work": evidence["counts"], "seconds": evidence["seconds"], "cuda_peak_bytes": evidence["cuda_peak_bytes"],
        "serialized_guard_parity": evidence["serialized_guard_parity"], "source_commitment": evidence["source_commitment"],
        "initial_guard_joint": evidence["base_guard"]["joint_correct"], "candidate_guard_joint": evidence["candidate_guard"]["joint_correct"],
        "action_harms": evidence["action_harms"], "scientific_endpoint": "terminal_candidate_regardless_of_publication"}
    summary.update(tier=binding["tier"], scope=binding["scope"], seed=binding["seed"],
                   image_id=execution["image_id"], server_capabilities=evidence["capabilities"],
                   policy_sha256=binding["policy_sha256"], original=binding["original_manifest"],
                   train_wire_sha256=evidence["train_wire_sha256"], guard_wire_sha256=evidence["guard_wire_sha256"])
    retain(cell / "summary.json", canonical(summary)); return summary
