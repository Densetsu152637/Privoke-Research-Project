"""Host-only controller for opt-in v3 servers; never performs physical fitting."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import time
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services/pretrained-v3/src"))
from common import pb, rpc, runtime_pb2, runtime_pb2_grpc, parameters_pb2, channel, fetch, canonical, digest
from privoke_model.v3_contract import POLICY, TIERS, parse, validate_manifest, validate_execution, validate_policy

def exclusive(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle: handle.write(payload)

def init_cell(cell, tier, scope, seed, *, steps=2):
    cell = Path(cell).resolve()
    if cell.exists() and any(cell.iterdir()): raise ValueError("Refusing to reuse nonempty cell.")
    cell.mkdir(parents=True, exist_ok=True)
    initial = ROOT / "models/experiments/pretrained_v3_20261012/initials" / tier
    manifest_bytes = (initial / "manifest.json").read_bytes(); manifest = validate_manifest(parse(manifest_bytes))
    policy = dict(POLICY, steps=steps, epochs=steps // 8)
    if steps == 2: policy.update(window_batches=1, epochs=2)
    validate_policy(policy, pilot=steps == 2)
    exclusive(cell / "policy.json", canonical(policy))
    binding = {"schema": 1, "tier": tier, "model_id": manifest["model_id"], "scope": scope, "seed": seed,
        "original_manifest": digest(manifest_bytes), "original_blob": manifest["blob"], "initial_directory": str(initial),
        "policy_sha256": digest(canonical(policy)), "terminal_candidate_is_scientific_endpoint_even_if_rejected": True,
        "endpoint_scoring_authorized": False}
    exclusive(cell / "cell.json", canonical(binding))
    return binding

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

def start(cell):
    # Sequential server admission; raw readiness clients execute only on the host.
    results = {}
    for role in ("checkpoint", "runtime", "fuzzer"):
        result = compose(cell, "up", "-d", "--no-deps", role)
        exclusive(cell / ("startup-" + role + ".log"), (result.stdout + result.stderr).encode())
        if result.returncode: raise RuntimeError("Compose startup failed: " + role)
        results[role] = health(role)
    exclusive(cell / "readiness.json", canonical(results))
    return results

def assert_semantic(response, model, snapshot):
    if response.error or len(response.layers) != 1 or response.layers[0].layer != 4 or response.layers[0].status != "ok" or response.layers[0].error:
        raise ValueError("Actual sole successful semantic execution required.")
    for key, expected in (("model_id", model), ("model_version", snapshot), ("artifact_checksum", snapshot)):
        if response.metadata.get("privoke.semantic." + key) != expected: raise ValueError("Actual semantic identity mismatch: " + key)

def cycle(cell):
    binding = parse((cell / "cell.json").read_bytes()); policy = parse((cell / "policy.json").read_bytes())
    request_id = "v3-" + binding["tier"] + "-" + binding["scope"] + "-" + str(binding["seed"]) + "-" + cell.name
    request = parameters_pb2.FuzzerTrainingRequest(request_id=request_id, source_id="host-v3-frozen-study",
        model_id=binding["model_id"], seed=binding["seed"], prompt_count=policy["window_batches"] * 32,
        metadata={"expected_base": binding["original_manifest"], "policy_sha256": binding["policy_sha256"]})
    exclusive(cell / "host-dispatch.pb", request.SerializeToString(deterministic=True))
    with channel("127.0.0.1:50172") as connection:
        stub = rpc.V3FuzzerServiceStub(connection)
        method = stub.RunTrainingCycle if binding["scope"] == "heads" else stub.RunUnderlyingTrainingCycle
        response = method(request, timeout=7200)
    exclusive(cell / "host-response.pb", response.SerializeToString(deterministic=True))
    if response.metadata.get("publication_status") not in ("applied", "rejected"):
        raise ValueError("Unknown publication outcome; stop without another fit.")
    candidate_sha = response.metadata["candidate_manifest"]
    with channel("127.0.0.1:50173") as connection:
        checkpoint = rpc.CheckpointServiceStub(connection)
        manifest_bytes = fetch(checkpoint, candidate_sha); manifest = validate_manifest(parse(manifest_bytes))
        evidence_bytes = fetch(checkpoint, manifest["evidence"]); evidence = validate_execution(parse(evidence_bytes))
        exclusive(cell / "terminal-manifest.json", manifest_bytes); exclusive(cell / "terminal-evidence.json", evidence_bytes)
        exclusive(cell / "terminal-candidate.safetensors", fetch(checkpoint, manifest["blob"]))
        published = checkpoint.ResolveCurrent(pb.Model(model_id=binding["model_id"]), timeout=15).sha256
        receipt = checkpoint.GetCommitStatus(pb.StatusRequest(request_id=request_id), timeout=15)
        exclusive(cell / "host-receipt.pb", receipt.SerializeToString(deterministic=True))
    # One actual serialized-candidate request on a TRAIN row, not an endpoint dataset.
    fit_request = pb.FitRequest.FromString((cell / "fuzzer" / digest(request_id.encode()) / "fit-request.pb").read_bytes())
    with channel("127.0.0.1:50171") as connection:
        result = runtime_pb2_grpc.PrivokeRuntimeServiceStub(connection).AnalyzePrompt(runtime_pb2.AnalyzePromptRequest(
            text=fit_request.train[0].text, semantic_model_id=binding["model_id"], layers=[4], metadata={"v3_checkpoint": candidate_sha}), timeout=120)
    assert_semantic(result, binding["model_id"], candidate_sha)
    exclusive(cell / "candidate-inference.pb", result.SerializeToString(deterministic=True))
    summary = {"request_id": request_id, "status": receipt.status, "reason": receipt.reason,
        "candidate": candidate_sha, "published": published, "encoder_changes": evidence["changes"],
        "work": evidence["counts"], "seconds": evidence["seconds"], "cuda_peak_bytes": evidence["cuda_peak_bytes"],
        "serialized_guard_parity": evidence["serialized_guard_parity"], "source_commitment": evidence["source_commitment"],
        "initial_guard_joint": evidence["base_guard"]["joint_correct"], "candidate_guard_joint": evidence["candidate_guard"]["joint_correct"],
        "action_harms": evidence["action_harms"], "scientific_endpoint": "terminal_candidate_regardless_of_publication"}
    exclusive(cell / "summary.json", canonical(summary)); return summary
