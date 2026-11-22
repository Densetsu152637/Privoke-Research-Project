"""Golden generator for the Rust V3 fuzzer service (`rust/services/v3-fuzzer`, the second half of stage 21).

The oracle is the maintained Python `services/pretrained-v3/src/fuzzer_server.py`, run in process on the host. Its two network
dependencies, the V3 runtime (`TrainingService`) and the checkpoint service (`CheckpointService`), are replaced by scripted
answers, so no stack, model or accelerator is needed. The fit request that the oracle builds (the real frozen schedule over the
committed pinned inputs) crosses the fake channel and is recorded, together with the response or abort, every file of the work
directory and the rows of the `cycles` table, so that the Rust service can be replayed against the same bytes.

Every request is semantic-only: the fit request carries `layers=[4]`, and no detector layer ever runs.

Subcommands (host Python, for example `evaluation/.venv-v1-v3-pipeline`; `--generated` or `PRIVOKE_GENERATED` names the generated
protobuf clients, that is a directory holding `privoke/v1` and `privoke/experimental`, for example
`<main checkout>/extension/client-runtime/generated`):

  synthetic   committed golden: scripted cycles over the committed fixtures of `rust/crates/privoke-curriculum`. The runtime
              evidence and the candidate manifest are synthesised, valid under `validate_execution` and `validate_manifest`, and
              contain no study data beyond the committed fixtures. Output:
              `rust/services/v3-fuzzer/tests/fixtures/v3_fuzzer_cycles_golden.json`.
  recorded    LOCAL golden, git-ignored: the retained real fits (work directories of the audience pilots and the 18 pretrained cells
              under `models/experiments`) answered from their recorded fit responses, manifests and receipts. The files hold prompt
              text, so the output is never committed. Output: `rust/services/v3-fuzzer/tests/local/recorded_cycles_golden.json`.

Usage:
  python evaluation/generate_v3_fuzzer_golden.py synthetic --generated <dir>
  python evaluation/generate_v3_fuzzer_golden.py recorded --models <main checkout>/models/experiments \n      --results <main checkout>/evaluation/results --generated <dir>
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

EVALUATION = Path(__file__).resolve().parent
ROOT = EVALUATION.parent
SERVICE_SRC = ROOT / "services" / "pretrained-v3" / "src"
FIXTURES = ROOT / "rust" / "crates" / "privoke-curriculum" / "tests" / "fixtures"
SYNTHETIC_OUTPUT = ROOT / "rust" / "services" / "v3-fuzzer" / "tests" / "fixtures" / "v3_fuzzer_cycles_golden.json"
RECORDED_OUTPUT = ROOT / "rust" / "services" / "v3-fuzzer" / "tests" / "local" / "recorded_cycles_golden.json"
AU3_RELEASE_SHA256 = "7f17f43473deb4235ed189508008576abd19cf5eba0e9912d4c4ba4c58d7c010"
BC01 = "existing_taxonomy_benign_common_frozen_stream_v1"
AU3 = "audience_common_frozen_stream_v1"
# The four pinned BC01 inputs: the repository-relative path the Python loader joins to its root, and the fixture that holds the
# same bytes (the loader refuses a file whose SHA-256 differs from its pin).
BC01_FIXTURES = {
    "evaluation/results/iterative_fuzzer_20261011/taxonomy-coverage/release/taxonomy-coverage-v1.json": "bc01/taxonomy-coverage-v1.json",
    "evaluation/results/iterative_fuzzer_20261011/train-benign-coverage/pool-authored.json": "bc01/pool-authored.json",
    "evaluation/results/iterative_fuzzer_20261011/train-benign-coverage/r1/benign-manifest.json": "bc01/benign-manifest.json",
    "evaluation/results/iterative_fuzzer_20261011/train-benign-coverage/r1/exclusion-proof.json": "bc01/exclusion-proof.json",
}
WORK_FILES = ("cycle-request.pb", "source.json", "fit-request.pb", "fit-response.pb", "evidence.json", "commit-request.pb",
              "receipt.pb", "fit-status-after-error.pb", "unknown-commit.pb")
HEALTH_SUFFIX = "/Health"


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def bootstrap(generated: Path) -> None:
    """Make the service's own modules importable the way the service imports them."""
    os.environ["V3_GENERATED"] = str(generated)
    if str(SERVICE_SRC) in sys.path:
        sys.path.remove(str(SERVICE_SRC))
    sys.path.insert(0, str(SERVICE_SRC))
    if str(EVALUATION) not in sys.path:
        sys.path.append(str(EVALUATION))
    import common  # noqa: F401,PLC0415 - puts the generated clients, shared/python and the runtime sources on sys.path


def legacy():
    import generate_fuzzer_golden  # noqa: PLC0415 - shared fake channel and context, imported after the path is set up

    return generate_fuzzer_golden


class FakeRpcError(Exception):
    """What a failed call raises; subclassed from `grpc.RpcError` when grpc is importable."""


def rpc_error_class():
    import grpc  # noqa: PLC0415

    class _Error(grpc.RpcError, FakeRpcError):
        def code(self):
            return grpc.StatusCode.UNAVAILABLE

        def details(self):
            return "scripted failure"

    return _Error


def make_channel(handlers, log):
    base = legacy().FakeChannel

    class Channel(base):
        def unary_stream(self, path, *args, **kwargs):
            return self.unary_unary(path, *args, **kwargs)

        def stream_unary(self, path, *args, **kwargs):
            def call(iterator, timeout=None, metadata=None):
                raise NotImplementedError("StageCheckpoint is not part of the fuzzer cycle")

            return call

    return Channel(handlers, log)


def frozen_policy(steps: int) -> dict:
    from privoke_model.v3_contract import POLICY  # noqa: PLC0415

    policy = dict(POLICY, steps=steps, epochs=steps // 8)
    if steps == 2:
        policy.update(window_batches=1, epochs=2)
    return policy


def prepare_input_root(scratch: Path) -> Path:
    """A tree with the pinned BC01 inputs at the repository-relative paths the Python loader joins to its root."""
    root = scratch / "inputs"
    for relative, fixture in BC01_FIXTURES.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(FIXTURES / fixture, target)
    return root


def source_hashes(sampler: str) -> dict:
    """The `source_hashes` member that the live Python files give (the Rust service is configured with the same digests)."""
    names = {
        BC01: ("services/pretrained-v3/src/fuzzer_training.py", "services/privoke-fuzzer/src/prompt_generation/taxonomy_coverage.py",
               "services/privoke-fuzzer/src/prompt_generation/benign_coverage.py", "services/privoke-fuzzer/src/training/transforms.py"),
        AU3: ("services/pretrained-v3/src/audience_schedule.py", "services/privoke-fuzzer/src/prompt_generation/audience_coverage.py",
              "services/privoke-fuzzer/src/training/transforms.py"),
    }[sampler]
    return {name: sha((ROOT / name).read_bytes()) for name in names}


# ---------------------------------------------------------------------------------------------------------------------------
# Synthetic runtime evidence and checkpoint manifests, valid under the Python contract.
# ---------------------------------------------------------------------------------------------------------------------------


class Synthesis:
    """Builds the evidence, manifest and receipts that a real runtime and checkpoint service would return."""

    def __init__(self, contract, canonical, digest, classification, production):
        self.contract = contract
        self.canonical = canonical
        self.digest = digest
        self.classification = classification
        self.production = production

    def action(self, packed: int, confidence: float) -> str:
        result = self.production.ClassificationResult(self.classification.Classification(packed), "guard", "guard validation", confidence=confidence)
        return result.action().name

    def guard(self, targets, predictions, confidences) -> dict:
        actions = self.classification.PriVokeAction
        rows = []
        for target, prediction, confidence in zip(targets, predictions, confidences):
            action, target_action = self.action(prediction, confidence), self.action(target, 0.999)
            rows.append({"target": target, "prediction": prediction, "action": action, "action_value": actions[action].value,
                         "target_action": target_action, "target_action_value": actions[target_action].value, "confidence": confidence,
                         "joint_correct": target == prediction and action == target_action})
        return {"examples": len(rows), "rows": rows, "joint_correct": sum(row["joint_correct"] for row in rows),
                "action_correct": sum(row["action"] == row["target_action"] for row in rows)}

    def evidence(self, fit_request, source: dict, tier: str, quality: str) -> dict:
        contract = self.contract
        policy = json.loads(fit_request.policy_json)
        spec = contract.TIERS[tier]
        full = fit_request.scope == 2
        layers = spec["num_hidden_layers"]
        steps, rows, micro = policy["steps"], policy["batch_rows"], policy["microbatch"]
        microbatches = steps * rows // micro
        targets = [row["packed_target"] for row in source["guard_sidecar"]]
        others = [targets[(index + 5) % len(targets)] for index in range(len(targets))]
        right, wrong = list(targets), [others[i] if i % 2 == 0 else targets[i] for i in range(len(targets))]
        if quality == "improves":
            base_predictions, candidate_predictions = [others[i] if i % 3 == 0 else targets[i] for i in range(len(targets))], right
        else:  # "regresses": the candidate loses rows that the base had right
            base_predictions, candidate_predictions = right, wrong
        confidence = [0.9] * len(targets)
        base_guard = self.guard(targets, base_predictions, confidence)
        candidate_guard = self.guard(targets, candidate_predictions, confidence)
        harms = sum(any(max(0, d * (b["action_value"] - b["target_action_value"])) > max(0, d * (a["action_value"] - a["target_action_value"]))
                        for d in (-1, 1)) for a, b in zip(base_guard["rows"], candidate_guard["rows"]))
        counts = {"optimizer_steps": steps, "train_rows": steps * rows, "microbatch_forward": microbatches,
                  "microbatch_backward": microbatches, "encoder_block_forward": microbatches * layers,
                  "encoder_block_backward": microbatches * layers if full else 0}
        evidence = {
            "schema": 1, "model_id": "privoke-v3-" + tier, "tier": tier, "request_id": fit_request.request_id, "base": fit_request.base,
            "scope": "full_encoder" if full else "heads", "layers": [4], "source_commitment": fit_request.source_commitment,
            "policy": policy, "train_wire_sha256": source["train_wire_sha256"], "guard_wire_sha256": source["guard_wire_sha256"],
            "phases": {"training": {"layer": 4, "status": "ok", "examples": steps * rows},
                       "base_heldout": {"layer": 4, "status": "ok", "examples": policy["guard_rows"]},
                       "candidate_heldout": {"layer": 4, "status": "ok", "examples": policy["guard_rows"]}},
            "base_guard": base_guard, "candidate_guard": candidate_guard, "action_harms": harms,
            "changes": {"heads": 6, "encoder": 39 if full else 0, "embeddings": 5 if full else 0, "first_block": 16 if full else 0,
                        "last_block": 16 if full else 0, "pooler": 2 if full else 0, "blocks": [16 if full else 0] * layers},
            "changed_tensors": [], "counts": counts,
            "block_counts": {"forward": [microbatches] * layers, "backward": [microbatches if full else 0] * layers},
            "losses": [round(1.0 / (step + 1), 6) for step in range(steps)],
            "gradient_trace": [{"step": step + 1, "norm_before_clip": 0.5 + step / 100, "encoder_nonzero_gradients": 3 if full and step else 0}
                               for step in range(steps)],
            "parameter_count": spec["parameters"], "trainable_count": spec["parameters"] if full else 20 * (spec["hidden_size"] + 1),
            "device": "cpu", "torch": "synthetic-oracle", "seconds": 0.5, "cuda_peak_bytes": 0,
            "candidate_blob": self.digest(("synthetic candidate " + fit_request.request_id + str(fit_request.scope)).encode()),
            "serialized_guard_parity": True,
        }
        return self.contract.validate_execution(evidence)

    def manifest(self, tier: str, scope: str, base: str, blob: str, evidence_sha: str) -> dict:
        contract = self.contract
        spec = contract.TIERS[tier]
        weights, config = contract.SOURCE_PINS[tier]
        return {"schema": 1, "architecture": contract.ARCHITECTURE, "model_id": "privoke-v3-" + tier, "tier": tier, "parent": base,
                "original": self.digest(b"synthetic original " + tier.encode()), "blob": blob, "config": config, "vocab": contract.VOCAB_SHA256,
                "source": {"repository": spec["repository"], "revision": spec["revision"], "weights_sha256": weights,
                           "config_sha256": config, "vocab_sha256": contract.VOCAB_SHA256},
                "tensors": {"encoder.synthetic.weight": {"shape": [spec["parameters"]], "dtype": "F32", "sha256": self.digest(b"synthetic tensor")}},
                "parameter_count": spec["parameters"], "scope": scope, "evidence": evidence_sha}


# ---------------------------------------------------------------------------------------------------------------------------
# The sequence runner.
# ---------------------------------------------------------------------------------------------------------------------------


def snapshot_work(state: Path, request_id: str, digest) -> dict:
    directory = state / digest(request_id.encode())
    if not directory.is_dir():
        return {"work_dir": None, "files": {}}
    files = {path.name: [sha(path.read_bytes()), path.stat().st_size] for path in sorted(directory.iterdir())}
    return {"work_dir": directory.name, "files": files}


def snapshot_rows(state: Path) -> list:
    connection = sqlite3.connect(state / "cycles.sqlite")
    try:
        return [[identity, fingerprint, None if response is None else b64(bytes(response))]
                for identity, fingerprint, response in connection.execute("SELECT id,fingerprint,response FROM cycles ORDER BY id")]
    finally:
        connection.close()


def run_sequence(label: str, *, generated: Path, sampler: str, policy: dict, cycles: list, answerers, source_override=None,
                 closure: str = "synthetic-closure") -> dict:
    """Run `cycles` against one fresh state directory.

    `cycles` are dictionaries with `request` (a protobuf request) and `scope`; `answerers(state)` returns the scripted runtime and
    checkpoint handlers for one cycle (it is called with the cycle and the service's wire log) and a function that reports what
    they answered.
    """
    bootstrap(generated)
    import fuzzer_server  # noqa: PLC0415
    import fuzzer_training  # noqa: PLC0415
    from common import canonical, digest, parameters_pb2, pb  # noqa: PLC0415

    results = []
    saved_environment = dict(os.environ)
    saved = (fuzzer_server.channel, fuzzer_server.source_identity, fuzzer_server.schedule)
    with tempfile.TemporaryDirectory() as scratch:
        scratch_path = Path(scratch)
        state = scratch_path / "state"
        input_root = prepare_input_root(scratch_path)
        real_schedule = fuzzer_training.schedule

        def schedule(seed, policy, input_root=input_root, *, sampler=None):
            training, guard, source = real_schedule(seed, policy, input_root, sampler=sampler)
            if source_override is not None:
                source["source_hashes"] = dict(source_override)
            return training, guard, source

        log = []
        current = {}
        service = None
        handlers = answerers(current)
        try:
            os.environ["V3_SAMPLING_STRATEGY"] = sampler
            if sampler == AU3:
                # The committed fixture holds the release byte for byte (a Windows checkout converts the bundled copy's line ends).
                os.environ["V3_AUDIENCE_MANIFEST_PATH"] = str(FIXTURES / "au3" / "audience-v3-manifest-v1.json")
                os.environ["V3_AUDIENCE_MANIFEST_SHA256"] = AU3_RELEASE_SHA256
            fuzzer_server.channel = lambda target: make_channel(handlers, log)
            fuzzer_server.source_identity = lambda: closure
            fuzzer_server.schedule = schedule
            service = fuzzer_server.FuzzerServer("runtime:50171", "checkpoint:50170", state, policy)
            health = service.Health(pb.HealthRequest(), legacy().Context())
            for cycle in cycles:
                request = cycle["request"](schedule, canonical, digest, parameters_pb2) if callable(cycle["request"]) else cycle["request"]
                current.clear()
                current.update(cycle.get("script", {}))
                current["request"] = request
                current["trace"] = {}
                start = len(log)
                method = service.RunUnderlyingTrainingCycle if cycle["scope"] == "full_encoder" else service.RunTrainingCycle
                try:
                    response = method(request, legacy().Context())
                    outcome = {"ok": b64(response.SerializeToString(deterministic=True))}
                except legacy().Aborted as exc:
                    outcome = {"abort": [exc.code.name, exc.message]}
                except Exception as exc:  # noqa: BLE001 - the servicer does not catch these; grpc would report UNKNOWN
                    outcome = {"error": [type(exc).__name__, str(exc)]}
                wire = [[path, sha(raw), len(raw)] for path, raw in log[start:]]
                entry = {"scope": cycle["scope"], "request": b64(request.SerializeToString(deterministic=True)), "label": cycle["label"],
                         "wire": wire, "outcome": outcome, "answers": dict(current["trace"]),
                         **snapshot_work(state, request.request_id, digest)}
                if "after" in cycle:
                    entry["recorded"] = cycle["after"](state, outcome)
                results.append(entry)
            rows = snapshot_rows(state)
        finally:
            if service is not None:
                service.db.close()
            fuzzer_server.channel, fuzzer_server.source_identity, fuzzer_server.schedule = saved
            os.environ.clear()
            os.environ.update(saved_environment)
    return {"label": label, "sampler": sampler, "policy_json": b64(canonical(policy)), "source_hashes": source_hashes(sampler) if source_override is None else source_override,
            "source_closure": closure, "health": b64(health.SerializeToString(deterministic=True)), "cycles": results, "sqlite": rows}


# ---------------------------------------------------------------------------------------------------------------------------
# Synthetic sequences.
# ---------------------------------------------------------------------------------------------------------------------------


def synthetic_answerers(generated: Path, tier: str, base: str):
    """The scripted runtime and checkpoint service of a synthetic sequence."""
    bootstrap(generated)
    from common import canonical, chunks, digest, pb  # noqa: PLC0415
    from privoke_contracts import classification  # noqa: PLC0415
    from privoke_model import v3_contract as contract  # noqa: PLC0415
    from src import classification as production  # noqa: PLC0415

    synthesis = Synthesis(contract, canonical, digest, classification, production)
    error = rpc_error_class()
    catalog = {}

    def receipt(request_id, model_id, status, candidate, reason, base_sha):
        return pb.Receipt(status=status, request_id=request_id, model_id=model_id, base=base_sha, candidate=candidate, reason=reason)

    def make(current):
        trace = lambda: current["trace"]  # noqa: E731

        def resolve(request):
            sha_value = current.get("resolve", base)
            trace()["resolve"] = sha_value
            return pb.Ref(sha256=sha_value)

        def fit(request):
            trace()["fit_layers"] = list(request.layers)
            script = current.get("fit", "ok")
            if script == "rpc-error":
                trace()["fit"] = {"error": True}
                raise error()
            source = json.loads(request.source_json)
            evidence = synthesis.evidence(request, source, tier, current.get("quality", "improves"))
            if script == "tamper-base":
                evidence = dict(evidence, base=digest(b"another base"))
            evidence_json = canonical(evidence)
            evidence_sha = digest(evidence_json)
            manifest_evidence = evidence_sha if current.get("manifest", "ok") == "ok" else digest(b"another evidence")
            manifest = canonical(synthesis.manifest(tier, evidence["scope"], request.base, evidence["candidate_blob"], manifest_evidence))
            candidate = digest(manifest)
            catalog[candidate] = manifest
            response = pb.FitResponse(candidate=candidate, evidence=evidence_sha, evidence_json=evidence_json)
            trace()["fit"] = {"response": b64(response.SerializeToString(deterministic=True))}
            return response

        def fit_status(request):
            answer = receipt(request.request_id, "", current.get("fit_status", "running"), "", "", "")
            trace()["fit_status"] = b64(answer.SerializeToString(deterministic=True))
            return answer

        def fetch(request):
            payload = catalog[request.sha256]
            trace()["fetch"] = b64(payload)
            return list(chunks(payload))

        def commit(request):
            script = current.get("commit", "applied")
            if script in ("rpc-error-applied", "rpc-error-unknown"):
                trace()["commit"] = {"error": True}
                raise error()
            status = "rejected" if script == "rejected" else "applied"
            candidate = digest(b"another candidate") if script == "mismatch" else request.candidate
            answer = receipt(request.request_id, request.model_id, status, candidate, "guard_rejected" if status == "rejected" else "guard_passed", request.expected_base)
            trace()["commit"] = {"receipt": b64(answer.SerializeToString(deterministic=True))}
            return answer

        def commit_status(request):
            known = current["trace"]["fit"]["response"] if "response" in current["trace"].get("fit", {}) else None
            candidate = pb.FitResponse.FromString(base64.b64decode(known)).candidate if known else ""
            status = "unknown" if current.get("commit") == "rpc-error-unknown" else "applied"
            answer = receipt(request.request_id, current["request"].model_id, status, candidate, "" if status == "unknown" else "guard_passed", current["request"].metadata.get("expected_base", ""))
            trace()["commit_status"] = b64(answer.SerializeToString(deterministic=True))
            return answer

        health = lambda request: pb.HealthResponse(ready=True, role="stub")  # noqa: E731
        return {
            "/privoke.experimental.v3.CheckpointService/ResolveCurrent": resolve,
            "/privoke.experimental.v3.TrainingService/FitCandidate": fit,
            "/privoke.experimental.v3.TrainingService/GetFitStatus": fit_status,
            "/privoke.experimental.v3.CheckpointService/FetchBlob": fetch,
            "/privoke.experimental.v3.CheckpointService/CommitCandidate": commit,
            "/privoke.experimental.v3.CheckpointService/GetCommitStatus": commit_status,
            "/privoke.experimental.v3.TrainingService/Health": health,
            "/privoke.experimental.v3.CheckpointService/Health": health,
        }

    return make


def request_builder(*, request_id: str, tier: str, seed: int, base: str, prompt_count: int, policy: dict, sampler: str,
                    expected_base=None, policy_sha=None, commit_source=True):
    """A function that builds the host's request: it commits to the policy and to the source that the schedule yields."""

    def build(schedule, canonical, digest, parameters_pb2):
        metadata = {"expected_base": base if expected_base is None else expected_base,
                    "policy_sha256": digest(canonical(policy)) if policy_sha is None else policy_sha}
        if commit_source:
            _, _, source = schedule(seed, policy, sampler=sampler)
            metadata["source_commitment"] = digest(canonical(source))
        else:
            metadata["source_commitment"] = digest(b"no such source")
        return parameters_pb2.FuzzerTrainingRequest(request_id=request_id, source_id="privoke-updater", model_id="privoke-v3-" + tier,
                                                    prompt_count=prompt_count, seed=seed, metadata=metadata)

    return build


def sequence_bc01_pilot(generated: Path) -> dict:
    policy = frozen_policy(2)
    tier, base = "efficient", sha(b"synthetic base efficient")

    def req(request_id, seed, **kwargs):
        return request_builder(request_id=request_id, tier=tier, seed=seed, base=base, prompt_count=32, policy=policy, sampler=BC01, **kwargs)

    first = req("v3-synth-heads-1", 42)
    cycles = [
        {"label": "heads applied", "scope": "heads", "request": first, "script": {"quality": "improves", "commit": "applied"}},
        {"label": "the same identity answers from its row", "scope": "heads", "request": first},
        {"label": "the same identity in the other scope is refused", "scope": "full_encoder", "request": first},
        {"label": "full encoder rejected by the guard", "scope": "full_encoder", "request": req("v3-synth-full-1", 43),
         "script": {"quality": "regresses", "commit": "rejected"}},
        {"label": "a budget that is not the frozen one", "scope": "heads", "request": request_builder(
            request_id="v3-synth-budget", tier=tier, seed=44, base=base, prompt_count=31, policy=policy, sampler=BC01)},
        {"label": "an expected base that is not current", "scope": "heads", "request": req("v3-synth-base", 45, expected_base=sha(b"stale base"))},
        {"label": "an identity whose outcome is unknown is never replayed", "scope": "heads", "request": req("v3-synth-base", 45, expected_base=sha(b"stale base"))},
        {"label": "a policy commitment that differs", "scope": "heads", "request": req("v3-synth-policy", 46, policy_sha=sha(b"other policy"))},
        {"label": "a source commitment that differs", "scope": "heads", "request": req("v3-synth-source", 47, commit_source=False)},
        {"label": "a fit whose response is lost", "scope": "heads", "request": req("v3-synth-lost", 48), "script": {"fit": "rpc-error", "fit_status": "running"}},
        {"label": "evidence for another base", "scope": "heads", "request": req("v3-synth-evidence", 49), "script": {"fit": "tamper-base"}},
        {"label": "a candidate whose manifest differs", "scope": "heads", "request": req("v3-synth-manifest", 50), "script": {"manifest": "wrong-evidence"}},
        {"label": "a commit whose acknowledgement is lost but applied", "scope": "heads", "request": req("v3-synth-commit-lost", 51), "script": {"commit": "rpc-error-applied"}},
        {"label": "a commit whose outcome is unknown", "scope": "full_encoder", "request": req("v3-synth-commit-unknown", 52), "script": {"commit": "rpc-error-unknown"}},
        {"label": "a receipt for another candidate", "scope": "heads", "request": req("v3-synth-receipt", 53), "script": {"commit": "mismatch"}},
    ]
    return run_sequence("synthetic-bc01-pilot", generated=generated, sampler=BC01, policy=policy, cycles=cycles,
                        answerers=synthetic_answerers(generated, tier, base))


def sequence_au3_pilot(generated: Path) -> dict:
    policy = frozen_policy(2)
    tier, base = "efficient", sha(b"synthetic base au3")

    def req(request_id, seed, **kwargs):
        return request_builder(request_id=request_id, tier=tier, seed=seed, base=base, prompt_count=32, policy=policy, sampler=AU3, **kwargs)

    first = req("v3-synth-au3-heads", 42)
    cycles = [
        {"label": "AU3 heads applied", "scope": "heads", "request": first, "script": {"quality": "improves", "commit": "applied"}},
        {"label": "AU3 full encoder rejected", "scope": "full_encoder", "request": req("v3-synth-au3-full", 43), "script": {"quality": "regresses", "commit": "rejected"}},
        {"label": "AU3 replay", "scope": "heads", "request": first},
    ]
    return run_sequence("synthetic-au3-pilot", generated=generated, sampler=AU3, policy=policy, cycles=cycles,
                        answerers=synthetic_answerers(generated, tier, base))


def sequence_bc01_window(generated: Path) -> dict:
    policy = frozen_policy(64)
    tier, base = "balanced", sha(b"synthetic base balanced")
    request = request_builder(request_id="v3-synth-window-heads", tier=tier, seed=44, base=base, prompt_count=256, policy=policy, sampler=BC01)
    cycles = [{"label": "an eight batch window", "scope": "heads", "request": request, "script": {"quality": "improves", "commit": "applied"}}]
    return run_sequence("synthetic-bc01-window", generated=generated, sampler=BC01, policy=policy, cycles=cycles,
                        answerers=synthetic_answerers(generated, tier, base))


def synthetic_golden(generated: Path) -> dict:
    bootstrap(generated)
    sequences = [sequence_bc01_pilot(generated), sequence_au3_pilot(generated), sequence_bc01_window(generated)]
    return document("synthetic", sequences)


# ---------------------------------------------------------------------------------------------------------------------------
# Recorded sequences.
# ---------------------------------------------------------------------------------------------------------------------------


def recorded_cells(models: Path):
    """Every retained fit with its work directory: (label, cell directory, work directory, recorded response, source closure)."""
    roots = [("pretrained-cell", models / "pretrained_v3_20261012" / "cells"), ("pretrained-pilot", models / "pretrained_v3_20261012" / "pilots"),
             ("audience-pilot", models / "audience_v3_20261013" / "pilots")]
    for kind, root in roots:
        if not root.is_dir():
            continue
        for cell in sorted(root.iterdir()):
            fuzzer = cell / "fuzzer"
            if not fuzzer.is_dir():
                continue
            works = [path for path in sorted(fuzzer.iterdir()) if (path / "receipt.pb").is_file()]
            if len(works) == 1:
                yield f"{kind}/{cell.name}", cell, works[0]


def recorded_sequence(generated: Path, label: str, cell: Path, work: Path, results: Path | None = None) -> dict | None:
    bootstrap(generated)
    from common import pb, parameters_pb2  # noqa: PLC0415

    request = parameters_pb2.FuzzerTrainingRequest.FromString((work / "cycle-request.pb").read_bytes())
    fit_request = pb.FitRequest.FromString((work / "fit-request.pb").read_bytes())
    fit_response = pb.FitResponse.FromString((work / "fit-response.pb").read_bytes())
    receipt = pb.Receipt.FromString((work / "receipt.pb").read_bytes())
    recorded_source = json.loads((work / "source.json").read_bytes())
    sampler = recorded_source["sampler"]
    blob = cell / "checkpoint" / "blobs" / fit_response.candidate
    if not blob.is_file():
        return None
    manifest = blob.read_bytes()
    policy = json.loads(fit_request.policy_json)
    scope = "full_encoder" if fit_request.scope == 2 else "heads"
    base = request.metadata["expected_base"]

    def answerers(generated_current):
        from common import chunks  # noqa: PLC0415

        def trace(current, key, value):
            current["trace"][key] = value

        def resolve(_request):
            trace(generated_current, "resolve", base)
            return pb.Ref(sha256=base)

        def fit(request):
            trace(generated_current, "fit_layers", list(request.layers))
            trace(generated_current, "fit", {"response": b64(fit_response.SerializeToString(deterministic=True))})
            return fit_response

        def fetch(_request):
            trace(generated_current, "fetch", b64(manifest))
            return list(chunks(manifest))

        def commit(_request):
            trace(generated_current, "commit", {"receipt": b64(receipt.SerializeToString(deterministic=True))})
            return receipt

        health = lambda _request: pb.HealthResponse(ready=True, role="stub")  # noqa: E731
        return {
            "/privoke.experimental.v3.CheckpointService/ResolveCurrent": resolve,
            "/privoke.experimental.v3.TrainingService/FitCandidate": fit,
            "/privoke.experimental.v3.CheckpointService/FetchBlob": fetch,
            "/privoke.experimental.v3.CheckpointService/CommitCandidate": commit,
            "/privoke.experimental.v3.TrainingService/Health": health,
            "/privoke.experimental.v3.CheckpointService/Health": health,
        }

    recorded_names = ("cycle-request.pb", "source.json", "fit-request.pb", "fit-response.pb", "evidence.json", "commit-request.pb", "receipt.pb")
    host_response = cell / "host-response.pb"
    if not host_response.is_file() and results is not None:
        # The audience pilots kept the host's response with their controller records, not with the cell.
        found = sorted((results / "audience_v3_20261013" / "pilots").glob(f"*/{cell.name}-response.pb"))
        host_response = found[0] if found else host_response

    def after(state, outcome):
        """Whether the oracle's own output is byte-identical to what the retained run wrote."""
        written = state / sha(request.request_id.encode())
        report = {name: (written / name).is_file() and sha((written / name).read_bytes()) == sha((work / name).read_bytes())
                  for name in recorded_names}
        report["response"] = host_response.is_file() and outcome.get("ok") == b64(host_response.read_bytes())
        return report

    cycles = [{"label": label, "scope": scope, "request": request, "after": after}]
    return run_sequence("recorded:" + label, generated=generated, sampler=sampler, policy=policy, cycles=cycles, answerers=answerers,
                        source_override=recorded_source["source_hashes"], closure="recorded-closure")


def recorded_golden(generated: Path, models: Path, results: Path | None = None) -> dict:
    bootstrap(generated)
    sequences = []
    skipped = []
    for label, cell, work in recorded_cells(models):
        sequence = recorded_sequence(generated, label, cell, work, results)
        if sequence is None:
            skipped.append(label)
        else:
            sequences.append(sequence)
    result = document("recorded", sequences)
    result["skipped"] = skipped
    return result


def document(kind: str, sequences: list) -> dict:
    return {"schema": 1, "kind": kind, "oracle": "services/pretrained-v3/src/fuzzer_server.py", "python": sys.version.split()[0],
            "normalisation": "tests/conformance/normalization.toml: no timestamp or generated identifier appears in these records",
            "sequences": sequences}


def summary(golden: dict) -> dict:
    kinds = {"ok": 0, "abort": 0, "error": 0}
    cycles = 0
    for sequence in golden["sequences"]:
        for cycle in sequence["cycles"]:
            cycles += 1
            kinds[next(iter(cycle["outcome"]))] += 1
    return {"kind": golden["kind"], "sequences": len(golden["sequences"]), "cycles": cycles, **kinds,
            "sqlite_rows": sum(len(sequence["sqlite"]) for sequence in golden["sequences"])}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("synthetic", "recorded"))
    parser.add_argument("--generated", type=Path, default=os.environ.get("PRIVOKE_GENERATED"),
                        help="directory with the generated protobuf clients (privoke/v1 and privoke/experimental)")
    parser.add_argument("--models", type=Path, help="models/experiments of a checkout holding the retained V3 fits (recorded)")
    parser.add_argument("--results", type=Path, help="evaluation/results of the same checkout (the audience pilots' recorded responses; optional)")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.generated is None:
        parser.error("--generated or PRIVOKE_GENERATED is required")
    generated = Path(args.generated)
    if args.command == "synthetic":
        golden, output = synthetic_golden(generated), args.output or SYNTHETIC_OUTPUT
    else:
        if args.models is None:
            parser.error("--models is required for recorded")
        golden, output = recorded_golden(generated, args.models, args.results), args.output or RECORDED_OUTPUT
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(golden, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    report = summary(golden)
    if golden["kind"] == "recorded":
        matches = [cycle["recorded"] for sequence in golden["sequences"] for cycle in sequence["cycles"] if "recorded" in cycle]
        report["python_equals_recorded_files"] = sum(all(item.values()) for item in matches)
        report["skipped"] = golden["skipped"]
    print(json.dumps({**report, "output": str(output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
