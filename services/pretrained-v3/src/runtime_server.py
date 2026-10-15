"""Isolated v3 semantic inference and physical training server."""
from __future__ import annotations
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import common
from common import pb, rpc, runtime_pb2, runtime_pb2_grpc, channel, fetch, chunks, canonical, digest, OPTIONS
import grpc
import torch
from privoke_model.v3_contract import parse, validate_manifest, validate_policy, check_sha
from src.v3.model import PretrainedV3
from src.v3.training import fit, assess
from src.classification import Visibility, PriVokeAction
from src.hosting.serialization import classification_for_response, _masked_text
from fuzzer_training import validate_schedule

def classification(value):
    return runtime_pb2.RuntimeClassification(**value.to_dict(), packed=value.pack())

def detection(result):
    span = result.span or (0, 0)
    return runtime_pb2.RuntimeDetectionResult(classification=classification(result.classification), action=result.action().name,
        section_of_text=result.section_of_text, span_start=span[0], span_end=span[1], has_span=result.span is not None,
        confidence=result.confidence or 0, has_confidence=result.confidence is not None, reasoning=result.reasoning,
        metadata={k: str(v) for k, v in result.metadata.items()})

def preflight(device):
    import importlib.metadata as metadata
    required = {"transformers": "4.57.6", "numpy": "1.26.4", "grpcio": "1.82.1", "protobuf": "7.35.1", "tokenizers": "0.22.2", "safetensors": "0.8.0", "python-dotenv": "1.2.4"}
    versions = {key: metadata.version(key) for key in required}
    if versions != required or torch.__version__.split("+")[0] != "2.11.0": raise ValueError("V3 dependency versions differ from admitted environment.")
    torch.set_num_threads(int(os.getenv("V3_TORCH_THREADS", "4")))
    torch.use_deterministic_algorithms(True)
    torch.backends.cuda.matmul.allow_tf32 = False
    versions.update(torch=torch.__version__, device=device, threads=str(torch.get_num_threads()))
    versions["source_closure"] = common.source_identity()
    if device.startswith("cuda"):
        if not torch.cuda.is_available() or torch.cuda.get_device_capability() != (12, 0) or "sm_120" not in torch.cuda.get_arch_list():
            raise ValueError("Expected admitted CUDA sm_120 capability.")
        versions.update(cuda=str(torch.version.cuda), gpu=torch.cuda.get_device_name(), arch=",".join(torch.cuda.get_arch_list()))
    probe = torch.ones(2, device=device, requires_grad=True)
    probe.square().sum().backward()
    if not torch.equal(probe.grad, torch.full_like(probe, 2)): raise ValueError("Device autograd readiness failed.")
    return versions

class RuntimeServer(rpc.TrainingServiceServicer, runtime_pb2_grpc.PrivokeRuntimeServiceServicer):
    def __init__(self, checkpoint_target, directory, device="cpu"):
        self.capabilities = preflight(device)
        self.device = device; self.directory = Path(directory); self.directory.mkdir(parents=True, exist_ok=True)
        self.stub_channel = channel(checkpoint_target); self.stub = rpc.CheckpointServiceStub(self.stub_channel)
        if not self.stub.Health(pb.HealthRequest(), timeout=10).ready: raise ValueError("Checkpoint server not ready.")
        self.lock = threading.RLock(); self.cache = {}
        self.db = sqlite3.connect(self.directory / "fits.sqlite", isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS fits(id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,status TEXT NOT NULL,candidate TEXT NOT NULL,reason TEXT NOT NULL)")

    def materialize(self, sha):
        check_sha(sha); path = self.directory / "assets" / sha; path.parent.mkdir(exist_ok=True)
        if not path.exists():
            payload = fetch(self.stub, sha)
            with path.open("xb") as handle: handle.write(payload)
        if digest(path.read_bytes()) != sha: raise ValueError("Runtime cached asset bytes corrupted.")
        return path

    def load(self, sha):
        manifest = validate_manifest(parse(fetch(self.stub, sha)))
        model = PretrainedV3.load(manifest, self.materialize(manifest["blob"]), self.materialize(manifest["config"]), self.materialize(manifest["vocab"]), device=self.device)
        return manifest, model

    def AnalyzePrompt(self, request, context):
        if list(request.layers) != [4] or not request.semantic_model_id or request.HasField("semantic_presence_gate"):
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "V3 inference requires explicit sole semantic layer/model and no presence gate.")
        start, identity = time.monotonic(), {}
        try:
            with self.lock:
                sha = request.metadata.get("v3_checkpoint") or self.stub.ResolveCurrent(pb.Model(model_id=request.semantic_model_id), timeout=10).sha256
                if sha not in self.cache:
                    self.cache.clear(); self.cache[sha] = self.load(sha)
                manifest, model = self.cache[sha]
                if manifest["model_id"] != request.semantic_model_id: raise ValueError("Snapshot belongs to another model.")
                identity = {"model_id": manifest["model_id"], "model_version": sha, "artifact_checksum": sha,
                    "parameter_fingerprint": manifest["blob"], "parameter_count": str(manifest["parameter_count"]),
                    "backbone_sha256": manifest["source"]["weights_sha256"], "tokenizer_sha256": manifest["vocab"], "architecture": manifest["architecture"]}
                findings = model.findings(request.text, identity)
            result = findings[0] if findings else None
            action = result.action() if result else PriVokeAction.ALLOW
            clean = classification_for_response(Visibility[request.visibility_hint] if request.visibility_hint else None)
            return runtime_pb2.AnalyzePromptResponse(request_id=request.request_id, action=action.name, allowed=action != PriVokeAction.BLOCK,
                masked_text=_masked_text(request.text, result, action) or "", classification=classification(result.classification if result else clean),
                reason=result.reasoning if result else "No privacy risk detected.", evidence=detection(result) if result else None,
                metadata={"privoke.semantic." + k: v for k, v in identity.items()},
                layers=[runtime_pb2.RuntimeLayerExecution(layer=4, status="ok", results=[detection(r) for r in findings])],
                elapsed_ms=(time.monotonic() - start) * 1000)
        except Exception as error:
            return runtime_pb2.AnalyzePromptResponse(request_id=request.request_id, action="BLOCK", allowed=False,
                classification=classification(classification_for_response(None)), error=type(error).__name__ + ": " + str(error),
                metadata={"privoke.semantic." + k: v for k, v in identity.items()},
                layers=[runtime_pb2.RuntimeLayerExecution(layer=4, status="error", error=str(error))], elapsed_ms=(time.monotonic() - start) * 1000)

    def FitCandidate(self, request, context):
        if list(request.layers) != [4] or request.scope not in (pb.HEADS, pb.FULL_ENCODER) or not request.request_id or len(request.request_id) > 200:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Explicit bounded fit identity/scope and semantic-only selection required.")
        policy = parse(bytes(request.policy_json)); validate_policy(policy, pilot=policy.get("steps") == 2)
        check_sha(request.base); check_sha(request.source_commitment)
        source = parse(bytes(request.source_json), 80 * 1024 * 1024)
        if digest(bytes(request.source_json)) != request.source_commitment:
            raise ValueError("Fit source commitment differs from supplied canonical bytes.")
        validate_schedule(list(request.train), list(request.guard), source, policy)
        fingerprint = digest(request.SerializeToString(deterministic=True))
        with self.lock:
            prior = self.db.execute("SELECT fingerprint,status FROM fits WHERE id=?", (request.request_id,)).fetchone()
            if prior: context.abort(grpc.StatusCode.ALREADY_EXISTS, "Fit previously attempted; query status without physical replay.")
            self.db.execute("INSERT INTO fits VALUES (?,?, 'started','','')", (request.request_id, fingerprint))
            work = self.directory / "attempts" / digest(request.request_id.encode()); work.mkdir(parents=True, exist_ok=False)
            (work / "request.pb").write_bytes(request.SerializeToString(deterministic=True))
            try:
                manifest, model = self.load(request.base)
                if manifest["model_id"] != request.model_id: raise ValueError("Fit model/base mismatch.")
                evidence = fit(model, request, policy, cancel_check=context.is_active)
                candidate_file = work / "candidate.safetensors"; tensors = model.export(candidate_file)
                candidate_bytes = candidate_file.read_bytes()
                candidate = dict(manifest, parent=request.base, original=manifest["original"] or request.base,
                    blob=digest(candidate_bytes), tensors=tensors, scope=evidence["scope"])
                # Independently reconstruct the serialized candidate before it can be staged.
                parity_manifest = dict(candidate, evidence="0" * 64)
                reloaded = PretrainedV3.load(parity_manifest, candidate_file, self.materialize(manifest["config"]), self.materialize(manifest["vocab"]), device=self.device)
                if assess(reloaded, list(request.guard)) != evidence["candidate_guard"]: raise ValueError("Serialized candidate/guard inference differs.")
                evidence.update(candidate_blob=candidate["blob"], serialized_guard_parity=True, capabilities=self.capabilities, source=source,
                    source_hashes={path.relative_to(common.ROOT).as_posix(): digest(path.read_bytes()) for path in (Path(__file__), common.ROOT / "extension/client-runtime/src/v3/model.py", common.ROOT / "extension/client-runtime/src/v3/training.py", common.ROOT / "shared/python/privoke_model/v3_contract.py")})
                evidence_bytes = canonical(evidence); candidate["evidence"] = digest(evidence_bytes)
                (work / "evidence.json").write_bytes(evidence_bytes); (work / "manifest.json").write_bytes(canonical(candidate))
                self.stub.StageCheckpoint(chunks(evidence_bytes), timeout=120)
                candidate_sha = self.stub.StageCheckpoint(chunks(candidate_bytes, canonical(candidate)), timeout=120).sha256
                self.db.execute("UPDATE fits SET status='completed',candidate=? WHERE id=?", (candidate_sha, request.request_id))
                return pb.FitResponse(candidate=candidate_sha, evidence=candidate["evidence"], evidence_json=evidence_bytes)
            except BaseException as error:
                self.db.execute("UPDATE fits SET status='failed',reason=? WHERE id=?", (type(error).__name__ + ": " + str(error), request.request_id))
                raise

    def GetFitStatus(self, request, context):
        with self.lock: row = self.db.execute("SELECT status,candidate,reason FROM fits WHERE id=?", (request.request_id,)).fetchone()
        return pb.Receipt(request_id=request.request_id, status=row[0] if row else "unknown", candidate=row[1] if row else "", reason=row[2] if row else "")
    def Health(self, request, context):
        return pb.HealthResponse(ready=True, role="runtime", capabilities=self.capabilities)

if __name__ == "__main__":
    service = RuntimeServer(os.environ["V3_CHECKPOINT_TARGET"], os.environ["V3_RUNTIME_STATE"], os.getenv("V3_DEVICE", "cpu"))
    server = grpc.server(ThreadPoolExecutor(max_workers=4), options=OPTIONS)
    rpc.add_TrainingServiceServicer_to_server(service, server)
    runtime_pb2_grpc.add_PrivokeRuntimeServiceServicer_to_server(service, server)
    if not server.add_insecure_port(os.getenv("V3_BIND", "127.0.0.1") + ":" + os.getenv("V3_PORT", "50171")): raise ValueError("V3 runtime bind failed.")
    server.start(); server.wait_for_termination()
