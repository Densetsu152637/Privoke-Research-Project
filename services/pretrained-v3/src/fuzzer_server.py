"""Experimental network fuzzer; only checkpoint references leave the runtime."""
from __future__ import annotations
import os
from pathlib import Path
import sqlite3
import threading
from common import pb, rpc, parameters_pb2, channel, canonical, digest, fetch, serve, source_identity
from privoke_model.v3_contract import parse, validate_policy, validate_execution, validate_manifest, publication_passes
from fuzzer_training import schedule

class FuzzerServer(rpc.V3FuzzerServiceServicer):
    def __init__(self, runtime_target, checkpoint_target, directory, policy):
        self.runtime_channel = channel(runtime_target); self.runtime = rpc.TrainingServiceStub(self.runtime_channel)
        self.checkpoint_channel = channel(checkpoint_target); self.checkpoint = rpc.CheckpointServiceStub(self.checkpoint_channel)
        self.directory = Path(directory); self.directory.mkdir(parents=True, exist_ok=True)
        self.policy = validate_policy(policy, pilot=policy["steps"] == 2)
        self.sampler = os.getenv("V3_SAMPLING_STRATEGY", "existing_taxonomy_benign_common_frozen_stream_v1")
        if self.sampler not in ("existing_taxonomy_benign_common_frozen_stream_v1", "audience_common_frozen_stream_v1"):
            raise ValueError("Unknown configured v3 sampler.")
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.directory / "cycles.sqlite", isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS cycles(id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, response BLOB)")
        for stub in (self.runtime, self.checkpoint):
            if not stub.Health(pb.HealthRequest(), timeout=15).ready: raise ValueError("Dependency not ready.")

    def RunTrainingCycle(self, request, context): return self.run(request, context, pb.HEADS)
    def RunUnderlyingTrainingCycle(self, request, context): return self.run(request, context, pb.FULL_ENCODER)

    def run(self, request, context, scope):
        import grpc
        if not request.request_id or len(request.request_id) > 200 or request.prompt_count != self.policy["window_batches"] * 32:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Frozen request ID/original prompt budget required.")
        source_pin = "BC01"
        if self.sampler == "audience_common_frozen_stream_v1":
            from audience_schedule import trusted_release
            source_pin = trusted_release().sha256
        fingerprint_payload = str(scope).encode() + request.SerializeToString(deterministic=True)
        if self.sampler == "audience_common_frozen_stream_v1":
            fingerprint_payload += self.sampler.encode() + source_pin.encode()
        fingerprint = digest(fingerprint_payload)
        with self.lock:
            prior = self.db.execute("SELECT fingerprint,response FROM cycles WHERE id=?", (request.request_id,)).fetchone()
            if prior:
                if prior[0] != fingerprint: context.abort(grpc.StatusCode.ALREADY_EXISTS, "Cycle ID reused with different content/scope.")
                if prior[1] is not None: return parameters_pb2.FuzzerTrainingResponse.FromString(bytes(prior[1]))
                context.abort(grpc.StatusCode.FAILED_PRECONDITION, "Prior cycle outcome unknown; query runtime/commit status, never replay fit.")
            self.db.execute("INSERT INTO cycles VALUES (?,?,NULL)", (request.request_id, fingerprint))
            work = self.directory / digest(request.request_id.encode()); work.mkdir(exist_ok=False)
            (work / "cycle-request.pb").write_bytes(request.SerializeToString(deterministic=True))
            base = request.metadata.get("expected_base")
            if base != self.checkpoint.ResolveCurrent(pb.Model(model_id=request.model_id), timeout=15).sha256:
                raise ValueError("Cycle expected base differs from private current catalog.")
            training, guard, source = schedule(request.seed, self.policy, sampler=self.sampler)
            if (request.metadata.get("policy_sha256") != digest(canonical(self.policy))
                    or request.metadata.get("source_commitment") != digest(canonical(source))):
                raise ValueError("Host frozen policy/source differs from actual dispatched schedule.")
            (work / "source.json").write_bytes(canonical(source))
            fit_request = pb.FitRequest(request_id=request.request_id, model_id=request.model_id, base=base, scope=scope,
                layers=[4], train=training, guard=guard, policy_json=canonical(self.policy), source_commitment=digest(canonical(source)), source_json=canonical(source))
            (work / "fit-request.pb").write_bytes(fit_request.SerializeToString(deterministic=True))
            try:
                fitted = self.runtime.FitCandidate(fit_request, timeout=float(os.getenv("V3_FIT_TIMEOUT", "7200")))
            except grpc.RpcError:
                status = self.runtime.GetFitStatus(pb.StatusRequest(request_id=request.request_id), timeout=15)
                (work / "fit-status-after-error.pb").write_bytes(status.SerializeToString(deterministic=True))
                raise RuntimeError("Physical fit response uncertain; stopped without replay. Status=" + status.status)
            evidence = validate_execution(parse(bytes(fitted.evidence_json), 80 * 1024 * 1024))
            if (digest(bytes(fitted.evidence_json)) != fitted.evidence or evidence["request_id"] != request.request_id
                    or evidence["base"] != base or evidence["source_commitment"] != digest(canonical(source))
                    or evidence["train_wire_sha256"] != source["train_wire_sha256"] or evidence["guard_wire_sha256"] != source["guard_wire_sha256"]
                    or evidence["policy"] != self.policy or evidence["scope"] != ("heads" if scope == pb.HEADS else "full_encoder")
                    or not evidence.get("serialized_guard_parity")):
                raise ValueError("Runtime fit evidence does not match dispatched source/scope/policy.")
            manifest = validate_manifest(parse(fetch(self.checkpoint, fitted.candidate)))
            if manifest["evidence"] != fitted.evidence or manifest["blob"] != evidence["candidate_blob"]:
                raise ValueError("Runtime candidate differs from checkpoint service snapshot.")
            (work / "fit-response.pb").write_bytes(fitted.SerializeToString(deterministic=True))
            (work / "evidence.json").write_bytes(bytes(fitted.evidence_json))
            commit = pb.Commit(request_id=request.request_id, model_id=request.model_id, expected_base=base,
                candidate=fitted.candidate, evidence=fitted.evidence)
            (work / "commit-request.pb").write_bytes(commit.SerializeToString(deterministic=True))
            try:
                receipt = self.checkpoint.CommitCandidate(commit, timeout=120)
            except grpc.RpcError:
                receipt = self.checkpoint.GetCommitStatus(pb.StatusRequest(request_id=request.request_id), timeout=15)
                if receipt.status == "unknown":
                    (work / "unknown-commit.pb").write_bytes(receipt.SerializeToString(deterministic=True))
                    raise RuntimeError("Commit outcome unknown; stop without replay.")
            if receipt.status not in ("applied", "rejected") or receipt.candidate != fitted.candidate or receipt.base != base:
                raise ValueError("Terminal publication receipt differs from fitted candidate.")
            (work / "receipt.pb").write_bytes(receipt.SerializeToString(deterministic=True))
            response = parameters_pb2.FuzzerTrainingResponse(accepted=receipt.status == "applied", model_id=request.model_id,
                base_version=base, applied_version=fitted.candidate if receipt.status == "applied" else base,
                prompts_generated=len(training), message=receipt.status + ": " + receipt.reason,
                metadata={"candidate_manifest": fitted.candidate, "evidence_sha256": fitted.evidence, "publication_status": receipt.status,
                    "terminal_candidate_retained": "true", "source_commitment": digest(canonical(source)), "semantic_layers": "4",
                    "scope": evidence["scope"], "guard_passed": str(publication_passes(evidence)).lower()})
            self.db.execute("UPDATE cycles SET response=? WHERE id=?", (response.SerializeToString(deterministic=True), request.request_id))
            return response

    def Health(self, request, context):
        return pb.HealthResponse(ready=True, role="fuzzer", capabilities={"schema": "1", "policy_sha256": digest(canonical(self.policy)), "source_closure": source_identity(), "sampler": self.sampler})

if __name__ == "__main__":
    policy = parse(Path(os.environ["V3_POLICY_FILE"]).read_bytes())
    service = FuzzerServer(os.environ["V3_RUNTIME_TARGET"], os.environ["V3_CHECKPOINT_TARGET"], os.environ["V3_FUZZER_STATE"], policy)
    serve(service, rpc.add_V3FuzzerServiceServicer_to_server, int(os.getenv("V3_PORT", "50172")))
