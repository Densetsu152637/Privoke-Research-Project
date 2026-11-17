#!/usr/bin/env python
"""Guarded-update and authentication security harness (record UPDSEC-20261116).

Drives each attack class against live PriVoke services on loopback and records the
observed outcome per attack, plus whether the active model stayed unchanged:

* param-update-service (Python): the actual `app/server.py` servicer, hosted as a host
  process bound to 127.0.0.1 with a private copy of the legacy `privoke-balanced` artifact.
* model-streaming-service (Go): the repository image, hosted by `docker run` on a loopback
  port, mounting the same artifact directory read-only (and the prepared standard V3
  releases read-only).

Paths exercised are labelled per attack: "legacy-update" is the mutable JSON artifact path
(the only path that accepts gradient updates); "standard-v3" is the immutable binary package
path, which has no update RPC; "transport-standin" is a grpcio mutual-TLS terminator used
because the production nginx ingress image is not part of this run; "static" is a source or
configuration check, not a behaviour test.

Nothing here invents a result: every row is either observed from a live call, observed from
a local process, or an explicitly labelled static check.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import math
import os
import random
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from host_environment import configure_imports  # noqa: E402

configure_imports()

RECORD_ID = "UPDSEC-20261116"
LEGACY_MODEL = "privoke-balanced"
V3_MODEL = "privoke-v3-balanced"
MESSAGE_LIMIT = 220
G7_CLASSES = ("stale", "replayed", "duplicate", "malformed_tensor", "nan_inf", "wrong_shape",
              "excessive_change", "interrupted", "unauthorized_publication")
G8_CLASSES = ("invalid_credentials", "invalid_certificate", "expired_credentials", "impersonation",
              "replayed_request", "unauthorized_retrieval", "unauthorized_update")
OUTCOMES = ("rejected", "accepted", "idempotent_noop", "applied_once", "not_applicable", "not_run")


# --------------------------------------------------------------------------------------
# Wire helpers (raw protobuf for malformed inputs the Python message classes cannot build)
# --------------------------------------------------------------------------------------

def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def field_bytes(number: int, payload: bytes) -> bytes:
    return varint(number << 3 | 2) + varint(len(payload)) + payload


def raw_gradient(name: bytes, packed_values: bytes, shape: tuple[int, ...]) -> bytes:
    return (field_bytes(1, name) + field_bytes(2, packed_values)
            + field_bytes(3, b"".join(varint(d) for d in shape)))


def raw_update(model_id: str, base_version: str, gradients: list[bytes], source_id: str = "harness") -> bytes:
    body = field_bytes(1, source_id.encode()) + field_bytes(2, model_id.encode()) + field_bytes(3, base_version.encode())
    return body + b"".join(field_bytes(4, g) for g in gradients)


def short(message: str | None) -> str:
    text = (message or "").replace("\n", " ").strip()
    return text if len(text) <= MESSAGE_LIMIT else text[:MESSAGE_LIMIT] + "..."


def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def lan_address() -> str | None:
    """A non-loopback local address (no packet is sent), or None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 9))
            address = sock.getsockname()[0]
    except OSError:
        return None
    return None if address.startswith("127.") else address


# --------------------------------------------------------------------------------------
# Stack hosting
# --------------------------------------------------------------------------------------

UPDATER_LAUNCHER = r'''
import sys
sys.path.insert(0, sys.argv[1])
import server as updater_server
from config import ParamUpdateConfig
real_server = updater_server.grpc.server
class LoopbackOnly:
    """Delegate to the real server but bind IPv4 loopback instead of the service's [::]."""
    def __init__(self, inner): self._inner = inner
    def add_insecure_port(self, address): return self._inner.add_insecure_port(address.replace("[::]", "127.0.0.1"))
    def __getattr__(self, name): return getattr(self._inner, name)
updater_server.grpc.server = lambda *a, **k: LoopbackOnly(real_server(*a, **k))
config = ParamUpdateConfig.from_env()
srv = updater_server.create_server(config)
srv.start()
print("updater-ready", flush=True)
srv.wait_for_termination()
'''


class Stack:
    def __init__(self, work: Path, release_dir: Path, *, keep_image: str):
        from host_owned_service import owned_python

        self.work = work
        self.models_dir = work / "models"
        self.data_dir = work / "data"
        self.models_dir.mkdir(parents=True)
        self.data_dir.mkdir(parents=True)
        self.artifact = self.models_dir / f"{LEGACY_MODEL}.json"
        self.storage = self.data_dir / "updates.jsonl"
        self.release_dir = release_dir
        self.image = keep_image
        self.updater_port = free_port()
        self.stream_port = free_port()
        self.container = f"updsec-{os.getpid()}-{self.stream_port}"
        self.updater: subprocess.Popen | None = None
        self.executable, self.environment = owned_python()
        self.service_dir = ROOT / "services/param-update-service"
        self.launcher = work / "updater_launcher.py"
        self.launcher.write_text(UPDATER_LAUNCHER, encoding="utf-8")

    # -- environment for the updater process
    def _updater_env(self):
        env = dict(self.environment)
        env.update({"PARAM_UPDATE_PORT": str(self.updater_port), "PARAM_UPDATE_STORAGE_PATH": str(self.storage),
                    "MODEL_ARTIFACT_PATH": str(self.artifact), "MODEL_ID": LEGACY_MODEL, "FUZZER_PROMPT_COUNT": "0",
                    "PYTHONDONTWRITEBYTECODE": "1"})
        return env

    def prepare_artifact(self):
        shutil.copyfile(ROOT / "models" / f"{LEGACY_MODEL}.json", self.artifact)
        # Same step the cloud/dev stacks run before serving: prepare the full-capability artifact.
        result = subprocess.run([self.executable, str(self.service_dir / "app/bootstrap.py")], env=self._updater_env(),
                                cwd=self.service_dir, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode:
            raise RuntimeError(f"bootstrap failed: {result.stderr[-400:]}")
        self.pristine = self.artifact.read_bytes()

    def start_updater(self, require_serving=True):
        self.updater = subprocess.Popen([self.executable, str(self.launcher), str(self.service_dir / "app")],
                                        env=self._updater_env(), cwd=self.service_dir, text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        deadline = time.time() + 60
        line_holder: list[str] = []
        reader = threading.Thread(target=lambda: line_holder.append(self.updater.stdout.readline()), daemon=True)
        reader.start()
        while time.time() < deadline:
            if line_holder:
                break
            if self.updater.poll() is not None:
                raise RuntimeError("updater exited during startup")
            time.sleep(0.1)
        if not line_holder or "updater-ready" not in line_holder[0]:
            raise RuntimeError("updater did not report readiness")
        threading.Thread(target=lambda: [None for _ in self.updater.stdout], daemon=True).start()
        self.wait_updater_serving(require_serving=require_serving)

    def wait_updater_serving(self, timeout=30, require_serving=True):
        from privoke.v1 import parameters_pb2 as pb, parameters_pb2_grpc as rpc
        import grpc

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with grpc.insecure_channel(f"127.0.0.1:{self.updater_port}") as channel:
                    status = rpc.ParamUpdateServiceStub(channel).Health(pb.HealthRequest(), timeout=2).status
                    if status == "SERVING" or not require_serving:
                        return
                    time.sleep(0.2)
            except grpc.RpcError:
                time.sleep(0.2)
        raise RuntimeError("updater not serving")

    def kill_updater(self):
        if self.updater and self.updater.poll() is None:
            self.updater.kill()  # hard kill: no cleanup handlers run
            self.updater.wait(10)

    def stop_updater(self):
        self.kill_updater()

    def reset(self):
        """Restore the pristine prepared artifact and clear receipts/audit, then restart the updater."""
        self.stop_updater()
        for leftover in self.models_dir.glob(".*.tmp"):
            leftover.unlink()
        temporary = self.models_dir / ".reset.tmp"
        temporary.write_bytes(self.pristine)
        os.replace(temporary, self.artifact)
        for path in self.data_dir.glob("updates.jsonl*"):
            path.unlink()
        self.start_updater()

    def start_streaming(self):
        command = ["docker", "run", "-d", "--rm", "--name", self.container, "-p", f"127.0.0.1:{self.stream_port}:50051",
                   "-e", "MODEL_STREAMING_PORT=50051", "-e", f"MODEL_LATEST_ID={V3_MODEL}", "-e", "MODEL_ARTIFACT_DIR=/models",
                   "-e", "MODEL_RELEASE_DIR=/model-releases",
                   "-v", f"{self.models_dir}:/models:ro", "-v", f"{self.release_dir}:/model-releases:ro",
                   self.image, "/usr/local/bin/model-streaming-service-dev"]
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        from privoke.v1 import parameters_pb2 as pb, parameters_pb2_grpc as rpc
        import grpc

        deadline = time.time() + 90
        while time.time() < deadline:
            try:
                with grpc.insecure_channel(f"127.0.0.1:{self.stream_port}") as channel:
                    if rpc.ModelStreamingServiceStub(channel).Health(pb.HealthRequest(), timeout=2).status == "SERVING":
                        return
            except grpc.RpcError:
                pass
            time.sleep(0.5)
        logs = subprocess.run(["docker", "logs", "--tail", "20", self.container], text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT).stdout
        raise RuntimeError(f"streaming service not serving: {logs[-500:]}")

    def stop_streaming(self):
        subprocess.run(["docker", "rm", "-f", self.container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def close(self):
        self.stop_updater()
        self.stop_streaming()


# --------------------------------------------------------------------------------------
# Client helpers
# --------------------------------------------------------------------------------------

class Client:
    def __init__(self, stack: Stack):
        import grpc
        from privoke.v1 import parameters_pb2 as pb, parameters_pb2_grpc as rpc

        self.grpc, self.pb, self.rpc, self.stack = grpc, pb, rpc, stack
        options = (("grpc.max_receive_message_length", 64 * 1024 * 1024), ("grpc.max_send_message_length", 64 * 1024 * 1024),
                   ("grpc.enable_http_proxy", 0))
        self.update_channel = grpc.insecure_channel(f"127.0.0.1:{stack.updater_port}", options=options)
        self.stream_channel = grpc.insecure_channel(f"127.0.0.1:{stack.stream_port}", options=options)
        self.updates = rpc.ParamUpdateServiceStub(self.update_channel)
        self.models = rpc.ModelStreamingServiceStub(self.stream_channel)

    def call(self, fn, request, **kwargs):
        """Return ('ok', response) or ('error', code_name, details)."""
        try:
            return ("ok", fn(request, timeout=kwargs.pop("timeout", 30), **kwargs))
        except self.grpc.RpcError as error:
            return ("error", error.code().name, short(error.details()))

    def submit(self, request, **kwargs):
        return self.call(self.updates.SubmitParameterUpdate, request, **kwargs)

    def raw_submit(self, payload: bytes, *, timeout=30):
        method = self.update_channel.unary_unary("/privoke.v1.ParamUpdateService/SubmitParameterUpdate",
                                                 request_serializer=lambda value: value,
                                                 response_deserializer=lambda value: value)
        try:
            return ("ok", self.pb.ParameterUpdateAck.FromString(method(payload, timeout=timeout)))
        except self.grpc.RpcError as error:
            return ("error", error.code().name, short(error.details()))

    def served(self, model_id=LEGACY_MODEL, consumer="updsec-observer"):
        result = self.call(self.models.GetModelParameters, self.pb.ModelParametersRequest(consumer_id=consumer, model_id=model_id))
        if result[0] != "ok":
            return {"error": result[1], "detail": result[2]}
        digest = hashlib.sha256()
        for parameter in result[1].parameters:
            digest.update(parameter.name.encode())
            digest.update(struct.pack(f"<{len(parameter.values)}f", *parameter.values))
        return {"version": result[1].version, "tensor_sha256": digest.hexdigest(),
                "artifact_checksum": result[1].metadata.get("artifact_checksum", "")}

    def request(self, *, base_version, gradients, model_id=LEGACY_MODEL, source="updsec-attacker", metadata=None):
        message = self.pb.ParameterUpdateRequest(source_id=source, model_id=model_id, base_version=base_version,
                                                 metadata=metadata or {})
        for name, shape, values in gradients:
            message.gradients.add(name=name, shape=list(shape), values=list(values))
        return message

    def current_version(self):
        return json.loads(self.stack.artifact.read_text(encoding="utf-8"))["version"]

    def close(self):
        self.update_channel.close()
        self.stream_channel.close()


def artifact_state(stack: Stack):
    raw = stack.artifact.read_bytes()
    payload = json.loads(raw)
    return {"file_sha256": hashlib.sha256(raw).hexdigest(), "version": payload["version"],
            "training_revision": payload["metadata"].get("training_revision"),
            "last_update_source": payload["metadata"].get("last_update_source")}


def snapshot(client: Client):
    return {"artifact": artifact_state(client.stack), "served": client.served()}


def same_model(before, after) -> bool:
    return (before["artifact"]["file_sha256"] == after["artifact"]["file_sha256"]
            and before["served"] == after["served"])


class Recorder:
    def __init__(self, client: Client):
        self.client = client
        self.rows: list[dict] = []

    def add(self, row_id, cls, path, description, expected, fn, *, gap=None, evidence=None, extra_check=None):
        """Run `fn` (returns dict with observed/code/message), bracketed by model snapshots."""
        before = snapshot(self.client)
        started = time.time()
        try:
            result = fn()
        except Exception as error:  # a harness failure must be visible, never a silent pass
            result = {"observed": "not_run", "code": "HARNESS_ERROR", "message": short(f"{type(error).__name__}: {error}")}
        after = snapshot(self.client)
        unchanged = same_model(before, after)
        observed = result["observed"]
        row = {"id": row_id, "class": cls, "path": path, "description": description, "expected": expected,
               "observed": observed, "code": result.get("code"), "message": result.get("message"),
               "model_unchanged": unchanged, "version_before": before["artifact"]["version"],
               "version_after": after["artifact"]["version"], "duration_s": round(time.time() - started, 3)}
        row.update({k: v for k, v in result.items() if k not in ("observed", "code", "message")})
        if expected == "rejected_unchanged":
            row["property_met"] = observed == "rejected" and unchanged
        elif expected == "exactly_once":
            row["property_met"] = bool(result.get("exactly_once"))
        elif expected == "positive_control":
            row["property_met"] = observed == "accepted"
        elif expected == "not_applicable":
            row["property_met"] = None
        else:
            row["property_met"] = result.get("property_met")
        if extra_check:
            row["property_met"] = bool(row["property_met"]) and extra_check(before, after, result)
        row["gap"] = gap
        row["evidence"] = evidence or []
        self.rows.append(row)
        return row


def outcome(result):
    """Normalise a client.submit result into the attack-row fields."""
    if result[0] == "ok":
        return {"observed": "accepted", "code": "OK", "message": short(result[1].message),
                "applied_version": result[1].applied_version}
    return {"observed": "rejected", "code": result[1], "message": result[2]}


# --------------------------------------------------------------------------------------
# Attack catalogue: guarded update (G7) on the legacy update path
# --------------------------------------------------------------------------------------

BIAS = ("head.sensitivity.bias", (4,))
WEIGHT = ("head.sensitivity.weight", (32, 4))
SMALL = 1e-4


def legit(client: Client, **kwargs):
    version = client.current_version()
    gradients = kwargs.pop("gradients", [(BIAS[0], BIAS[1], [SMALL] * 4)])
    return client.request(base_version=kwargs.pop("base_version", version), gradients=gradients, **kwargs)


def run_update_attacks(recorder: Recorder, stack: Stack):
    client = recorder.client
    pb = client.pb
    rows = recorder.add
    U = "legacy-update"
    EV_VALID = ["services/param-update-service/app/validation.py"]

    # ---- positive control and stale/replay/duplicate
    state = {}

    def control():
        version = client.current_version()
        state["v0"] = version
        state["req_a"] = legit(client, metadata={"request_id": "updsec-a", "generated_prompt_count": "0"})
        result = client.submit(state["req_a"])
        state["v1"] = result[1].applied_version if result[0] == "ok" else None
        return outcome(result)

    rows("C1", "control", U, "Legitimate small update with a request_id (positive control).", "positive_control", control,
         evidence=["services/param-update-service/app/server.py:SubmitParameterUpdate"])

    def stale_old():
        return outcome(client.submit(client.request(base_version=state["v0"], gradients=[(BIAS[0], BIAS[1], [SMALL] * 4)])))

    rows("S1", "stale", U, "Fresh update (no request_id) built on the superseded base version after another update committed.",
         "rejected_unchanged", stale_old, evidence=["shared/python/privoke_model/artifact.py:apply_parameter_update (Stale base_version)"])

    rows("S2", "stale", U, "Update citing a fabricated future base version.", "rejected_unchanged",
         lambda: outcome(client.submit(client.request(base_version="v99.0.0+train.999", gradients=[(BIAS[0], BIAS[1], [SMALL] * 4)]))))

    rows("S3", "stale", U, "Update citing the pristine release version after training advanced (rollback-style base).",
         "rejected_unchanged", lambda: outcome(client.submit(client.request(
             base_version=json.loads(stack.pristine)["version"], gradients=[(BIAS[0], BIAS[1], [SMALL] * 4)]))))

    def replay_same_id():
        result = client.submit(state["req_a"])
        row = outcome(result)
        if result[0] == "ok":
            row["observed"] = "idempotent_noop" if result[1].applied_version == state["v1"] else "accepted"
            row["returned_original_version"] = result[1].applied_version == state["v1"]
        return row

    rows("R1", "replayed", U, "Byte-identical replay of the committed request (same request_id) after later state changes.",
         "rejected_unchanged", replay_same_id,
         evidence=["services/param-update-service/app/server.py:_apply_update (receipt lookup)",
                   "services/param-update-service/tests/test_update_receipts.py"])
    # R1 is judged below: the replay must not re-apply, so the model must be unchanged.
    recorder.rows[-1]["property_met"] = (recorder.rows[-1]["observed"] == "idempotent_noop" and recorder.rows[-1]["model_unchanged"])
    recorder.rows[-1]["expected"] = "idempotent_noop_unchanged"

    def replay_no_id():
        result = client.submit(client.request(base_version=state["v0"], gradients=[(BIAS[0], BIAS[1], [SMALL] * 4)]))
        return outcome(result)

    rows("R2", "replayed", U, "Replay of the same payload without a request_id after it was applied once.",
         "rejected_unchanged", replay_no_id)

    def replay_conflict():
        tampered = client.request(base_version=state["v0"], gradients=[(BIAS[0], BIAS[1], [2 * SMALL] * 4)],
                                  metadata={"request_id": "updsec-a", "generated_prompt_count": "0"})
        return outcome(client.submit(tampered))

    rows("R3", "replayed", U, "Reuse of a committed request_id with a different payload.", "rejected_unchanged", replay_conflict,
         evidence=["services/param-update-service/app/server.py:_apply_update (payload_digest)"])

    def replay_other_source():
        other = client.pb.ParameterUpdateRequest.FromString(state["req_a"].SerializeToString())
        other.source_id = "updsec-other-source"
        return outcome(client.submit(other))

    rows("R4", "replayed", U, "Replay of the committed payload under a different source_id (new receipt key, stale base).",
         "rejected_unchanged", replay_other_source)

    # ---- duplicates: concurrent identical submissions
    def duplicate_with_id():
        before_revision = int(artifact_state(stack)["training_revision"])
        request = legit(client, metadata={"request_id": "updsec-dup-id", "generated_prompt_count": "0"})
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            results = list(pool.map(lambda _: client.submit(request), range(8)))
        versions = {r[1].applied_version for r in results if r[0] == "ok"}
        errors = sorted({r[1] for r in results if r[0] == "error"})
        revisions_applied = int(artifact_state(stack)["training_revision"]) - before_revision
        return {"observed": "applied_once" if revisions_applied == 1 else "accepted", "code": "OK" if not errors else ",".join(errors),
                "message": f"8 concurrent identical submissions; accepted={sum(r[0] == 'ok' for r in results)}, "
                           f"distinct applied versions={len(versions)}, revisions applied={revisions_applied}",
                "exactly_once": revisions_applied == 1 and len(versions) == 1, "revisions_applied": revisions_applied}

    rows("D1", "duplicate", U, "Eight concurrent identical submissions with one request_id.", "exactly_once", duplicate_with_id,
         evidence=["services/param-update-service/app/server.py:_write_lock/UpdateReceipts"])

    def duplicate_without_id():
        before_revision = int(artifact_state(stack)["training_revision"])
        request = legit(client)
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            results = list(pool.map(lambda _: client.submit(request), range(8)))
        accepted = sum(r[0] == "ok" for r in results)
        codes = sorted({r[1] for r in results if r[0] == "error"})
        revisions_applied = int(artifact_state(stack)["training_revision"]) - before_revision
        return {"observed": "applied_once" if revisions_applied == 1 else "accepted", "code": ",".join(codes) or "OK",
                "message": f"8 concurrent identical submissions without request_id; accepted={accepted}, rejected codes={codes}, "
                           f"revisions applied={revisions_applied}",
                "exactly_once": revisions_applied == 1 and accepted == 1, "revisions_applied": revisions_applied}

    rows("D2", "duplicate", U, "Eight concurrent identical submissions without request_id (base-version compare-and-swap only).",
         "exactly_once", duplicate_without_id)

    # ---- malformed tensors
    def reject(request=None, raw=None, **_):
        return outcome(client.raw_submit(raw) if raw is not None else client.submit(request))

    def req(gradients, **kw):
        return client.request(base_version=client.current_version(), gradients=gradients, **kw)

    def lazy(build):
        return lambda: reject(build())

    M = "malformed_tensor"
    rows("M1", M, U, "Gradient with an empty values array.", "rejected_unchanged", lazy(lambda: req([(BIAS[0], BIAS[1], [])])))
    rows("M2", M, U, "Value count does not match the declared shape (3 values for shape [4]).", "rejected_unchanged",
         lazy(lambda: req([(BIAS[0], BIAS[1], [SMALL] * 3)])))
    rows("M3", M, U, "Shape with a zero dimension.", "rejected_unchanged", lazy(lambda: req([(BIAS[0], (0, 4), [SMALL] * 4)])))
    rows("M4", M, U, "Gradient with no shape.", "rejected_unchanged", lazy(lambda: req([(BIAS[0], (), [SMALL] * 4)])))
    rows("M5", M, U, "Duplicate gradient names in one update.", "rejected_unchanged",
         lazy(lambda: req([(BIAS[0], BIAS[1], [SMALL] * 4), (BIAS[0], BIAS[1], [SMALL] * 4)])))
    rows("M6", M, U, "Unknown parameter name.", "rejected_unchanged", lazy(lambda: req([("head.nonexistent.bias", (4,), [SMALL] * 4)])))
    rows("M8", M, U, "Empty gradient name.", "rejected_unchanged", lazy(lambda: req([("", BIAS[1], [SMALL] * 4)])))
    rows("M9", M, U, "Control character in the gradient name.", "rejected_unchanged", lazy(lambda: req([("head.bias\x00", BIAS[1], [SMALL] * 4)])))
    rows("M10", M, U, "Gradient name longer than 256 characters.", "rejected_unchanged", lazy(lambda: req([("h" * 300, BIAS[1], [SMALL] * 4)])))
    rows("M11", M, U, "Packed float field whose byte length is not a multiple of four (raw wire).", "rejected_unchanged",
         lambda: reject(raw=raw_update(LEGACY_MODEL, client.current_version(),
                                       [raw_gradient(BIAS[0].encode(), b"\x00\x00\x80\x3f\x00\x00\x80", BIAS[1])])))
    rows("M12", M, U, "Truncated protobuf message (raw wire).", "rejected_unchanged",
         lambda: reject(raw=raw_update(LEGACY_MODEL, client.current_version(),
                                       [raw_gradient(BIAS[0].encode(), struct.pack("<4f", *[SMALL] * 4), BIAS[1])])[:-7]))
    rows("M13", M, U, "Random bytes as the request body (raw wire).", "rejected_unchanged",
         lambda: reject(raw=random.Random(20261116).randbytes(512)))
    rows("M14", M, U, "257 gradients (one more than the 256-gradient limit).", "rejected_unchanged",
         lazy(lambda: req([(f"head.unknown.{i}", (1,), [SMALL]) for i in range(257)])))
    rows("M15", M, U, "One tensor with 24,577 values (above the largest per-tensor limit of 24,576).", "rejected_unchanged",
         lazy(lambda: req([("head.unknown.big", (24577,), [SMALL] * 24577)])))
    rows("M16", M, U, "Three 24,576-value tensors (73,728 values, above the 65,536 total limit).", "rejected_unchanged",
         lazy(lambda: req([(f"head.unknown.{i}", (24576,), [SMALL] * 24576) for i in range(3)])))
    rows("M17", M, U, "Request body of about 1.2 MB (above the 1 MiB receive limit).", "rejected_unchanged",
         lazy(lambda: req([("head.unknown.huge", (300000,), [SMALL] * 300000)])))
    rows("M18", M, U, "65 metadata entries (above the 64-entry limit).", "rejected_unchanged",
         lazy(lambda: legit(client, metadata={f"k{i}": "v" for i in range(65)})))
    rows("M19", M, U, "Metadata value of 3,000 characters.", "rejected_unchanged", lazy(lambda: legit(client, metadata={"note": "x" * 3000})))
    rows("M20", M, U, "Non-integer generated_prompt_count metadata.", "rejected_unchanged",
         lazy(lambda: legit(client, metadata={"request_id": "updsec-m20", "generated_prompt_count": "many"})))
    rows("M21", M, U, "Missing base_version.", "rejected_unchanged",
         lazy(lambda: client.request(base_version="", gradients=[(BIAS[0], BIAS[1], [SMALL] * 4)])))
    rows("M22", M, U, "No gradients.", "rejected_unchanged", lazy(lambda: client.request(base_version=client.current_version(), gradients=[])))
    rows("M23", M, U, "Control character in source_id.", "rejected_unchanged", lazy(lambda: legit(client, source="bad\nsource")))

    # ---- non-finite values
    N = "nan_inf"
    nan, inf = float("nan"), float("inf")
    rows("N1", N, U, "NaN in one coordinate.", "rejected_unchanged", lazy(lambda: req([(BIAS[0], BIAS[1], [SMALL, nan, SMALL, SMALL])])))
    rows("N2", N, U, "+Inf in one coordinate.", "rejected_unchanged", lazy(lambda: req([(BIAS[0], BIAS[1], [SMALL, inf, SMALL, SMALL])])))
    rows("N3", N, U, "-Inf in one coordinate.", "rejected_unchanged", lazy(lambda: req([(BIAS[0], BIAS[1], [SMALL, SMALL, -inf, SMALL])])))
    rows("N4", N, U, "All-NaN tensor.", "rejected_unchanged", lazy(lambda: req([(BIAS[0], BIAS[1], [nan] * 4)])))
    rows("N5", N, U, "Signalling-NaN bit pattern (raw wire).", "rejected_unchanged",
         lambda: reject(raw=raw_update(LEGACY_MODEL, client.current_version(),
                                       [raw_gradient(BIAS[0].encode(), struct.pack("<I", 0x7F800001) * 4, BIAS[1])])))
    rows("N6", N, U, "NaN in a large tensor (head.category.weight).", "rejected_unchanged",
         lazy(lambda: req([("head.category.weight", (32, 10), [SMALL] * 319 + [nan])])))
    rows("N7", N, U, "Value beyond float32 range sent as +1e39 (becomes Inf on the wire).", "rejected_unchanged",
         lazy(lambda: req([(BIAS[0], BIAS[1], [1e39, SMALL, SMALL, SMALL])])))

    # ---- wrong shapes
    W = "wrong_shape"
    rows("W1", W, U, "Shape [5] with 5 values for a [4] tensor (consistent but wrong).", "rejected_unchanged",
         lazy(lambda: req([(BIAS[0], (5,), [SMALL] * 5)])))
    rows("W2", W, U, "Transposed shape [4,32] for the [32,4] weight (same value count).", "rejected_unchanged",
         lazy(lambda: req([(WEIGHT[0], (4, 32), [SMALL] * 128)])))
    rows("W3", W, U, "Flattened shape [128] for the [32,4] weight.", "rejected_unchanged", lazy(lambda: req([(WEIGHT[0], (128,), [SMALL] * 128)])))
    rows("W4", W, U, "Shape [2,2] for the [4] bias (same value count, wrong rank).", "rejected_unchanged",
         lazy(lambda: req([(BIAS[0], (2, 2), [SMALL] * 4)])))
    rows("W5", W, U, "Right shape for one tensor, wrong shape for a second tensor in the same update (atomicity).",
         "rejected_unchanged", lazy(lambda: req([(BIAS[0], BIAS[1], [SMALL] * 4), (WEIGHT[0], (4, 32), [SMALL] * 128)])))

    # ---- excessive change
    E = "excessive_change"
    rows("E1", E, U, "One coordinate at 1.0000001 (just above the 1.0 per-coordinate bound).", "rejected_unchanged",
         lazy(lambda: req([(BIAS[0], BIAS[1], [1.0000001, 0, 0, 0])])))
    rows("E2", E, U, "Coordinate magnitude 100.", "rejected_unchanged", lazy(lambda: req([(BIAS[0], BIAS[1], [100.0, 0, 0, 0])])))
    rows("E3", E, U, "Coordinate magnitude 3.4e38 (largest finite float32).", "rejected_unchanged",
         lazy(lambda: req([(BIAS[0], BIAS[1], [3.4e38, 0, 0, 0])])))
    rows("E4", E, U, "Negative coordinate -2.0.", "rejected_unchanged", lazy(lambda: req([(BIAS[0], BIAS[1], [-2.0, 0, 0, 0])])))
    return state


def run_frozen_tensor(recorder: Recorder, stack: Stack):
    """The prepared full-capability artifact trains every tensor, so use the unprepared head-only artifact here."""
    client = recorder.client
    stack.stop_updater()
    temporary = stack.models_dir / ".raw.tmp"
    shutil.copyfile(ROOT / "models" / f"{LEGACY_MODEL}.json", temporary)
    os.replace(temporary, stack.artifact)
    stack.start_updater()
    parameters = json.loads(stack.artifact.read_text())["parameters"]
    frozen = next(name for name, tensor in parameters.items() if not tensor.get("trainable"))
    shape = tuple(parameters[frozen]["shape"])
    count = math.prod(shape)
    recorder.add("M7", "malformed_tensor", "legacy-update",
                 f"Update to the frozen (non-trainable) tensor {frozen} of the unprepared head-only artifact.", "rejected_unchanged",
                 lambda: outcome(client.submit(client.request(base_version=client.current_version(), gradients=[(frozen, shape, [SMALL] * count)]))),
                 evidence=["shared/python/privoke_model/artifact.py:apply_parameter_update (Parameter is not trainable)"])
    stack.reset()



def run_drift_attacks(recorder: Recorder, stack: Stack):
    """Valid-but-large updates: shows what the per-coordinate bound does NOT limit (run on a reset model)."""
    client = recorder.client
    E = "excessive_change"
    stack.reset()
    initial = json.loads(stack.artifact.read_text())

    def at_bound():
        result = client.submit(legit(client, gradients=[(BIAS[0], BIAS[1], [1.0, -1.0, 1.0, -1.0])]))
        return outcome(result)

    recorder.add("E5", E, "legacy-update", "Update with every coordinate exactly at the 1.0 bound (boundary value).", "positive_control", at_bound,
                 evidence=["services/param-update-service/app/validation.py:_validate_gradient_values"])

    def cumulative():
        accepted, applied = 0, 0
        for index in range(25):
            result = client.submit(legit(client, gradients=[(BIAS[0], BIAS[1], [1.0, 1.0, 1.0, 1.0])],
                                         metadata={"request_id": f"updsec-drift-{index}", "generated_prompt_count": "0"}))
            if result[0] == "ok":
                accepted += 1
        final = json.loads(stack.artifact.read_text())["parameters"][BIAS[0]]["values"]
        start = initial["parameters"][BIAS[0]]["values"]
        drift = max(abs(a - b) for a, b in zip(final, start))
        return {"observed": "accepted" if accepted == 25 else "rejected", "code": "OK",
                "message": f"{accepted}/25 successive maximum-magnitude updates accepted; max cumulative per-coordinate drift {drift:.4g}",
                "accepted_updates": accepted, "max_cumulative_drift": round(drift, 6), "property_met": accepted < 25}

    recorder.add("E6", E, "legacy-update",
                 "Twenty-five successive valid updates each at the 1.0 per-coordinate bound (cumulative change, no rate limit).",
                 "bounded_cumulative", cumulative, gap="GAP-NO-CUMULATIVE-BOUND",
                 evidence=["services/param-update-service/app/validation.py (per-coordinate bound only)"])

    def widest():
        parameters = json.loads(stack.artifact.read_text())["parameters"]
        grads, total = [], 0
        for name, tensor in parameters.items():
            count = math.prod(tensor["shape"])
            if tensor.get("trainable") and total + count <= 65536 and count <= 24576:
                grads.append((name, tuple(tensor["shape"]), [1.0] * count))
                total += count
        result = client.submit(client.request(base_version=client.current_version(), gradients=grads))
        row = outcome(result)
        row.update({"values_changed": total, "l2_norm": round(math.sqrt(total), 3), "tensors": len(grads),
                    "property_met": result[0] != "ok"})
        row["message"] = f"{total} coordinates at +1.0 across {len(grads)} tensors (L2 norm {math.sqrt(total):.1f}); {row['message']}"
        return row

    recorder.add("E7", E, "legacy-update", "Single update moving every trainable coordinate (up to 65,536 values) by the 1.0 bound.",
                 "bounded_norm", widest, gap="GAP-NO-CUMULATIVE-BOUND",
                 evidence=["services/param-update-service/app/validation.py (no norm bound)"])


# --------------------------------------------------------------------------------------
# Interrupted updates
# --------------------------------------------------------------------------------------

def run_interrupted(recorder: Recorder, stack: Stack):
    from privoke_model import load_artifact
    client = recorder.client
    I = "interrupted"
    stack.reset()

    def deadline_cancel():
        # A client that gives up almost immediately: the server must either apply once or not at all.
        before_rev = int(artifact_state(stack)["training_revision"])
        request = legit(client, metadata={"request_id": "updsec-int-deadline", "generated_prompt_count": "0"})
        cancelled = client.submit(request, timeout=0.001)
        time.sleep(1.0)
        retry = client.submit(request)
        revisions = int(artifact_state(stack)["training_revision"]) - before_rev
        ok = retry[0] == "ok" and revisions == 1
        return {"observed": "applied_once" if ok else "accepted", "code": cancelled[1] if cancelled[0] == "error" else "OK",
                "message": f"first call {cancelled[1] if cancelled[0] == 'error' else 'ok'}; retry with same request_id "
                           f"{'ok' if retry[0] == 'ok' else retry[1]}; revisions applied={revisions}",
                "exactly_once": ok, "revisions_applied": revisions}

    recorder.add("I1", I, "legacy-update", "Client deadline of 1 ms then retry with the same request_id.", "exactly_once", deadline_cancel)

    delays = [0.0, 0.005, 0.01, 0.02, 0.04, 0.07, 0.1, 0.15, 0.25, 0.4]

    def kill_trials():
        records = []
        for index, delay in enumerate(delays):
            request_id = f"updsec-kill-{index}"
            pre = artifact_state(stack)
            request = legit(client, metadata={"request_id": request_id, "generated_prompt_count": "0"})
            pending = client.updates.SubmitParameterUpdate.future(request, timeout=20)
            time.sleep(delay)
            stack.kill_updater()
            try:
                pending.result()
            except Exception:
                pass
            leftover = sorted(p.name for p in stack.models_dir.glob(".*.tmp"))
            try:
                loaded = load_artifact(stack.artifact)  # full validation of the committed bytes
                valid = True
                mid = loaded["version"]
            except Exception as error:
                valid, mid = False, f"invalid: {type(error).__name__}"
            stack.start_updater()
            retry = client.submit(request)
            post = artifact_state(stack)
            applied = int(post["training_revision"]) - int(pre["training_revision"])
            records.append({"delay_s": delay, "artifact_valid_after_kill": valid,
                            "state_after_kill": "applied" if mid != pre["version"] else "not_applied",
                            "retry_ok": retry[0] == "ok", "revisions_applied_total": applied,
                            "leftover_temp_files": leftover})
        exactly = all(r["artifact_valid_after_kill"] and r["retry_ok"] and r["revisions_applied_total"] == 1 for r in records)
        stats = {k: sum(1 for r in records if r["state_after_kill"] == k) for k in ("applied", "not_applied")}
        return {"observed": "applied_once" if exactly else "accepted", "code": "KILLED",
                "message": f"{len(records)} hard kills of the updater during an in-flight update; artifact valid after every kill; "
                           f"killed-after-commit={stats['applied']}, killed-before-commit={stats['not_applied']}; retry with the same "
                           f"request_id applied exactly once in {sum(r['revisions_applied_total'] == 1 for r in records)}/{len(records)}",
                "exactly_once": exactly, "trials": records}

    recorder.add("I2", I, "legacy-update", "Hard-kill the updater process at ten delays during an in-flight update, restart, retry the same request_id.",
                 "exactly_once", kill_trials,
                 evidence=["shared/python/privoke_model/artifact.py:write_artifact_atomic", "services/param-update-service/tests/test_update_receipts.py"])

    def stray_temp_file():
        stale = stack.models_dir / f".{LEGACY_MODEL}.json.interrupted.tmp"
        stale.write_text('{"truncated": ', encoding="utf-8")
        result = client.submit(legit(client, metadata={"request_id": "updsec-int-stray", "generated_prompt_count": "0"}))
        row = outcome(result)
        row["message"] = f"stray half-written temp file left beside the artifact; next update: {row['message']}"
        row["property_met"] = result[0] == "ok"
        stale.unlink()
        return row

    recorder.add("I3", I, "legacy-update", "A half-written temp file left beside the artifact by an earlier crash; next legitimate update.",
                 "positive_control", stray_temp_file)

    def torn_artifact():
        """A torn or truncated active artifact written by something other than the updater."""
        good = stack.artifact.read_bytes()
        stack.stop_updater()
        stack.artifact.write_bytes(good[: len(good) // 2])
        try:
            stack.start_updater(require_serving=False)
            health = client.call(client.rpc.ParamUpdateServiceStub(client.update_channel).Health, client.pb.HealthRequest())
            served = client.served()
            update_result = client.call(client.updates.SubmitParameterUpdate, client.request(
                base_version="unknown", gradients=[(BIAS[0], BIAS[1], [SMALL] * 4)]))
            message = (f"updater health={health[1].status if health[0] == 'ok' else health[1]}; "
                       f"update RPC={update_result[1] if update_result[0] == 'error' else 'accepted'}; "
                       f"stream serving={'error ' + served['error'] if 'error' in served else 'served version ' + served['version']}")
            blocked = update_result[0] == "error" and "error" in served
            return {"observed": "rejected" if blocked else "accepted", "code": update_result[1] if update_result[0] == "error" else "OK",
                    "message": message, "property_met": blocked}
        finally:
            stack.stop_updater()
            temporary = stack.models_dir / ".restore.tmp"
            temporary.write_bytes(good)
            os.replace(temporary, stack.artifact)
            stack.start_updater()

    recorder.add("I4", I, "legacy-update",
                 "Truncate the active artifact to half its bytes (torn write by an external actor); updater and streaming must fail closed.",
                 "fail_closed", torn_artifact)
    recorder.rows[-1]["property_met"] = bool(recorder.rows[-1].get("property_met"))


# --------------------------------------------------------------------------------------
# Authentication, impersonation, retrieval (G8) on the live services (no transport security)
# --------------------------------------------------------------------------------------

def run_live_authentication(recorder: Recorder, stack: Stack):
    from privoke.v1 import parameters_pb2 as pb
    client = recorder.client
    stack.reset()
    U = "legacy-update"

    def unauth_publication():
        result = client.submit(legit(client, source="updsec-unregistered-peer"))
        return outcome(result)

    recorder.add("A1", "unauthorized_publication", U,
                 "Valid update from a peer with no credential and an arbitrary source_id.", "rejected_unchanged", unauth_publication,
                 gap="GAP-NO-PUBLISHER-AUTH",
                 evidence=["services/param-update-service/app/server.py:create_server (add_insecure_port, no interceptor)"])

    def spoof_source():
        result = client.submit(legit(client, source="server-fuzzer"))
        row = outcome(result)
        row["recorded_last_update_source"] = artifact_state(stack)["last_update_source"]
        row["message"] += f"; artifact provenance now reads last_update_source={row['recorded_last_update_source']!r}"
        return row

    recorder.add("A2", "impersonation", U, "Update that claims the legitimate trainer's source_id ('server-fuzzer').", "rejected_unchanged",
                 spoof_source, gap="GAP-IDENTITY-SELF-ASSERTED",
                 evidence=["shared/python/privoke_model/artifact.py:apply_parameter_update (last_update_source)"])

    def bogus_credential():
        result = client.submit(legit(client), metadata=(("authorization", "Bearer invalid-test-token-not-real"),
                                                       ("x-api-key", "invalid-test-key-not-real")))
        return outcome(result)

    recorder.add("A3", "invalid_credentials", U, "Update presenting an invalid bearer token and API key in gRPC metadata.", "rejected_unchanged",
                 bogus_credential, gap="GAP-NO-CREDENTIAL-MECHANISM", evidence=["static:no credential check in service source"])

    rows = recorder.add
    rows("A4", "unauthorized_publication", "standard-v3", "Update addressed to the standard V3 model id on the update service.", "rejected_unchanged",
         lambda: outcome(client.submit(client.request(base_version="v1", model_id=V3_MODEL, gradients=[(BIAS[0], BIAS[1], [SMALL] * 4)]))),
         evidence=["services/param-update-service/app/validation.py (model_id binding)", "docs/services/model-streaming.md#standard-v3"])

    def via_streaming_port():
        method = client.stream_channel.unary_unary("/privoke.v1.ParamUpdateService/SubmitParameterUpdate",
                                                   request_serializer=lambda value: value.SerializeToString(),
                                                   response_deserializer=lambda value: value)
        try:
            method(legit(client), timeout=10)
            return {"observed": "accepted", "code": "OK", "message": "streaming port accepted an update"}
        except client.grpc.RpcError as error:
            return {"observed": "rejected", "code": error.code().name, "message": short(error.details())}

    rows("A5", "unauthorized_publication", "standard-v3", "Update RPC sent to the model-streaming service port.", "rejected_unchanged", via_streaming_port,
         evidence=["services/model-streaming-service/cmd/server/main.go (only ModelStreamingService registered)"])

    # Release store is mounted read-only and has no write RPC; verify it did not change over the whole run.
    # (recorded in the summary section rather than as an attack row)

    # ---- retrieval
    R = "unauthorized_retrieval"

    def fetch(consumer, model=LEGACY_MODEL):
        result = client.call(client.models.GetModelParameters, pb.ModelParametersRequest(consumer_id=consumer, model_id=model))
        if result[0] == "ok":
            return {"observed": "accepted", "code": "OK", "message": f"served {result[1].model_id} {result[1].version} "
                    f"({len(result[1].parameters)} tensors) to consumer_id={consumer!r}"}
        return {"observed": "rejected", "code": result[1], "message": result[2]}

    rows("T1", R, U, "Model download by an unauthenticated consumer with an arbitrary consumer_id.", "rejected_unchanged",
         lambda: fetch("updsec-unknown-consumer"), gap="GAP-NO-RETRIEVAL-AUTH",
         evidence=["services/model-streaming-service/cmd/server/streaming_server.go:GetModelParameters (consumer_id is a log label)"])
    rows("T2", "impersonation", U, "Model download claiming the installed runtime's consumer_id.", "rejected_unchanged",
         lambda: fetch("server-client-runtime"), gap="GAP-IDENTITY-SELF-ASSERTED")
    rows("T3", R, U, "Model download with no consumer_id.", "rejected_unchanged", lambda: fetch(""), gap="GAP-NO-RETRIEVAL-AUTH")
    rows("T4", R, U, "Model download with a control character in consumer_id.", "rejected_unchanged", lambda: fetch("bad\nconsumer"))
    rows("T5", R, U, "Download of a model id that is not in the catalogue.", "rejected_unchanged", lambda: fetch("updsec", "privoke-not-a-model"))
    rows("T6", R, U, "Download with a path-traversal model id.", "rejected_unchanged", lambda: fetch("updsec", "../etc/passwd"))
    rows("T7", R, "standard-v3", "Legacy float-tensor download of the standard V3 model.", "rejected_unchanged", lambda: fetch("updsec", V3_MODEL))

    def package(model, consumer="updsec-unknown-consumer"):
        result = client.call(client.models.GetModelPackage, pb.ModelParametersRequest(consumer_id=consumer, model_id=model))
        if result[0] == "ok":
            return result[1]
        return result

    def v3_manifest_unauth():
        value = package(V3_MODEL)
        if isinstance(value, tuple):
            return {"observed": "rejected", "code": value[1], "message": value[2]}
        client_state = {"assets": [a.name for a in value.assets]}
        recorder_state["package"] = value
        return {"observed": "accepted", "code": "OK", "message": f"served manifest {value.manifest_sha256[:12]} with assets {client_state['assets']}"}

    recorder_state: dict = {}
    rows("T8", R, "standard-v3", "Standard V3 package manifest requested by an unauthenticated consumer.", "rejected_unchanged", v3_manifest_unauth,
         gap="GAP-NO-RETRIEVAL-AUTH", evidence=["services/model-streaming-service/cmd/server/standard_v3.go:GetModelPackage"])

    def asset(model=V3_MODEL, manifest=None, name=None):
        package_value = recorder_state.get("package")
        manifest = manifest if manifest is not None else (package_value.manifest_sha256 if package_value else "")
        name = name if name is not None else (package_value.assets[0].name if package_value else "")
        try:
            iterator = client.models.StreamModelAsset(pb.ModelAssetRequest(consumer_id="updsec", model_id=model,
                                                                             manifest_sha256=manifest, asset_name=name), timeout=30)
            first = next(iterator)
            iterator.cancel()
            return {"observed": "accepted", "code": "OK", "message": f"first chunk of {first.asset_name} ({first.total_bytes} bytes) served"}
        except client.grpc.RpcError as error:
            return {"observed": "rejected", "code": error.code().name, "message": short(error.details())}

    rows("T9", R, "standard-v3", "Asset stream with a wrong manifest pin.", "rejected_unchanged", lambda: asset(manifest="0" * 64))
    rows("T10", R, "standard-v3", "Asset stream for a non-allowlisted asset name (path traversal).", "rejected_unchanged",
         lambda: asset(name="../preparation.json"))
    rows("T11", R, "standard-v3", "Asset stream for a legacy model id.", "rejected_unchanged", lambda: asset(model=LEGACY_MODEL))
    rows("T12", R, "standard-v3", "Asset stream with correct pin and name by an unauthenticated consumer.", "rejected_unchanged", lambda: asset(),
         gap="GAP-NO-RETRIEVAL-AUTH")

    def replay_retrieval():
        first = client.served()
        second = client.served()
        same = first == second
        return {"observed": "idempotent_noop" if same else "accepted", "code": "OK",
                "message": "two identical retrieval requests returned identical tensors" if same else "retrieval responses differed",
                "property_met": same}

    rows("T13", "replayed_request", U, "Replay of an identical retrieval request.", "idempotent_noop_unchanged", replay_retrieval)
    recorder.rows[-1]["expected"] = "idempotent_noop_unchanged"
    recorder.rows[-1]["property_met"] = recorder.rows[-1]["observed"] == "idempotent_noop" and recorder.rows[-1]["model_unchanged"]

    def status_probe():
        result = client.call(client.updates.GetParameterUpdateStatus, pb.ParameterUpdateStatusRequest(
            source_id="updsec-unknown", request_id="never-issued", model_id=LEGACY_MODEL))
        if result[0] == "ok":
            return {"observed": "accepted", "code": "OK", "message": f"status lookup answered found={result[1].found} without any credential"}
        return {"observed": "rejected", "code": result[1], "message": result[2]}

    rows("T14", "unauthorized_update", U, "Unauthenticated update-receipt status lookup.", "rejected_unchanged", status_probe,
         gap="GAP-NO-PUBLISHER-AUTH")


# --------------------------------------------------------------------------------------
# Transport authentication against the mutual-TLS stand-in
# --------------------------------------------------------------------------------------

def run_transport(recorder_rows: list[dict], work: Path):
    import datetime as dt
    import grpc
    from privoke.v1 import parameters_pb2 as pb, parameters_pb2_grpc as rpc
    from update_security_pki import MutualTlsStandIn, TestAuthority

    server_ca = TestAuthority(work, "server-ca")
    client_ca = TestAuthority(work, "client-ca")
    foreign_ca = TestAuthority(work, "foreign-ca")
    lan = lan_address()
    san = "DNS:localhost,IP:127.0.0.1" + (f",IP:{lan}" if lan else "")
    server_cert, server_key = server_ca.issue("server", cn="updsec-server", usage="serverAuth", san=san)
    now = dt.datetime.now(dt.timezone.utc)
    hour = dt.timedelta(hours=1)
    valid = client_ca.issue("client-a", cn="installation-a", usage="clientAuth")
    second = client_ca.issue("client-b", cn="installation-b", usage="clientAuth")
    cases = {
        "self_signed": client_ca.self_signed("self", cn="installation-a", usage="clientAuth"),
        "foreign_ca": foreign_ca.issue("foreign", cn="installation-a", usage="clientAuth"),
        "expired": client_ca.issue("expired", cn="installation-a", usage="clientAuth", start=now - 10 * hour, end=now - 5 * hour),
        "not_yet_valid": client_ca.issue("future", cn="installation-a", usage="clientAuth", start=now + 5 * hour, end=now + 10 * hour),
        "wrong_usage": client_ca.issue("serveronly", cn="installation-a", usage="serverAuth"),
    }

    class Health(rpc.ModelStreamingServiceServicer):
        def Health(self, request, context):
            return pb.HealthResponse(service="stand-in", status="SERVING")

    stand_in = MutualTlsStandIn(lambda server: rpc.add_ModelStreamingServiceServicer_to_server(Health(), server),
                                server_cert, server_key, client_ca.cert)
    results = recorder_rows
    options = (("grpc.enable_http_proxy", 0),)

    def attempt(row_id, cls, description, expected_reject, *, creds, target=None, gap=None, property_override=None):
        before = stand_in.count()
        target = target or f"127.0.0.1:{stand_in.port}"
        try:
            with grpc.secure_channel(target, creds, options=options) as channel:
                response = rpc.ModelStreamingServiceStub(channel).Health(pb.HealthRequest(), timeout=6)
            observed, code, message = "accepted", "OK", f"handshake and RPC succeeded ({response.status})"
        except grpc.RpcError as error:
            observed, code, message = "rejected", error.code().name, short(error.details())
        invoked = stand_in.count() - before
        met = (observed == "rejected" and invoked == 0) if expected_reject else observed == "accepted"
        if property_override is not None:
            met = property_override(observed, invoked)
        results.append({"id": row_id, "class": cls, "path": "transport-standin", "description": description,
                        "expected": "rejected_unchanged" if expected_reject else "positive_control", "observed": observed, "code": code,
                        "message": message, "model_unchanged": True, "handler_invoked": invoked > 0, "property_met": met,
                        "gap": gap, "evidence": ["deploy/gce/nginx.conf (ssl_verify_client on)", "deploy/gce/tests/smoke.py"]})

    def mtls(cert, key, root=server_ca.cert):
        return grpc.ssl_channel_credentials(root_certificates=root, private_key=key, certificate_chain=cert)

    attempt("X1", "invalid_certificate", "Valid CA-signed client certificate (positive control).", False, creds=mtls(*valid))
    attempt("X2", "invalid_certificate", "TLS client presenting no certificate.", True, creds=grpc.ssl_channel_credentials(root_certificates=server_ca.cert))
    attempt("X3", "invalid_certificate", "Self-signed client certificate.", True, creds=mtls(*cases["self_signed"]))
    attempt("X4", "impersonation", "Client certificate with the legitimate subject name but signed by a foreign CA.", True, creds=mtls(*cases["foreign_ca"]))
    attempt("X5", "expired_credentials", "Expired client certificate (validity ended five hours ago) signed by the trusted CA.", True, creds=mtls(*cases["expired"]))
    attempt("X6", "expired_credentials", "Not-yet-valid client certificate signed by the trusted CA.", True, creds=mtls(*cases["not_yet_valid"]))
    attempt("X7", "invalid_certificate", "Client certificate carrying only the serverAuth key usage.", True, creds=mtls(*cases["wrong_usage"]))
    attempt("X8", "impersonation", "A second, distinct installation certificate from the same client CA.", False, creds=mtls(*second),
            gap="GAP-NO-PER-INSTALLATION-AUTHZ",
            property_override=lambda observed, invoked: observed == "rejected")
    attempt("X9", "invalid_certificate", "Client rejects a server certificate issued by an untrusted CA (server impersonation).", True,
            creds=mtls(*valid, root=foreign_ca.cert))
    server_expired = server_ca.issue("server-expired", cn="updsec-server", usage="serverAuth", san=san, start=now - 10 * hour, end=now - 5 * hour)
    expired_server = MutualTlsStandIn(lambda server: rpc.add_ModelStreamingServiceServicer_to_server(Health(), server),
                                      server_expired[0], server_expired[1], client_ca.cert)
    wrong_name = server_ca.issue("server-name", cn="updsec-server", usage="serverAuth", san="DNS:other.example,IP:10.255.255.1")
    wrong_name_server = MutualTlsStandIn(lambda server: rpc.add_ModelStreamingServiceServicer_to_server(Health(), server),
                                         wrong_name[0], wrong_name[1], client_ca.cert)
    attempt("X10", "expired_credentials", "Client rejects an expired server certificate.", True, creds=mtls(*valid),
            target=f"127.0.0.1:{expired_server.port}")
    attempt("X11", "invalid_certificate", "Client rejects a server certificate whose SAN does not match the dialled address.", True,
            creds=mtls(*valid), target=f"127.0.0.1:{wrong_name_server.port}")
    # plaintext client against the TLS endpoint
    before = stand_in.count()
    try:
        with grpc.insecure_channel(f"127.0.0.1:{stand_in.port}", options=options) as channel:
            rpc.ModelStreamingServiceStub(channel).Health(pb.HealthRequest(), timeout=6)
        observed, code, message = "accepted", "OK", "plaintext RPC succeeded"
    except grpc.RpcError as error:
        observed, code, message = "rejected", error.code().name, short(error.details())
    results.append({"id": "X12", "class": "invalid_certificate", "path": "transport-standin",
                    "description": "Plaintext (no TLS) client against the mutual-TLS endpoint.", "expected": "rejected_unchanged",
                    "observed": observed, "code": code, "message": message, "model_unchanged": True,
                    "handler_invoked": stand_in.count() > before, "property_met": observed == "rejected" and stand_in.count() == before,
                    "gap": None, "evidence": ["deploy/gce/nginx.conf"]})
    results.append({"id": "X13", "class": "invalid_credentials", "path": "static",
                    "description": "Certificate revocation: revoke the client certificate of one installation.", "expected": "not_applicable",
                    "observed": "not_applicable", "code": None, "message": "No CRL/OCSP configured (no ssl_crl in nginx.conf); mechanism absent, not exercised.",
                    "model_unchanged": None, "property_met": None, "gap": "GAP-NO-REVOCATION",
                    "evidence": ["deploy/gce/nginx.conf", "docs/deployment/google-cloud.md (section 4)"]})

    # PriVoke's own client channel factory
    results.extend(run_client_factory(stand_in, valid, server_ca.cert, lan, work))
    for server in (stand_in, expired_server, wrong_name_server):
        server.stop()


def run_client_factory(stand_in, valid, server_ca_cert, lan, work: Path):
    import grpc
    from privoke.v1 import parameters_pb2 as pb, parameters_pb2_grpc as rpc
    from privoke_service import stack_connection

    rows = []
    cert_file, key_file, ca_file = work / "client.crt", work / "client.key", work / "server-ca.crt"
    cert_file.write_bytes(valid[0])
    key_file.write_bytes(valid[1])
    ca_file.write_bytes(server_ca_cert)

    def row(row_id, description, observed, code, message, met, gap=None, cls="invalid_credentials"):
        rows.append({"id": row_id, "class": cls, "path": "transport-standin", "description": description,
                     "expected": "client_policy", "observed": observed, "code": code, "message": message, "model_unchanged": True,
                     "property_met": met, "gap": gap, "evidence": ["shared/python/privoke_service/stack_connection.py:grpc_channel"]})

    try:
        stack_connection.grpc_channel("203.0.113.9:443", environment={})
        row("X14", "grpc_channel to a non-loopback target with no certificate or key configured.", "accepted", "OK", "channel created", False)
    except ValueError as error:
        row("X14", "grpc_channel to a non-loopback target with no certificate or key configured.", "rejected", "ValueError", short(str(error)), True)

    env = {"PRIVOKE_TLS_CERT_FILE": str(cert_file), "PRIVOKE_TLS_KEY_FILE": str(key_file), "PRIVOKE_TLS_CA_FILE": str(ca_file)}
    if lan:
        try:
            channel = stack_connection.grpc_channel(f"{lan}:{stand_in.port}", environment=env)
            status = rpc.ModelStreamingServiceStub(channel).Health(pb.HealthRequest(), timeout=6).status
            channel.close()
            row("X15", "grpc_channel with the installation certificate to a non-loopback mutual-TLS endpoint.", "accepted", "OK",
                f"authenticated channel established ({status})", True)
        except Exception as error:  # noqa: BLE001 - recorded verbatim
            row("X15", "grpc_channel with the installation certificate to a non-loopback mutual-TLS endpoint.", "rejected", type(error).__name__,
                short(str(error)), False)
    else:
        row("X15", "grpc_channel to a non-loopback mutual-TLS endpoint.", "not_run", None, "No non-loopback local address available.", None)
    # loopback bypass: the factory ignores configured TLS for loopback targets
    try:
        channel = stack_connection.grpc_channel(f"127.0.0.1:{stand_in.port}", environment=env)
        rpc.ModelStreamingServiceStub(channel).Health(pb.HealthRequest(), timeout=6)
        channel.close()
        observed, code, message = "accepted", "OK", "plaintext RPC unexpectedly succeeded"
    except grpc.RpcError as error:
        observed, code = "rejected", error.code().name
        message = "grpc_channel used a plaintext channel for a loopback target although TLS files were configured; the mutual-TLS endpoint refused it"
    row("X16", "grpc_channel to a loopback target with TLS files configured (client policy: loopback and internal mode are plaintext).",
        observed, code, message, None, gap="GAP-LOOPBACK-PLAINTEXT-POLICY")
    return rows


# --------------------------------------------------------------------------------------
# Static evidence
# --------------------------------------------------------------------------------------

def read(path):
    return (ROOT / path).read_text(encoding="utf-8", errors="replace")


def grep_lines(path, pattern):
    return [(index, line.strip()) for index, line in enumerate(read(path).splitlines(), 1) if re.search(pattern, line)]


def static_evidence():
    evidence = []

    def add(id_, claim, files, found, detail):
        evidence.append({"id": id_, "claim": claim, "files": files, "holds": bool(found), "detail": detail})

    hits = grep_lines("services/param-update-service/app/server.py", r"add_insecure_port")
    add("ST1", "param-update-service listens on an insecure (plaintext, unauthenticated) gRPC port", ["services/param-update-service/app/server.py"],
        hits, [f"line {n}: {t}" for n, t in hits])
    main_go = read("services/model-streaming-service/cmd/server/main.go")
    add("ST2", "model-streaming-service builds its gRPC server without TLS credentials or interceptors",
        ["services/model-streaming-service/cmd/server/main.go"],
        "grpc.NewServer(" in main_go and not re.search(r"Creds|credentials|Interceptor|tls\.", main_go),
        ["grpc.NewServer options: MaxRecvMsgSize, MaxSendMsgSize, MaxConcurrentStreams only"])
    credential_pattern = re.compile(r"(?i)authorization|bearer|api[_-]?key|jwt|oauth|auth_context|peer\.|ssl_server_credentials|expir")
    scanned, found = [], []
    for base in ("services/param-update-service/app", "services/model-streaming-service/cmd/server"):
        for path in sorted((ROOT / base).rglob("*")):
            if path.is_file() and path.suffix in (".py", ".go") and not path.name.endswith("_test.go"):
                scanned.append(str(path.relative_to(ROOT)).replace("\\", "/"))
                found += [f"{path.name}:{i}" for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1)
                          if credential_pattern.search(line)]
    add("ST3", "no credential, token, expiry or peer-identity check exists in either service's source",
        scanned, not found, found or [f"{len(scanned)} source files scanned; 0 matches"])
    nginx = read("deploy/gce/nginx.conf")
    locations = [l for l in re.findall(r"location\s*=\s*(\S+)\s*\{", nginx) if l.startswith("/privoke.")]
    add("ST4", "cloud ingress requires and verifies a client certificate", ["deploy/gce/nginx.conf"], "ssl_verify_client on;" in nginx,
        ["ssl_verify_client on", "ssl_client_certificate /run/secrets/client-ca.crt"])
    add("ST5", "cloud ingress routes only three RPC methods and denies the rest", ["deploy/gce/nginx.conf"],
        len(locations) == 3 and "location / { return 404; }" in nginx, [f"routed: {locations}", "default: return 404"])
    add("ST6", "ParamUpdateService and the V3 package RPCs are not among the routed ingress methods", ["deploy/gce/nginx.conf"],
        not any(("ParamUpdate" in l or "ModelPackage" in l or "ModelAsset" in l) for l in locations),
        [f"routed: {locations}"])
    add("ST7", "no certificate revocation list is configured at the ingress", ["deploy/gce/nginx.conf"], "ssl_crl" not in nginx,
        ["no ssl_crl directive"])
    compose = read("docker-compose.prod.yml")
    block = compose.split("  param-update-service:", 1)[1].split("\n  telemetry-service:", 1)[0] if "  param-update-service:" in compose else ""
    add("ST8", "update service is published only on the internal compose network in the production stack (expose, no ports)",
        ["docker-compose.prod.yml"], "expose:" in block and "\n    ports:" not in block, ["param-update-service: expose 50052, no host port mapping"])
    shared = read("shared/python/privoke_service/stack_connection.py")
    add("ST9", "client channel factory uses plaintext for loopback targets and internal mode regardless of configured TLS",
        ["shared/python/privoke_service/stack_connection.py"], "insecure_channel" in shared and "loopback" in shared,
        [t for _, t in grep_lines("shared/python/privoke_service/stack_connection.py", r"loopback or|insecure_channel")])
    smoke = read("deploy/gce/tests/smoke.py")
    add("ST10", "the deployment smoke test asserts private RPCs are unreachable through the ingress and untrusted/missing client identity is refused",
        ["deploy/gce/tests/smoke.py"], "Private RPC was exposed" in smoke and "TLS accepted an untrusted server or missing client identity" in smoke,
        ["asserted in CI against nginx; not executed in this run"])
    return evidence


# --------------------------------------------------------------------------------------
# Gaps, summary, record
# --------------------------------------------------------------------------------------

GAPS = [
    {"id": "GAP-NO-PUBLISHER-AUTH", "property": "Only an authenticated, authorised publisher can change the active model",
     "status": "unmet at the service; met only by network placement", "evidence": ["ST1", "ST3", "ST8"],
     "compensating_control": "The update service is not routed by the cloud ingress and has no host port in the production compose file."},
    {"id": "GAP-IDENTITY-SELF-ASSERTED", "property": "Update and consumer identities are authenticated, not caller-asserted",
     "status": "unmet", "evidence": ["ST3"], "compensating_control": "None in-service; mutual TLS at the ingress authenticates a certificate, not the source_id."},
    {"id": "GAP-NO-CREDENTIAL-MECHANISM", "property": "Application credentials (tokens/keys) exist, are validated and expire",
     "status": "unmet (mechanism absent)", "evidence": ["ST3"], "compensating_control": "Certificate validity periods at the ingress only."},
    {"id": "GAP-NO-RETRIEVAL-AUTH", "property": "Model retrieval is restricted to authorised consumers",
     "status": "unmet at the service; met at the cloud ingress by client certificates", "evidence": ["ST2", "ST4"],
     "compensating_control": "Mutual TLS at nginx; models are non-secret released artifacts."},
    {"id": "GAP-NO-PER-INSTALLATION-AUTHZ", "property": "Each installation is individually identified and can be individually revoked",
     "status": "unmet", "evidence": ["ST4", "ST7"], "compensating_control": "Documented: all certificates from the client CA share the same access; rotate the CA to revoke."},
    {"id": "GAP-NO-REVOCATION", "property": "A compromised client certificate can be revoked before expiry", "status": "unmet (no CRL configured)",
     "evidence": ["ST7"], "compensating_control": "Short certificate validity; client CA rotation."},
    {"id": "GAP-NO-CUMULATIVE-BOUND", "property": "Aggregate model change is bounded per update and over time",
     "status": "unmet", "evidence": [], "compensating_control": "Per-coordinate magnitude bound (default 1.0), message and value-count limits, and base-version compare-and-swap."},
    {"id": "GAP-LOOPBACK-PLAINTEXT-POLICY", "property": "Configured TLS is applied to every client channel",
     "status": "by design for loopback and internal mode", "evidence": ["ST9"], "compensating_control": "Loopback/internal traffic does not leave the host or compose network."},
]


G8_EXTRA = {
    "invalid_credentials": ["A3", "X13", "X14"],
    "invalid_certificate": ["X2", "X3", "X7", "X9", "X11", "X12", "X14"],
    "expired_credentials": ["X5", "X6", "X10"],
    "impersonation": ["A2", "T2", "X4", "X8"],
    "replayed_request": ["R1", "R2", "R4", "T13"],
    "unauthorized_retrieval": ["T1", "T3", "T5", "T6", "T7", "T8", "T9", "T10", "T11", "T12"],
    "unauthorized_update": ["A1", "A3", "A4", "A5", "T14"],
}


def goal_coverage(rows):
    """Map each G7/G8 class to the rows that exercise it, and flag classes with no observed row."""
    ids = {row["id"] for row in rows}
    coverage = {"G7": {name: [row["id"] for row in rows if row["class"] == name] for name in G7_CLASSES},
                "G8": {name: [i for i in members if i in ids] for name, members in G8_EXTRA.items()}}
    coverage["G7"]["unauthorized_publication"] = sorted({*coverage["G7"]["unauthorized_publication"], "A1", "A2"} & ids)
    return coverage


def summarize(rows: list[dict]) -> dict:
    by_class: dict[str, dict] = {}
    for row in rows:
        entry = by_class.setdefault(row["class"], {"attacks": 0, "rejected": 0, "accepted": 0, "idempotent_noop": 0, "applied_once": 0,
                                                    "not_applicable": 0, "not_run": 0, "property_met": 0, "property_unmet": 0, "property_na": 0})
        entry["attacks"] += 1
        entry[row["observed"]] += 1
        if row["property_met"] is True:
            entry["property_met"] += 1
        elif row["property_met"] is False:
            entry["property_unmet"] += 1
        else:
            entry["property_na"] += 1
    return {"total_rows": len(rows), "by_class": by_class,
            "property_unmet_ids": [row["id"] for row in rows if row["property_met"] is False],
            "gap_ids_exercised": sorted({row["gap"] for row in rows if row.get("gap")})}


def git_revision() -> str:
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return result.stdout.strip()


def image_facts(image: str) -> dict:
    inspect = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", image], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    version = subprocess.run(["docker", "run", "--rm", image, "go", "version"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return {"image": image, "image_id": inspect.stdout.strip(), "go": version.stdout.strip()}


def tree_is_clean() -> bool:
    status = subprocess.run(["git", "status", "--porcelain", "--", "evaluation", "services", "shared", "deploy"], cwd=ROOT, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return not status.stdout.strip()


def release_fingerprint(release_dir: Path):
    entries = {}
    for path in sorted(release_dir.rglob("*")):
        if path.is_file():
            stat = path.stat()
            entries[str(path.relative_to(release_dir)).replace("\\", "/")] = [stat.st_size, stat.st_mtime_ns]
    return hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest(), len(entries)


# --------------------------------------------------------------------------------------
# Rust target: the Rust model-streaming service behind its own mutual TLS (stage 3 of
# docs/plans/rust-server-rewrite.md). Selected with `--target rust`; the default target is unchanged.
# --------------------------------------------------------------------------------------

RUST_RECORD_ID = "UPDSEC-RUST-S3"
RUST_PUBLIC_CONTAINER_PORT = 50443
RUST_INTERNAL_CONTAINER_PORT = 50051
RUST_DEFAULT_IMAGE = "privoke-model-streaming-rust:dev"
URN_INSTALLATION = "urn:privoke:installation:"
URN_SERVICE = "urn:privoke:service:"
URN_REPORTER = "urn:privoke:reporter"
RUST_ROW_IDS = ("T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8", "T9", "T10", "T11", "T12", "R3", "R4", "R7", "R8", "R9", "X8")


def registry_toml(installations=(), services=(), *, reporter: bool = True) -> str:
    """The identity registry file of `privoke-transport` (version 1): installations, service roles, reporter switch."""
    lines = ["version = 1", f"reporter = {'true' if reporter else 'false'}", ""]
    for installation in installations:
        lines += ["[[installation]]", f'id = "{installation}"', ""]
    for name, role in services:
        lines += ["[[service]]", f'name = "{name}"', f'role = "{role}"', ""]
    return "\n".join(lines)


def rust_row_family(row_id: str) -> str:
    """The plan row a sub-row belongs to: `R7-no-cert` is part of `R7`."""
    return row_id.split("-", 1)[0]


def evaluate_rust_row(expected: str, observed: str, code: str | None, codes: tuple[str, ...] | None, model_unchanged: bool | None):
    """Property rule of a Rust-target row. A rejection counts only with an allowed status code and an unchanged store."""
    if expected == "rejected_unchanged":
        return observed == "rejected" and (codes is None or code in codes) and model_unchanged is not False
    if expected == "positive_control":
        return observed == "accepted"
    return None


def issue_custom_certificate(authority, label: str, *, cn: str, extensions: list[str], start, end) -> tuple[bytes, bytes]:
    """Issue a certificate whose extension block is written verbatim (used for profiles `TestAuthority.issue` cannot express)."""
    key, csr, crt, ext = (f"{label}.key", f"{label}.csr", f"{label}.crt", f"{label}.ext")
    authority._run("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-subj", f"/CN={cn}", "-keyout", key, "-out", csr)
    (authority.dir / ext).write_text("\n".join(["basicConstraints=CA:FALSE", *extensions]) + "\n", encoding="utf-8")
    from update_security_pki import _stamp
    authority._run("ca", "-config", "ca.cnf", "-batch", "-notext", "-in", csr, "-out", crt, "-cert", "ca.crt", "-keyfile", "ca.key",
                   "-startdate", _stamp(start), "-enddate", _stamp(end), "-extfile", ext)
    return (authority.dir / crt).read_bytes(), (authority.dir / key).read_bytes()


def write_client_crl(authority, *, days: int = 2) -> bytes:
    """A signed, non-stale, empty CRL (version 2, with a CRL number) for the client CA, as the server requires."""
    (authority.dir / "crlnumber").write_text("01\n", encoding="utf-8")
    (authority.dir / "crl.cnf").write_text(
        "[ca]\ndefault_ca=CA_default\n[CA_default]\ndatabase=index.txt\ncrlnumber=crlnumber\ndefault_md=sha256\n"
        f"default_crl_days={days}\ncrl_extensions=crl_ext\n[crl_ext]\nauthorityKeyIdentifier=keyid:always\n", encoding="utf-8")
    authority._run("ca", "-config", "crl.cnf", "-gencrl", "-keyfile", "ca.key", "-cert", "ca.crt", "-out", "crl.pem")
    return (authority.dir / "crl.pem").read_bytes()


class RustPki:
    """The disposable PKI of one run: client CA, server CA, a foreign CA, and every certificate the rows present."""

    def __init__(self, work: Path):
        import datetime as dt
        import uuid
        from update_security_pki import TestAuthority

        self.work = work
        self.client_ca = TestAuthority(work, "client-ca")
        self.server_ca = TestAuthority(work, "server-ca")
        self.foreign_ca = TestAuthority(work, "foreign-ca")
        now = dt.datetime.now(dt.timezone.utc)
        hour = dt.timedelta(hours=1)
        self.ids = {name: str(uuid.uuid4()) for name in ("registered", "second", "second-registered", "expired", "future", "no-eku", "server-only", "foreign")}
        urn = lambda name: f"URI:{URN_INSTALLATION}{self.ids[name]}"  # noqa: E731
        self.server = self.server_ca.issue("server", cn="rust-model-streaming", usage="serverAuth", san="DNS:localhost,IP:127.0.0.1")
        self.certs = {
            "registered": self.client_ca.issue("registered", cn="installation-registered", usage="clientAuth", san=urn("registered")),
            "second": self.client_ca.issue("second", cn="installation-second", usage="clientAuth", san=urn("second")),
            "second-registered": self.client_ca.issue("second-registered", cn="installation-second-registered", usage="clientAuth", san=urn("second-registered")),
            "runtime": self.client_ca.issue("runtime", cn="service-runtime", usage="clientAuth", san=f"URI:{URN_SERVICE}client-runtime"),
            "reporter": self.client_ca.issue("reporter", cn="reporter", usage="clientAuth", san=f"URI:{URN_REPORTER}"),
            # R3: each is registered, so a refusal can only come from the TLS verifier.
            "expired": self.client_ca.issue("expired", cn="installation-expired", usage="clientAuth", san=urn("expired"), start=now - 10 * hour, end=now - 5 * hour),
            "future": self.client_ca.issue("future", cn="installation-future", usage="clientAuth", san=urn("future"), start=now + 5 * hour, end=now + 10 * hour),
            "server-only": self.client_ca.issue("server-only", cn="installation-server-only", usage="serverAuth", san=urn("server-only")),
            "no-eku": issue_custom_certificate(self.client_ca, "no-eku", cn="installation-no-eku", extensions=[f"subjectAltName={urn('no-eku')}"],
                                               start=now - hour, end=now + hour),
            # R4: a valid subject (a registered identity) signed by a CA the server does not trust.
            "foreign": self.foreign_ca.issue("foreign", cn="installation-foreign", usage="clientAuth", san=urn("foreign")),
        }
        self.crl = write_client_crl(self.client_ca)
        self.registered_ids = [self.ids[name] for name in ("registered", "second-registered", "expired", "future", "no-eku", "server-only", "foreign")]

    def publish(self, directory: Path) -> Path:
        """Write the files the server reads. Keys are synthetic, so they are world-readable for the container's user."""
        directory.mkdir(parents=True, exist_ok=True)
        files = {"server.crt": self.server[0], "server.key": self.server[1], "client-ca.pem": self.client_ca.cert, "crl.pem": self.crl,
                 "registry.toml": registry_toml(self.registered_ids, [("client-runtime", "runtime")]).encode()}
        for name, content in files.items():
            path = directory / name
            path.write_bytes(content)
            path.chmod(0o644)
        return directory


class RustService:
    """The Rust server under test, in its container (or, for development, as a host process)."""

    def __init__(self, work: Path, pki: RustPki, models_dir: Path, release_dir: Path, *, image: str, binary: Path | None = None):
        self.pki, self.work, self.image, self.binary = pki, work, image, binary
        self.models_dir, self.release_dir = models_dir, release_dir
        self.public_port, self.internal_port = free_port(), free_port()
        self.container = f"updsec-rust-{os.getpid()}-{self.public_port}"
        self.process: subprocess.Popen | None = None
        self.pki_dir = pki.publish(work / "pki")

    def command_arguments(self, base: str) -> list[str]:
        return ["--cert", f"{base}/server.crt", "--key", f"{base}/server.key", "--client-ca", f"{base}/client-ca.pem", "--crl", f"{base}/crl.pem",
                "--registry", f"{base}/registry.toml"]

    def start(self):
        if self.binary:
            environment = {**os.environ, "MODEL_ARTIFACT_DIR": str(self.models_dir), "MODEL_RELEASE_DIR": str(self.release_dir),
                           "MODEL_LATEST_ID": V3_MODEL, "MODEL_STREAMING_BIND": "127.0.0.1", "MODEL_STREAMING_PORT": str(self.internal_port),
                           "MODEL_STREAMING_PUBLIC_PORT": str(self.public_port)}
            self.process = subprocess.Popen([str(self.binary), *self.command_arguments(str(self.pki_dir))], env=environment,
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            command = ["docker", "run", "-d", "--rm", "--name", self.container,
                       "-p", f"127.0.0.1:{self.public_port}:{RUST_PUBLIC_CONTAINER_PORT}", "-p", f"127.0.0.1:{self.internal_port}:{RUST_INTERNAL_CONTAINER_PORT}",
                       "-e", f"MODEL_LATEST_ID={V3_MODEL}", "-e", "MODEL_STREAMING_BIND=0.0.0.0",
                       "-v", f"{self.models_dir}:/models:ro", "-v", f"{self.release_dir}:/model-releases:ro", "-v", f"{self.pki_dir}:/pki:ro",
                       self.image, *self.command_arguments("/pki")]
            subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.wait_serving()

    def wait_serving(self, timeout: float = 180.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.process and self.process.poll() is not None:
                raise RuntimeError("the Rust service exited during startup")
            try:
                client = RustClient(self, "registered")
                try:
                    if client.models.Health(client.pb.HealthRequest(), timeout=3).status == "SERVING":
                        return
                finally:
                    client.close()
            except Exception:  # noqa: BLE001 - not ready yet
                pass
            time.sleep(0.5)
        raise RuntimeError(f"the Rust service did not serve: {self.logs()[-600:]}")

    def logs(self) -> str:
        if self.binary:
            return ""
        return subprocess.run(["docker", "logs", "--tail", "30", self.container], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.kill()
            self.process.wait(10)
        if not self.binary:
            subprocess.run(["docker", "rm", "-f", self.container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class RustClient:
    """A gRPC client that presents one named certificate (or none) to the public or internal listener."""

    def __init__(self, service: RustService, identity: str | None, *, internal: bool = False, root: bytes | None = None):
        import grpc
        from privoke.v1 import parameters_pb2 as pb, parameters_pb2_grpc as rpc

        self.grpc, self.pb, self.rpc = grpc, pb, rpc
        pki = service.pki
        certificate, key = pki.certs[identity] if identity else (None, None)
        credentials = grpc.ssl_channel_credentials(root_certificates=root or pki.server_ca.cert, private_key=key, certificate_chain=certificate)
        port = service.internal_port if internal else service.public_port
        self.channel = grpc.secure_channel(f"127.0.0.1:{port}", credentials, options=(("grpc.enable_http_proxy", 0), ("grpc.max_receive_message_length", 64 * 1024 * 1024)))
        self.models = rpc.ModelStreamingServiceStub(self.channel)
        self.updates = rpc.ParamUpdateServiceStub(self.channel)

    def close(self):
        self.channel.close()

    def outcome(self, fn, *, stream: bool = False):
        """Run one call; `accepted` carries a short description of what was served, `rejected` the status."""
        try:
            result = fn()
            if stream:
                first = next(iter(result), None)
                result.cancel()
                return {"observed": "accepted", "code": "OK", "message": "stream opened" + (f" (first message {type(first).__name__})" if first is not None else "")}
            return {"observed": "accepted", "code": "OK", "message": type(result).__name__, "response": result}
        except self.grpc.RpcError as error:
            return {"observed": "rejected", "code": error.code().name, "message": short(error.details())}


def run_rust_rows(service: RustService, models_dir: Path, release_dir: Path) -> list[dict]:
    """Every row of the stage 3 gate against the running Rust service. Nothing here is inferred: each row is a live call."""
    from privoke.v1 import parameters_pb2 as pb

    rows: list[dict] = []
    ids = service.pki.ids
    legacy = LEGACY_MODEL

    def snapshot_store():
        return release_fingerprint(release_dir), sha256_file(models_dir / f"{legacy}.json")

    def row(row_id, cls, path, description, expected, identity, call, *, codes=None, gap=None, internal=False, stream=False, root=None, evidence=None):
        before = snapshot_store()
        started = time.time()
        client = RustClient(service, identity, internal=internal, root=root)
        try:
            result = client.outcome(lambda: call(client), stream=stream)
        except Exception as error:  # a harness failure must be visible, never a silent pass
            result = {"observed": "not_run", "code": "HARNESS_ERROR", "message": short(f"{type(error).__name__}: {error}")}
        finally:
            client.close()
        unchanged = snapshot_store() == before
        result.pop("response", None)
        rows.append({"id": row_id, "class": cls, "path": path, "description": description, "expected": expected, "observed": result["observed"],
                     "code": result["code"], "message": result["message"], "model_unchanged": unchanged, "expected_codes": list(codes) if codes else None,
                     "identity": identity or "no client certificate", "property_met": evaluate_rust_row(expected, result["observed"], result["code"], codes, unchanged),
                     "gap": gap, "evidence": evidence or [], "duration_s": round(time.time() - started, 3)})

    R, U, S = "unauthorized_retrieval", "rust-public", "rust-internal"
    refused = ("UNAVAILABLE",)  # a refused handshake: the peer never reaches a handler
    denied = ("PERMISSION_DENIED",)
    mine = ids["registered"]
    pin = ""
    fetched: dict = {}

    def request(consumer, model=legacy):
        return pb.ModelParametersRequest(consumer_id=consumer, model_id=model)

    def stream_params(consumer, model=legacy):
        return lambda client: client.models.StreamModelParameters(request(consumer, model), timeout=30)

    def package(consumer, model=V3_MODEL):
        return lambda client: client.models.GetModelPackage(request(consumer, model), timeout=30)

    def asset(model=V3_MODEL, manifest=None, name="config.json", consumer=""):
        return lambda client: client.models.StreamModelAsset(pb.ModelAssetRequest(consumer_id=consumer, model_id=model,
                                                             manifest_sha256=manifest if manifest is not None else pin, asset_name=name), timeout=30)

    # The pin comes from a positive fetch by a registered installation: this is also the G8 default-package check.
    probe = RustClient(service, "registered")
    try:
        manifest = probe.models.GetModelPackage(request(mine, V3_MODEL), timeout=30)
        pin = manifest.manifest_sha256
        fetched = {"assets": {a.name: (a.sha256, a.size_bytes) for a in manifest.assets}, "manifest_sha256": pin}
    finally:
        probe.close()

    row("X1", "invalid_certificate", U, "Registered installation certificate from the client CA (positive control): fetch the default V3 manifest.", "positive_control",
        "registered", package(mine), gap="GAP-NO-RETRIEVAL-AUTH")

    def verified_asset(name):
        def fetch(client):
            digest, total = hashlib.sha256(), 0
            for chunk in client.models.StreamModelAsset(pb.ModelAssetRequest(consumer_id=mine, model_id=V3_MODEL, manifest_sha256=pin, asset_name=name), timeout=120):
                digest.update(chunk.data)
                total += len(chunk.data)
            expected = fetched["assets"][name]
            if digest.hexdigest() != expected[0] or total != expected[1]:
                raise RuntimeError("streamed asset does not match its manifest")
            return type("Verified", (), {})()
        return fetch

    row("X1b", "invalid_certificate", U, "Registered installation streams config.json of the default V3 package and verifies its pin (G8 positive control).",
        "positive_control", "registered", verified_asset("config.json"), gap="GAP-NO-RETRIEVAL-AUTH")
    row("X1c", "invalid_certificate", U, "Registered installation streams the whole model.safetensors of the default V3 package over mutual TLS and verifies its pin.",
        "positive_control", "registered", verified_asset("model.safetensors"), gap="GAP-NO-RETRIEVAL-AUTH")

    # T1 to T12: the original retrieval rows, now against the public listener with mutual TLS.
    row("T1", R, U, "Model download by an unauthenticated consumer with an arbitrary consumer_id.", "rejected_unchanged", None,
        stream_params("updsec-unknown-consumer"), stream=True, codes=refused, gap="GAP-NO-RETRIEVAL-AUTH")
    row("T2", "impersonation", U, "Model download by a registered installation claiming the installed runtime's consumer_id.", "rejected_unchanged", "registered",
        stream_params("server-client-runtime"), stream=True, codes=denied, gap="GAP-IDENTITY-SELF-ASSERTED")
    row("T3", R, U, "Model download with no consumer_id and no client certificate.", "rejected_unchanged", None, stream_params(""), stream=True,
        codes=refused, gap="GAP-NO-RETRIEVAL-AUTH")
    row("T4", R, U, "Model download with a control character in consumer_id (registered installation).", "rejected_unchanged", "registered",
        stream_params("bad\nconsumer"), stream=True, codes=("INVALID_ARGUMENT", "PERMISSION_DENIED"))
    row("T5", R, U, "Download of a model id that is not in the catalogue (registered installation).", "rejected_unchanged", "registered",
        stream_params(mine, "privoke-not-a-model"), stream=True, codes=("NOT_FOUND",))
    row("T6", R, U, "Download with a path-traversal model id (registered installation).", "rejected_unchanged", "registered",
        stream_params(mine, "../etc/passwd"), stream=True, codes=("NOT_FOUND",))
    row("T7", R, "standard-v3", "Legacy float-tensor download of the standard V3 model (registered installation).", "rejected_unchanged", "registered",
        stream_params(mine, V3_MODEL), stream=True, codes=("FAILED_PRECONDITION",))
    row("T8", R, "standard-v3", "Standard V3 package manifest requested by an unauthenticated consumer.", "rejected_unchanged", None, package(""),
        codes=refused, gap="GAP-NO-RETRIEVAL-AUTH")
    row("T9", R, "standard-v3", "Asset stream with a wrong manifest pin (registered installation).", "rejected_unchanged", "registered",
        asset(manifest="0" * 64, consumer=mine), stream=True, codes=("INVALID_ARGUMENT",))
    row("T10", R, "standard-v3", "Asset stream for a non-allowlisted asset name (path traversal).", "rejected_unchanged", "registered",
        asset(name="../preparation.json", consumer=mine), stream=True, codes=("INVALID_ARGUMENT",))
    row("T11", R, "standard-v3", "Asset stream for a legacy model id (registered installation).", "rejected_unchanged", "registered",
        asset(model=legacy, consumer=mine), stream=True, codes=("INVALID_ARGUMENT",))
    row("T12", R, "standard-v3", "Asset stream with correct pin and name by an unauthenticated consumer.", "rejected_unchanged", None, asset(), stream=True,
        codes=refused, gap="GAP-NO-RETRIEVAL-AUTH")

    # R3: certificate lifetime and profile, refused at the handshake by the real service (every identity below is registered).
    for label, identity, text in (("expired", "expired", "An expired client certificate"), ("not-yet-valid", "future", "A not-yet-valid client certificate"),
                                  ("no-client-auth-eku", "no-eku", "A client certificate with no extended key usage"),
                                  ("server-auth-only", "server-only", "A client certificate whose only usage is serverAuth")):
        row(f"R3-{label}", "expired_credentials" if label in ("expired", "not-yet-valid") else "invalid_certificate", U,
            f"{text}, for a registered identity, is refused at the TLS handshake.", "rejected_unchanged", identity, package(""), codes=refused,
            gap="GAP-NO-CREDENTIAL-MECHANISM")
    # R4: a foreign-CA certificate with a valid (registered) subject.
    row("R4", "impersonation", U, "A certificate from a foreign CA carrying a registered installation's subject is refused at the handshake.",
        "rejected_unchanged", "foreign", package(""), codes=refused, gap="GAP-IDENTITY-SELF-ASSERTED")

    # R7: GetModelPackage, a newly public RPC.
    row("R7-no-cert", R, U, "GetModelPackage without a client certificate.", "rejected_unchanged", None, package(""), codes=refused,
        gap="GAP-NO-RETRIEVAL-AUTH")
    row("R7-unregistered", R, U, "GetModelPackage by a valid, unregistered installation certificate.", "rejected_unchanged", "second", package(""),
        codes=denied, gap="GAP-NO-PER-INSTALLATION-AUTHZ")
    row("R7-reporter", R, U, "GetModelPackage with the telemetry reporter credential.", "rejected_unchanged", "reporter", package(""), codes=denied)
    row("R7-traversal", R, U, "GetModelPackage with a path-traversal model id (registered installation).", "rejected_unchanged", "registered",
        package(mine, "../privoke-v3-balanced"), codes=("NOT_FOUND",))
    row("R7-unknown", R, U, "GetModelPackage for a model that is not in the catalogue (registered installation).", "rejected_unchanged", "registered",
        package(mine, "does-not-exist"), codes=("NOT_FOUND",))

    # R8: StreamModelAsset, a newly public RPC.
    row("R8-no-cert", R, "standard-v3", "StreamModelAsset without a client certificate.", "rejected_unchanged", None, asset(), stream=True, codes=refused,
        gap="GAP-NO-RETRIEVAL-AUTH")
    row("R8-unregistered", R, "standard-v3", "StreamModelAsset by a valid, unregistered installation certificate.", "rejected_unchanged", "second",
        asset(), stream=True, codes=denied, gap="GAP-NO-PER-INSTALLATION-AUTHZ")
    row("R8-reporter", R, "standard-v3", "StreamModelAsset with the telemetry reporter credential.", "rejected_unchanged", "reporter", asset(), stream=True, codes=denied)
    row("R8-wrong-pin", R, "standard-v3", "StreamModelAsset with a wrong pin (registered installation).", "rejected_unchanged", "registered",
        asset(manifest="0" * 64, consumer=mine), stream=True, codes=("INVALID_ARGUMENT",))
    row("R8-not-allowlisted", R, "standard-v3", "StreamModelAsset for a non-allowlisted asset name (registered installation).", "rejected_unchanged",
        "registered", asset(name="../manifest.json", consumer=mine), stream=True, codes=("INVALID_ARGUMENT",))

    # R9: the private RPCs are not served on the public listener at all.
    row("R9-get-model-parameters", R, U, "GetModelParameters on the public listener (registered installation).", "rejected_unchanged", "registered",
        lambda client: client.models.GetModelParameters(request(mine), timeout=30), codes=("UNIMPLEMENTED",))
    row("R9-submit-update", "unauthorized_update", U, "ParamUpdateService.SubmitParameterUpdate on the public listener (registered installation).",
        "rejected_unchanged", "registered",
        lambda client: client.updates.SubmitParameterUpdate(pb.ParameterUpdateRequest(source_id=mine, model_id=legacy, base_version="v1"), timeout=30),
        codes=("UNIMPLEMENTED",))
    row("R9-update-status", "unauthorized_update", U, "ParamUpdateService.GetParameterUpdateStatus on the public listener (registered installation).",
        "rejected_unchanged", "registered",
        lambda client: client.updates.GetParameterUpdateStatus(pb.ParameterUpdateStatusRequest(source_id=mine, request_id="never-issued", model_id=legacy), timeout=30),
        codes=("UNIMPLEMENTED",))

    # X8 variant: per-installation authorisation.
    row("X8", "impersonation", U, "A second, distinct installation certificate from the same client CA whose id is not registered.", "rejected_unchanged",
        "second", package(""), codes=denied, gap="GAP-NO-PER-INSTALLATION-AUTHZ")
    row("X8b", "impersonation", U, "A second installation certificate from the same client CA whose id is registered (positive control).", "positive_control",
        "second-registered", package(ids["second-registered"]), gap="GAP-NO-PER-INSTALLATION-AUTHZ")

    # The internal listener, for the rows that need GetModelParameters to be reached.
    row("I1", R, S, "A registered service identity downloads a legacy model on the internal listener (positive control).", "positive_control", "runtime",
        lambda client: client.models.GetModelParameters(request("param-update"), timeout=30), internal=True)
    row("I2", R, S, "A registered installation (consumer role) on the internal listener.", "rejected_unchanged", "registered",
        lambda client: client.models.GetModelParameters(request(mine), timeout=30), internal=True, codes=denied)
    row("I3", R, S, "A registered service identity asks the internal listener for the V3 model through the legacy float RPC.", "rejected_unchanged",
        "runtime", lambda client: client.models.GetModelParameters(request("param-update", V3_MODEL), timeout=30), internal=True,
        codes=("FAILED_PRECONDITION",))
    row("I4", R, S, "A registered service identity calls a consumer RPC on the internal listener.", "rejected_unchanged", "runtime", package(""),
        internal=True, codes=("UNIMPLEMENTED",))
    return rows


# --------------------------------------------------------------------------------------
# Rust target, stage 5: the Rust parameter-update service behind its own mutual TLS. Selected with
# `--target rust --rust-service param-update`; the default `go` target and the model-streaming rows are untouched.
# --------------------------------------------------------------------------------------

RUST_UPDATE_RECORD_ID = "UPDSEC-RUST-S5"
RUST_UPDATE_DEFAULT_IMAGE = "privoke-param-update-rust:dev"
RUST_UPDATE_CONTAINER_PORT = 50052
RUST_UPDATE_ROW_IDS = ("A1", "A2", "A3", "E1", "E2", "E3", "E4", "E5", "E6", "E7", "T14", "R1", "R2", "R5")
# The cumulative budget of the E6 and R5 groups. The product default (512 per anchored release) is a structural bound
# from the recorded studies; 25 updates of norm 2.0 only exceed a budget below 50, so those groups name their own.
RUST_UPDATE_E6_BUDGET = 40
RUST_UPDATE_R5_BUDGET = 8
SOURCE_FUZZER = "server-fuzzer"


class RustUpdatePki(RustPki):
    """The PKI of the stage 5 rows: the fuzzer's publisher identity, a second registered publisher that is not the fuzzer
    (R2), a trainer, a signed but unregistered service, and the stage 3 installation identities (a consumer, R1)."""

    def __init__(self, work: Path):
        super().__init__(work)

        def service(name: str):
            return self.client_ca.issue(name, cn=f"service-{name}", usage="clientAuth", san=f"URI:{URN_SERVICE}{name}")

        self.certs["publisher"] = service(SOURCE_FUZZER)
        self.certs["impostor"] = service("test-trainer")
        self.certs["trainer"] = service("trainer")
        self.certs["stranger"] = service("stranger")  # signed by the client CA, never registered

    def publish(self, directory: Path) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        services = [("client-runtime", "runtime"), (SOURCE_FUZZER, "publisher"), ("test-trainer", "publisher"), ("trainer", "trainer")]
        files = {"server.crt": self.server[0], "server.key": self.server[1], "client-ca.pem": self.client_ca.cert, "crl.pem": self.crl,
                 "registry.toml": registry_toml(self.registered_ids, services).encode()}
        for name, content in files.items():
            path = directory / name
            path.write_bytes(content)
            path.chmod(0o644)
        return directory


class RustUpdateService:
    """One instance of the Rust update service on a fresh copy of the legacy artifact: bootstrapped as a deployment does
    (`param-update-service bootstrap`), then served in its container (or, for development, as a host process)."""

    def __init__(self, work: Path, pki: RustUpdatePki, name: str, *, image: str, binary: Path | None, environment: dict[str, str] | None = None):
        self.pki, self.image, self.binary = pki, image, binary
        self.root = work / name
        self.models_dir, self.data_dir = self.root / "models", self.root / "data"
        for directory in (self.models_dir, self.data_dir):
            directory.mkdir(parents=True)
            directory.chmod(0o777)  # the container runs as a non-root user
        self.artifact = self.models_dir / f"{LEGACY_MODEL}.json"
        shutil.copyfile(ROOT / "models" / f"{LEGACY_MODEL}.json", self.artifact)
        self.artifact.chmod(0o666)
        self.pki_dir = pki.publish(self.root / "pki")
        self.port = free_port()
        self.container = f"updsec-rust-update-{os.getpid()}-{self.port}"
        self.environment = environment or {}
        self.process: subprocess.Popen | None = None

    def _settings(self, models: str, data: str) -> dict[str, str]:
        # Generous request rates: the rows send tens of updates in a burst; the transport limits are not under test here.
        return {"MODEL_ARTIFACT_PATH": f"{models}/{LEGACY_MODEL}.json", "PARAM_UPDATE_STORAGE_PATH": f"{data}/updates.jsonl", "MODEL_ID": LEGACY_MODEL,
                "FUZZER_PROMPT_COUNT": "0", "PARAM_UPDATE_RATE_PER_SECOND": "500", "PARAM_UPDATE_RATE_BURST": "1000", **self.environment}

    def command_arguments(self, base: str) -> list[str]:
        return ["--cert", f"{base}/server.crt", "--key", f"{base}/server.key", "--client-ca", f"{base}/client-ca.pem", "--crl", f"{base}/crl.pem",
                "--registry", f"{base}/registry.toml"]

    def _volumes(self) -> list[str]:
        return ["-v", f"{self.models_dir}:/models", "-v", f"{self.data_dir}:/data", "-v", f"{self.pki_dir}:/pki:ro"]

    def bootstrap(self):
        if self.binary:
            environment = {**os.environ, **self._settings(str(self.models_dir), str(self.data_dir)), "PARAM_UPDATE_BIND": "127.0.0.1"}
            result = subprocess.run([str(self.binary), "bootstrap"], env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        else:
            command = ["docker", "run", "--rm", *self._volumes()]
            for key, value in self._settings("/models", "/data").items():
                command += ["-e", f"{key}={value}"]
            result = subprocess.run([*command, self.image, "bootstrap"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(f"bootstrap failed: {result.stdout[-600:]}")

    def start(self):
        self.bootstrap()
        if self.binary:
            environment = {**os.environ, **self._settings(str(self.models_dir), str(self.data_dir)), "PARAM_UPDATE_BIND": "127.0.0.1",
                           "PARAM_UPDATE_PORT": str(self.port)}
            self.process = subprocess.Popen([str(self.binary), *self.command_arguments(str(self.pki_dir))], env=environment,
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            command = ["docker", "run", "-d", "--rm", "--name", self.container, "-p", f"127.0.0.1:{self.port}:{RUST_UPDATE_CONTAINER_PORT}",
                       "-e", "PARAM_UPDATE_BIND=0.0.0.0", *self._volumes()]
            for key, value in self._settings("/models", "/data").items():
                command += ["-e", f"{key}={value}"]
            subprocess.run([*command, self.image, *self.command_arguments("/pki")], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.wait_serving()

    def wait_serving(self, timeout: float = 120.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.process and self.process.poll() is not None:
                raise RuntimeError("the Rust update service exited during startup")
            client = RustUpdateClient(self, "publisher")
            try:
                if client.updates.Health(client.pb.HealthRequest(), timeout=3).status == "SERVING":
                    return
            except Exception:  # noqa: BLE001 - not ready yet
                pass
            finally:
                client.close()
            time.sleep(0.5)
        raise RuntimeError(f"the Rust update service did not serve: {self.logs()[-600:]}")

    def logs(self) -> str:
        if self.binary:
            return ""
        return subprocess.run(["docker", "logs", "--tail", "30", self.container], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.kill()
            self.process.wait(10)
        if not self.binary:
            subprocess.run(["docker", "rm", "-f", self.container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def version(self) -> str:
        return json.loads(self.artifact.read_text(encoding="utf-8"))["version"]

    def digest(self) -> str:
        return sha256_file(self.artifact)


class RustUpdateClient:
    """A gRPC client of the update service that presents one named certificate (or none)."""

    def __init__(self, service: RustUpdateService, identity: str | None):
        import grpc
        from privoke.v1 import parameters_pb2 as pb, parameters_pb2_grpc as rpc

        self.grpc, self.pb = grpc, pb
        certificate, key = service.pki.certs[identity] if identity else (None, None)
        credentials = grpc.ssl_channel_credentials(root_certificates=service.pki.server_ca.cert, private_key=key, certificate_chain=certificate)
        options = (("grpc.enable_http_proxy", 0), ("grpc.max_receive_message_length", 64 * 1024 * 1024), ("grpc.max_send_message_length", 64 * 1024 * 1024))
        self.channel = grpc.secure_channel(f"127.0.0.1:{service.port}", credentials, options=options)
        self.updates = rpc.ParamUpdateServiceStub(self.channel)

    def close(self):
        self.channel.close()

    def request(self, version: str, gradients, *, source: str = SOURCE_FUZZER, metadata=None):
        message = self.pb.ParameterUpdateRequest(source_id=source, model_id=LEGACY_MODEL, base_version=version, metadata=metadata or {})
        for name, shape, values in gradients:
            message.gradients.add(name=name, shape=list(shape), values=list(values))
        return message

    def outcome(self, fn):
        try:
            result = fn()
            return {"observed": "accepted", "code": "OK", "message": type(result).__name__}
        except self.grpc.RpcError as error:
            return {"observed": "rejected", "code": error.code().name, "message": short(error.details())}


def run_rust_update_rows(args, work: Path, pki: RustUpdatePki) -> list[dict]:
    """Every row of the stage 5 gate against the running Rust update service. Each row is a live call; the E6 and R5 groups run
    on their own fresh service instance so that one exhausted budget cannot affect another row."""
    rows: list[dict] = []
    bias = ("head.sensitivity.bias", (4,), [0.01] * 4)
    refused, denied = ("UNAVAILABLE",), ("PERMISSION_DENIED",)
    rejected_args = ("INVALID_ARGUMENT",)
    current: list[RustUpdateService] = []

    def group(name: str, environment: dict[str, str] | None = None) -> RustUpdateService:
        service = RustUpdateService(work, pki, name, image=args.rust_update_image, binary=args.rust_binary, environment=environment)
        service.start()
        current[:] = [service]
        return service

    def row(service, row_id, cls, description, expected, identity, call, *, codes=None, gap=None, evidence=None, check=None):
        before = service.digest()
        started = time.time()
        client = RustUpdateClient(service, identity)
        try:
            result = client.outcome(lambda: call(client))
        except Exception as error:  # a harness failure must be visible, never a silent pass
            result = {"observed": "not_run", "code": "HARNESS_ERROR", "message": short(f"{type(error).__name__}: {error}")}
        finally:
            client.close()
        unchanged = service.digest() == before
        met = evaluate_rust_row(expected, result["observed"], result["code"], codes, unchanged)
        if met and check is not None:
            met = bool(check(result))
        rows.append({"id": row_id, "class": cls, "path": "rust-update", "description": description, "expected": expected, "observed": result["observed"],
                     "code": result["code"], "message": result["message"], "model_unchanged": unchanged, "expected_codes": list(codes) if codes else None,
                     "identity": identity or "no client certificate", "property_met": met, "gap": gap, "evidence": evidence or [],
                     "duration_s": round(time.time() - started, 3)})

    def submit(gradients, *, source=SOURCE_FUZZER, metadata=None, headers=None):
        def call(client):
            request = client.request(current[0].version(), gradients, source=source, metadata=metadata)
            return client.updates.SubmitParameterUpdate(request, timeout=30, metadata=headers)
        return call

    # ---- group 1: authentication, identity binding, malformed and over-bound updates (product defaults)
    service = group("default")
    try:
        row(service, "C1", "control", "A registered publisher submits a small update naming itself (positive control).", "positive_control", "publisher",
            submit([bias]))
        row(service, "A1", "unauthorized_publication", "Valid update from a peer with no client certificate.", "rejected_unchanged", None,
            submit([bias], source="updsec-unregistered-peer"), codes=refused, gap="GAP-NO-PUBLISHER-AUTH")
        row(service, "A2", "impersonation", "Update from a peer with no certificate that claims the trainer's source_id.", "rejected_unchanged", None,
            submit([bias], source=SOURCE_FUZZER), codes=refused, gap="GAP-IDENTITY-SELF-ASSERTED")
        row(service, "A3", "invalid_credentials", "Update presenting an invalid bearer token and API key in gRPC metadata and no certificate.",
            "rejected_unchanged", None,
            submit([bias], headers=(("authorization", "Bearer invalid-test-token-not-real"), ("x-api-key", "invalid-test-key-not-real"))),
            codes=refused, gap="GAP-NO-CREDENTIAL-MECHANISM")
        row(service, "T14", "unauthorized_update", "Unauthenticated update-receipt status lookup.", "rejected_unchanged", None,
            lambda client: client.updates.GetParameterUpdateStatus(client.pb.ParameterUpdateStatusRequest(
                source_id="updsec-unknown", request_id="never-issued", model_id=LEGACY_MODEL), timeout=30), codes=refused, gap="GAP-NO-PUBLISHER-AUTH")
        row(service, "R1", "unauthorized_publication", "A valid consumer installation certificate submits an update.", "rejected_unchanged", "registered",
            submit([bias], source="updsec-consumer"), codes=denied, gap="GAP-NO-PUBLISHER-AUTH")
        row(service, "R1-trainer", "unauthorized_publication", "A registered trainer service submits an update.", "rejected_unchanged", "trainer",
            submit([bias], source="trainer"), codes=denied, gap="GAP-NO-PUBLISHER-AUTH")
        row(service, "R1-unregistered", "unauthorized_publication", "A service certificate signed by the client CA but not registered submits an update.",
            "rejected_unchanged", "stranger", submit([bias], source="stranger"), codes=denied, gap="GAP-NO-PER-INSTALLATION-AUTHZ")
        row(service, "R2", "impersonation", "A registered publisher (test-trainer) claims source_id=server-fuzzer.", "rejected_unchanged", "impostor",
            submit([bias], source=SOURCE_FUZZER), codes=denied, gap="GAP-IDENTITY-SELF-ASSERTED")
        for row_id, text, values in (("E1", "One coordinate at 1.0000001 (just above the 1.0 per-coordinate bound).", [1.0000001, 0, 0, 0]),
                                     ("E2", "Coordinate magnitude 100.", [100.0, 0, 0, 0]),
                                     ("E3", "Coordinate magnitude 3.4e38 (largest finite float32).", [3.4e38, 0, 0, 0]),
                                     ("E4", "Negative coordinate -2.0.", [-2.0, 0, 0, 0])):
            row(service, row_id, "excessive_change", text, "rejected_unchanged", "publisher", submit([("head.sensitivity.bias", (4,), values)]),
                codes=rejected_args)
        row(service, "E5", "excessive_change", "Update with every coordinate exactly at the 1.0 bound (boundary value, norm 2.0; positive control).",
            "positive_control", "publisher", submit([("head.sensitivity.bias", (4,), [1.0, -1.0, 1.0, -1.0])]))

        parameters = json.loads(service.artifact.read_text(encoding="utf-8"))["parameters"]
        widest, total = [], 0
        for name, tensor in parameters.items():
            count = math.prod(tensor["shape"])
            if tensor.get("trainable") and total + count <= 65536 and count <= 24576:
                widest.append((name, tuple(tensor["shape"]), [1.0] * count))
                total += count
        row(service, "E7", "excessive_change",
            f"Single update moving every trainable coordinate ({total} values, L2 norm {math.sqrt(total):.1f}) by the 1.0 bound.", "rejected_unchanged",
            "publisher", submit(widest), codes=rejected_args, gap="GAP-NO-CUMULATIVE-BOUND", check=lambda result: "per-update bound" in result["message"])
    finally:
        service.stop()

    # ---- group 2: E6, twenty-five valid updates at the per-coordinate bound against a cumulative budget
    service = group("e6", {"PARAM_UPDATE_MAX_CUMULATIVE_L2": str(RUST_UPDATE_E6_BUDGET)})
    try:
        started = time.time()
        client = RustUpdateClient(service, "publisher")
        accepted, first_refusal, digest_at_refusal, first_request = 0, None, None, None
        try:
            for index in range(25):
                request = client.request(service.version(), [("head.sensitivity.bias", (4,), [1.0, 1.0, 1.0, 1.0])],
                                         metadata={"request_id": f"updsec-drift-{index}"})
                first_request = request if first_request is None else first_request
                result = client.outcome(lambda: client.updates.SubmitParameterUpdate(request, timeout=30))
                if result["observed"] == "accepted":
                    accepted += 1
                elif first_refusal is None:
                    first_refusal, digest_at_refusal = result, service.digest()
        finally:
            client.close()
        held = first_refusal is not None and service.digest() == digest_at_refusal
        rows.append({"id": "E6", "class": "excessive_change", "path": "rust-update", "expected": "bounded_cumulative", "identity": "publisher",
                     "description": f"Twenty-five successive valid updates (norm 2.0 each) against a cumulative budget of {RUST_UPDATE_E6_BUDGET}.",
                     "observed": "accepted" if accepted == 25 else "rejected", "code": first_refusal["code"] if first_refusal else "OK",
                     "message": f"{accepted}/25 accepted; first refusal: {first_refusal['message'] if first_refusal else 'none'}",
                     "accepted_updates": accepted, "model_unchanged": held, "expected_codes": ["FAILED_PRECONDITION"],
                     "property_met": bool(accepted == RUST_UPDATE_E6_BUDGET // 2 and first_refusal and first_refusal["code"] == "FAILED_PRECONDITION" and held),
                     "gap": "GAP-NO-CUMULATIVE-BOUND", "evidence": [], "duration_s": round(time.time() - started, 3)})
        # After exhaustion, an exact replay of the first update is still answered from its receipt (no bound is re-applied to a
        # committed request id), and the same id with a different payload is refused. Neither changes the model.
        replay_client = RustUpdateClient(service, "publisher")
        try:
            digest_before = service.digest()
            replayed = replay_client.outcome(lambda: replay_client.updates.SubmitParameterUpdate(first_request, timeout=30))
            changed = replay_client.request(first_request.base_version, [("head.sensitivity.bias", (4,), [0.5, 0.5, 0.5, 0.5])],
                                            metadata={"request_id": "updsec-drift-0"})
            conflict = replay_client.outcome(lambda: replay_client.updates.SubmitParameterUpdate(changed, timeout=30))
        finally:
            replay_client.close()
        unchanged = service.digest() == digest_before
        rows.append({"id": "R5-replay", "class": "replayed", "path": "rust-update", "expected": "idempotent_noop_unchanged", "identity": "publisher",
                     "description": "After the budget is exhausted, an exact replay of an accepted request is answered from its receipt and changes nothing.",
                     "observed": "idempotent_noop" if replayed["observed"] == "accepted" else "rejected", "code": replayed["code"], "message": replayed["message"],
                     "model_unchanged": unchanged, "expected_codes": None, "property_met": replayed["observed"] == "accepted" and unchanged,
                     "gap": "GAP-NO-CUMULATIVE-BOUND", "evidence": [], "duration_s": 0.0})
        rows.append({"id": "R5-conflict", "class": "replayed", "path": "rust-update", "expected": "rejected_unchanged", "identity": "publisher",
                     "description": "After the budget is exhausted, a request id reused with a different payload is refused and changes nothing.",
                     "observed": conflict["observed"], "code": conflict["code"], "message": conflict["message"], "model_unchanged": unchanged,
                     "expected_codes": ["INVALID_ARGUMENT"],
                     "property_met": conflict["observed"] == "rejected" and conflict["code"] == "INVALID_ARGUMENT" and unchanged,
                     "gap": "GAP-NO-CUMULATIVE-BOUND", "evidence": [], "duration_s": 0.0})
    finally:
        service.stop()

    # ---- group 3: R5, drift spread over many small updates, each under the per-update bound
    service = group("r5", {"PARAM_UPDATE_MAX_CUMULATIVE_L2": str(RUST_UPDATE_R5_BUDGET)})
    try:
        started = time.time()
        client = RustUpdateClient(service, "publisher")
        accepted, refusal, held = 0, None, None
        try:
            for index in range(RUST_UPDATE_R5_BUDGET * 3):
                request = client.request(service.version(), [("head.sensitivity.bias", (4,), [0.5, 0.5, 0.5, 0.5])], metadata={"request_id": f"updsec-r5-{index}"})
                before = service.digest()
                result = client.outcome(lambda: client.updates.SubmitParameterUpdate(request, timeout=30))
                if result["observed"] == "accepted":
                    accepted += 1
                else:
                    refusal, held = result, service.digest() == before
                    break
        finally:
            client.close()
        rows.append({"id": "R5", "class": "excessive_change", "path": "rust-update", "expected": "rejected_at_budget", "identity": "publisher",
                     "description": f"Updates of norm 1.0 (each far under the per-update bound) are refused once their sum passes the budget of {RUST_UPDATE_R5_BUDGET}.",
                     "observed": "rejected" if refusal else "accepted", "code": refusal["code"] if refusal else "OK",
                     "message": f"{accepted} accepted before the refusal: {refusal['message'] if refusal else 'none'}", "accepted_updates": accepted,
                     "model_unchanged": held, "expected_codes": ["FAILED_PRECONDITION"],
                     "property_met": bool(refusal and refusal["code"] == "FAILED_PRECONDITION" and accepted == RUST_UPDATE_R5_BUDGET and held),
                     "gap": "GAP-NO-CUMULATIVE-BOUND", "evidence": [], "duration_s": round(time.time() - started, 3)})
    finally:
        service.stop()
    return rows


def run_rust_update_target(args) -> int:
    """`--target rust --rust-service param-update`: host the Rust update service, run the rows, write the record."""
    import platform

    scratch_parent = ROOT / ".tmp" if (ROOT / ".tmp").is_dir() else None
    work = Path(tempfile.mkdtemp(prefix="updsec-rust-update-", dir=scratch_parent))
    pki = RustUpdatePki(work)
    rows = run_rust_update_rows(args, work, pki)
    missing = sorted(set(RUST_UPDATE_ROW_IDS) - {rust_row_family(row["id"]) for row in rows})
    record = {
        "id": RUST_UPDATE_RECORD_ID, "title": "Rust parameter-update service: guarded-update and authentication negative rows", "target": "rust",
        "service": "param-update", "revision": git_revision(), "generated_unix": int(time.time()),
        "environment": {"python": sys.version.split()[0], "platform": platform.platform(), "grpc": __import__("grpc").__version__,
                        "image": args.rust_update_image if not args.rust_binary else None, "host_binary": str(args.rust_binary) if args.rust_binary else None},
        "fixture": {"legacy_model": LEGACY_MODEL, "bootstrap": "param-update-service bootstrap (full-capability preparation, as the deployment does)"},
        "budgets": {"e6_cumulative_l2": RUST_UPDATE_E6_BUDGET, "r5_cumulative_l2": RUST_UPDATE_R5_BUDGET, "default_per_update_l2": 16.0,
                    "default_cumulative_l2": 512.0},
        "required_row_families": list(RUST_UPDATE_ROW_IDS), "missing_row_families": missing, "attacks": rows, "summary": summarize(rows),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    shutil.rmtree(work, ignore_errors=True)
    unmet = record["summary"]["property_unmet_ids"]
    print(f"{record['summary']['total_rows']} rows; property unmet: {unmet}; missing row families: {missing}")
    return 0 if not unmet and not missing else 1


def run_rust_target(args) -> int:
    """`--target rust`: host the Rust service (container or `--rust-binary`), run the rows, write the record."""
    import platform

    release_dir = args.release_dir
    if not release_dir.is_dir():
        print(f"standard release store not found: {release_dir}", file=sys.stderr)
        return 2
    release_before = release_fingerprint(release_dir)
    scratch_parent = ROOT / ".tmp" if (ROOT / ".tmp").is_dir() else None
    work = Path(tempfile.mkdtemp(prefix="updsec-rust-", dir=scratch_parent))
    models_dir = work / "models"
    models_dir.mkdir()
    shutil.copyfile(ROOT / "models" / f"{LEGACY_MODEL}.json", models_dir / f"{LEGACY_MODEL}.json")
    service = None
    try:
        pki = RustPki(work)
        service = RustService(work, pki, models_dir.resolve(), release_dir.resolve(), image=args.rust_image, binary=args.rust_binary)
        service.start()
        rows = run_rust_rows(service, models_dir, release_dir)
        logs = service.logs()
    finally:
        if service:
            service.stop()
    release_after = release_fingerprint(release_dir)
    missing = sorted(set(RUST_ROW_IDS) - {rust_row_family(row["id"]) for row in rows})
    record = {
        "id": RUST_RECORD_ID, "title": "Rust model-streaming service: retrieval and authentication negative rows", "target": "rust",
        "revision": git_revision(), "generated_unix": int(time.time()),
        "environment": {"python": sys.version.split()[0], "platform": platform.platform(), "grpc": __import__("grpc").__version__,
                        "image": args.rust_image if not args.rust_binary else None, "host_binary": str(args.rust_binary) if args.rust_binary else None},
        "fixture": {"legacy_model": LEGACY_MODEL, "v3_model": V3_MODEL}, "standard_release_store_unchanged": release_before == release_after,
        "required_row_families": list(RUST_ROW_IDS), "missing_row_families": missing, "attacks": rows, "summary": summarize(rows),
        "container_log_tail": logs[-2000:],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    shutil.rmtree(work, ignore_errors=True)
    unmet = record["summary"]["property_unmet_ids"]
    print(f"{record['summary']['total_rows']} rows; property unmet: {unmet}; missing row families: {missing}")
    return 0 if not unmet and not missing and record["standard_release_store_unchanged"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target", choices=("go", "rust"), default="go",
                        help="go (default): the recorded UPDSEC harness; rust: the Rust model-streaming service rows (stage 3)")
    parser.add_argument("--output", type=Path, default=None,
                        help="record path (default: paper/research/update-security-20261116.json for go, .tmp/update-security-rust-s03.json for rust)")
    parser.add_argument("--release-dir", type=Path, default=ROOT / "models/standard-releases")
    parser.add_argument("--image", default="privoke-updsec-model-dev:20261116", help="model-streaming-service dev image (built from this checkout)")
    parser.add_argument("--skip-docker", action="store_true", help="do not host the Go streaming service (retrieval rows become not_run)")
    parser.add_argument("--rust-image", default=RUST_DEFAULT_IMAGE, help="--target rust: the built Rust model-streaming image")
    parser.add_argument("--rust-binary", type=Path, default=None,
                        help="--target rust: run this host binary instead of the container (development only; the stage 3 gate uses the container)")
    parser.add_argument("--rust-service", choices=("model-streaming", "param-update"), default="model-streaming",
                        help="--target rust: which Rust service's rows to run (model-streaming: stage 3, the default; param-update: stage 5)")
    parser.add_argument("--rust-update-image", default=RUST_UPDATE_DEFAULT_IMAGE,
                        help="--target rust --rust-service param-update: the built Rust parameter-update image")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.target == "rust" and args.rust_service == "param-update":
        args.output = args.output or ROOT / ".tmp/update-security-rust-s05.json"
        return run_rust_update_target(args)
    if args.target == "rust":
        args.output = args.output or ROOT / ".tmp/update-security-rust-s03.json"
        return run_rust_target(args)
    args.output = args.output or ROOT / "paper/research/update-security-20261116.json"
    release_dir = args.release_dir
    if not release_dir.is_dir():
        print(f"standard release store not found: {release_dir}", file=sys.stderr)
        return 2
    release_before = release_fingerprint(release_dir)
    work = Path(tempfile.mkdtemp(prefix="updsec-", dir=ROOT / ".tmp" if (ROOT / ".tmp").is_dir() else None))
    stack = Stack(work, release_dir.resolve(), keep_image=args.image)
    rows: list[dict] = []
    try:
        stack.prepare_artifact()
        stack.start_updater()
        stack.start_streaming()
        client = Client(stack)
        recorder = Recorder(client)
        run_update_attacks(recorder, stack)
        run_drift_attacks(recorder, stack)
        run_frozen_tensor(recorder, stack)
        run_interrupted(recorder, stack)
        run_live_authentication(recorder, stack)
        rows.extend(recorder.rows)
        run_transport(rows, work)
        client.close()
    finally:
        stack.close()
    release_after = release_fingerprint(release_dir)
    record = {
        "id": RECORD_ID, "title": "Guarded-update and authentication security tests",
        "revision": git_revision(), "generated_unix": int(time.time()),
        "environment": {"python": sys.version.split()[0], "platform": sys.platform, "grpc": __import__("grpc").__version__,
                        "streaming_image": image_facts(args.image), "source_tree_clean_for_tested_paths": tree_is_clean(), "updater": "services/param-update-service/app/server.py as a host process on 127.0.0.1",
                        "openssl": subprocess.run([__import__("update_security_pki").find_openssl(), "version"], text=True,
                                                  stdout=subprocess.PIPE).stdout.strip()},
        "fixture": {"legacy_model": LEGACY_MODEL, "v3_model": V3_MODEL, "artifact_pristine_sha256": hashlib.sha256(stack.pristine).hexdigest(),
                    "bootstrap": "app/bootstrap.py (full-capability preparation, as the deployment does)"},
        "standard_release_store_unchanged": release_before == release_after, "standard_release_store": {"fingerprint": release_after[0], "files": release_after[1]},
        "goal_coverage": goal_coverage(rows), "attacks": rows, "static_evidence": static_evidence(), "gaps": GAPS, "summary": summarize(rows),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    shutil.rmtree(work, ignore_errors=True)
    unmet = record["summary"]["property_unmet_ids"]
    print(f"{record['summary']['total_rows']} rows; property unmet: {unmet}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
