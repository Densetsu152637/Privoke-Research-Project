"""Host-side controller used by the worker tests: spawns the worker with dedicated pipes.

The controller side is the model for the stage W2 pool: two anonymous pipes, only those
ends inherited by the child, stdout and stderr captured separately.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from src import worker_protocol as proto

RUNTIME_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = RUNTIME_ROOT.parents[1]
WORKER_SCRIPT = RUNTIME_ROOT / "src" / "worker_main.py"
TEST_ENTRY = Path(__file__).resolve().parent / "worker_test_entry.py"


def _environment(extra=None):
    environment = os.environ.copy()
    paths = [str(RUNTIME_ROOT), str(REPOSITORY_ROOT / "shared/python"),
             str(RUNTIME_ROOT / "generated"), str(REPOSITORY_ROOT / "models")]
    if environment.get("PYTHONPATH"):
        paths.append(environment["PYTHONPATH"])
    environment["PYTHONPATH"] = os.pathsep.join(paths)
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONUNBUFFERED"] = "1"
    environment["OMP_NUM_THREADS"] = "1"  # deterministic CPU kernels and a stable torch_threads value
    environment.update(extra or {})
    return environment


class WorkerProcess:
    """One worker child. ``entry`` selects the stock script or the patching test entry."""

    def __init__(self, model_roots=(), *, arguments=(), environment=None, entry="stock", patch=None):
        request_read, self._request_write = os.pipe()
        self._response_read, response_write = os.pipe()
        script = WORKER_SCRIPT if entry == "stock" else TEST_ENTRY
        env = _environment(environment)
        if patch:
            env["PRIVOKE_WORKER_TEST_PATCH"] = patch
        command = [sys.executable, str(script)]
        keep: tuple = ()
        startupinfo = None
        if os.name == "nt":
            import msvcrt
            handles = [msvcrt.get_osfhandle(request_read), msvcrt.get_osfhandle(response_write)]
            for handle in handles:
                os.set_handle_inheritable(handle, True)
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.lpAttributeList = {"handle_list": handles}
            numbers = handles
        else:
            numbers = [request_read, response_write]
            keep = tuple(numbers)
        command += ["--request-fd", str(numbers[0]), "--response-fd", str(numbers[1])]
        for root in model_roots:
            command += ["--model-root", str(root)]
        command += list(arguments)
        self.stderr_file = tempfile.TemporaryFile()
        self.stdout_file = tempfile.TemporaryFile()
        kwargs = {"startupinfo": startupinfo} if startupinfo is not None else {"pass_fds": keep}
        self.process = subprocess.Popen(command, cwd=RUNTIME_ROOT, env=env, stdin=subprocess.DEVNULL,
                                        stdout=self.stdout_file, stderr=self.stderr_file,
                                        close_fds=True, **kwargs)
        os.close(request_read)
        os.close(response_write)
        self.requests = os.fdopen(self._request_write, "wb", buffering=0)
        self.responses = os.fdopen(self._response_read, "rb", buffering=0)
        self._next_id = 1

    # -- protocol helpers ---------------------------------------------------------------
    def read_frame(self, timeout=240.0):
        result, failure = [], []

        def target():
            try:
                result.append(proto.read_frame(self.responses))
            except Exception as exc:  # noqa: BLE001 - surfaced to the test
                failure.append(exc)

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        thread.join(timeout)
        if thread.is_alive():
            self.kill()
            raise TimeoutError("Worker did not answer in time.\n" + self.stderr_text())
        if failure:
            raise failure[0]
        return result[0]

    def wait_ready(self, timeout=240.0):
        frame = self.read_frame(timeout)
        if frame is None or frame.kind != proto.Kind.READY:
            raise RuntimeError(f"Worker did not become ready: {frame}\n" + self.stderr_text())
        return frame

    def send_raw(self, data: bytes):
        self.requests.write(data)
        self.requests.flush()

    def call(self, method, payload=b"", *, metadata=None, deadline_ms=0, timeout=240.0):
        request_id = self._next_id
        self._next_id += 1
        flags = 0
        if metadata:
            payload = proto.encode_metadata(metadata) + payload
            flags = proto.FLAG_METADATA
        self.send_raw(proto.encode_frame(proto.Kind.REQUEST, method, request_id, payload,
                                         flags=flags, deadline_ms=deadline_ms))
        frame = self.read_frame(timeout)
        if frame is not None and frame.request_id != request_id:
            raise AssertionError(f"Response id {frame.request_id} for request {request_id}")
        return frame

    # -- lifecycle ----------------------------------------------------------------------
    def stderr_text(self):
        self.stderr_file.seek(0)
        return self.stderr_file.read().decode("utf-8", "replace")

    def stdout_bytes(self):
        self.stdout_file.seek(0)
        return self.stdout_file.read()

    def kill(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait()

    def close(self, timeout=60.0):
        try:
            self.requests.close()
        except OSError:
            pass
        try:
            self.process.wait(timeout)
        except subprocess.TimeoutExpired:
            self.kill()
        code = self.process.returncode
        self.responses.close()
        self.final_stderr = self.stderr_text()
        self.final_stdout = self.stdout_bytes()
        self.stderr_file.close()
        self.stdout_file.close()
        return code

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ---------------------------------------------------------------------------------------
# The oracle: the real gRPC server path, run in this process on an ephemeral loopback port
# ---------------------------------------------------------------------------------------

LEGACY_MODEL_ROOT = REPOSITORY_ROOT / "models"
# V3 packages are gitignored: read-only from the main checkout when this is a worktree.
V3_MODEL_ROOT_CANDIDATES = (REPOSITORY_ROOT / "models" / "standard-releases",
                            Path("D:/Git Repositories/Privoke-Research-Project/models/standard-releases"))
V3_MODEL_ID = "privoke-v3-balanced"


def v3_model_root():
    for candidate in V3_MODEL_ROOT_CANDIDATES:
        if (candidate / V3_MODEL_ID / "manifest.json").is_file():
            return candidate
    return None


def identity(value: bytes) -> bytes:
    return value


class GrpcOracle:
    """``create_grpc_server`` with models served from the same read-only paths as the worker."""

    def __init__(self, model_roots):
        import grpc
        from src import worker_main
        from src.LLM.privoke import parameter_stream
        from src.LLM.privoke.streamed_model import GLOBAL_STREAMED_MODEL_CACHE
        from src.config import GLOBAL_CONFIG, LLMChoice
        from src.hosting.grpc_server import create_grpc_server
        self._streamer = parameter_stream.ModelParameterStreamer
        self._saved_fetch = self._streamer.fetch
        self._saved_choice = GLOBAL_CONFIG.llm_choice
        self._cache = GLOBAL_STREAMED_MODEL_CACHE
        self.provider = worker_main.LocalModelProvider(model_roots)
        provider = self.provider
        self._streamer.fetch = lambda streamer: provider.fetch(streamer.model_id)
        GLOBAL_CONFIG.llm_choice = LLMChoice.Streamed
        self._cache.clear()
        import torch
        self._threads = torch.get_num_threads()
        torch.set_num_threads(1)  # the worker child runs with OMP_NUM_THREADS=1
        self.server = create_grpc_server(max_message_bytes=8 * proto.MIB, max_response_bytes=64 * proto.MIB)
        port = self.server.add_insecure_port("127.0.0.1:0")
        self.server.start()
        self.channel = grpc.insecure_channel(f"127.0.0.1:{port}", options=(
            ("grpc.max_receive_message_length", 64 * proto.MIB), ("grpc.max_send_message_length", 8 * proto.MIB)))

    def call(self, method: proto.Method, payload: bytes, metadata=(), timeout=600.0) -> bytes:
        rpc = self.channel.unary_unary("/privoke.v1.PrivokeRuntimeService/" + proto.GRPC_METHOD_NAMES[method],
                                       request_serializer=identity, response_deserializer=identity)
        return rpc(payload, metadata=tuple(metadata), timeout=timeout)

    def close(self):
        from src.config import GLOBAL_CONFIG
        self.channel.close()
        self.server.stop(0).wait()
        import torch
        torch.set_num_threads(self._threads)
        self._streamer.fetch = self._saved_fetch
        GLOBAL_CONFIG.llm_choice = self._saved_choice
        self._cache.clear()


def response_type(method: proto.Method):
    from privoke.v1 import runtime_pb2 as pb
    return {
        proto.Method.ANALYZE_PROMPT: pb.AnalyzePromptResponse,
        proto.Method.DETECT_ANNOTATION_PRESENCE: pb.DetectAnnotationPresenceResponse,
        proto.Method.HEALTH: pb.RuntimeHealthResponse,
        proto.Method.COMPUTE_SEMANTIC_GRADIENTS: pb.ComputeSemanticGradientsResponse,
        proto.Method.COMPUTE_UNDERLYING_MODEL_GRADIENTS: pb.ComputeSemanticGradientsResponse,
        proto.Method.COMPUTE_PRESENCE_GRADIENTS: pb.ComputePresenceGradientsResponse,
    }[method]


WALL_CLOCK_FIELDS = ("elapsed_ms",)


def normalised(method: proto.Method, payload: bytes) -> bytes:
    """Deterministic re-serialisation with the wall-clock fields (``elapsed_ms`` and metadata["elapsed_ms"]) cleared."""
    message = response_type(method).FromString(payload)
    for name in WALL_CLOCK_FIELDS:
        if name in message.DESCRIPTOR.fields_by_name:
            message.ClearField(name)
        if "metadata" in message.DESCRIPTOR.fields_by_name and name in message.metadata:
            del message.metadata[name]  # the response metadata map repeats the elapsed time
    return message.SerializeToString(deterministic=True)
