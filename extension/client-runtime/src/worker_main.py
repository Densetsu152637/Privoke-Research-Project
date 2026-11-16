"""PriVoke inference worker: the client-runtime pipeline behind a framed pipe (stage W1).

Run as ``python src/worker_main.py --request-fd N --response-fd M --model-root DIR``. The
worker never opens a socket, reads models only from read-only paths, never reports
telemetry, and keeps stdout out of the protocol. The protocol is specified in
``docs/runtime/worker-protocol.md``; frames are encoded by ``worker_protocol.py``.

The handlers are the existing ``PrivokeRuntimeService`` methods, called with the decoded
protobuf request and a small context object. ``grpc_main.py`` and the gRPC servicer are
unchanged and remain the oracle for the parity tests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path


CURRENT_DIR = Path(__file__).resolve().parent
PACKAGE_PARENT = CURRENT_DIR.parent
SHARED_PYTHON_ROOT = PACKAGE_PARENT.parents[1] / "shared" / "python"
while str(CURRENT_DIR) in sys.path:
    sys.path.remove(str(CURRENT_DIR))
if str(PACKAGE_PARENT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_PARENT))
if str(SHARED_PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON_ROOT))
GENERATED_DIR = PACKAGE_PARENT / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from src import worker_protocol as proto  # noqa: E402  (stdlib only; safe before redirection)

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_SANDBOX = 3
EXIT_STARTUP = 4
EXIT_STREAM = 5
EXIT_PIPE_CLOSED = 6

IMPLEMENTATION = "privoke-client-runtime-python"
MODEL_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")
WARMUP_TEXT = "Worker warm-up: the weather is mild today."

# Indirection so a harness can simulate an OS layer that refuses socket creation.
def _open_socket(family, kind):
    import socket
    return socket.socket(family, kind)


# ---------------------------------------------------------------------------------------
# Process plumbing
# ---------------------------------------------------------------------------------------

def _open_pipe_stream(descriptor: int, writable: bool):
    """Wrap an inherited pipe. POSIX: a file descriptor. Windows: an inheritable HANDLE."""
    if os.name == "nt":
        import msvcrt
        descriptor = msvcrt.open_osfhandle(descriptor, 0)
    return os.fdopen(descriptor, "wb" if writable else "rb", buffering=0)


def _redirect_standard_streams() -> None:
    """Point fd 1 (and ``sys.stdout``) at stderr, and fd 0 at the null device.

    C libraries that write to fd 1 and stray ``print`` calls then land on stderr and
    cannot interleave with frames, which only ever travel on the dedicated pipe.
    """
    try:
        sys.stdout.flush()
    except Exception:
        pass
    try:
        os.dup2(2, 1)
    except OSError:
        null = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null, 1)
        os.dup2(null, 2)
        os.close(null)
    sys.stdout = sys.stderr
    try:
        null = os.open(os.devnull, os.O_RDONLY)
        os.dup2(null, 0)
        os.close(null)
        sys.stdin = open(os.devnull, "r")
    except OSError:
        pass


def sandbox_self_check(open_socket=None) -> list[str]:
    """Return the network capabilities the process still has. An empty list means sandboxed.

    This is a self-check only. Enforcement is the operating-system layer's job (stage W2).
    """
    import socket
    open_socket = open_socket or _open_socket
    findings = []
    for label, family, kind in (("tcp4", socket.AF_INET, socket.SOCK_STREAM),
                                ("udp4", socket.AF_INET, socket.SOCK_DGRAM),
                                ("tcp6", getattr(socket, "AF_INET6", None), socket.SOCK_STREAM)):
        if family is None:
            continue
        try:
            handle = open_socket(family, kind)
        except OSError:
            continue
        except Exception:
            continue
        findings.append(label)
        try:
            handle.close()
        except Exception:
            pass
    return findings


# ---------------------------------------------------------------------------------------
# Models from read-only paths
# ---------------------------------------------------------------------------------------

def _raw_config_text(text: str) -> str:
    """The exact source text of the top-level ``config`` value, as the Go service streams it."""
    decoder = json.JSONDecoder()
    index = text.index("{") + 1
    while True:
        while text[index] in " \t\r\n,":
            index += 1
        if text[index] == "}":
            raise ValueError("Artifact has no config.")
        key, index = decoder.raw_decode(text, index)
        while text[index] in " \t\r\n:":
            index += 1
        start = index
        _, index = decoder.raw_decode(text, index)
        if key == "config":
            return text[start:index]


class LocalModelProvider:
    """Reads admitted model artifacts from read-only directories instead of model-streaming.

    ``<root>/<model_id>.json``      legacy Tiny and sparse presence artifacts (same bytes the
                                    model-streaming service serves).
    ``<root>/<model_id>/``          pinned V3 package (manifest.json and the four assets).
    """

    def __init__(self, roots, latest_model_id: str | None = None):
        self.roots = tuple(Path(root).absolute() for root in roots)
        for root in self.roots:
            if not root.is_dir():
                raise ValueError(f"Model root is not a directory: {root}")
        self.latest_model_id = latest_model_id
        self._packages = {}

    def fetch(self, model_id: str):
        if model_id == "latest":
            if not self.latest_model_id:
                raise ValueError("latest is not resolvable in the worker; name the model explicitly.")
            model_id = self.latest_model_id
        if not MODEL_ID_PATTERN.fullmatch(model_id or ""):
            raise ValueError("model_id is not a valid model identifier.")
        for root in self.roots:
            package = root / model_id
            if (package / "manifest.json").is_file():
                return self._v3_package(model_id, package)
            artifact = root / (model_id + ".json")
            if artifact.is_file():
                return self._artifact_snapshot(model_id, artifact)
        raise ValueError(f"Model {model_id} is not available in the worker model roots.")

    def _v3_package(self, model_id: str, directory: Path):
        # Pinned and immutable: verify the package (hash every asset) once per process.
        cached = self._packages.get(directory)
        if cached is not None:
            return cached
        from src.LLM.privoke.v3_package import NativeV3Package
        from privoke_model.standard_v3 import STANDARD_PINS, admitted_manifest, digest_file, safe_file, verify_package
        manifest_path = safe_file(directory, "manifest.json")
        manifest = admitted_manifest(manifest_path.read_bytes(), model_id)
        pin = STANDARD_PINS[manifest["model_id"]]
        if manifest["model_id"] != model_id or digest_file(manifest_path) != pin:
            raise ValueError("Model package identity differs from the pinned manifest.")
        verify_package(directory, model_id)
        package = NativeV3Package(model_id, pin, directory, manifest)
        self._packages[directory] = package
        return package

    def _artifact_snapshot(self, model_id: str, path: Path):
        from privoke_model.artifact import float32, load_artifact
        from src.LLM.privoke.parameter_stream import ParameterSnapshot
        raw = path.read_bytes()
        artifact = load_artifact(path)
        if artifact["model_id"] != model_id:
            raise ValueError("Artifact model_id differs from its file name.")
        architecture = artifact["architecture"]
        from privoke_model.pretrained_context import PRETRAINED_CONTEXT_ARCHITECTURE, PRETRAINED_CONTEXT_MODEL_ID
        from privoke_model.scratch_presence import SCRATCH_PRESENCE_ARCHITECTURE, SCRATCH_PRESENCE_MODEL_IDS
        if (architecture in (SCRATCH_PRESENCE_ARCHITECTURE, PRETRAINED_CONTEXT_ARCHITECTURE)
                or model_id in SCRATCH_PRESENCE_MODEL_IDS or model_id == PRETRAINED_CONTEXT_MODEL_ID):
            raise ValueError("Scratch-presence and pretrained-context artifacts are not served by the W1 worker.")
        tensors = artifact["parameters"]
        names = sorted(tensors)
        metadata = {key: str(value) for key, value in (artifact.get("metadata") or {}).items()}
        config_text = _raw_config_text(raw.decode("utf-8"))
        metadata.update({
            "architecture": architecture,
            "model_config": config_text,
            "artifact_checksum": artifact["checksum"],
            "artifact_file_checksum": hashlib.sha256(raw).hexdigest(),
            "trainable_parameters": ",".join(name for name in names if tensors[name]["trainable"]),
        })
        if architecture == "privoke_sparse_presence_v1":
            config = artifact["config"]
            metadata.update({"task": config["task"], "profile": config["profile"],
                             "text_normalization": config["normalization"],
                             "arithmetic": "float32_parameters_float64_features_fsum_v1"})
        return ParameterSnapshot(
            model_id=artifact["model_id"],
            version=artifact["version"],
            generated_at_unix=int(artifact["generated_at_unix"]),
            parameters={name: tuple(float32(value) for value in tensors[name]["values"]) for name in names},
            shapes={name: tuple(int(size) for size in tensors[name]["shape"]) for name in names},
            metadata=metadata,
        )


def _install_offline_runtime(provider: LocalModelProvider) -> None:
    """Make the pipeline load models from ``provider`` and make every network path fail."""
    from src.LLM.privoke import parameter_stream
    parameter_stream.ModelParameterStreamer.fetch = lambda self: provider.fetch(self.model_id)

    def no_network(*_args, **_kwargs):
        raise RuntimeError("The worker has no network access.")

    parameter_stream.grpc_channel = no_network
    try:
        from src.telemetry import event_emitter
        event_emitter.grpc_channel = no_network
    except Exception:
        pass


# ---------------------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------------------

class WorkerContext:
    """The slice of ``grpc.ServicerContext`` the handlers use, backed by frame fields."""

    def __init__(self, metadata, deadline_monotonic: float):
        self._metadata = tuple(metadata)
        self._deadline = deadline_monotonic

    def invocation_metadata(self):
        return self._metadata

    def is_active(self) -> bool:
        return time.monotonic() < self._deadline

    def time_remaining(self) -> float:
        return max(0.0, self._deadline - time.monotonic())


class Dispatcher:
    def __init__(self):
        from privoke.v1 import runtime_pb2
        from src.hosting.grpc_server import PrivokeRuntimeService
        self.pb = runtime_pb2
        self.service = PrivokeRuntimeService(telemetry_reporter=None)
        self.table = {
            proto.Method.ANALYZE_PROMPT: (runtime_pb2.AnalyzePromptRequest, self.service.AnalyzePrompt),
            proto.Method.DETECT_ANNOTATION_PRESENCE: (runtime_pb2.DetectAnnotationPresenceRequest,
                                                      self.service.DetectAnnotationPresence),
            proto.Method.HEALTH: (runtime_pb2.RuntimeHealthRequest, self.service.Health),
            proto.Method.COMPUTE_SEMANTIC_GRADIENTS: (runtime_pb2.ComputeSemanticGradientsRequest,
                                                      self.service.ComputeSemanticGradients),
            proto.Method.COMPUTE_UNDERLYING_MODEL_GRADIENTS: (runtime_pb2.ComputeSemanticGradientsRequest,
                                                              self.service.ComputeUnderlyingModelGradients),
            proto.Method.COMPUTE_PRESENCE_GRADIENTS: (runtime_pb2.ComputePresenceGradientsRequest,
                                                      self.service.ComputePresenceGradients),
        }

    def handle(self, request: proto.Request) -> bytes:
        """Return the serialized response, or raise ``proto.FrameError``."""
        limits = proto.METHOD_LIMITS[request.method]
        deadline_ms = min(request.deadline_ms or limits.default_deadline_ms, limits.max_deadline_ms)
        started = time.monotonic()
        message_type, handler = self.table[request.method]
        try:
            message = message_type.FromString(request.payload)
        except Exception as exc:
            raise proto.FrameError(proto.CODE_INVALID_PAYLOAD,
                                   f"Payload is not a valid {message_type.DESCRIPTOR.name}: {exc}",
                                   request.request_id) from None
        self._check_layers(request, message)
        context = WorkerContext(request.metadata, started + deadline_ms / 1000.0)
        response = handler(message, context)
        if time.monotonic() - started > deadline_ms / 1000.0:
            raise proto.FrameError(proto.CODE_DEADLINE_EXCEEDED,
                                   f"{request.method.name} exceeded its {deadline_ms} ms deadline.",
                                   request.request_id)
        payload = response.SerializeToString(deterministic=True)
        if len(payload) > limits.max_response_payload:
            raise proto.FrameError(proto.CODE_RESPONSE_TOO_LARGE,
                                   f"{request.method.name} response of {len(payload)} bytes exceeds the "
                                   f"{limits.max_response_payload} byte limit.", request.request_id)
        return payload

    def _check_layers(self, request: proto.Request, message) -> None:
        """Never run an implicit pipeline: an empty layer list means the whole pipeline here."""
        if request.method in (proto.Method.HEALTH,):
            return
        if not message.layers:
            raise proto.FrameError(proto.CODE_INVALID_LAYERS,
                                   "An explicit non-empty layer selection is required; an empty list "
                                   "would select the complete detector pipeline.", request.request_id)
        if request.method == proto.Method.ANALYZE_PROMPT and self.pb.DETECTION_LAYER_RUNTIME in message.layers:
            raise proto.FrameError(proto.CODE_INVALID_LAYERS,
                                   "DETECTION_LAYER_RUNTIME selects the complete pipeline; name layers explicitly.",
                                   request.request_id)


# ---------------------------------------------------------------------------------------
# Serving
# ---------------------------------------------------------------------------------------

class FrameWriter:
    def __init__(self, stream):
        self._stream = stream

    def send(self, data: bytes) -> None:
        self._stream.write(data)
        self._stream.flush()


def _warm_up(dispatcher: Dispatcher, layers, semantic_models) -> list[str]:
    from src.pipeline import analyse_text
    loaded = []
    plans = [(tuple(layers), None)] if layers else []
    plans += [(("semantic",), model_id) for model_id in semantic_models]
    for plan_layers, model_id in plans:
        analysis = analyse_text(WARMUP_TEXT, layers=plan_layers, semantic_model_id=model_id)
        failed = [f"{execution.layer}: {execution.error}" for execution in analysis.layers
                  if execution.status != "ok"]
        if failed:
            raise RuntimeError("Warm-up failed: " + "; ".join(failed))
        loaded.extend(plan_layers if model_id is None else [f"semantic:{model_id}"])
    return loaded


def serve(requests, writer: FrameWriter, dispatcher: Dispatcher) -> int:
    while True:
        try:
            request = proto.read_request(requests)
        except proto.FrameError as exc:
            writer.send(proto.encode_error(exc.request_id, exc.code, exc.message))
            continue
        except proto.StreamBroken as exc:
            try:
                writer.send(proto.encode_error(exc.request_id, exc.code, exc.message))
            except OSError:
                pass
            print(f"worker: stream broken: {exc.code}: {exc.message}", file=sys.stderr, flush=True)
            return EXIT_STREAM
        if request is None:
            return EXIT_OK
        try:
            payload = dispatcher.handle(request)
            frame = proto.encode_frame(proto.Kind.RESPONSE, request.method, request.request_id, payload)
        except proto.FrameError as exc:
            frame = proto.encode_error(request.request_id, exc.code, exc.message)
        except Exception as exc:
            import traceback
            traceback.print_exc(file=sys.stderr)
            frame = proto.encode_error(request.request_id, proto.CODE_INTERNAL,
                                       f"{exc.__class__.__name__}: {exc}"[:512])
        try:
            writer.send(frame)
        except (BrokenPipeError, OSError):
            return EXIT_PIPE_CLOSED


def _parse_arguments(argv):
    parser = argparse.ArgumentParser(description="PriVoke inference worker (framed pipe protocol).")
    parser.add_argument("--request-fd", type=int, required=True,
                        help="Inherited read end for request frames (Windows: inheritable HANDLE value).")
    parser.add_argument("--response-fd", type=int, required=True,
                        help="Inherited write end for response frames (Windows: inheritable HANDLE value).")
    parser.add_argument("--model-root", action="append", default=[],
                        help="Read-only directory holding model artifacts or V3 packages (repeatable).")
    parser.add_argument("--latest-model-id", default=None,
                        help="Model that the alias 'latest' resolves to; unset leaves the alias refused.")
    parser.add_argument("--warm-layers", default="regex,ner",
                        help="Comma-separated layers exercised before READY ('' disables).")
    parser.add_argument("--warm-semantic-model", action="append", default=[],
                        help="Semantic model loaded before READY (repeatable).")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_arguments(sys.argv[1:] if argv is None else argv)
    if args.request_fd in (0, 1, 2) or args.response_fd in (0, 1, 2) or args.request_fd == args.response_fd:
        print("worker: pipe descriptors must be distinct and not 0, 1 or 2.", file=sys.stderr)
        return EXIT_USAGE
    try:
        requests = _open_pipe_stream(args.request_fd, writable=False)
        responses = _open_pipe_stream(args.response_fd, writable=True)
    except OSError as exc:
        print(f"worker: cannot open the pipe descriptors: {exc}", file=sys.stderr)
        return EXIT_USAGE
    _redirect_standard_streams()
    writer = FrameWriter(responses)

    sandboxed = os.environ.get("PRIVOKE_WORKER_SANDBOX") == "1"
    if sandboxed:
        findings = sandbox_self_check()
        if findings:
            message = "Sandbox self-check failed: this process can open " + ", ".join(findings) + " sockets."
            print("worker: " + message, file=sys.stderr, flush=True)
            writer.send(proto.encode_error(0, "SANDBOX_VIOLATION", message))
            return EXIT_SANDBOX

    os.environ["TELEMETRY_ENABLED"] = "false"
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
    try:
        from src.config import GLOBAL_CONFIG, LLMChoice
        from src.dependency_check import check_required_detector_dependencies
        check_required_detector_dependencies()
        GLOBAL_CONFIG.llm_choice = LLMChoice.Streamed
        provider = LocalModelProvider(args.model_root, args.latest_model_id)
        _install_offline_runtime(provider)
        dispatcher = Dispatcher()
        layers = [layer for layer in args.warm_layers.split(",") if layer]
        loaded = _warm_up(dispatcher, layers, args.warm_semantic_model)
    except Exception as exc:
        message = f"Worker startup failed: {exc.__class__.__name__}: {exc}"
        print("worker: " + message, file=sys.stderr, flush=True)
        try:
            writer.send(proto.encode_error(0, "STARTUP_FAILED", message[:512]))
        except OSError:
            pass
        return EXIT_STARTUP

    limits = {proto.GRPC_METHOD_NAMES[method]: {
        "max_request_payload": value.max_request_payload, "max_response_payload": value.max_response_payload,
        "default_deadline_ms": value.default_deadline_ms, "max_deadline_ms": value.max_deadline_ms}
        for method, value in proto.METHOD_LIMITS.items()}
    ready = {"protocol_version": proto.PROTOCOL_VERSION, "implementation": IMPLEMENTATION, "pid": os.getpid(),
             "sandbox_self_check": "passed" if sandboxed else "not_requested", "telemetry": "disabled",
             "loaded": loaded, "limits": limits}
    writer.send(proto.encode_frame(proto.Kind.READY, 0, 0,
                                   json.dumps(ready, sort_keys=True).encode("utf-8")))
    return serve(requests, writer, dispatcher)


if __name__ == "__main__":
    raise SystemExit(main())
