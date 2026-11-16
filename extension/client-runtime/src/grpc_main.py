from __future__ import annotations

import os
import signal
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

from src.config import GLOBAL_CONFIG, LLMChoice
from src.dependency_check import check_required_detector_dependencies, check_standard_v3_dependencies
from src.env import env_bool, env_positive_float, env_positive_int
from concurrent import futures

from privoke.v1 import runtime_pb2_grpc
from src.hosting.grpc_server import PrivokeRuntimeService
from src.telemetry import TelemetryReporter
from privoke_service.stack_connection import bind_server, build_server, stack_target


_SHOULD_STOP = False


def main() -> None:
    global _SHOULD_STOP
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    check_required_detector_dependencies()
    if os.getenv("MODEL_ID", "latest") == "latest" or os.getenv("MODEL_ID", "").startswith("privoke-v3-"):
        check_standard_v3_dependencies()
    if env_bool("PRIVOKE_REQUIRE_TRAINING_CPU", False):
        try:
            import torch
            with torch.enable_grad():
                probe = torch.tensor(1.0, device="cpu", requires_grad=True)
                (probe * probe).backward()
                if probe.grad is None or probe.grad.item() != 2.0:
                    raise RuntimeError("CPU autograd probe failed.")
        except ImportError as exc:
            raise RuntimeError("Automatic underlying training requires the CPU training dependency; rebuild with PRIVOKE_INSTALL_TRAINING_CPU=true.") from exc

    GLOBAL_CONFIG.llm_choice = LLMChoice.parse(
        os.getenv("PRIVOKE_LLM_CHOICE", "streamed")
    )
    GLOBAL_CONFIG.wait_for_regex = env_bool(
        "PRIVOKE_WAIT_FOR_REGEX", GLOBAL_CONFIG.wait_for_regex
    )
    host = os.getenv("PRIVOKE_GRPC_HOST", "127.0.0.1").strip() or "127.0.0.1"
    port = env_positive_int("PRIVOKE_GRPC_PORT", 50054)
    telemetry_target = stack_target("TELEMETRY") if env_bool("TELEMETRY_ENABLED", False) else ""
    if env_bool("TELEMETRY_ENABLED", False) and not telemetry_target:
        # Telemetry has its own public port and credential, so it has no fallback to PRIVOKE_CLOUD_TARGET.
        print("Telemetry is enabled but PRIVOKE_CLOUD_TELEMETRY_TARGET is not set; telemetry is off.", file=sys.stderr, flush=True)
    telemetry_reporter = (
        TelemetryReporter(
            target=telemetry_target,
            event_epsilon=env_positive_float("TELEMETRY_LDP_EPSILON", 1.0),
            daily_epsilon=env_positive_float("TELEMETRY_LDP_DAILY_EPSILON", 8.0),
            ledger_path=os.getenv("TELEMETRY_PRIVACY_LEDGER_PATH") or None,
            timeout_seconds=env_positive_float("TELEMETRY_TIMEOUT_SECONDS", 1.0),
            queue_size=env_positive_int("TELEMETRY_QUEUE_SIZE", 1024),
        )
        if telemetry_target
        else None
    )
    # Mutual TLS and a peer-identity check apply whenever server TLS is configured; plaintext is refused on any
    # non-loopback address. The workstation default (127.0.0.1) stays plaintext.
    server = build_server(
        futures.ThreadPoolExecutor(max_workers=8),
        options=(
            ("grpc.max_receive_message_length", env_positive_int("PRIVOKE_MAX_GRPC_MESSAGE_BYTES", 262_144)),
            ("grpc.max_send_message_length", env_positive_int("PRIVOKE_MAX_GRPC_RESPONSE_BYTES", 1_048_576)),
        ),
    )
    runtime_pb2_grpc.add_PrivokeRuntimeServiceServicer_to_server(
        PrivokeRuntimeService(
            max_text_chars=env_positive_int("PRIVOKE_MAX_PROMPT_CHARS", 20_000),
            telemetry_reporter=telemetry_reporter,
        ),
        server,
    )
    bind_server(server, host, port)
    server.start()
    print(f"PriVoke runtime gRPC server listening on {host}:{port}", flush=True)
    try:
        while not _SHOULD_STOP:
            time.sleep(0.25)
    finally:
        server.stop(5).wait()
        if telemetry_reporter is not None:
            telemetry_reporter.close()


def _stop(signum, frame) -> None:
    global _SHOULD_STOP
    _SHOULD_STOP = True


if __name__ == "__main__":
    main()
