from __future__ import annotations

from concurrent import futures
import os
import signal
import sys
import time
from pathlib import Path
from typing import Callable

import grpc


CURRENT_DIR = Path(__file__).resolve().parent
PACKAGE_ROOT = CURRENT_DIR.parent
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))
GENERATED_DIR = PACKAGE_ROOT / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from privoke.v1 import (
    parameters_pb2,
    parameters_pb2_grpc,
    runtime_pb2,
    runtime_pb2_grpc,
)
from src.runtime_supervisor import RuntimeProcessStatus, RuntimeProcessSupervisor
from src.grpc_web_bridge import GrpcWebBridge


_SHOULD_STOP = False


class PrivokeRuntimeControlService(
    runtime_pb2_grpc.PrivokeRuntimeControlServiceServicer
):
    def __init__(
        self,
        supervisor: RuntimeProcessSupervisor,
        model_streaming_health_check: Callable[[], tuple[str, str]],
    ) -> None:
        self.supervisor = supervisor
        self.model_streaming_health_check = model_streaming_health_check

    def SetRuntimeEnabled(self, request, context):
        return _control_response(self.supervisor.set_enabled(bool(request.enabled)))

    def Status(self, request, context):
        return _control_response(self.supervisor.status())

    def ModelStreamingHealth(self, request, context):
        service, status = self.model_streaming_health_check()
        return runtime_pb2.RuntimeHealthResponse(service=service, status=status)


def main() -> None:
    global _SHOULD_STOP
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    runtime_port = _env_positive_int("PRIVOKE_GRPC_PORT", 50054)
    control_host = (
        os.getenv("PRIVOKE_CONTROL_GRPC_HOST", "127.0.0.1").strip()
        or "127.0.0.1"
    )
    control_port = _env_positive_int("PRIVOKE_CONTROL_GRPC_PORT", 50056)
    model_streaming_target = (
        os.getenv("MODEL_STREAMING_TARGET", "127.0.0.1:50051").strip()
        or "127.0.0.1:50051"
    )
    model_streaming_health_timeout = _env_positive_float(
        "MODEL_STREAMING_HEALTH_TIMEOUT_SECONDS",
        3.0,
    )
    supervisor = RuntimeProcessSupervisor(
        runtime_port=runtime_port,
        startup_timeout_seconds=_env_positive_float(
            "PRIVOKE_RUNTIME_START_TIMEOUT_SECONDS",
            30.0,
        ),
        stop_timeout_seconds=_env_positive_float(
            "PRIVOKE_RUNTIME_STOP_TIMEOUT_SECONDS",
            10.0,
        ),
    )

    if _env_bool("PRIVOKE_RUNTIME_START_ENABLED", True):
        initial_status = supervisor.start()
        print(initial_status.message, flush=True)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    runtime_pb2_grpc.add_PrivokeRuntimeControlServiceServicer_to_server(
        PrivokeRuntimeControlService(
            supervisor,
            lambda: _model_streaming_health(
                model_streaming_target,
                model_streaming_health_timeout,
            ),
        ),
        server,
    )
    server.add_insecure_port(f"{control_host}:{control_port}")
    server.start()
    print(
        f"PriVoke runtime supervisor listening on {control_host}:{control_port}",
        flush=True,
    )
    bridge = None
    try:
        if _env_bool("PRIVOKE_GRPC_WEB_ENABLED", True):
            bridge_host = (
                os.getenv("PRIVOKE_GRPC_WEB_HOST", "127.0.0.1").strip()
                or "127.0.0.1"
            )
            bridge_port = _env_positive_int("PRIVOKE_GRPC_WEB_PORT", 8080)
            bridge = GrpcWebBridge(
                host=bridge_host,
                port=bridge_port,
                control_target=f"{control_host}:{control_port}",
                runtime_target=f"127.0.0.1:{runtime_port}",
            )
            bridge.start()
            print(
                f"PriVoke gRPC-Web bridge listening on {bridge_host}:{bridge_port}",
                flush=True,
            )

        while not _SHOULD_STOP:
            time.sleep(0.25)
    finally:
        if bridge is not None:
            bridge.stop()
        server.stop(5).wait()
        supervisor.stop()


def _control_response(status: RuntimeProcessStatus):
    return runtime_pb2.RuntimeControlStatus(
        enabled=status.enabled,
        status=status.status,
        message=status.message,
        process_id=status.process_id,
    )


def _model_streaming_health(target: str, timeout_seconds: float) -> tuple[str, str]:
    service = "model-streaming-service"
    try:
        with grpc.insecure_channel(target) as channel:
            response = parameters_pb2_grpc.ModelStreamingServiceStub(channel).Health(
                parameters_pb2.HealthRequest(),
                timeout=timeout_seconds,
            )
        return response.service or service, response.status or "UNKNOWN"
    except (grpc.RpcError, OSError):
        return service, "NOT_SERVING"


def _env_bool(name: str, default: bool) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    normalised = raw_value.strip().lower()
    if normalised in {"1", "true", "yes", "on"}:
        return True
    if normalised in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value.")


def _env_positive_float(name: str, default: float) -> float:
    raw_value = os.getenv(name)
    value = default if raw_value is None else float(raw_value)
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero.")
    return value


def _env_positive_int(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    value = default if raw_value is None else int(raw_value)
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero.")
    return value


def _stop(signum, frame) -> None:
    global _SHOULD_STOP
    _SHOULD_STOP = True


if __name__ == "__main__":
    main()
