from __future__ import annotations

from concurrent import futures
import os
import signal
import sys
import time
from pathlib import Path

import grpc


CURRENT_DIR = Path(__file__).resolve().parent
PACKAGE_ROOT = CURRENT_DIR.parent
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))
GENERATED_DIR = PACKAGE_ROOT / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from privoke.v1 import runtime_pb2, runtime_pb2_grpc
from src.env import env_bool, env_positive_float, env_positive_int
from src.runtime_supervisor import RuntimeProcessStatus, RuntimeProcessSupervisor


_SHOULD_STOP = False


class PrivokeRuntimeControlService(
    runtime_pb2_grpc.PrivokeRuntimeControlServiceServicer
):
    def __init__(self, supervisor: RuntimeProcessSupervisor) -> None:
        self.supervisor = supervisor

    def SetRuntimeEnabled(self, request, context):
        return _control_response(self.supervisor.set_enabled(bool(request.enabled)))

    def Status(self, request, context):
        return _control_response(self.supervisor.status())


def main() -> None:
    global _SHOULD_STOP
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    runtime_port = env_positive_int("PRIVOKE_GRPC_PORT", 50054)
    control_host = (
        os.getenv("PRIVOKE_CONTROL_GRPC_HOST", "127.0.0.1").strip()
        or "127.0.0.1"
    )
    control_port = env_positive_int("PRIVOKE_CONTROL_GRPC_PORT", 50056)
    supervisor = RuntimeProcessSupervisor(
        runtime_port=runtime_port,
        startup_timeout_seconds=env_positive_float(
            "PRIVOKE_RUNTIME_START_TIMEOUT_SECONDS",
            30.0,
        ),
        stop_timeout_seconds=env_positive_float(
            "PRIVOKE_RUNTIME_STOP_TIMEOUT_SECONDS",
            10.0,
        ),
    )

    if env_bool("PRIVOKE_RUNTIME_START_ENABLED", True):
        initial_status = supervisor.start()
        print(initial_status.message, flush=True)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    runtime_pb2_grpc.add_PrivokeRuntimeControlServiceServicer_to_server(
        PrivokeRuntimeControlService(supervisor),
        server,
    )
    server.add_insecure_port(f"{control_host}:{control_port}")
    server.start()
    print(
        f"PriVoke runtime supervisor listening on {control_host}:{control_port}",
        flush=True,
    )

    try:
        while not _SHOULD_STOP:
            time.sleep(0.25)
    finally:
        server.stop(5).wait()
        supervisor.stop()


def _control_response(status: RuntimeProcessStatus):
    return runtime_pb2.RuntimeControlStatus(
        enabled=status.enabled,
        status=status.status,
        message=status.message,
        process_id=status.process_id,
    )


def _stop(signum, frame) -> None:
    global _SHOULD_STOP
    _SHOULD_STOP = True


if __name__ == "__main__":
    main()
