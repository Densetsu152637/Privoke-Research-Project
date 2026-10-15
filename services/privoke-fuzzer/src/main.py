from __future__ import annotations

import logging
import signal
import sys
import threading
from concurrent import futures
from pathlib import Path

import grpc
from privoke_service import configure_logging

GENERATED_DIR = Path(__file__).resolve().parents[1] / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from config import FuzzerConfig
from fuzzer_service import FuzzerTrainingService
from privoke.v1 import parameters_pb2_grpc

SERVICE_NAME = "privoke-fuzzer"
MAX_REQUEST_BYTES = 262_144
MAX_RESPONSE_BYTES = 1_048_576
LOGGER = logging.getLogger(__name__)


def main() -> None:
    configure_logging()
    config = FuzzerConfig.from_env()
    stop_event = threading.Event()
    _install_signal_handlers(stop_event)
    server = create_server(config)
    server.start()
    LOGGER.info(
        "%s awaiting training requests port=%s model=%s",
        SERVICE_NAME,
        config.port,
        config.model_id,
    )

    try:
        stop_event.wait()
    finally:
        server.stop(5).wait()


def create_server(config: FuzzerConfig):
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=4),
        options=(
            ("grpc.max_receive_message_length", MAX_REQUEST_BYTES),
            ("grpc.max_send_message_length", MAX_RESPONSE_BYTES),
        ),
    )
    parameters_pb2_grpc.add_FuzzerServiceServicer_to_server(
        FuzzerTrainingService(config),
        server,
    )
    server.add_insecure_port(f"[::]:{config.port}")
    return server


def _install_signal_handlers(stop_event: threading.Event) -> None:
    def request_stop(signum, frame) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)


if __name__ == "__main__":
    main()
