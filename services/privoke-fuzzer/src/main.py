from __future__ import annotations

import logging
import signal
import sys
import time
from concurrent import futures
from pathlib import Path

import grpc


GENERATED_DIR = Path(__file__).resolve().parents[1] / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from config import FuzzerConfig
from fuzzer_service import FuzzerTrainingService
from privoke.v1 import parameters_pb2_grpc


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    force=True,
)

_SHOULD_STOP = False


def main() -> None:
    global _SHOULD_STOP

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    config = FuzzerConfig.from_env()
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=4),
        options=(
            ("grpc.max_receive_message_length", 262_144),
            ("grpc.max_send_message_length", 1_048_576),
        ),
    )
    parameters_pb2_grpc.add_FuzzerServiceServicer_to_server(
        FuzzerTrainingService(config),
        server,
    )
    server.add_insecure_port(f"[::]:{config.port}")
    server.start()
    logging.info(
        "privoke-fuzzer awaiting training requests port=%s model=%s",
        config.port,
        config.model_id,
    )

    try:
        while not _SHOULD_STOP:
            time.sleep(0.25)
    finally:
        server.stop(5).wait()


def _stop(signum, frame) -> None:
    global _SHOULD_STOP
    _SHOULD_STOP = True


if __name__ == "__main__":
    main()
