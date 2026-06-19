import json
import logging
import os
import sys
import threading
import time
import uuid
from concurrent import futures
from dataclasses import dataclass
from pathlib import Path

import grpc

GENERATED_DIR = Path(__file__).resolve().parents[1] / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from privoke.v1 import parameters_pb2, parameters_pb2_grpc

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


@dataclass(frozen=True)
class FuzzerRequestConfig:
    target: str
    prompt_count: int
    model_id: str
    source_id: str
    timeout_seconds: float
    interval_seconds: float
    initial_delay_seconds: float
    retry_seconds: float
    max_attempts: int
    seed: int

    @classmethod
    def from_env(cls) -> "FuzzerRequestConfig":
        return cls(
            target=os.getenv("FUZZER_TARGET", "privoke-fuzzer:50053"),
            prompt_count=_env_int("FUZZER_PROMPT_COUNT", 0),
            model_id=os.getenv("MODEL_ID", "privoke-baseline"),
            source_id=os.getenv("PARAM_UPDATE_SOURCE_ID", "param-update-service"),
            timeout_seconds=_env_float("FUZZER_REQUEST_TIMEOUT_SECONDS", 30.0),
            interval_seconds=_env_float("FUZZER_REQUEST_INTERVAL_SECONDS", 0.0),
            initial_delay_seconds=_env_float(
                "FUZZER_REQUEST_INITIAL_DELAY_SECONDS",
                2.0,
            ),
            retry_seconds=_env_float("FUZZER_REQUEST_RETRY_SECONDS", 2.0),
            max_attempts=_env_int("FUZZER_REQUEST_MAX_ATTEMPTS", 3),
            seed=_env_int("FUZZER_REQUEST_SEED", 1337),
        )


class ParamUpdateService(parameters_pb2_grpc.ParamUpdateServiceServicer):
    def __init__(self, storage_path: Path):
        self.storage_path = storage_path
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)

    def SubmitParameterUpdate(self, request, context):
        payload = {
            "source_id": request.source_id,
            "model_id": request.model_id,
            "base_version": request.base_version,
            "gradients": [
                {"name": gradient.name, "values": list(gradient.values)}
                for gradient in request.gradients
            ],
            "metadata": dict(request.metadata),
        }

        with self.storage_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload) + "\n")

        logging.info(
            "accepted parameter update source=%s model=%s gradients=%d",
            request.source_id,
            request.model_id,
            len(request.gradients),
        )

        return parameters_pb2.ParameterUpdateAck(
            accepted=True,
            model_id=request.model_id,
            applied_version=f"{request.base_version}-updated",
            message="Parameter update persisted for downstream training.",
        )

    def Health(self, request, context):
        return parameters_pb2.HealthResponse(
            service="param-update-service",
            status="SERVING",
        )


def serve() -> None:
    port = os.getenv("PARAM_UPDATE_PORT", "50052")
    storage_path = Path(os.getenv("PARAM_UPDATE_STORAGE_PATH", "/tmp/updates.jsonl"))
    fuzzer_config = FuzzerRequestConfig.from_env()

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    parameters_pb2_grpc.add_ParamUpdateServiceServicer_to_server(
        ParamUpdateService(storage_path), server
    )
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    logging.info("param-update-service listening on %s", port)
    start_fuzzer_requester(fuzzer_config)
    server.wait_for_termination()


def start_fuzzer_requester(config: FuzzerRequestConfig) -> None:
    if config.prompt_count <= 0:
        return

    thread = threading.Thread(
        target=_request_fuzzer_loop,
        args=(config,),
        daemon=True,
        name="fuzzer-training-requester",
    )
    thread.start()


def _request_fuzzer_loop(config: FuzzerRequestConfig) -> None:
    if config.initial_delay_seconds > 0:
        time.sleep(config.initial_delay_seconds)

    attempts = 0
    while True:
        attempts += 1
        try:
            response = request_fuzzer_training(config)
            logging.info(
                "fuzzer training response accepted=%s model=%s version=%s prompts=%s",
                response.accepted,
                response.model_id,
                response.applied_version,
                response.prompts_generated,
            )
            attempts = 0
        except Exception as exc:
            logging.warning("fuzzer training request failed: %s", exc)
            if config.interval_seconds <= 0 and attempts >= config.max_attempts:
                return
            time.sleep(config.retry_seconds)
            continue

        if config.interval_seconds <= 0:
            return
        time.sleep(config.interval_seconds)


def request_fuzzer_training(config: FuzzerRequestConfig):
    with grpc.insecure_channel(config.target) as channel:
        client = parameters_pb2_grpc.FuzzerServiceStub(channel)
        return client.RunTrainingCycle(
            parameters_pb2.FuzzerTrainingRequest(
                request_id=_request_id(config.source_id),
                source_id=config.source_id,
                model_id=config.model_id,
                prompt_count=config.prompt_count,
                seed=config.seed,
                metadata={"initiator": "param-update-service"},
            ),
            timeout=config.timeout_seconds,
        )


def _request_id(source_id: str) -> str:
    return f"{source_id}-{int(time.time())}-{uuid.uuid4().hex[:8]}"


def _env_int(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        return int(raw_value)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        return float(raw_value)
    except ValueError:
        return default


if __name__ == "__main__":
    serve()
