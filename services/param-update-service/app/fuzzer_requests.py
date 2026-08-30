from __future__ import annotations

import logging
import math
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

SHARED_DIR = Path(__file__).resolve().parents[3] / "shared/python"
if SHARED_DIR.exists() and str(SHARED_DIR) not in sys.path:
    sys.path.insert(0, str(SHARED_DIR))

import grpc
from privoke.v1 import parameters_pb2, parameters_pb2_grpc
from privoke_service import env_float, env_int, env_string, validate_text

LOGGER = logging.getLogger(__name__)


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
    def from_env(cls) -> FuzzerRequestConfig:
        config = cls(
            target=env_string("FUZZER_TARGET", "privoke-fuzzer:50053", strip=True),
            prompt_count=env_int("FUZZER_PROMPT_COUNT", 0),
            model_id=env_string("MODEL_ID", "privoke-baseline", strip=True),
            source_id=env_string(
                "PARAM_UPDATE_SOURCE_ID",
                "param-update-service",
                strip=True,
            ),
            timeout_seconds=env_float("FUZZER_REQUEST_TIMEOUT_SECONDS", 30.0),
            interval_seconds=env_float("FUZZER_REQUEST_INTERVAL_SECONDS", 0.0),
            initial_delay_seconds=env_float(
                "FUZZER_REQUEST_INITIAL_DELAY_SECONDS",
                2.0,
            ),
            retry_seconds=env_float("FUZZER_REQUEST_RETRY_SECONDS", 2.0),
            max_attempts=env_int("FUZZER_REQUEST_MAX_ATTEMPTS", 3),
            seed=env_int("FUZZER_REQUEST_SEED", 1337),
        )
        config.validate()
        return config

    def validate(self) -> None:
        validate_text(self.target, "FUZZER_TARGET", required=True, limit=256)
        validate_text(self.model_id, "MODEL_ID", required=True)
        validate_text(self.source_id, "PARAM_UPDATE_SOURCE_ID", required=True)
        if self.prompt_count < 0:
            raise ValueError("FUZZER_PROMPT_COUNT must not be negative.")
        if self.max_attempts <= 0:
            raise ValueError("FUZZER_REQUEST_MAX_ATTEMPTS must be positive.")
        for name, value, allow_zero in (
            ("FUZZER_REQUEST_TIMEOUT_SECONDS", self.timeout_seconds, False),
            ("FUZZER_REQUEST_INTERVAL_SECONDS", self.interval_seconds, True),
            ("FUZZER_REQUEST_INITIAL_DELAY_SECONDS", self.initial_delay_seconds, True),
            ("FUZZER_REQUEST_RETRY_SECONDS", self.retry_seconds, True),
        ):
            if not math.isfinite(value) or value < 0 or (not allow_zero and value == 0):
                requirement = "non-negative" if allow_zero else "positive"
                raise ValueError(f"{name} must be finite and {requirement}.")


def start_fuzzer_requester(config: FuzzerRequestConfig) -> None:
    if config.prompt_count <= 0:
        return

    thread = threading.Thread(
        target=request_fuzzer_loop,
        args=(config,),
        daemon=True,
        name="fuzzer-training-requester",
    )
    thread.start()


def request_fuzzer_loop(config: FuzzerRequestConfig) -> None:
    if config.initial_delay_seconds > 0:
        time.sleep(config.initial_delay_seconds)

    attempts = 0
    cycle_request_id = request_id(config.source_id)
    while True:
        attempts += 1
        try:
            response = request_fuzzer_training(
                config,
                training_request_id=cycle_request_id,
            )
            LOGGER.info(
                "fuzzer training response accepted=%s model=%s version=%s prompts=%s",
                response.accepted,
                response.model_id,
                response.applied_version,
                response.prompts_generated,
            )
            attempts = 0
        except (grpc.RpcError, RuntimeError) as exc:
            LOGGER.warning("fuzzer training request failed: %s", exc)
            if config.interval_seconds <= 0 and attempts >= config.max_attempts:
                return
            time.sleep(config.retry_seconds)
            continue

        if config.interval_seconds <= 0:
            return
        time.sleep(config.interval_seconds)
        cycle_request_id = request_id(config.source_id)


def request_fuzzer_training(
    config: FuzzerRequestConfig,
    training_request_id: str | None = None,
):
    with grpc.insecure_channel(config.target) as channel:
        client = parameters_pb2_grpc.FuzzerServiceStub(channel)
        return client.RunTrainingCycle(
            parameters_pb2.FuzzerTrainingRequest(
                request_id=training_request_id or request_id(config.source_id),
                source_id=config.source_id,
                model_id=config.model_id,
                prompt_count=config.prompt_count,
                seed=config.seed,
                metadata={"initiator": "param-update-service"},
            ),
            timeout=config.timeout_seconds,
        )


def request_id(source_id: str) -> str:
    return f"{source_id}-{int(time.time())}-{uuid.uuid4().hex[:8]}"
