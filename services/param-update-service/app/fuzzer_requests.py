from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass

import grpc

from privoke.v1 import parameters_pb2, parameters_pb2_grpc


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
            prompt_count=env_int("FUZZER_PROMPT_COUNT", 0),
            model_id=os.getenv("MODEL_ID", "privoke-baseline"),
            source_id=os.getenv("PARAM_UPDATE_SOURCE_ID", "param-update-service"),
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
                request_id=request_id(config.source_id),
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


def env_int(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        return int(raw_value)
    except ValueError:
        return default


def env_float(name: str, default: float) -> float:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        return float(raw_value)
    except ValueError:
        return default
