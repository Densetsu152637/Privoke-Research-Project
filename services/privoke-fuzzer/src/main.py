from __future__ import annotations

import logging
import os
import random
import signal
import sys
import time
from pathlib import Path
from typing import Iterable

import grpc


GENERATED_DIR = Path(__file__).resolve().parents[1] / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from privoke.v1 import parameters_pb2, parameters_pb2_grpc


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

_SHOULD_STOP = False


def main() -> None:
    global _SHOULD_STOP

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    config = FuzzerConfig.from_env()
    random.seed(config.seed)
    logging.info(
        "starting fuzzer id=%s model=%s interval=%ss",
        config.fuzzer_id,
        config.model_id,
        config.interval_seconds,
    )

    while not _SHOULD_STOP:
        try:
            snapshot = fetch_snapshot(config)
            ack = submit_update(config, snapshot)
            logging.info(
                "submitted update accepted=%s model=%s version=%s",
                ack.accepted,
                ack.model_id,
                ack.applied_version,
            )
        except Exception as exc:
            logging.warning("fuzz cycle failed: %s", exc)

        _sleep_interruptibly(config.interval_seconds)


class FuzzerConfig:
    def __init__(
        self,
        model_streaming_target: str,
        param_update_target: str,
        model_id: str,
        fuzzer_id: str,
        interval_seconds: float,
        timeout_seconds: float,
        perturbation_scale: float,
        seed: int,
    ):
        self.model_streaming_target = model_streaming_target
        self.param_update_target = param_update_target
        self.model_id = model_id
        self.fuzzer_id = fuzzer_id
        self.interval_seconds = interval_seconds
        self.timeout_seconds = timeout_seconds
        self.perturbation_scale = perturbation_scale
        self.seed = seed

    @classmethod
    def from_env(cls) -> "FuzzerConfig":
        return cls(
            model_streaming_target=os.getenv(
                "MODEL_STREAMING_TARGET",
                "model-streaming-service:50051",
            ),
            param_update_target=os.getenv(
                "PARAM_UPDATE_TARGET",
                "param-update-service:50052",
            ),
            model_id=os.getenv("MODEL_ID", "privoke-baseline"),
            fuzzer_id=os.getenv("FUZZER_ID", "privoke-fuzzer"),
            interval_seconds=_env_float("FUZZ_INTERVAL_SECONDS", 15.0),
            timeout_seconds=_env_float("FUZZ_TIMEOUT_SECONDS", 10.0),
            perturbation_scale=_env_float("FUZZ_PERTURBATION_SCALE", 0.01),
            seed=_env_int("FUZZ_SEED", 1337),
        )


def fetch_snapshot(config: FuzzerConfig):
    with grpc.insecure_channel(config.model_streaming_target) as channel:
        client = parameters_pb2_grpc.ModelStreamingServiceStub(channel)
        return client.GetModelParameters(
            parameters_pb2.ModelParametersRequest(
                consumer_id=config.fuzzer_id,
                model_id=config.model_id,
            ),
            timeout=config.timeout_seconds,
        )


def submit_update(config: FuzzerConfig, snapshot):
    gradients = list(perturb_parameters(snapshot.parameters, config.perturbation_scale))
    with grpc.insecure_channel(config.param_update_target) as channel:
        client = parameters_pb2_grpc.ParamUpdateServiceStub(channel)
        return client.SubmitParameterUpdate(
            parameters_pb2.ParameterUpdateRequest(
                source_id=config.fuzzer_id,
                model_id=snapshot.model_id,
                base_version=snapshot.version,
                gradients=gradients,
                metadata={
                    "strategy": "bounded_random_perturbation",
                    "snapshot_generated_at_unix": str(snapshot.generated_at_unix),
                    "perturbation_scale": str(config.perturbation_scale),
                },
            ),
            timeout=config.timeout_seconds,
        )


def perturb_parameters(
    parameters: Iterable,
    perturbation_scale: float,
) -> Iterable:
    for parameter in parameters:
        yield parameters_pb2.Parameter(
            name=parameter.name,
            values=[
                _bounded_noise(perturbation_scale)
                for _ in parameter.values
            ],
        )


def _bounded_noise(scale: float) -> float:
    return random.uniform(-scale, scale)


def _sleep_interruptibly(seconds: float) -> None:
    deadline = time.monotonic() + max(0.0, seconds)
    while not _SHOULD_STOP and time.monotonic() < deadline:
        time.sleep(min(0.25, deadline - time.monotonic()))


def _stop(signum, frame) -> None:
    global _SHOULD_STOP
    _SHOULD_STOP = True


def _env_float(name: str, default: float) -> float:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        return float(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number.") from exc


def _env_int(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        return int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer.") from exc


if __name__ == "__main__":
    main()
