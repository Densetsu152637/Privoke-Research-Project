from __future__ import annotations

import math
import os

from training import BatchTrainingConfig


class FuzzerConfig:
    def __init__(
        self,
        model_streaming_target: str,
        param_update_target: str,
        privoke_runtime_target: str,
        model_id: str,
        fuzzer_id: str,
        port: int,
        timeout_seconds: float,
        seed: int,
        max_prompt_count: int,
        max_concurrent_cycles: int,
        prompt_dataset_path: str | None,
        training_learning_rate: float,
        training_max_gradient: float,
        training_transformations_per_example: int,
        training_runtime_max_in_flight: int,
        model_streaming_fetch_max_attempts: int,
        model_streaming_connect_timeout_seconds: float,
        model_streaming_retry_initial_seconds: float,
        model_streaming_retry_max_seconds: float,
    ):
        self.model_streaming_target = model_streaming_target
        self.param_update_target = param_update_target
        self.privoke_runtime_target = privoke_runtime_target
        self.model_id = model_id
        self.fuzzer_id = fuzzer_id
        self.port = port
        self.timeout_seconds = timeout_seconds
        self.seed = seed
        self.max_prompt_count = max_prompt_count
        self.max_concurrent_cycles = max_concurrent_cycles
        self.prompt_dataset_path = prompt_dataset_path
        self.training_learning_rate = training_learning_rate
        self.training_max_gradient = training_max_gradient
        self.training_transformations_per_example = (
            training_transformations_per_example
        )
        self.training_runtime_max_in_flight = training_runtime_max_in_flight
        self.model_streaming_fetch_max_attempts = model_streaming_fetch_max_attempts
        self.model_streaming_connect_timeout_seconds = (
            model_streaming_connect_timeout_seconds
        )
        self.model_streaming_retry_initial_seconds = (
            model_streaming_retry_initial_seconds
        )
        self.model_streaming_retry_max_seconds = model_streaming_retry_max_seconds

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
            privoke_runtime_target=os.getenv(
                "PRIVOKE_RUNTIME_TARGET",
                "client-runtime:50054",
            ),
            model_id=os.getenv("MODEL_ID", "privoke-baseline"),
            fuzzer_id=os.getenv("FUZZER_ID", "privoke-fuzzer"),
            port=env_int("FUZZER_PORT", 50053),
            timeout_seconds=env_float("FUZZ_TIMEOUT_SECONDS", 10.0),
            seed=env_int("FUZZ_SEED", 1337),
            max_prompt_count=env_int("FUZZ_MAX_PROMPT_COUNT", 256),
            max_concurrent_cycles=env_int("FUZZ_MAX_CONCURRENT_CYCLES", 1),
            prompt_dataset_path=os.getenv("FUZZ_PROMPT_DATASET_PATH"),
            training_learning_rate=env_float("FUZZ_TRAINING_LEARNING_RATE", 0.03),
            training_max_gradient=env_float("FUZZ_TRAINING_MAX_GRADIENT", 0.05),
            training_transformations_per_example=env_int(
                "FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE",
                1,
            ),
            training_runtime_max_in_flight=env_int(
                "FUZZ_TRAINING_RUNTIME_MAX_IN_FLIGHT",
                8,
            ),
            model_streaming_fetch_max_attempts=env_int(
                "MODEL_STREAMING_FETCH_MAX_ATTEMPTS",
                5,
            ),
            model_streaming_connect_timeout_seconds=env_float(
                "MODEL_STREAMING_CONNECT_TIMEOUT_SECONDS",
                2.0,
            ),
            model_streaming_retry_initial_seconds=env_float(
                "MODEL_STREAMING_RETRY_INITIAL_SECONDS",
                1.0,
            ),
            model_streaming_retry_max_seconds=env_float(
                "MODEL_STREAMING_RETRY_MAX_SECONDS",
                4.0,
            ),
        ).validated()

    def validated(self) -> "FuzzerConfig":
        if self.max_prompt_count <= 0:
            raise ValueError("FUZZ_MAX_PROMPT_COUNT must be positive.")
        if self.max_concurrent_cycles <= 0:
            raise ValueError("FUZZ_MAX_CONCURRENT_CYCLES must be positive.")
        if self.training_runtime_max_in_flight <= 0:
            raise ValueError(
                "FUZZ_TRAINING_RUNTIME_MAX_IN_FLIGHT must be positive."
            )
        if self.training_transformations_per_example < 0:
            raise ValueError(
                "FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE must not be negative."
            )
        for name, value in (
            ("FUZZ_TIMEOUT_SECONDS", self.timeout_seconds),
            ("FUZZ_TRAINING_LEARNING_RATE", self.training_learning_rate),
            ("FUZZ_TRAINING_MAX_GRADIENT", self.training_max_gradient),
            (
                "MODEL_STREAMING_CONNECT_TIMEOUT_SECONDS",
                self.model_streaming_connect_timeout_seconds,
            ),
            (
                "MODEL_STREAMING_RETRY_INITIAL_SECONDS",
                self.model_streaming_retry_initial_seconds,
            ),
            (
                "MODEL_STREAMING_RETRY_MAX_SECONDS",
                self.model_streaming_retry_max_seconds,
            ),
        ):
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be finite and positive.")
        if self.model_streaming_fetch_max_attempts <= 0:
            raise ValueError("MODEL_STREAMING_FETCH_MAX_ATTEMPTS must be positive.")
        if not self.model_id or len(self.model_id) > 128:
            raise ValueError("MODEL_ID must contain 1 to 128 characters.")
        if not self.fuzzer_id or len(self.fuzzer_id) > 128:
            raise ValueError("FUZZER_ID must contain 1 to 128 characters.")
        for name, value in (("MODEL_ID", self.model_id), ("FUZZER_ID", self.fuzzer_id)):
            if any(ord(character) < 32 or ord(character) == 127 for character in value):
                raise ValueError(f"{name} must not contain control characters.")
        return self

    def batch_training_config(self, seed: int) -> BatchTrainingConfig:
        return BatchTrainingConfig(
            learning_rate=self.training_learning_rate,
            max_gradient=self.training_max_gradient,
            transformations_per_example=self.training_transformations_per_example,
            seed=seed,
        )


def env_float(name: str, default: float) -> float:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        return float(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number.") from exc


def env_int(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        return int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer.") from exc
