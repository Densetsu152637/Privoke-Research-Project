"""Validated configuration for the fuzzer training service."""

from __future__ import annotations

import math
import os
from dataclasses import dataclass

from privoke_service import env_float, env_int, env_string, validate_text
from training import BatchTrainingConfig


@dataclass(frozen=True)
class FuzzerConfig:
    model_streaming_target: str
    param_update_target: str
    privoke_runtime_target: str
    model_id: str
    fuzzer_id: str
    port: int
    timeout_seconds: float
    seed: int
    max_prompt_count: int
    max_concurrent_cycles: int
    prompt_dataset_path: str | None
    training_learning_rate: float
    training_max_gradient: float
    training_transformations_per_example: int
    training_runtime_max_in_flight: int
    model_streaming_fetch_max_attempts: int
    model_streaming_connect_timeout_seconds: float
    model_streaming_retry_initial_seconds: float
    model_streaming_retry_max_seconds: float

    @classmethod
    def from_env(cls) -> FuzzerConfig:
        return cls(
            model_streaming_target=env_string(
                "MODEL_STREAMING_TARGET",
                "model-streaming-service:50051",
                strip=True,
            ),
            param_update_target=env_string(
                "PARAM_UPDATE_TARGET",
                "param-update-service:50052",
                strip=True,
            ),
            privoke_runtime_target=env_string(
                "PRIVOKE_RUNTIME_TARGET",
                "client-runtime:50054",
                strip=True,
            ),
            model_id=env_string("MODEL_ID", "privoke-baseline", strip=True),
            fuzzer_id=env_string("FUZZER_ID", "privoke-fuzzer", strip=True),
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

    def validated(self) -> FuzzerConfig:
        _validate_positive_ints(
            FUZZ_MAX_PROMPT_COUNT=self.max_prompt_count,
            FUZZ_MAX_CONCURRENT_CYCLES=self.max_concurrent_cycles,
            FUZZ_TRAINING_RUNTIME_MAX_IN_FLIGHT=self.training_runtime_max_in_flight,
            MODEL_STREAMING_FETCH_MAX_ATTEMPTS=self.model_streaming_fetch_max_attempts,
        )
        if self.training_transformations_per_example < 0:
            raise ValueError(
                "FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE must not be negative."
            )
        _validate_positive_floats(
            FUZZ_TIMEOUT_SECONDS=self.timeout_seconds,
            FUZZ_TRAINING_LEARNING_RATE=self.training_learning_rate,
            FUZZ_TRAINING_MAX_GRADIENT=self.training_max_gradient,
            MODEL_STREAMING_CONNECT_TIMEOUT_SECONDS=(
                self.model_streaming_connect_timeout_seconds
            ),
            MODEL_STREAMING_RETRY_INITIAL_SECONDS=(
                self.model_streaming_retry_initial_seconds
            ),
            MODEL_STREAMING_RETRY_MAX_SECONDS=self.model_streaming_retry_max_seconds,
        )
        if not 1 <= self.port <= 65_535:
            raise ValueError("FUZZER_PORT must be between 1 and 65535.")
        for name, value in (
            ("MODEL_STREAMING_TARGET", self.model_streaming_target),
            ("PARAM_UPDATE_TARGET", self.param_update_target),
            ("PRIVOKE_RUNTIME_TARGET", self.privoke_runtime_target),
            ("MODEL_ID", self.model_id),
            ("FUZZER_ID", self.fuzzer_id),
        ):
            validate_text(value, name, required=True, limit=256)
        return self

    def batch_training_config(self, seed: int) -> BatchTrainingConfig:
        return BatchTrainingConfig(
            learning_rate=self.training_learning_rate,
            max_gradient=self.training_max_gradient,
            transformations_per_example=self.training_transformations_per_example,
            seed=seed,
        )


def _validate_positive_ints(**values: int) -> None:
    for name, value in values.items():
        if value <= 0:
            raise ValueError(f"{name} must be positive.")


def _validate_positive_floats(**values: float) -> None:
    for name, value in values.items():
        if not math.isfinite(value) or value <= 0:
            raise ValueError(f"{name} must be finite and positive.")
