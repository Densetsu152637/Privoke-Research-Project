from __future__ import annotations

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
        prompt_dataset_path: str | None,
        training_learning_rate: float,
        training_max_gradient: float,
        training_transformations_per_example: int,
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
        self.prompt_dataset_path = prompt_dataset_path
        self.training_learning_rate = training_learning_rate
        self.training_max_gradient = training_max_gradient
        self.training_transformations_per_example = (
            training_transformations_per_example
        )
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
                "privoke-runtime:50054",
            ),
            model_id=os.getenv("MODEL_ID", "privoke-baseline"),
            fuzzer_id=os.getenv("FUZZER_ID", "privoke-fuzzer"),
            port=env_int("FUZZER_PORT", 50053),
            timeout_seconds=env_float("FUZZ_TIMEOUT_SECONDS", 10.0),
            seed=env_int("FUZZ_SEED", 1337),
            max_prompt_count=env_int("FUZZ_MAX_PROMPT_COUNT", 256),
            prompt_dataset_path=os.getenv("FUZZ_PROMPT_DATASET_PATH"),
            training_learning_rate=env_float("FUZZ_TRAINING_LEARNING_RATE", 0.03),
            training_max_gradient=env_float("FUZZ_TRAINING_MAX_GRADIENT", 0.05),
            training_transformations_per_example=env_int(
                "FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE",
                1,
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
        )

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
