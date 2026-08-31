"""Validated configuration for the fuzzer training service."""

from __future__ import annotations

import math
import os
from dataclasses import dataclass

from privoke_service import env_float, env_int, env_string, validate_text
from training import BatchTrainingConfig


@dataclass(frozen=True)
class FuzzerConfig:
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

    @classmethod
    def from_env(cls) -> FuzzerConfig:
        return cls(
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
        ).validated()

    def validated(self) -> FuzzerConfig:
        _validate_positive_ints(
            FUZZ_MAX_PROMPT_COUNT=self.max_prompt_count,
            FUZZ_MAX_CONCURRENT_CYCLES=self.max_concurrent_cycles,
        )
        if self.training_transformations_per_example < 0:
            raise ValueError(
                "FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE must not be negative."
            )
        _validate_positive_floats(
            FUZZ_TIMEOUT_SECONDS=self.timeout_seconds,
            FUZZ_TRAINING_LEARNING_RATE=self.training_learning_rate,
            FUZZ_TRAINING_MAX_GRADIENT=self.training_max_gradient,
        )
        if not 1 <= self.port <= 65_535:
            raise ValueError("FUZZER_PORT must be between 1 and 65535.")
        for name, value in (
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
