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
    presence_model_id: str
    fuzzer_id: str
    port: int
    timeout_seconds: float
    seed: int
    max_prompt_count: int
    max_concurrent_cycles: int
    prompt_dataset_path: str | None
    presence_dataset_path: str | None
    training_learning_rate: float
    training_max_gradient: float
    training_transformations_per_example: int
    minimum_exact_match_rate: float
    heldout_prompt_count: int
    curriculum_manifest_path: str | None = None
    curriculum_state_path: str | None = None
    curriculum_replay_fraction: float = 0.25
    training_replay_weight: float = 0.35

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
            presence_model_id=env_string("PRESENCE_MODEL_ID", "privoke-presence-balanced", strip=True),
            fuzzer_id=env_string("FUZZER_ID", "privoke-fuzzer", strip=True),
            port=env_int("FUZZER_PORT", 50053),
            timeout_seconds=env_float("FUZZ_TIMEOUT_SECONDS", 10.0),
            seed=env_int("FUZZ_SEED", 1337),
            max_prompt_count=env_int("FUZZ_MAX_PROMPT_COUNT", 256),
            max_concurrent_cycles=env_int("FUZZ_MAX_CONCURRENT_CYCLES", 1),
            prompt_dataset_path=os.getenv("FUZZ_PROMPT_DATASET_PATH"),
            presence_dataset_path=os.getenv("FUZZ_PRESENCE_DATASET_PATH"),
            training_learning_rate=env_float("FUZZ_TRAINING_LEARNING_RATE", 0.03),
            training_max_gradient=env_float("FUZZ_TRAINING_MAX_GRADIENT", 0.05),
            training_transformations_per_example=env_int(
                "FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE",
                1,
            ),
            minimum_exact_match_rate=env_float(
                "FUZZ_MIN_EXACT_MATCH_RATE",
                0.0,
            ),
            heldout_prompt_count=env_int("FUZZ_HELDOUT_PROMPT_COUNT", 16),
            curriculum_manifest_path=os.getenv("FUZZ_CURRICULUM_MANIFEST_PATH"),
            curriculum_state_path=os.getenv("FUZZ_CURRICULUM_STATE_PATH"),
            curriculum_replay_fraction=env_float("FUZZ_CURRICULUM_REPLAY_FRACTION", 0.25),
            training_replay_weight=env_float("FUZZ_TRAINING_REPLAY_WEIGHT", 0.35),
        ).validated()

    def validated(self) -> FuzzerConfig:
        if not math.isfinite(self.training_replay_weight) or not 0 < self.training_replay_weight <= 1:
            raise ValueError("FUZZ_TRAINING_REPLAY_WEIGHT must be finite and in (0, 1].")
        if not math.isfinite(self.curriculum_replay_fraction) or not 0 < self.curriculum_replay_fraction < 1:
            raise ValueError("FUZZ_CURRICULUM_REPLAY_FRACTION must be between zero and one.")
        if self.curriculum_manifest_path and not self.curriculum_state_path:
            raise ValueError("Curriculum training requires a durable FUZZ_CURRICULUM_STATE_PATH.")
        if self.curriculum_manifest_path and self.heldout_prompt_count != 16:
            raise ValueError("Curriculum training requires the fixed 16-row gate.")
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
        if not math.isfinite(self.minimum_exact_match_rate) or self.minimum_exact_match_rate < 0:
            raise ValueError(
                "FUZZ_MIN_EXACT_MATCH_RATE must be finite and non-negative."
            )
        if self.minimum_exact_match_rate > 1:
            raise ValueError("FUZZ_MIN_EXACT_MATCH_RATE must not exceed 1.")
        if not 2 <= self.heldout_prompt_count <= 256:
            raise ValueError("FUZZ_HELDOUT_PROMPT_COUNT must be between 2 and 256.")
        expanded_count = self.max_prompt_count * (
            self.training_transformations_per_example + 1
        ) + self.heldout_prompt_count
        if expanded_count > 1024:
            raise ValueError("Expanded training plus held-out examples must not exceed 1024.")
        if not 1 <= self.port <= 65_535:
            raise ValueError("FUZZER_PORT must be between 1 and 65535.")
        for name, value in (
            ("PARAM_UPDATE_TARGET", self.param_update_target),
            ("PRIVOKE_RUNTIME_TARGET", self.privoke_runtime_target),
            ("MODEL_ID", self.model_id),
            ("PRESENCE_MODEL_ID", self.presence_model_id),
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
            golden_example_weight=self.training_replay_weight,
        )

    def presence_training_config(self, seed: int) -> BatchTrainingConfig:
        """Presence labels are already canonical rows and receive no augmentation."""
        return BatchTrainingConfig(
            learning_rate=self.training_learning_rate,
            max_gradient=self.training_max_gradient,
            transformations_per_example=0,
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
