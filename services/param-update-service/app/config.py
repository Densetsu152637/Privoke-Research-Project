"""Configuration for the parameter-update service."""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

from privoke_service import env_float, env_int, env_string, validate_text


@dataclass(frozen=True)
class ParamUpdateConfig:
    port: int
    storage_path: Path
    model_artifact_path: Path
    model_id: str
    max_abs_gradient: float
    max_message_bytes: int

    @classmethod
    def from_env(cls) -> ParamUpdateConfig:
        return cls(
            port=env_int("PARAM_UPDATE_PORT", 50052),
            storage_path=Path(
                env_string("PARAM_UPDATE_STORAGE_PATH", "/data/updates.jsonl")
            ),
            model_artifact_path=Path(
                env_string("MODEL_ARTIFACT_PATH", "/models/privoke-baseline.json")
            ),
            model_id=env_string("MODEL_ID", "privoke-baseline", strip=True),
            max_abs_gradient=env_float("PARAM_UPDATE_MAX_ABS_GRADIENT", 1.0),
            max_message_bytes=env_int(
                "PARAM_UPDATE_MAX_MESSAGE_BYTES",
                1_048_576,
            ),
        ).validated()

    def validated(self) -> ParamUpdateConfig:
        if not 1 <= self.port <= 65_535:
            raise ValueError("PARAM_UPDATE_PORT must be between 1 and 65535.")
        validate_text(self.model_id, "MODEL_ID", required=True)
        if not math.isfinite(self.max_abs_gradient) or self.max_abs_gradient <= 0:
            raise ValueError(
                "PARAM_UPDATE_MAX_ABS_GRADIENT must be finite and positive."
            )
        if self.max_message_bytes <= 0:
            raise ValueError("PARAM_UPDATE_MAX_MESSAGE_BYTES must be positive.")
        return self
