"""Configuration for the telemetry service."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from privoke_service import env_int, env_string


@dataclass(frozen=True)
class TelemetryConfig:
    port: int
    database_path: Path
    max_message_bytes: int
    max_query_limit: int = 1_000

    @classmethod
    def from_env(cls) -> TelemetryConfig:
        return cls(
            port=env_int("TELEMETRY_PORT", 50055),
            database_path=Path(env_string("TELEMETRY_DB_PATH", "/data/telemetry.db")),
            max_message_bytes=env_int("TELEMETRY_MAX_MESSAGE_BYTES", 131_072),
            max_query_limit=env_int("TELEMETRY_MAX_QUERY_LIMIT", 1_000),
        ).validated()

    def validated(self) -> TelemetryConfig:
        if not 1 <= self.port <= 65_535:
            raise ValueError("TELEMETRY_PORT must be between 1 and 65535.")
        if self.max_message_bytes <= 0:
            raise ValueError("TELEMETRY_MAX_MESSAGE_BYTES must be positive.")
        if self.max_query_limit <= 0:
            raise ValueError("TELEMETRY_MAX_QUERY_LIMIT must be positive.")
        return self
