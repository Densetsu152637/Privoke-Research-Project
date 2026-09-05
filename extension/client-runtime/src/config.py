from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from enum import Enum

import multiprocessing
import os
import threading
from privoke_service.stack_connection import stack_target

from .env import (
    env_bool,
    env_non_negative_float,
    env_optional_str,
    env_positive_float,
    env_positive_int,
)


class LLMChoice(Enum):

    Streamed = 0
    Local = 1
    Open = 2

    @classmethod
    def parse(cls, raw_value: str | "LLMChoice") -> "LLMChoice":
        if isinstance(raw_value, cls):
            return raw_value
        if not isinstance(raw_value, str):
            raise ValueError("LLM choice must be a string.")

        aliases = {
            "streamed": cls.Streamed,
            "privoke": cls.Streamed,
            "model-streaming": cls.Streamed,
            "model_streaming": cls.Streamed,
            "local": cls.Local,
            "lm-studio": cls.Local,
            "lm_studio": cls.Local,
            "lmstudio": cls.Local,
            "open": cls.Open,
            "openai": cls.Open,
        }
        normalised = raw_value.strip().lower()
        try:
            return aliases[normalised]
        except KeyError as exc:
            allowed = "streamed, local, open"
            raise ValueError(
                f"Unsupported LLM choice '{raw_value}'. Use: {allowed}."
            ) from exc

    @property
    def api_name(self) -> str:
        match self:
            case LLMChoice.Streamed:
                return "streamed"
            case LLMChoice.Local:
                return "local"
            case LLMChoice.Open:
                return "openai"


@dataclass(frozen=True)
class StreamedEndpointConfig:
    target: str
    model_id: str
    consumer_id: str
    timeout_seconds: float

    @classmethod
    def from_env(cls) -> "StreamedEndpointConfig":
        return cls(
            target=stack_target("MODEL_STREAMING"),
            model_id=os.getenv("MODEL_ID", "latest"),
            consumer_id=os.getenv("MODEL_STREAMING_CONSUMER_ID", "client-runtime"),
            timeout_seconds=env_positive_float(
                "MODEL_STREAMING_TIMEOUT_SECONDS",
                10.0,
            ),
        )


@dataclass(frozen=True)
class LocalEndpointConfig:
    base_url: str
    model: str | None
    api_key: str | None
    timeout_seconds: float
    temperature: float
    max_tokens: int
    response_format: str

    @classmethod
    def from_env(cls) -> "LocalEndpointConfig":
        return cls(
            base_url=os.getenv("LM_STUDIO_BASE_URL", "http://localhost:1234/v1"),
            model=env_optional_str("LM_STUDIO_MODEL"),
            api_key=env_optional_str("LM_STUDIO_API_KEY"),
            timeout_seconds=env_positive_float("LM_STUDIO_TIMEOUT_SECONDS", 60.0),
            temperature=env_non_negative_float("LM_STUDIO_TEMPERATURE", 0.25),
            max_tokens=env_positive_int("LM_STUDIO_MAX_TOKENS", 512),
            response_format=os.getenv("LM_STUDIO_RESPONSE_FORMAT", "json_schema"),
        )


@dataclass(frozen=True)
class OpenAIEndpointConfig:
    api_key: str | None
    model: str
    base_url: str | None
    timeout_seconds: float
    temperature: float
    max_tokens: int

    @classmethod
    def from_env(cls) -> "OpenAIEndpointConfig":
        return cls(
            api_key=env_optional_str("OPENAI_API_KEY"),
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            base_url=env_optional_str("OPENAI_BASE_URL")
            or env_optional_str("OPENAI_API_BASE"),
            timeout_seconds=env_positive_float("OPENAI_TIMEOUT_SECONDS", 60.0),
            temperature=env_non_negative_float("OPENAI_TEMPERATURE", 0.25),
            max_tokens=env_positive_int("OPENAI_MAX_TOKENS", 512),
        )


@dataclass(frozen=True)
class LLMRuntimeConfig:
    choice: LLMChoice
    streamed: StreamedEndpointConfig
    local: LocalEndpointConfig
    openai: OpenAIEndpointConfig

    @classmethod
    def from_env(cls) -> "LLMRuntimeConfig":
        return cls(
            choice=LLMChoice.parse(os.getenv("PRIVOKE_LLM_CHOICE", "streamed")),
            streamed=StreamedEndpointConfig.from_env(),
            local=LocalEndpointConfig.from_env(),
            openai=OpenAIEndpointConfig.from_env(),
        )

@dataclass
class GlobalConfig:
    """Global configuration"""

    wait_for_regex: bool = field(
        default_factory=lambda: env_bool("PRIVOKE_WAIT_FOR_REGEX", True)
    )
    threadpool: ThreadPoolExecutor = field(
        default_factory=lambda: ThreadPoolExecutor(
            max_workers=multiprocessing.cpu_count()
        )
    )
    _llm_config: LLMRuntimeConfig = field(
        default_factory=LLMRuntimeConfig.from_env,
        repr=False,
    )
    _lock: threading.RLock = field(
        default_factory=threading.RLock,
        init=False,
        repr=False,
    )

    @property
    def llm_choice(self) -> LLMChoice:
        return self.get_llm_config().choice

    @llm_choice.setter
    def llm_choice(self, value: LLMChoice | str) -> None:
        self.update_llm_config(choice=LLMChoice.parse(value))

    def get_llm_config(self) -> LLMRuntimeConfig:
        with self._lock:
            return self._llm_config

    def set_llm_config(self, llm_config: LLMRuntimeConfig) -> LLMRuntimeConfig:
        with self._lock:
            self._llm_config = llm_config
            return self._llm_config

    def update_llm_config(
        self,
        *,
        choice: LLMChoice | None = None,
        streamed: StreamedEndpointConfig | None = None,
        local: LocalEndpointConfig | None = None,
        openai: OpenAIEndpointConfig | None = None,
    ) -> LLMRuntimeConfig:
        with self._lock:
            config = self._llm_config
            if choice is not None:
                config = replace(config, choice=choice)
            if streamed is not None:
                config = replace(config, streamed=streamed)
            if local is not None:
                config = replace(config, local=local)
            if openai is not None:
                config = replace(config, openai=openai)
            self._llm_config = config
            return config

GLOBAL_CONFIG = GlobalConfig()
