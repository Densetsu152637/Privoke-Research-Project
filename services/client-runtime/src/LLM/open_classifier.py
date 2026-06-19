
import os
import json
from typing import List
from dotenv import load_dotenv
from .prompt import system_prompt, user_prompt
from .abs_classifier import AbstractClassifier
from ..classification import ClassificationResult, build_results
from ..env import env_float, env_positive_int

load_dotenv()

class OpenClassifier(AbstractClassifier):
    """
    Semantic privacy risk classifier using OpenAI API.
    Detects implicit identifiers, contextual risks, and indirect privacy threats.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        timeout_seconds: float | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        use_environment: bool = True,
    ):
        """Initialize OpenAI client with runtime or environment configuration."""
        from openai import OpenAI

        if use_environment:
            resolved_api_key = api_key if api_key is not None else os.getenv(
                "OPENAI_API_KEY"
            )
            resolved_base_url = (
                base_url
                if base_url is not None
                else os.getenv("OPENAI_BASE_URL") or os.getenv("OPENAI_API_BASE")
            )
        else:
            resolved_api_key = api_key
            resolved_base_url = base_url

        if not resolved_api_key:
            raise ValueError(
                "OpenAI API key is not configured. Set OPENAI_API_KEY or "
                "provide openai.api_key via /config/llm."
            )

        resolved_timeout = (
            timeout_seconds
            if timeout_seconds is not None
            else (
                env_float("OPENAI_TIMEOUT_SECONDS", 60.0)
                if use_environment
                else 60.0
            )
        )
        if resolved_timeout <= 0:
            raise ValueError("OPENAI_TIMEOUT_SECONDS must be greater than zero.")

        client_options = {
            "api_key": resolved_api_key,
            "timeout": resolved_timeout,
        }
        if resolved_base_url:
            client_options["base_url"] = resolved_base_url

        self.client = OpenAI(**client_options)
        self.model = (
            model
            if not use_environment
            else model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        )
        self.temperature = (
            temperature
            if temperature is not None
            else (
                env_float("OPENAI_TEMPERATURE", 0.25)
                if use_environment
                else 0.25
            )
        )
        self.max_tokens = (
            max_tokens
            if max_tokens is not None
            else (
                env_positive_int("OPENAI_MAX_TOKENS", 512)
                if use_environment
                else 512
            )
        )

    def classify(self, text: str) -> List[ClassificationResult]:
        response = self.client.chat.completions.create(
            model=self.model,
            messages = [
                {
                    "role": "system", 
                    "content": system_prompt
                },
                {
                    "role": "user", 
                    "content": user_prompt(text)
                }
            ],
            response_format = {
                "type": "json_object"
            },
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )

        content = response.choices[0].message.content.strip()

        return build_results(json.loads(content))
