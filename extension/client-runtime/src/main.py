from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def _prepare_import_paths() -> None:
    current_dir = Path(__file__).resolve().parent
    package_parent = current_dir.parent

    if __package__:
        return

    # Running ``python src/main.py`` adds ``src`` to sys.path. That makes the
    # local ``src/regex`` package shadow the third-party ``regex`` dependency
    # used by Presidio. Import the source tree as the ``src`` package instead.
    current_path = str(current_dir)
    while current_path in sys.path:
        sys.path.remove(current_path)

    package_path = str(package_parent)
    if package_path not in sys.path:
        sys.path.insert(0, package_path)


_prepare_import_paths()

if __package__:
    from .config import GLOBAL_CONFIG, LLMChoice
    from .env import env_bool, env_positive_int
    from .hosting import run_server
    from .hosting.server import DEFAULT_HOST, DEFAULT_PORT
else:
    from src.config import GLOBAL_CONFIG, LLMChoice
    from src.env import env_bool, env_positive_int
    from src.hosting import run_server
    from src.hosting.server import DEFAULT_HOST, DEFAULT_PORT


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the localhost-only PriVoke prompt inspection server."
    )
    parser.add_argument(
        "--host",
        default=os.getenv("PRIVOKE_HOST", DEFAULT_HOST),
        help="Loopback host to bind. Defaults to 127.0.0.1.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=env_positive_int("PRIVOKE_PORT", DEFAULT_PORT),
        help="Local TCP port to bind. Defaults to 8765.",
    )
    parser.add_argument(
        "--llm-choice",
        default=os.getenv("PRIVOKE_LLM_CHOICE", "streamed").lower(),
        help=(
            "Semantic classifier backend: streamed=model-streaming-service, "
            "local/lm-studio=LM Studio, open/openai=OpenAI."
        ),
    )
    parser.add_argument(
        "--max-prompt-chars",
        type=int,
        default=env_positive_int("PRIVOKE_MAX_PROMPT_CHARS", 20_000),
        help="Maximum prompt text length accepted by the API.",
    )
    parser.add_argument(
        "--cors-origin",
        default=os.getenv("PRIVOKE_CORS_ORIGIN", ""),
        help="Exact trusted CORS origin for local web clients; disabled by default.",
    )
    parser.add_argument(
        "--wait-for-regex",
        action=argparse.BooleanOptionalAction,
        default=env_bool("PRIVOKE_WAIT_FOR_REGEX", GLOBAL_CONFIG.wait_for_regex),
        help="Run regex rules before starting slower detector jobs.",
    )

    args = parser.parse_args()
    _configure_runtime(args.llm_choice, args.wait_for_regex)
    run_server(
        host=args.host,
        port=args.port,
        max_text_chars=args.max_prompt_chars,
        cors_origin=args.cors_origin,
    )


def _configure_runtime(llm_choice: str, wait_for_regex: bool) -> None:
    GLOBAL_CONFIG.llm_choice = _llm_choice(llm_choice)
    GLOBAL_CONFIG.wait_for_regex = wait_for_regex


def _llm_choice(raw_value: str) -> LLMChoice:
    return LLMChoice.parse(raw_value)

if __name__ == "__main__":
    main()
