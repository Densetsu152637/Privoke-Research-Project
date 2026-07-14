from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path


CURRENT_DIR = Path(__file__).resolve().parent
PACKAGE_PARENT = CURRENT_DIR.parent
while str(CURRENT_DIR) in sys.path:
    sys.path.remove(str(CURRENT_DIR))
if str(PACKAGE_PARENT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_PARENT))

GENERATED_DIR = PACKAGE_PARENT / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from src.config import GLOBAL_CONFIG, LLMChoice
from src.env import env_bool, env_positive_int
from src.hosting.grpc_server import create_grpc_server


_SHOULD_STOP = False


def main() -> None:
    global _SHOULD_STOP
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    GLOBAL_CONFIG.llm_choice = LLMChoice.parse(
        os.getenv("PRIVOKE_LLM_CHOICE", "streamed")
    )
    GLOBAL_CONFIG.wait_for_regex = env_bool(
        "PRIVOKE_WAIT_FOR_REGEX", GLOBAL_CONFIG.wait_for_regex
    )
    port = env_positive_int("PRIVOKE_GRPC_PORT", 50054)
    server = create_grpc_server(
        max_text_chars=env_positive_int("PRIVOKE_MAX_PROMPT_CHARS", 20_000)
    )
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    print(f"PriVoke runtime gRPC server listening on port {port}", flush=True)
    try:
        while not _SHOULD_STOP:
            time.sleep(0.25)
    finally:
        server.stop(5).wait()


def _stop(signum, frame) -> None:
    global _SHOULD_STOP
    _SHOULD_STOP = True


if __name__ == "__main__":
    main()
