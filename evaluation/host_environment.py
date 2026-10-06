"""Repository paths shared by standalone Python evaluation and test scripts."""
from __future__ import annotations

import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "extension/client-runtime/generated"
RUNTIME_TARGET = "127.0.0.1:50054"
FUZZER_TARGET = "127.0.0.1:50053"


def configure_imports() -> None:
    """Use local shared contracts and generated clients without a runtime install."""
    for path in (ROOT / "shared/python", GENERATED, ROOT / "models"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))


def python_environment(*paths: Path) -> dict[str, str]:
    """Carry repository imports into an isolated component Python process."""
    environment = os.environ.copy()
    imports = [str(path) for path in (
        *paths, ROOT / "evaluation", ROOT / "shared/python", GENERATED, ROOT / "models")]
    if environment.get("PYTHONPATH"):
        imports.append(environment["PYTHONPATH"])
    environment["PYTHONPATH"] = os.pathsep.join(imports)
    environment.setdefault("MODEL_ID", "privoke-balanced")
    return environment
