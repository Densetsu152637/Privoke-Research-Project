from __future__ import annotations

import sys
from pathlib import Path


CURRENT_DIR = Path(__file__).resolve().parent
PACKAGE_ROOT = CURRENT_DIR.parent
SHARED_PYTHON_ROOT = PACKAGE_ROOT.parents[1] / "shared" / "python"
while str(CURRENT_DIR) in sys.path:
    sys.path.remove(str(CURRENT_DIR))
for path in (PACKAGE_ROOT, SHARED_PYTHON_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))


def check_required_detector_dependencies() -> None:
    """Load every dependency required by the always-local detector layers."""
    from src.NER import EntityNERDetector
    from src.regex.rule_detector import RuleDetector

    RuleDetector()
    EntityNERDetector()


def check_standard_v3_dependencies() -> None:
    import importlib.metadata
    import torch
    expected = {"transformers": "4.57.6", "numpy": "1.26.4", "tokenizers": "0.22.2", "safetensors": "0.8.0"}
    if torch.__version__.split("+")[0] != "2.11.0" or any(importlib.metadata.version(name) != version for name, version in expected.items()):
        raise RuntimeError("Standard V3 requires the pinned native inference dependencies; install requirements.txt and requirements-inference-cpu.txt.")


if __name__ == "__main__":
    check_required_detector_dependencies()
    import os
    if os.getenv("MODEL_ID", "latest") == "latest" or os.getenv("MODEL_ID", "").startswith("privoke-v3-"):
        check_standard_v3_dependencies()
    print("Required regex and NER dependencies are available.", flush=True)
