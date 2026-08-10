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


if __name__ == "__main__":
    check_required_detector_dependencies()
    print("Required regex and NER dependencies are available.", flush=True)
