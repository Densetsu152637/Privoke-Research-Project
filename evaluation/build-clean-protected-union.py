#!/usr/bin/env python3
"""Build the fixed protected-key union from verified local study inputs."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared/python"))
sys.path.insert(0, str(ROOT / "evaluation"))

from privoke_eval.clean_augmentation_protection_io import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
