"""Roots for prompt-bearing Stage 13a output, and the confinement rule for writing under them.

Prompt-bearing files may only be written under the Git-ignored ``evaluation/results/s13a`` directory of the main
checkout. The root can be moved with S13A_RESULTS_ROOT (and its ``returned`` directory with S13A_RETURNED_ROOT)
only when ``git check-ignore`` confirms the moved root is ignored, or under tests (S13A_TESTING=1).
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

MAIN_CHECKOUT = Path("D:/Git Repositories/Privoke-Research-Project")
DEFAULT_RESULTS_ROOT = MAIN_CHECKOUT / "evaluation" / "results" / "s13a"


def under_tests():
    return os.environ.get("S13A_TESTING") == "1"


def is_git_ignored(path):
    """True when ``path`` lies in a Git repository and is ignored there."""
    path = Path(path).resolve()
    probe = path
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    top = subprocess.run(["git", "-C", str(probe if probe.is_dir() else probe.parent), "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True)
    if top.returncode != 0:
        return False
    return subprocess.run(["git", "-C", top.stdout.strip(), "check-ignore", "-q", str(path)]).returncode == 0


def _root(env_name, default):
    override = os.environ.get(env_name)
    if not override:
        return default
    if under_tests() or is_git_ignored(override):
        return Path(override)
    raise SystemExit(f"{env_name}={override} is not confirmed ignored by `git check-ignore`; refusing to use it")


def results_root():
    return _root("S13A_RESULTS_ROOT", DEFAULT_RESULTS_ROOT)


def returned_root():
    return _root("S13A_RETURNED_ROOT", results_root() / "returned")


def require_under(path, root, what="output"):
    """Exit unless ``path`` is the root or lies below it (``root in path.parents``)."""
    root = Path(root).resolve()
    target = Path(path).resolve()
    if root != target and root not in target.parents:
        raise SystemExit(f"{what} {path} holds prompt text and may only be written under {root}")
    return target
