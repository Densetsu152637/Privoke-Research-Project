"""Launch host services with a directly owned interpreter PID on Windows.

Windows venv python.exe is a redirector with a separate interpreter child.
Use that same base interpreter and explicitly retain the active venv packages.
"""
import os
import importlib
from pathlib import Path
import sys
from host_environment import python_environment


def owned_python():
    if os.name == "nt":
        executable = sys._base_executable
        packages = Path(sys.prefix) / "Lib/site-packages"
        if not Path(executable).is_file() or not packages.is_dir():
            raise RuntimeError("Cannot bind direct host interpreter and active venv packages")
        return executable, python_environment(packages)
    return sys.executable, python_environment()


def attest_dependencies(names):
    return {"python": sys.version, "executable": str(Path(sys.executable).resolve()),
            "prefix": sys.prefix, "packages": {name: {
                "version": importlib.import_module(name).__version__,
                "module_file": str(Path(importlib.import_module(name).__file__).resolve())}
                for name in names}}


def verify_dependencies(actual, names):
    expected = attest_dependencies(names)
    executable, _ = owned_python()
    if actual["python"] != expected["python"] or actual["packages"] != expected["packages"]:
        raise AssertionError("Owned child Python/dependency versions or module paths differ from active host environment")
    if Path(actual["executable"]).resolve() != Path(executable).resolve():
        raise AssertionError("Owned child executable differs from direct host interpreter")
