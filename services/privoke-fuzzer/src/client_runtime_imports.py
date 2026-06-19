from __future__ import annotations

import importlib
import importlib.machinery
import os
import sys
import types
from pathlib import Path
from typing import Iterator


DEFAULT_PACKAGE_NAME = "privoke_client_runtime"
CLIENT_RUNTIME_SRC_ENV = "PRIVOKE_CLIENT_RUNTIME_SRC"


def client_runtime_src_path() -> Path:
    configured_path = os.getenv(CLIENT_RUNTIME_SRC_ENV)
    if configured_path:
        return _existing_src_path(Path(configured_path))

    services_dir = Path(__file__).resolve().parents[2]
    return _existing_src_path(services_dir / "client-runtime" / "src")


def install_client_runtime_package(
    package_name: str = DEFAULT_PACKAGE_NAME,
) -> Path:
    src_path = client_runtime_src_path()
    existing_module = sys.modules.get(package_name)

    if existing_module is None:
        module = types.ModuleType(package_name)
        spec = importlib.machinery.ModuleSpec(
            package_name,
            loader=None,
            is_package=True,
        )
        spec.submodule_search_locations = [str(src_path)]

        module.__file__ = str(src_path)
        module.__path__ = [str(src_path)]
        module.__package__ = package_name
        module.__spec__ = spec
        sys.modules[package_name] = module
        return src_path

    search_locations = getattr(existing_module, "__path__", None)
    if search_locations is None:
        raise RuntimeError(f"{package_name} is already loaded and is not a package.")

    if str(src_path) not in search_locations:
        search_locations.append(str(src_path))

    return src_path


def import_client_module(
    module_name: str,
    package_name: str = DEFAULT_PACKAGE_NAME,
):
    install_client_runtime_package(package_name)
    qualified_name = (
        package_name if not module_name else f"{package_name}.{module_name}"
    )
    return importlib.import_module(qualified_name)


def iter_client_runtime_modules(
    package_name: str = DEFAULT_PACKAGE_NAME,
) -> Iterator[str]:
    src_path = install_client_runtime_package(package_name)

    for path in sorted(src_path.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue

        relative_path = path.relative_to(src_path).with_suffix("")
        module_parts = list(relative_path.parts)
        if module_parts[-1] == "__init__":
            module_parts.pop()

        if module_parts:
            yield f"{package_name}.{'.'.join(module_parts)}"
        else:
            yield package_name


def _existing_src_path(path: Path) -> Path:
    src_path = path.resolve()
    if not src_path.exists():
        raise RuntimeError(f"Client runtime source path does not exist: {src_path}")
    if not src_path.is_dir():
        raise RuntimeError(f"Client runtime source path is not a directory: {src_path}")
    return src_path
