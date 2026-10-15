from __future__ import annotations

import os
import socket
# The runtime is a fixed-argv child process; no caller-controlled shell is used.
import subprocess  # nosec B404
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence


CURRENT_DIR = Path(__file__).resolve().parent
SUPERVISOR_ROOT = CURRENT_DIR.parent
CLIENT_RUNTIME_ROOT = SUPERVISOR_ROOT.parent / "client-runtime"
SHARED_PYTHON_ROOT = SUPERVISOR_ROOT.parents[1] / "shared" / "python"
if str(SHARED_PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON_ROOT))

from privoke_service.stack_connection import load_runtime_environment, use_local_stack


@dataclass(frozen=True)
class RuntimeProcessStatus:
    enabled: bool
    status: str
    message: str
    process_id: int = 0


class RuntimeProcessSupervisor:
    """Owns the detector runtime child while keeping its control plane alive."""

    def __init__(
        self,
        *,
        command: Sequence[str] | None = None,
        runtime_port: int = 50057,
        startup_timeout_seconds: float = 30.0,
        stop_timeout_seconds: float = 10.0,
        environment: Mapping[str, str] | None = None,
        process_factory: Callable[..., subprocess.Popen] = subprocess.Popen,
        dependency_check_factory: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    ) -> None:
        if environment is None:
            load_runtime_environment(CLIENT_RUNTIME_ROOT)
        runtime_python = _runtime_python(environment)
        self.command = tuple(command or (
            runtime_python,
            str(CLIENT_RUNTIME_ROOT / "src" / "grpc_main.py"),
        ))
        self.dependency_check_command = None if command else (
            runtime_python,
            str(CLIENT_RUNTIME_ROOT / "src" / "dependency_check.py"),
        )
        self.runtime_port = runtime_port
        self.startup_timeout_seconds = startup_timeout_seconds
        self.stop_timeout_seconds = stop_timeout_seconds
        self.environment = dict(os.environ if environment is None else environment)
        self.environment["PRIVOKE_GRPC_PORT"] = str(runtime_port)
        self.environment["PRIVOKE_GRPC_HOST"] = "127.0.0.1"
        self.process_factory = process_factory
        self.dependency_check_factory = dependency_check_factory
        self._process: subprocess.Popen | None = None
        self._last_message = "Client runtime has not been started."
        self._lock = threading.RLock()

    def start(self) -> RuntimeProcessStatus:
        with self._lock:
            current = self._current_status()
            if current.enabled:
                return current

            if self._runtime_port_is_open():
                self._last_message = (
                    f"Client runtime port {self.runtime_port} is already in use by "
                    "a process not owned by this supervisor. Stop that process and retry."
                )
                return self._current_status()

            dependency_error = self._dependency_error()
            if dependency_error:
                self._last_message = (
                    "Client runtime dependencies are unavailable: "
                    f"{dependency_error}"
                )
                return self._current_status()

            try:
                process = self.process_factory(
                    self.command,
                    cwd=str(CLIENT_RUNTIME_ROOT),
                    env=self.environment,
                )
            except Exception as exc:
                self._last_message = f"Client runtime failed to start: {_error_message(exc)}"
                return self._current_status()

            self._process = process
            if not self._wait_until_ready(process):
                exit_code = process.poll()
                detail = (
                    f"exited with code {exit_code}"
                    if exit_code is not None
                    else f"did not listen on port {self.runtime_port} in time"
                )
                self._last_message = f"Client runtime {detail}."
                self._terminate_process(process)
                self._process = None
                return self._current_status()

            self._last_message = "Client runtime started."
            return self._current_status()

    def stop(self) -> RuntimeProcessStatus:
        with self._lock:
            process = self._process
            if process is None or process.poll() is not None:
                self._process = None
                self._last_message = "Client runtime is stopped."
                return self._current_status()

            self._terminate_process(process)
            self._process = None
            self._last_message = "Client runtime stopped."
            return self._current_status()

    def set_enabled(self, enabled: bool, use_local: bool | None = None) -> RuntimeProcessStatus:
        with self._lock:
            if use_local is not None and use_local != use_local_stack(self.environment):
                self.stop()
                self.environment["PRIVOKE_USE_LOCAL_STACK"] = str(use_local).lower()
            return self.start() if enabled else self.stop()

    def status(self) -> RuntimeProcessStatus:
        with self._lock:
            return self._current_status()

    def _current_status(self) -> RuntimeProcessStatus:
        process = self._process
        if process is None:
            return RuntimeProcessStatus(False, "STOPPED", self._last_message)

        exit_code = process.poll()
        if exit_code is not None:
            self._process = None
            self._last_message = f"Client runtime exited with code {exit_code}."
            return RuntimeProcessStatus(False, "STOPPED", self._last_message)

        return RuntimeProcessStatus(
            True,
            "RUNNING",
            self._last_message,
            process_id=max(0, int(process.pid)),
        )

    def _wait_until_ready(self, process: subprocess.Popen) -> bool:
        deadline = time.monotonic() + self.startup_timeout_seconds
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return False
            if self._runtime_port_is_open():
                # Do not mistake a socket opened just before child failure for a
                # healthy runtime. Give the child one scheduler turn to prove it
                # remains alive before reporting startup success.
                time.sleep(0.1)
                return process.poll() is None
            time.sleep(0.1)
        return False

    def _runtime_port_is_open(self) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", self.runtime_port), 0.2):
                return True
        except OSError:
            return False

    def _terminate_process(self, process: subprocess.Popen) -> None:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=self.stop_timeout_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=self.stop_timeout_seconds)

    def _dependency_error(self) -> str | None:
        if self.dependency_check_command is None:
            return None
        try:
            result = self.dependency_check_factory(
                self.dependency_check_command,
                cwd=str(CLIENT_RUNTIME_ROOT),
                env=self.environment,
                capture_output=True,
                text=True,
                timeout=self.startup_timeout_seconds,
                check=False,
            )
        except Exception as exc:
            return _error_message(exc)
        if result.returncode == 0:
            return None
        output = (result.stderr or result.stdout or "").strip().splitlines()
        return (
            output[-1]
            if output
            else f"dependency check exited with code {result.returncode}"
        )


def _error_message(exc: Exception) -> str:
    message = str(exc).strip()
    return message or exc.__class__.__name__


def _runtime_python(environment: Mapping[str, str] | None) -> str:
    source_environment = os.environ if environment is None else environment
    configured = source_environment.get("PRIVOKE_RUNTIME_PYTHON", "").strip()
    if configured:
        return configured
    candidates = (
        CLIENT_RUNTIME_ROOT / ".venv" / "Scripts" / "python.exe",
        CLIENT_RUNTIME_ROOT / ".venv" / "bin" / "python",
    )
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return sys.executable
