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
PACKAGE_ROOT = CURRENT_DIR.parent


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
        runtime_port: int = 50054,
        startup_timeout_seconds: float = 30.0,
        stop_timeout_seconds: float = 10.0,
        environment: Mapping[str, str] | None = None,
        process_factory: Callable[..., subprocess.Popen] = subprocess.Popen,
    ) -> None:
        self.command = tuple(command or (sys.executable, str(CURRENT_DIR / "grpc_main.py")))
        self.runtime_port = runtime_port
        self.startup_timeout_seconds = startup_timeout_seconds
        self.stop_timeout_seconds = stop_timeout_seconds
        self.environment = dict(os.environ if environment is None else environment)
        self.environment["PRIVOKE_GRPC_PORT"] = str(runtime_port)
        self.process_factory = process_factory
        self._process: subprocess.Popen | None = None
        self._last_message = "Client runtime has not been started."
        self._lock = threading.RLock()

    def start(self) -> RuntimeProcessStatus:
        with self._lock:
            current = self._current_status()
            if current.enabled:
                return current

            try:
                process = self.process_factory(
                    self.command,
                    cwd=str(PACKAGE_ROOT),
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

    def set_enabled(self, enabled: bool) -> RuntimeProcessStatus:
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
            try:
                with socket.create_connection(("127.0.0.1", self.runtime_port), 0.2):
                    return True
            except OSError:
                time.sleep(0.1)
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


def _error_message(exc: Exception) -> str:
    message = str(exc).strip()
    return message or exc.__class__.__name__
