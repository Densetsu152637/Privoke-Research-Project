from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import struct
import subprocess  # nosec B404 - fixed local command, no caller-provided argv
import sys
import tempfile
import time
from typing import BinaryIO


HOST_NAME = "org.privoke.runtime_launcher"
MAX_MESSAGE_BYTES = 1024 * 1024
BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 8080
CONTROL_PORT = 50056


def repository_root() -> Path:
    configured = os.getenv("PRIVOKE_REPOSITORY_ROOT", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[3]


def ensure_supervisor(*, timeout_seconds: float = 10.0) -> dict[str, object]:
    if _port_is_open(BRIDGE_PORT):
        return {
            "ok": True,
            "started": False,
            "message": "PriVoke supervisor bridge is already running.",
        }
    if _port_is_open(CONTROL_PORT):
        return {
            "ok": False,
            "started": False,
            "message": (
                "PriVoke control port 50056 is in use, but the bridge on port 8080 "
                "is unavailable. Stop the existing process or enable its gRPC-Web bridge."
            ),
        }

    root = repository_root()
    supervisor_main = root / "extension" / "runtime-supervisor" / "src" / "main.py"
    python_executable = _python_executable(root)
    if not supervisor_main.is_file():
        return _missing_path(supervisor_main, "supervisor entry point")
    if not python_executable.is_file():
        return _missing_path(python_executable, "Python interpreter")

    log_path = _log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment["PRIVOKE_REPOSITORY_ROOT"] = str(root)
    environment["PRIVOKE_RUNTIME_START_ENABLED"] = "false"

    creation_flags = 0
    popen_options: dict[str, object] = {}
    if os.name == "nt":
        # Keep the long-lived supervisor independent of the short-lived native
        # messaging host without allocating a visible console window.
        creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
        creation_flags |= getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0)
    else:
        popen_options["start_new_session"] = True

    with log_path.open("ab", buffering=0) as log_file:
        try:
            process = subprocess.Popen(  # nosec B603
                [str(python_executable), str(supervisor_main)],
                cwd=str(supervisor_main.parents[1]),
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                close_fds=True,
                creationflags=creation_flags,
                **popen_options,
            )
        except OSError as exc:
            return {
                "ok": False,
                "started": False,
                "message": f"Could not launch the PriVoke supervisor: {exc}",
                "log_path": str(log_path),
            }

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _port_is_open(BRIDGE_PORT):
            return {
                "ok": True,
                "started": True,
                "process_id": process.pid,
                "message": "PriVoke supervisor bridge started.",
                "log_path": str(log_path),
            }
        exit_code = process.poll()
        if exit_code is not None:
            return {
                "ok": False,
                "started": False,
                "message": f"PriVoke supervisor exited with code {exit_code}.",
                "log_path": str(log_path),
            }
        time.sleep(0.1)

    return {
        "ok": False,
        "started": False,
        "message": "PriVoke supervisor did not open its bridge within 10 seconds.",
        "log_path": str(log_path),
    }


def handle_message(message: object) -> dict[str, object]:
    if not isinstance(message, dict) or message.get("action") != "ensure_supervisor":
        return {
            "ok": False,
            "started": False,
            "message": "Unsupported native launcher request.",
        }
    return ensure_supervisor()


def serve(input_stream: BinaryIO, output_stream: BinaryIO) -> None:
    while True:
        message = _read_message(input_stream)
        if message is None:
            return
        _write_message(output_stream, handle_message(message))


def _read_message(stream: BinaryIO) -> object | None:
    header = stream.read(4)
    if not header:
        return None
    if len(header) != 4:
        raise ValueError("Incomplete native messaging header.")
    length = struct.unpack("=I", header)[0]
    if length > MAX_MESSAGE_BYTES:
        raise ValueError("Native messaging request is too large.")
    payload = stream.read(length)
    if len(payload) != length:
        raise ValueError("Incomplete native messaging request.")
    return json.loads(payload.decode("utf-8"))


def _write_message(stream: BinaryIO, message: dict[str, object]) -> None:
    payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
    stream.write(struct.pack("=I", len(payload)))
    stream.write(payload)
    stream.flush()


def _python_executable(root: Path) -> Path:
    configured = os.getenv("PRIVOKE_SUPERVISOR_PYTHON", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    windows_venv = root / "extension" / "client-runtime" / ".venv" / "Scripts" / "python.exe"
    posix_venv = root / "extension" / "client-runtime" / ".venv" / "bin" / "python"
    if windows_venv.is_file():
        return windows_venv
    if posix_venv.is_file():
        return posix_venv
    return Path(sys.executable).resolve()


def _port_is_open(port: int) -> bool:
    try:
        with socket.create_connection((BRIDGE_HOST, port), timeout=0.2):
            return True
    except OSError:
        return False


def _missing_path(path: Path, description: str) -> dict[str, object]:
    return {
        "ok": False,
        "started": False,
        "message": f"PriVoke {description} is missing: {path}",
    }


def _log_path() -> Path:
    configured = os.getenv("PRIVOKE_SUPERVISOR_LOG", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(tempfile.gettempdir()) / "PriVoke" / "runtime-supervisor.log"


if __name__ == "__main__":
    if os.name == "nt":
        import msvcrt

        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    serve(sys.stdin.buffer, sys.stdout.buffer)
