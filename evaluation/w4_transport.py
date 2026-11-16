"""Native-messaging transport support for the cross-platform study (stage W4, Windows host).

The extension talks to the Rust controller (`privoke-supervisor native-host`) over a native-messaging
port, so the study must let the browser start the controller itself. This module holds what that needs:

* temporary native-host registrations (a manifest file plus an HKCU registry value per browser family)
  that are removed again, under a host name the user's own registration does not use;
* process-tree and listening-port observation through PowerShell (`Get-NetTCPConnection`,
  `Get-CimInstance Win32_Process`), used to show that PriVoke opens no listening port and leaves no
  worker behind;
* run-to-run latency statistics.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import statistics
import subprocess
import threading
import time
import winreg
from pathlib import Path
from typing import Any

HOST_NAME = "org.privoke.runtime_controller"
# Ports of the Python stack that a W4 install must never listen on.
RETIRED_PORTS = (8080, 50056, 50057, 50066)
REGISTRY_ROOTS = {
    "chromium": r"Software\Google\Chrome\NativeMessagingHosts",
    "firefox": r"Software\Mozilla\NativeMessagingHosts",
}
SHIM_MARKER = "worker_shim.py"


def _powershell_json(script: str) -> list[dict[str, Any]]:
    output = subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True,
                            text=True, check=False).stdout.strip()
    if not output:
        return []
    rows = json.loads(output)
    return rows if isinstance(rows, list) else [rows]


def processes() -> list[dict[str, Any]]:
    return _powershell_json(
        "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,"
        "CommandLine | ConvertTo-Json -Compress")


def listeners() -> list[dict[str, Any]]:
    """Listening TCP sockets, from `Get-NetTCPConnection`."""
    return _powershell_json(
        "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
        "Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress")


def same_path(left: str | None, right: Path) -> bool:
    return bool(left) and Path(left).resolve() == right.resolve()


def descendants(rows: list[dict[str, Any]], roots: set[int]) -> set[int]:
    found = set(roots)
    grew = True
    while grew:
        grew = False
        for row in rows:
            if row["ParentProcessId"] in found and row["ProcessId"] not in found:
                found.add(row["ProcessId"])
                grew = True
    return found


def privoke_processes(exe: Path, rows: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Controller processes, their descendants, and any worker shim, as found now."""
    rows = processes() if rows is None else rows
    roots = {row["ProcessId"] for row in rows if same_path(row.get("ExecutablePath"), exe)}
    tree = descendants(rows, roots)
    return [{"pid": row["ProcessId"], "parent": row["ParentProcessId"], "name": row["Name"],
             "command": (row.get("CommandLine") or "")[:160]}
            for row in rows
            if row["ProcessId"] in tree or SHIM_MARKER in (row.get("CommandLine") or "")]


def chromium_extension_id(public_key_base64: str) -> str:
    digest = hashlib.sha256(base64.b64decode(public_key_base64)).hexdigest()[:32]
    return digest.translate(str.maketrans("0123456789abcdef", "abcdefghijklmnop"))


class NativeRuntime:
    """The controller as the browser starts it. There is no process of ours to run: registering the host
    is what makes it available, and removing the registration (plus killing the running host) makes the
    runtime unreachable."""

    def __init__(self, exe: Path, workdir: Path, identities: dict[str, str]) -> None:
        self.exe = exe
        self.directory = workdir / "native-host"
        self.identities = identities
        self.registered = False

    def _manifest(self, family: str) -> Path:
        if family == "chromium":
            body: dict[str, Any] = {"allowed_origins": [f"chrome-extension://{self.identities['chromium_extension_id']}/"]}
        else:
            body = {"allowed_extensions": [self.identities["firefox_extension_id"]]}
        manifest = {"name": HOST_NAME, "description": "PriVoke controller (W4 study, temporary).",
                    "path": str(self.exe), "type": "stdio", **body}
        path = self.directory / f"{HOST_NAME}.{family}.json"
        path.write_text(json.dumps(manifest, indent=2), encoding="utf8")
        return path

    def register(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        for family, root in REGISTRY_ROOTS.items():
            key_path = f"{root}\\{HOST_NAME}"
            try:
                existing = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
            except FileNotFoundError:
                existing = None
            if existing is not None and not self.registered:
                winreg.CloseKey(existing)
                raise OSError(f"HKCU\\{key_path} already exists; refusing to overwrite another registration")
            if existing is not None:
                winreg.CloseKey(existing)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, str(self._manifest(family)))
        self.registered = True

    def unregister(self) -> None:
        for root in REGISTRY_ROOTS.values():
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, f"{root}\\{HOST_NAME}")
            except FileNotFoundError:
                pass
        self.registered = False

    # The same names the bridge-mode supervisor offers, so the study's fault stages read the same.
    def start(self) -> None:
        if not self.registered:
            self.register()

    def running(self) -> bool:
        return self.registered

    def wait_ready(self, timeout: float = 0.0) -> bool:  # noqa: ARG002 - readiness is the first decision
        return self.registered

    def host_pids(self) -> set[int]:
        return {row["pid"] for row in privoke_processes(self.exe) if row["name"].lower() == self.exe.name.lower()}

    def pids(self) -> set[int]:
        return {row["pid"] for row in privoke_processes(self.exe)}

    def stop(self, wait: bool = True) -> None:
        self.unregister()
        for pid in self.host_pids():
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, check=False)
        if wait:
            deadline = time.monotonic() + 20
            while privoke_processes(self.exe) and time.monotonic() < deadline:
                time.sleep(0.5)

    def _suspend_op(self, name: str) -> None:
        pids = self.host_pids()
        if not pids:
            raise OSError("no controller process to suspend")
        for pid in pids:
            handle = ctypes.windll.kernel32.OpenProcess(0x0800, False, pid)
            if not handle:
                raise OSError("OpenProcess(PROCESS_SUSPEND_RESUME) failed")
            try:
                status = getattr(ctypes.windll.ntdll, name)(handle)
                if status != 0:
                    raise OSError(f"{name} returned {status:#x}")
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)

    def suspend(self) -> None:
        self._suspend_op("NtSuspendProcess")

    def resume(self) -> None:
        self._suspend_op("NtResumeProcess")


class ListenSampler(threading.Thread):
    """Samples listening sockets for the whole run and attributes them to PriVoke's process tree."""

    def __init__(self, exe: Path, interval: float = 3.0) -> None:
        super().__init__(daemon=True)
        self.exe = exe
        self.interval = interval
        self.samples = 0
        self.samples_with_controller = 0
        self.max_controller_tree = 0
        self.privoke_listeners: list[dict[str, Any]] = []
        self.retired_port_hits: list[dict[str, Any]] = []
        self.outbound: list[str] = []
        self._halt = threading.Event()

    def run(self) -> None:
        while not self._halt.is_set():
            self.sample()
            self._halt.wait(self.interval)

    def sample(self) -> None:
        rows = processes()
        tree = {row["pid"] for row in privoke_processes(self.exe, rows)}
        sockets = listeners()
        self.samples += 1
        if tree:
            self.samples_with_controller += 1
        self.max_controller_tree = max(self.max_controller_tree, len(tree))
        if tree:
            for row in _powershell_json(
                    "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | "
                    "Select-Object RemoteAddress,RemotePort,OwningProcess | ConvertTo-Json -Compress"):
                if row["OwningProcess"] in tree and row["RemoteAddress"] not in ("127.0.0.1", "::1"):
                    self.outbound.append(f"pid {row['OwningProcess']} -> {row['RemoteAddress']}:{row['RemotePort']}")
        for socket_row in sockets:
            row = {"pid": socket_row["OwningProcess"], "address": socket_row["LocalAddress"],
                   "port": socket_row["LocalPort"]}
            if row["pid"] in tree:
                self.privoke_listeners.append({**row, "at_sample": self.samples})
            if row["port"] in RETIRED_PORTS:
                self.retired_port_hits.append({**row, "at_sample": self.samples})

    def finish(self) -> dict[str, Any]:
        self._halt.set()
        self.join(timeout=30)
        return {"method": "Get-NetTCPConnection -State Listen and Win32_Process tree, sampled",
                "interval_s": self.interval, "samples": self.samples,
                "samples_with_controller_running": self.samples_with_controller,
                "max_processes_in_controller_tree": self.max_controller_tree,
                "listening_sockets_owned_by_controller_tree": self.privoke_listeners,
                "retired_port_listeners_seen": self.retired_port_hits,
                "non_loopback_connections_of_controller_tree": self.outbound}


def latency_summary(values: list[float]) -> dict[str, Any]:
    ordered = sorted(values)
    if not ordered:
        return {"count": 0}
    return {"count": len(ordered), "median_ms": round(statistics.median(ordered), 2),
            "p90_ms": round(ordered[min(len(ordered) - 1, int(0.9 * len(ordered)))], 2),
            "min_ms": round(ordered[0], 2), "max_ms": round(ordered[-1], 2)}


def spread_verdict(baseline_medians: list[float], candidate_medians: list[float]) -> dict[str, Any]:
    """Within the recorded run-to-run spread: the candidate's median of run medians is no higher than the
    baseline's highest run median (a lower latency is never a regression)."""
    baseline_median = statistics.median(baseline_medians)
    candidate_median = statistics.median(candidate_medians)
    ceiling = max(baseline_medians)
    return {"baseline_median_ms": round(baseline_median, 2),
            "baseline_run_spread_ms": [round(min(baseline_medians), 2), round(ceiling, 2)],
            "candidate_median_ms": round(candidate_median, 2),
            "candidate_run_medians_ms": [round(v, 2) for v in candidate_medians],
            "delta_ms": round(candidate_median - baseline_median, 2),
            "within_recorded_spread": candidate_median <= ceiling}
