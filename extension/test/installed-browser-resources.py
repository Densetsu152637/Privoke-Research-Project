#!/usr/bin/env python3
"""Sample private process and cgroup resource evidence for installed-browser runs."""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import signal
import sys
import time
import traceback

import psutil


ROOT = Path("/workspace")
PATTERNS = {
    "xvfb": ("/usr/bin/Xvfb", "Xvfb :"),
    "native_host": ("native_messaging_host.py", "privoke-native-host"),
    "supervisor_bridge": ("extension/runtime-supervisor/src/main.py",),
    "detector": ("extension/client-runtime/src/grpc_main.py",),
}


def _browser_profiles() -> list[Path]:
    path = Path(os.environ.get("XDG_CONFIG_HOME", "/tmp/privoke-xdg")) / "chromium"
    return [item for item in path.glob("profile-*") if item.is_dir()]


def _matches(role: str, command: str) -> bool:
    return any(pattern in command for pattern in PATTERNS.get(role, ()))


def _browser_match(command: str) -> bool:
    if "chromium" not in command.lower() and "/chrome" not in command.lower():
        return False
    return any(str(profile) in command for profile in _browser_profiles())


def _browser_process_ids(processes: list[psutil.Process]) -> tuple[set[int], set[int]]:
    """Include the complete Chromium process tree rooted at each run profile."""
    root_processes: list[psutil.Process] = []
    for process in processes:
        try:
            command = " ".join(process.cmdline())
            if _browser_match(command):
                root_processes.append(process)
        except (psutil.Error, OSError):
            continue
    root_ids = {root.pid for root in root_processes}
    included: set[int] = set()
    for root in root_processes:
        try:
            included.add(root.pid)
            included.update(child.pid for child in root.children(recursive=True))
        except (psutil.Error, OSError):
            continue
    return root_ids, included


def _pss_bytes(pid: int) -> int | None:
    try:
        for line in (Path("/proc") / str(pid) / "smaps_rollup").read_text().splitlines():
            if line.startswith("Pss:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


_PROC_STATES = set("RSDZTtXxKWPI")


def _process_stat_identity(
    pid: int,
    *,
    read_stat=None,
    pid_exists=None,
) -> tuple[str, int] | None:
    """Read strict Linux stat identity, distinguishing exit from unreadable evidence."""
    if not isinstance(pid, int) or pid <= 0:
        raise RuntimeError("requested process PID is invalid")
    read_stat = read_stat or (lambda value: (Path("/proc") / str(value) / "stat").read_text())
    pid_exists = pid_exists or psutil.pid_exists
    try:
        stat = read_stat(pid)
    except FileNotFoundError:
        if not pid_exists(pid):
            return None
        raise RuntimeError("process identity disappeared while PID remained live") from None
    except OSError as error:
        raise RuntimeError("could not read process start-tick identity") from error
    try:
        closing_paren = stat.rfind(")")
        opening_paren = stat.find("(")
        if opening_paren < 0 or closing_paren < opening_paren or int(stat[:opening_paren].strip()) != pid:
            raise ValueError("stat PID does not match requested PID")
        fields = stat[closing_paren + 1 :].split()
        if len(fields) < 20 or fields[0] not in _PROC_STATES:
            raise ValueError("stat framing or process state is invalid")
        ticks = int(fields[19])
        if ticks < 0:
            raise ValueError("start ticks are negative")
        return fields[0], ticks
    except (ValueError, IndexError) as error:
        raise RuntimeError("process stat did not contain a valid start-tick identity") from error


def _start_ticks(pid: int, *, read_stat=None, pid_exists=None) -> int | None:
    identity = _process_stat_identity(pid, read_stat=read_stat, pid_exists=pid_exists)
    return None if identity is None else identity[1]


def _cgroup_sample() -> dict[str, int | None]:
    result: dict[str, int | None] = {"memory_current_bytes": None, "cpu_usage_usec": None}
    try:
        result["memory_current_bytes"] = int(Path("/sys/fs/cgroup/memory.current").read_text().strip())
    except (OSError, ValueError):
        pass
    try:
        for line in Path("/sys/fs/cgroup/cpu.stat").read_text().splitlines():
            key, value = line.split()
            if key == "usage_usec":
                result["cpu_usage_usec"] = int(value)
    except (OSError, ValueError):
        pass
    return result


def _role_for_command(command: str, included_chromium: bool) -> str | None:
    return next((name for name in PATTERNS if _matches(name, command)), "chromium" if included_chromium else None)


def _termination_disposition(role: str, profile_root: bool, detail: str) -> None:
    if role == "chromium" and not profile_root:
        return
    raise RuntimeError(f"{role} process identity changed during resource sampling: {detail}")


def _processes() -> tuple[list[dict[str, object]], dict[str, int]]:
    rows: list[dict[str, object]] = []
    identity_races: dict[str, int] = {}
    processes = list(psutil.process_iter(("pid", "ppid", "cmdline", "create_time", "memory_info", "cpu_times")))
    chromium_root_ids, chromium_ids = _browser_process_ids(processes)
    for process in processes:
        try:
            info = process.info
            pid = int(info["pid"])
            profile_root = pid in chromium_root_ids
            included_chromium = pid in chromium_ids
            expected_command = " ".join(info.get("cmdline") or [])
            role_hint = _role_for_command(expected_command, included_chromium)
            if role_hint is None:
                continue
            expected_create_time = info.get("create_time")
            if not isinstance(expected_create_time, (int, float)) or not math.isfinite(expected_create_time):
                raise RuntimeError(f"{role_hint} process lacks enumeration-time creation identity")
            before = _process_stat_identity(pid)
            if before is None:
                _termination_disposition(role_hint, profile_root, "PID exited before stat snapshot")
                identity_races[role_hint] = identity_races.get(role_hint, 0) + 1
                continue
            fresh = psutil.Process(pid)
            fresh_create_time = fresh.create_time()
            if not math.isfinite(fresh_create_time):
                raise RuntimeError(f"{role_hint} process creation identity is invalid")
            if fresh_create_time != expected_create_time:
                _termination_disposition(role_hint, profile_root, "PID was reused after process enumeration")
                identity_races[role_hint] = identity_races.get(role_hint, 0) + 1
                continue
            if not fresh.is_running():
                _termination_disposition(role_hint, profile_root, "process exited before fresh metrics")
                identity_races[role_hint] = identity_races.get(role_hint, 0) + 1
                continue
            command = " ".join(fresh.cmdline())
            role = _role_for_command(command, included_chromium)
            if role is None or role != role_hint:
                raise RuntimeError(f"{role_hint} process role changed between enumeration and sampling")
            if profile_root and not _browser_match(command):
                raise RuntimeError("Chromium profile root no longer matches the sampled process command")
            parent_pid = fresh.ppid()
            parent_before = _process_stat_identity(parent_pid) if parent_pid > 0 else None
            memory = fresh.memory_info()
            cpu = fresh.cpu_times()
            pss_bytes = _pss_bytes(pid)
            after = _process_stat_identity(pid)
            if after is None or after[1] != before[1]:
                _termination_disposition(role, profile_root, "PID exited or changed start ticks during metrics")
                identity_races[role] = identity_races.get(role, 0) + 1
                continue
            parent_pid_after = fresh.ppid()
            parent_after = _process_stat_identity(parent_pid_after) if parent_pid_after > 0 else None
            parent_identity_stable = (
                parent_pid_after == parent_pid
                and parent_before is not None
                and parent_after is not None
                and parent_before[1] == parent_after[1]
            )
            if not fresh.is_running():
                # A same-identity process can exit after its metrics were read; these
                # metrics remain bound by matching stat ticks around the reads.
                pass
            rows.append({
                "role": role,
                "browser_profile_root": profile_root,
                "pid": pid,
                "ppid": parent_pid,
                "parent_start_ticks": parent_before[1] if parent_identity_stable else None,
                "start_time_epoch_seconds": fresh_create_time,
                "start_ticks": before[1],
                "rss_bytes": memory.rss if memory else None,
                "pss_bytes": pss_bytes,
                "cpu_seconds": (cpu.user + cpu.system) if cpu else None,
                "command_sha256": __import__("hashlib").sha256(command.encode()).hexdigest(),
            })
        except psutil.NoSuchProcess:
            info = process.info
            pid = int(info["pid"])
            expected_command = " ".join(info.get("cmdline") or [])
            included_chromium = pid in chromium_ids
            role_hint = _role_for_command(expected_command, included_chromium)
            if role_hint is None:
                continue
            _termination_disposition(role_hint, pid in chromium_root_ids, "process vanished during fresh reads")
            identity_races[role_hint] = identity_races.get(role_hint, 0) + 1
    return rows, identity_races


def _terminal_diagnostic_payload(status: str, samples_written: int, error: Exception | None = None) -> dict:
    if status not in {"stopped", "error"} or type(samples_written) is not int or samples_written < 0:
        raise ValueError("invalid sampler terminal state")
    frames = []
    exception_type = None
    if error is not None:
        status = "error"
        candidate = type(error).__name__
        exception_type = candidate if candidate.isidentifier() and len(candidate) <= 80 else "Exception"
        frames = [
            {"file": Path(frame.filename).name[:128], "function": frame.name[:128], "line": int(frame.lineno)}
            for frame in traceback.extract_tb(error.__traceback__)[-12:]
        ]
    elif status == "error":
        raise ValueError("error terminal state requires an exception")
    return {
        "schema_version": 1,
        "status": status,
        "samples_written": samples_written,
        "exception_type": exception_type,
        "frames": frames,
    }


def _write_terminal_diagnostic(path: Path, payload: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(payload, stream, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        stream.write("\n")


def sample(output: Path, interval_ms: int, progress: dict | None = None) -> None:
    stop = False

    def stop_sampling(_signum, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, stop_sampling)
    signal.signal(signal.SIGINT, stop_sampling)
    interval = interval_ms / 1000
    next_sample = time.monotonic()
    samples_written = 0
    with output.open("x", encoding="utf-8", buffering=1) as stream:
        while not stop:
            now = time.monotonic()
            roles, identity_races = _processes()
            stream.write(json.dumps({
                "sample_monotonic_ns": time.monotonic_ns(),
                "roles": roles,
                "process_identity_races": identity_races,
                "cgroup": _cgroup_sample(),
            }, separators=(",", ":")) + "\n")
            samples_written += 1
            if progress is not None:
                progress["samples_written"] = samples_written
            next_sample += interval
            time.sleep(max(0.0, next_sample - time.monotonic()))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--interval-ms", type=int, default=100)
    parser.add_argument("--terminal-diagnostic", required=True, type=Path)
    args = parser.parse_args()
    if args.interval_ms != 100:
        parser.error("The installed-browser protocol fixes sampling at 100 ms.")
    progress = {"samples_written": 0}
    try:
        sample(args.output, args.interval_ms, progress)
    except FileExistsError:
        print("Refusing to overwrite resource samples.", file=sys.stderr)
        return 2
    except Exception as error:
        try:
            _write_terminal_diagnostic(args.terminal_diagnostic, _terminal_diagnostic_payload(
                "error", progress["samples_written"], error,
            ))
        except OSError:
            pass
        return 1
    try:
        _write_terminal_diagnostic(args.terminal_diagnostic, _terminal_diagnostic_payload(
            "stopped", progress["samples_written"],
        ))
    except OSError:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
