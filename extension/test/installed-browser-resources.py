#!/usr/bin/env python3
"""Sample private process and cgroup resource evidence for installed-browser runs."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import sys
import time

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


def _start_ticks(
    pid: int,
    *,
    read_stat=None,
    pid_exists=None,
) -> int | None:
    """Read a process identity, distinguishing an exited PID from unreadable evidence."""
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
        fields = stat[stat.rfind(")") + 2 :].split()
        return int(fields[19])
    except (ValueError, IndexError) as error:
        raise RuntimeError("process stat did not contain a valid start-tick identity") from error


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


def _processes() -> tuple[list[dict[str, object]], dict[str, int]]:
    rows: list[dict[str, object]] = []
    identity_races: dict[str, int] = {}
    processes = list(psutil.process_iter(("pid", "ppid", "cmdline", "create_time", "memory_info", "cpu_times")))
    chromium_root_ids, chromium_ids = _browser_process_ids(processes)
    for process in processes:
        try:
            info = process.info
            command = " ".join(info.get("cmdline") or [])
            role = next((name for name in PATTERNS if _matches(name, command)), None)
            if role is None and info["pid"] in chromium_ids:
                role = "chromium"
            if role is None:
                continue
            memory = info.get("memory_info")
            cpu = info.get("cpu_times")
            start_ticks = _start_ticks(int(info["pid"]))
            if start_ticks is None:
                # psutil enumerated this Chromium child, but it exited before /proc
                # identity could be read. Record the race instead of emitting an
                # unidentifiable process row; unreadable live PIDs fail closed above.
                if role != "chromium":
                    raise RuntimeError(f"required {role} process exited during resource sampling")
                identity_races[role] = identity_races.get(role, 0) + 1
                continue
            rows.append({
                "role": role,
                "browser_profile_root": info["pid"] in chromium_root_ids,
                "pid": info["pid"],
                "ppid": info["ppid"],
                "parent_start_ticks": _start_ticks(int(info["ppid"])) if info.get("ppid") else None,
                "start_time_epoch_seconds": info.get("create_time"),
                "start_ticks": start_ticks,
                "rss_bytes": memory.rss if memory else None,
                "pss_bytes": _pss_bytes(int(info["pid"])),
                "cpu_seconds": (cpu.user + cpu.system) if cpu else None,
                "command_sha256": __import__("hashlib").sha256(command.encode()).hexdigest(),
            })
        except (psutil.Error, OSError, ValueError):
            continue
    return rows, identity_races


def sample(output: Path, interval_ms: int) -> None:
    stop = False

    def stop_sampling(_signum, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, stop_sampling)
    signal.signal(signal.SIGINT, stop_sampling)
    interval = interval_ms / 1000
    next_sample = time.monotonic()
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
            next_sample += interval
            time.sleep(max(0.0, next_sample - time.monotonic()))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--interval-ms", type=int, default=100)
    args = parser.parse_args()
    if args.interval_ms != 100:
        parser.error("The installed-browser protocol fixes sampling at 100 ms.")
    try:
        sample(args.output, args.interval_ms)
    except FileExistsError:
        print("Refusing to overwrite resource samples.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
