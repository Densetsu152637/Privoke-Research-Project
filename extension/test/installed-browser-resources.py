#!/usr/bin/env python3
"""Sample private process and cgroup resource evidence for installed-browser runs."""

from __future__ import annotations

import argparse
import json
import math
import hashlib
import os
from pathlib import Path
import re
import select
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


def _browser_match(argv: list[str]) -> bool:
    """Match only a browser root using its exact user-data-dir argument."""
    if not argv or Path(argv[0]).name.lower() not in {"chrome", "chromium"}:
        return False
    if any(argument == "--type" or argument.startswith("--type=") for argument in argv[1:]):
        return False

    user_data_dirs: list[str] = []
    index = 1
    while index < len(argv):
        argument = argv[index]
        if argument == "--user-data-dir":
            if index + 1 >= len(argv):
                return False
            user_data_dirs.append(argv[index + 1])
            index += 2
            continue
        if argument.startswith("--user-data-dir="):
            user_data_dirs.append(argument.split("=", 1)[1])
        index += 1
    if len(user_data_dirs) != 1:
        return False
    return any(user_data_dirs[0] == str(profile) for profile in _browser_profiles())


def _browser_process_ids(processes: list[psutil.Process]) -> tuple[set[int], set[int]]:
    """Include the complete Chromium process tree rooted at each run profile."""
    root_processes: list[psutil.Process] = []
    for process in processes:
        try:
            # Classify roots from process_iter's cached command line. A fresh
            # cmdline read here can race process exit and erase a required root
            # before _processes applies its strict identity checks.
            argv = process.info.get("cmdline") or []
            if _browser_match(argv):
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


def _termination_disposition(role: str, profile_root: bool, detail: str, *, transition=None, pid=None,
                             identity=None) -> bool:
    if transition is not None and transition.allow_predecessor_retirement(role, pid, identity, detail):
        return True
    if role == "chromium" and not profile_root:
        return False
    raise RuntimeError(f"{role} process identity changed during resource sampling: {detail}")


def _processes(transition=None) -> tuple[list[dict[str, object]], dict[str, int]]:
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
                authorized = _termination_disposition(role_hint, profile_root, "PID exited before stat snapshot",
                                                       transition=transition, pid=pid, identity=None)
                if not authorized:
                    identity_races[role_hint] = identity_races.get(role_hint, 0) + 1
                continue
            fresh = psutil.Process(pid)
            fresh_create_time = fresh.create_time()
            if not math.isfinite(fresh_create_time):
                raise RuntimeError(f"{role_hint} process creation identity is invalid")
            if fresh_create_time != expected_create_time:
                authorized = _termination_disposition(role_hint, profile_root, "PID was reused after process enumeration",
                                                       transition=transition, pid=pid, identity=before)
                if not authorized:
                    identity_races[role_hint] = identity_races.get(role_hint, 0) + 1
                continue
            if not fresh.is_running():
                terminal_identity = _process_stat_identity(pid)
                authorized = _termination_disposition(role_hint, profile_root, "process exited before fresh metrics",
                                                       transition=transition, pid=pid, identity=terminal_identity)
                if not authorized:
                    identity_races[role_hint] = identity_races.get(role_hint, 0) + 1
                continue
            command = " ".join(fresh.cmdline())
            role = _role_for_command(command, included_chromium)
            if role is None or role != role_hint:
                raise RuntimeError(f"{role_hint} process role changed between enumeration and sampling")
            if profile_root and not _browser_match(fresh.cmdline()):
                raise RuntimeError("Chromium profile root no longer matches the sampled process command")
            parent_pid = fresh.ppid()
            parent_before = _process_stat_identity(parent_pid) if parent_pid > 0 else None
            memory = fresh.memory_info()
            cpu = fresh.cpu_times()
            pss_bytes = _pss_bytes(pid)
            after = _process_stat_identity(pid)
            if after is None or after[1] != before[1]:
                authorized = _termination_disposition(role, profile_root, "PID exited or changed start ticks during metrics",
                                                       transition=transition, pid=pid, identity=after)
                if not authorized:
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
            before = _process_stat_identity(pid)
            authorized = _termination_disposition(role_hint, pid in chromium_root_ids, "process vanished during fresh reads",
                                                   transition=transition, pid=pid, identity=before)
            if not authorized:
                identity_races[role_hint] = identity_races.get(role_hint, 0) + 1
    return rows, identity_races


def _control_digest(record: dict) -> str:
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


class StartupTransition:
    """One bounded runner-attested detector transition during cold startup."""

    _COMMON = {"schema_version", "type", "transition_id", "session_id", "expires_at_ns",
               "predecessor", "supervisor", "source_revision", "protocol_sha256"}

    def __init__(self, source_revision=None, protocol_sha256=None):
        self.phase = "idle"
        self.record = None
        self.successor = None
        self.events = []
        self.buffer = bytearray()
        self.messages = 0
        self.last_rows = []
        self.retired = False
        self.dispatch_seen = False
        self.source_revision = source_revision
        self.protocol_sha256 = protocol_sha256

    @staticmethod
    def _identity(value, *, detector):
        expected = {"pid", "start_ticks", "command_sha256", "parent_pid", "parent_start_ticks"} if detector else {
            "pid", "start_ticks", "command_sha256"}
        if not isinstance(value, dict) or set(value) != expected:
            raise RuntimeError("startup transition identity schema is invalid")
        if any(type(value[key]) is not int or value[key] < 0 for key in
               ("pid", "start_ticks", "parent_pid", "parent_start_ticks") if key in value):
            raise RuntimeError("startup transition identity numbers are invalid")
        if value["pid"] <= 1 or not re_full_sha(value["command_sha256"]):
            raise RuntimeError("startup transition identity fingerprint is invalid")
        if "parent_pid" in value and value["parent_pid"] <= 1:
            raise RuntimeError("startup transition parent PID is invalid")
        return value

    def _read_controls(self):
        try:
            ready, _, _ = select.select([sys.stdin], [], [], 0)
        except (OSError, ValueError):
            return
        if not ready:
            return
        chunk = os.read(sys.stdin.fileno(), 4097)
        if not chunk:
            return
        if self.messages >= 3:
            raise RuntimeError("startup transition received an excess control record")
        self.buffer.extend(chunk)
        if len(self.buffer) > 4096:
            raise RuntimeError("startup transition control exceeded its byte bound")
        if b"\n" not in self.buffer:
            return
        line, separator, remainder = self.buffer.partition(b"\n")
        if remainder or not separator or not line:
            raise RuntimeError("startup transition control framing is invalid")
        self.buffer.clear()
        try:
            record = json.loads(line.decode("utf-8", errors="strict"), object_pairs_hook=_unique_object)
        except (UnicodeError, json.JSONDecodeError, ValueError):
            raise RuntimeError("startup transition control could not be decoded") from None
        self._accept(record)

    def _accept(self, record):
        self.messages += 1
        if (self.messages > 3 or not isinstance(record, dict)
                or type(record.get("schema_version")) is not int or record.get("schema_version") != 1):
            raise RuntimeError("startup transition control sequence is invalid")
        kind = record.get("type")
        expected_keys = self._COMMON | {"type"} | ({"operation"} if kind == "dispatch" else
                                       {"successor"} if kind == "commit" else set())
        if set(record) != expected_keys or kind not in {"prepare", "dispatch", "commit"}:
            raise RuntimeError("startup transition control fields are invalid")
        self._identity(record["predecessor"], detector=True)
        self._identity(record["supervisor"], detector=False)
        if (not isinstance(record["transition_id"], str) or not re_full_hex(record["transition_id"], 32)
                or not isinstance(record["session_id"], str) or not re_full_session(record["session_id"])
                or type(record["expires_at_ns"]) is not int or record["expires_at_ns"] <= time.monotonic_ns()
                or record["expires_at_ns"] > 2**53 - 1
                or record["expires_at_ns"] - time.monotonic_ns() > 90_000_000_000
                or not re_full_hex(record["source_revision"], 40)
                or not re_full_sha(record["protocol_sha256"])):
            raise RuntimeError("startup transition binding is invalid or expired")
        if ((self.source_revision is not None and record["source_revision"] != self.source_revision)
                or (self.protocol_sha256 is not None and record["protocol_sha256"] != self.protocol_sha256)):
            raise RuntimeError("startup transition source binding does not match the sampler process")
        if kind == "prepare":
            if self.phase != "idle" or self.messages != 1:
                raise RuntimeError("startup transition preparation is not one-shot")
            self.record = record
            self._validate_live_predecessor()
            self.phase = "prepared"
        else:
            if self.phase not in {"prepared", "dispatched"} or not self.record:
                raise RuntimeError("startup transition control has no matching preparation")
            if any(record[key] != self.record[key] for key in self._COMMON - {"type"}):
                raise RuntimeError("startup transition control binding changed")
            if time.monotonic_ns() >= self.record["expires_at_ns"]:
                raise RuntimeError("startup transition expired")
            if kind == "dispatch":
                if self.phase != "prepared" or record.get("operation") != "cloud_to_local_startup":
                    raise RuntimeError("startup transition dispatch is invalid")
                self.dispatch_seen = True
                self.phase = "dispatched"
            else:
                if self.phase != "dispatched":
                    raise RuntimeError("startup transition commit arrived before dispatch")
                successor = self._identity(record["successor"], detector=True)
                if not self.retired or not self.successor or successor != self.successor:
                    raise RuntimeError("startup transition successor was not observed exactly")
                self._validate_live_successor(successor)
                self.phase = "committed"
                self.successor = successor
        ack = {
            "schema_version": 1, "type": "ack", "sequence": kind,
            "transition_id": record["transition_id"], "request_sha256": _control_digest(record),
            "status": "accepted", "observed_at_ns": str(time.monotonic_ns()),
            "predecessor": {"pid": record["predecessor"]["pid"],
                            "start_ticks": record["predecessor"]["start_ticks"]},
            "supervisor": {"pid": record["supervisor"]["pid"],
                           "start_ticks": record["supervisor"]["start_ticks"]},
            "successor": ({"pid": self.successor["pid"], "start_ticks": self.successor["start_ticks"]}
                          if kind == "commit" else None),
        }
        sys.stdout.write(json.dumps(ack, sort_keys=True, separators=(",", ":")) + "\n")
        sys.stdout.flush()
        self.events.append({"type": kind, "transition_id": record["transition_id"],
                            "observed_at_ns": ack["observed_at_ns"], "request_sha256": ack["request_sha256"],
                            "predecessor": ack["predecessor"], "supervisor": ack["supervisor"],
                            "successor": ack["successor"]})

    def _validate_live_predecessor(self):
        predecessor = self.record["predecessor"]
        supervisor = self.record["supervisor"]
        self._require_observed(self.last_rows, "detector", predecessor)
        self._require_observed(self.last_rows, "supervisor_bridge", supervisor)
        self._require_live(predecessor)
        self._require_live(supervisor)

    def _validate_live_successor(self, successor):
        supervisor = self.record["supervisor"]
        self._require_observed(self.last_rows, "detector", successor)
        self._require_observed(self.last_rows, "supervisor_bridge", supervisor)
        self._require_live(successor)
        self._require_live(supervisor)
        if successor["pid"] == self.record["predecessor"]["pid"]:
            raise RuntimeError("startup transition reused the predecessor PID")
        predecessor_live = _process_stat_identity(self.record["predecessor"]["pid"])
        if predecessor_live is not None:
            raise RuntimeError("startup transition predecessor was not fully reaped")

    @staticmethod
    def _require_observed(rows, role, identity):
        if not any(row.get("role") == role and row.get("pid") == identity["pid"]
                   and row.get("start_ticks") == identity["start_ticks"]
                   and row.get("command_sha256") == identity["command_sha256"]
                   and ("parent_pid" not in identity or (row.get("ppid") == identity["parent_pid"]
                        and row.get("parent_start_ticks") == identity["parent_start_ticks"]))
                   for row in rows):
            raise RuntimeError("startup transition identity was not present in a valid sampler row")

    @staticmethod
    def _require_live(identity):
        live = _process_stat_identity(identity["pid"])
        if live is None or live[1] != identity["start_ticks"] or live[0] in {"Z", "X", "x"}:
            raise RuntimeError("startup transition identity is no longer live")
        root = Path("/proc") / str(identity["pid"])
        try:
            command = root.joinpath("cmdline").read_bytes().replace(b"\0", b" ").strip()
            status = root.joinpath("status").read_text()
        except OSError:
            raise RuntimeError("startup transition live identity became unreadable") from None
        if hashlib.sha256(command).hexdigest() != identity["command_sha256"]:
            raise RuntimeError("startup transition live command changed")
        if "parent_pid" in identity:
            match = re.search(r"^PPid:\s+(\d+)", status, re.M)
            if not match or int(match.group(1)) != identity["parent_pid"]:
                raise RuntimeError("startup transition live parent changed")
            parent = _process_stat_identity(identity["parent_pid"])
            if parent is None or parent[1] != identity["parent_start_ticks"]:
                raise RuntimeError("startup transition live parent identity changed")

    def allow_predecessor_retirement(self, role, pid, identity, detail):
        if (self.phase != "dispatched" or role != "detector" or not self.record
                or pid != self.record["predecessor"]["pid"]):
            return False
        expected = self.record["predecessor"]
        if identity is not None and identity[1] != expected["start_ticks"]:
            return False
        # A same-identity terminal state is safe evidence; unreadable or changed identity is not.
        if identity is not None and identity[0] not in {"Z", "X", "x"}:
            return False
        if self.retired:
            return True
        self.retired = True
        self.events.append({"type": "predecessor_retired", "transition_id": self.record["transition_id"],
                            "role": "detector", "reason": "authorized_startup_transition",
                            "pid": expected["pid"], "start_ticks": expected["start_ticks"],
                            "command_sha256": expected["command_sha256"],
                            "parent_pid": expected["parent_pid"],
                            "parent_start_ticks": expected["parent_start_ticks"],
                            "state": identity[0] if identity else "absent", "observed_at_ns": str(time.monotonic_ns())})
        return True

    def observe(self, rows):
        self.last_rows = rows
        if self.phase == "idle":
            return []
        record = self.record
        if time.monotonic_ns() >= record["expires_at_ns"] and self.phase != "committed":
            raise RuntimeError("startup transition expired before commit")
        supervisors = [row for row in rows if row.get("role") == "supervisor_bridge"]
        if len(supervisors) != 1 or not self._row_matches(supervisors[0], record["supervisor"]):
            raise RuntimeError("startup transition supervisor identity changed")
        detector_rows = [row for row in rows if row.get("role") == "detector"]
        predecessor = record["predecessor"]
        predecessor_rows = [row for row in detector_rows if row.get("pid") == predecessor["pid"]]
        if predecessor_rows:
            row = predecessor_rows[0]
            if not self._row_matches(row, predecessor):
                raise RuntimeError("startup transition predecessor PID was reused or changed")
            if self.phase == "committed":
                raise RuntimeError("startup transition predecessor returned after commit")
        elif self.phase == "dispatched":
            if not self.retired:
                # Absence is confirmed only when /proc no longer contains the exact PID.
                state = _process_stat_identity(predecessor["pid"])
                if state is None:
                    self.allow_predecessor_retirement("detector", predecessor["pid"], None, "absent")
                elif state[1] == predecessor["start_ticks"] and state[0] in {"Z", "X", "x"}:
                    self.allow_predecessor_retirement("detector", predecessor["pid"], state, "terminal")
                else:
                    raise RuntimeError("startup transition predecessor remains live or PID was reused")
        candidates = [row for row in detector_rows if row.get("pid") != predecessor["pid"]]
        if self.phase in {"prepared", "idle"} and candidates:
            raise RuntimeError("detector successor appeared before settings dispatch")
        if self.phase in {"dispatched", "committed"} and candidates:
            if len(candidates) != 1 or not self.retired:
                raise RuntimeError("startup transition observed an unexpected detector successor")
            row = candidates[0]
            if row.get("parent_start_ticks") != record["supervisor"]["start_ticks"]:
                raise RuntimeError("startup transition successor has a foreign parent")
            if (row.get("ppid") != record["supervisor"]["pid"]
                    or row.get("command_sha256") != predecessor["command_sha256"]):
                raise RuntimeError("startup transition successor executable or supervisor PID changed")
            candidate = {"pid": row["pid"], "start_ticks": row["start_ticks"],
                         "command_sha256": row["command_sha256"], "parent_pid": row["ppid"],
                         "parent_start_ticks": row["parent_start_ticks"]}
            if self.successor and candidate != self.successor:
                raise RuntimeError("startup transition observed more than one successor identity")
            self.successor = candidate
        elif self.phase == "dispatched" and self.successor:
            raise RuntimeError("startup transition successor disappeared before commit")
        elif self.phase == "committed":
            raise RuntimeError("committed detector successor disappeared")
        events, self.events = self.events, []
        return events

    @staticmethod
    def _row_matches(row, identity):
        return (row.get("pid") == identity["pid"] and row.get("start_ticks") == identity["start_ticks"]
                and row.get("command_sha256") == identity["command_sha256"]
                and ("parent_pid" not in identity or (row.get("ppid") == identity["parent_pid"]
                     and row.get("parent_start_ticks") == identity["parent_start_ticks"])))


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def re_full_sha(value):
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def re_full_hex(value, length):
    return isinstance(value, str) and len(value) == length and all(char in "0123456789abcdef" for char in value)


def re_full_session(value):
    return isinstance(value, str) and 1 <= len(value) <= 96 and all(char.isalnum() or char in "-_" for char in value)


def _terminal_diagnostic_payload(status: str, samples_written: int, error: Exception | None = None) -> dict:
    if status not in {"stopped", "error"} or type(samples_written) is not int or samples_written < 0:
        raise ValueError("invalid sampler terminal state")
    frames = []
    exception_type = None
    if error is not None:
        status = "error"
        candidate = type(error).__name__
        exception_type = candidate if candidate.isascii() and candidate.isidentifier() and len(candidate) <= 80 else "Exception"
        frames = [_safe_terminal_frame(frame) for frame in traceback.extract_tb(error.__traceback__)[-12:]]
    elif status == "error":
        raise ValueError("error terminal state requires an exception")
    return {
        "schema_version": 1,
        "status": status,
        "samples_written": samples_written,
        "exception_type": exception_type,
        "frames": frames,
    }


def _safe_terminal_frame(frame: traceback.FrameSummary) -> dict[str, object]:
    basename = Path(frame.filename).name
    function = frame.name
    if not basename or not basename.isascii() or len(basename) > 128 or not all(char.isalnum() or char in "._-" for char in basename):
        basename = "<unavailable>"
    if not function or not function.isascii() or len(function) > 128 or not all(char.isalnum() or char in "_<>.-" for char in function):
        function = "<unavailable>"
    line = frame.lineno if isinstance(frame.lineno, int) and frame.lineno > 0 else 1
    return {"file": basename, "function": function, "line": line}


def _write_terminal_diagnostic(path: Path, payload: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(payload, stream, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        stream.write("\n")


def sample(output: Path, interval_ms: int, progress: dict | None = None,
           source_revision: str | None = None, protocol_sha256: str | None = None) -> None:
    stop = False

    def stop_sampling(_signum, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, stop_sampling)
    signal.signal(signal.SIGINT, stop_sampling)
    interval = interval_ms / 1000
    next_sample = time.monotonic()
    samples_written = 0
    transition = StartupTransition(source_revision, protocol_sha256)
    with output.open("x", encoding="utf-8", buffering=1) as stream:
        while not stop:
            now = time.monotonic()
            transition._read_controls()
            roles, identity_races = _processes(transition)
            transition_events = transition.observe(roles)
            stream.write(json.dumps({
                "sample_monotonic_ns": time.monotonic_ns(),
                "roles": roles,
                "startup_transition_events": transition_events,
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
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--protocol-sha256", required=True)
    args = parser.parse_args()
    if args.interval_ms != 100:
        parser.error("The installed-browser protocol fixes sampling at 100 ms.")
    if not re_full_hex(args.source_revision, 40) or not re_full_sha(args.protocol_sha256):
        parser.error("source and protocol bindings must be lower-case SHA-256/Git hex.")
    progress = {"samples_written": 0}
    try:
        sample(args.output, args.interval_ms, progress, args.source_revision, args.protocol_sha256)
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
