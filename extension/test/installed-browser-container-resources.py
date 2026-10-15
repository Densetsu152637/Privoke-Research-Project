"""Prospective v10 whole-cgroup collector; independent of process enumeration."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import signal
import time
import traceback

MAX_SAFE_INTEGER = 2**53 - 1


def integer(value):
    if not re.fullmatch(r"[0-9]+", value):
        raise ValueError("invalid cgroup counter")
    result = int(value)
    if result > MAX_SAFE_INTEGER:
        raise ValueError("counter not exactly representable")
    return result


def read_cgroup(root=Path("/sys/fs/cgroup"), membership=Path("/proc/self/cgroup"),
                mountinfo=Path("/proc/self/mountinfo"), namespace=Path("/proc/self/ns/cgroup")):
    paths = [root, root / "cpu.stat", root / "memory.current"]
    def identity():
        membership_bytes = membership.read_bytes()
        if membership_bytes != b"0::/\n":
            raise RuntimeError("collector requires unified namespace-root membership")
        mounts = []
        for line in mountinfo.read_text(encoding="utf-8").splitlines():
            fields = line.split()
            if len(fields) >= 10 and fields[4].replace(r"\040", " ").replace(r"\134", "\\") == root.as_posix():
                separator = fields.index("-")
                if fields[3] != "/" or fields[separator + 1] != "cgroup2":
                    raise RuntimeError("collector requires unified namespace-root mount")
                mounts.append(line)
        if len(mounts) != 1:
            raise RuntimeError("collector requires one cgroup2 mount")
        stats = [p.stat() for p in paths]
        return {"membership_sha256": hashlib.sha256(membership_bytes).hexdigest(),
                "mount_sha256": hashlib.sha256(mounts[0].encode()).hexdigest(),
                "namespace_inode": namespace.stat().st_ino,
                "files": [{"device": s.st_dev, "inode": s.st_ino} for s in stats]}
    before = identity()
    counters = {}
    for line in paths[1].read_text(encoding="ascii").splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[0] in counters:
            raise ValueError("invalid cpu.stat")
        counters[fields[0]] = integer(fields[1])
    usage = counters["usage_usec"]
    memory = integer(paths[2].read_text(encoding="ascii").strip())
    if identity() != before:
        raise RuntimeError("cgroup identity changed during read")
    return before, usage, memory


class ObservationFailure(RuntimeError):
    def __init__(self, reason, previous, current):
        super().__init__(reason)
        def closed(row):
            return {key: row[key] for key in ("read_started_monotonic_ns", "sample_monotonic_ns", "observer_cpu_ns", "cpu_usage_usec")} | {
                "cgroup_identity_sha256": hashlib.sha256(json.dumps(row["cgroup_identity"], sort_keys=True).encode()).hexdigest()}
        self.observation_failure = {"reason": reason, "previous": closed(previous), "current": closed(current)}


def collect(output, source_revision, protocol_sha256, progress, *, read=read_cgroup,
            clock=time.monotonic_ns, cpu_clock=time.process_time_ns, sleep=time.sleep,
            stopped=lambda: False):
    prior = None
    with output.open("x", encoding="utf-8", buffering=1) as stream:
        while True:
            final_observation = stopped()
            read_started = clock()
            identity, usage, memory = read()
            now = clock()
            cpu = cpu_clock()
            for value in (read_started, now, cpu, usage, memory):
                if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
                    raise ValueError("invalid sampled counter")
            row = {"schema_version": 1, "read_started_monotonic_ns": read_started,
                   "sample_monotonic_ns": now, "final_observation": final_observation,
                   "observer_cpu_ns": cpu, "requested_interval_ms": 100,
                   "source_revision": source_revision, "protocol_sha256": protocol_sha256,
                   "cgroup_identity": identity, "cpu_usage_usec": usage,
                   "memory_current_bytes": memory}
            # Retain complete observations before cross-observation guards can reject them.
            stream.write(json.dumps(row, separators=(",", ":")) + "\n")
            progress["samples_written"] += 1
            if now < read_started:
                raise ObservationFailure("read_time_reversed", prior or row, row)
            if prior:
                if identity != prior["cgroup_identity"]:
                    raise ObservationFailure("cgroup_identity_changed", prior, row)
                if now <= prior["sample_monotonic_ns"] or read_started <= prior["sample_monotonic_ns"]:
                    raise ObservationFailure("nonpositive_sample_time", prior, row)
                if usage < prior["cpu_usage_usec"] or cpu < prior["observer_cpu_ns"]:
                    raise ObservationFailure("counter_decreased", prior, row)
            if final_observation:
                return
            prior = row
            # Schedule from completion. Never burst to catch up after a delayed read.
            sleep(0.1)


def terminal(status, count, error=None):
    frames = [] if error is None else [{"file": Path(f.filename).name,
             "function": f.name, "line": f.lineno}
             for f in traceback.extract_tb(error.__traceback__)[-12:]]
    payload = {"schema_version": 1, "status": status, "samples_written": count,
               "exception_type": None if error is None else type(error).__name__, "frames": frames}
    if isinstance(error, ObservationFailure):
        payload["observation_failure"] = error.observation_failure
    return payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--terminal-diagnostic", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--protocol-sha256", required=True)
    parser.add_argument("--interval-ms", type=int, default=100)
    args = parser.parse_args()
    if args.interval_ms != 100 or not re.fullmatch(r"[0-9a-f]{40}", args.source_revision) or not re.fullmatch(r"[0-9a-f]{64}", args.protocol_sha256):
        parser.error("invalid frozen source/protocol/cadence")
    stopping = False
    def stop(_signal, _frame):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    progress = {"samples_written": 0}
    error = None
    try:
        collect(args.output, args.source_revision, args.protocol_sha256, progress, stopped=lambda: stopping)
    except Exception as caught:
        error = caught
    payload = terminal("error" if error else "stopped", progress["samples_written"], error)
    try:
        with args.terminal_diagnostic.open("x", encoding="utf-8") as stream:
            json.dump(payload, stream)
    except OSError:
        return 1
    return 1 if error else 0


if __name__ == "__main__":
    raise SystemExit(main())
