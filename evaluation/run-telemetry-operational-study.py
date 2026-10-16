"""Controlled host-only telemetry mechanics; no user traffic or utility estimate.

The child process registers the shipped collector on loopback with its real store.
The controller uses the shipped reporter, randomizer, budget and gRPC clients.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import logging
import math
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "evaluation"))
from host_environment import configure_imports, python_environment
configure_imports()
sys.path.insert(0, str(ROOT / "extension/client-runtime"))

import grpc
from privoke.v1 import telemetry_pb2 as pb, telemetry_pb2_grpc as rpc
from src.telemetry.privacy import DOMAINS

PROTOCOL = "telemetry-operational-controlled-v1"
SOURCE_FILES = (
    "evaluation/run-telemetry-operational-study.py", "evaluation/host_environment.py",
    "extension/client-runtime/src/telemetry/event_emitter.py",
    "extension/client-runtime/src/telemetry/privacy.py",
    "services/telemetry-service/app/server.py", "services/telemetry-service/app/storage.py",
    "services/telemetry-service/app/validation.py", "services/telemetry-service/app/config.py",
    "shared/python/privoke_service/stack_connection.py", "shared/proto/privoke/v1/telemetry.proto",
    "extension/client-runtime/generated/privoke/v1/telemetry_pb2.py",
    "extension/client-runtime/generated/privoke/v1/telemetry_pb2_grpc.py",
)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def quantiles(values):
    ordered = sorted(values)
    if not ordered:
        return {"n": 0}
    return {"n": len(ordered), **{
        label: ordered[max(0, math.ceil(q * len(ordered)) - 1)]
        for label, q in (("p50", .5), ("p95", .95), ("max", 1))}}


def check_marginals(summary):
    names = [dimension.dimension for dimension in summary.dimensions]
    if len(names) != len(DOMAINS) or set(names) != set(DOMAINS):
        raise AssertionError("Expected exactly five unique declared dimensions")
    for dimension in summary.dimensions:
        values = [value.value for value in dimension.values]
        if len(values) != len(DOMAINS[dimension.dimension]) or set(values) != set(DOMAINS[dimension.dimension]):
            raise AssertionError("Expected exact unique declared domain values")
        if sum(value.observed_noisy_count for value in dimension.values) != summary.sample_count:
            raise AssertionError("Noisy marginal does not reconcile to accepted reports")
        if any(not math.isfinite(value.estimated_count) or not 0 <= value.estimated_count <= summary.sample_count
               for value in dimension.values):
            raise AssertionError("Estimated count is outside the declared clipped range")


def serve(args):
    # Import collector only in its separate service process to avoid component collisions.
    sys.path.insert(0, str(ROOT / "services/telemetry-service/app"))
    from server import TelemetryCollector
    from storage import TelemetryStore
    server = grpc.server(ThreadPoolExecutor(max_workers=4))
    rpc.add_TelemetryServiceServicer_to_server(TelemetryCollector(TelemetryStore(args.database)), server)
    port = server.add_insecure_port(f"127.0.0.1:{args.port}")
    if not port:
        raise RuntimeError("Owned collector could not bind loopback")
    server.start()
    save(args.ready, {"target": f"127.0.0.1:{port}", "pid": os.getpid(), "database": str(args.database)})
    server.wait_for_termination()


class OwnedCollector:
    def __init__(self, output):
        self.output = output
        self.process = None
        self.port = 0
        self.generation = 0
        self.lifecycle = []
        self.log = None

    def start(self):
        self.generation += 1
        ready = self.output / f"collector-ready-{self.generation}.json"
        self.log = (self.output / f"collector-{self.generation}.log").open("xb")
        self.process = subprocess.Popen([
            sys.executable, str(Path(__file__).resolve()), "--serve", "--database",
            str(self.output / "collector.sqlite3"), "--ready", str(ready), "--port", str(self.port),
        ], cwd=ROOT, env=python_environment(), stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 10
        while not ready.exists():
            if self.process.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("Owned collector failed to become ready within ten seconds")
            time.sleep(.05)
        row = json.loads(ready.read_text(encoding="utf-8"))
        if row["pid"] != self.process.pid:
            raise AssertionError("Collector PID does not match owned child")
        self.port = int(row["target"].rsplit(":", 1)[1])
        self.lifecycle.append({"event": "started", "generation": self.generation, **row})
        return row["target"]

    def stop(self):
        if self.process is not None:
            pid = self.process.pid
            self.process.terminate()
            try:
                code = self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                code = self.process.wait(timeout=5)
                self.lifecycle.append({"event": "emergency_kill", "pid": pid})
                raise RuntimeError("Collector required emergency cleanup")
            finally:
                self.log.close()
                self.process = None
            self.lifecycle.append({"event": "stopped", "pid": pid, "exit_code": code})


def study(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    protocol_bytes = args.protocol.read_bytes()
    (output / "protocol.md").write_bytes(protocol_bytes)
    source_names = set(SOURCE_FILES)
    for prefix in ("extension/client-runtime/src/classification", "shared/python/privoke_service"):
        source_names.update(path.relative_to(ROOT).as_posix() for path in (ROOT / prefix).rglob("*.py") if "__pycache__" not in path.parts)
    source_hashes = {name: sha(ROOT / name) for name in sorted(source_names)}
    manifest = {"protocol": PROTOCOL, "protocol_sha256": sha(output / "protocol.md"),
                "source_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "source_hashes": source_hashes, "python": sys.version, "platform": platform.platform(),
                "scope": "controlled prototype mechanics, not deployment traffic, monitoring utility or model evaluation",
                "status": "running", "phases": {}, "timings": {}}
    save(output / "manifest.json", manifest)
    logging.basicConfig(filename=output / "reporter.log", level=logging.INFO, force=True,
                        format="%(created).6f %(levelname)s %(message)s")
    sys.path.insert(0, str(ROOT / "extension/client-runtime"))
    from src.telemetry.event_emitter import TelemetryReporter
    from src.classification import PriVokeAction
    from src.telemetry.privacy import DailyPrivacyBudget
    collector = OwnedCollector(output)
    reporters = []
    channels = []
    all_report_ms, summary_ms, health_ms, drains = [], [], [], []
    counters = {"fixture_report_opportunities": 0}

    def client(target):
        channel = grpc.insecure_channel(target)
        channels.append(channel)
        grpc.channel_ready_future(channel).result(timeout=5)
        return rpc.TelemetryServiceStub(channel)

    def summary(stub, expected):
        started = time.perf_counter()
        response = stub.GetTelemetrySummary(pb.GetTelemetrySummaryRequest(), timeout=2)
        summary_ms.append((time.perf_counter() - started) * 1000)
        check_marginals(response)
        if response.sample_count != expected:
            raise AssertionError(f"Accepted report count {response.sample_count} != {expected}")
        return {"sample_count": response.sample_count, "dimensions": [
            {"dimension": dim.dimension, "values": [
                {"value": v.value, "observed_noisy_count": v.observed_noisy_count,
                 "estimated_count": v.estimated_count} for v in dim.values]} for dim in response.dimensions]}

    def health(stub, expect_serving):
        started = time.perf_counter()
        try:
            response = stub.Health(pb.TelemetryHealthRequest(), timeout=.5)
            serving, status = response.status == "SERVING", response.status
        except grpc.RpcError as error:
            serving, status = False, error.code().name
        elapsed = (time.perf_counter() - started) * 1000
        health_ms.append(elapsed)
        if serving != expect_serving:
            raise AssertionError("Separate Health probe disagrees with controlled service state")
        return {"serving": serving, "status": status, "rpc_ms": elapsed}

    def report_batch(target, prefix, instances, actions):
        batch = []
        started = time.perf_counter()
        for index in range(instances):
            ledger = output / "ledgers" / f"{prefix}-{index}.sqlite3"
            reporter = TelemetryReporter(target, ledger_path=str(ledger), timeout_seconds=1)
            reporters.append(reporter)
            batch.append(reporter)
            for action in actions:
                before = time.perf_counter()
                # Deliberate analysis-shaped input; no detector or model is invoked.
                reporter.report(SimpleNamespace(action=PriVokeAction[action], result=None))
                all_report_ms.append((time.perf_counter() - before) * 1000)
                counters["fixture_report_opportunities"] += 1
        deadline = time.monotonic() + 12
        while any(reporter._queue.unfinished_tasks for reporter in batch):
            if time.monotonic() >= deadline:
                raise AssertionError("Reporter did not reach terminal queue outcomes within twelve seconds")
            time.sleep(.01)
        elapsed = (time.perf_counter() - started) * 1000
        drains.append(elapsed)
        for reporter in batch:
            reporter.close()
            if reporter._thread.is_alive():
                raise AssertionError("Owned reporter failed to stop")
        return {"instances": instances, "opportunities": instances * len(actions),
                "batch_start_to_drained_ms": elapsed}

    try:
        target = collector.start()
        stub = client(target)
        manifest["initial_health"] = health(stub, True)
        summary(stub, 0)
        a1 = report_batch(target, "a1", 10, ["ALLOW"] * 10)
        a1["summary"] = summary(stub, 80)
        a1["reopen"] = report_batch(target, "a1", 10, ["BLOCK"] * 2)
        a1["after_reopen"] = summary(stub, 80)
        manifest["phases"]["A1_cap_reopen"] = a1
        save(output / "manifest.json", manifest)

        a2 = report_batch(target, "a2", 10, ["ALLOW"] * 8 + ["BLOCK"] * 8)
        a2.update({"offered_action_counts": {"ALLOW": 80, "BLOCK": 80},
                   "protocol_derived_reserved_input_action_counts": {"ALLOW": 80, "BLOCK": 0},
                   "summary": summary(stub, 160)})
        manifest["phases"]["A2_admission_order"] = a2
        save(output / "manifest.json", manifest)

        stopped_at = time.perf_counter()
        collector.stop()
        a3 = {"outage_probe": health(stub, False),
              "stop_to_observed_unavailable_ms": (time.perf_counter() - stopped_at) * 1000}
        a3["failed_delivery_batch"] = report_batch(target, "a3", 2, ["BLOCK"] * 8)
        a3["all_failure_ledgers_exhausted"] = all(
            not DailyPrivacyBudget(output / "ledgers" / f"a3-{index}.sqlite3").reserve(1)
            for index in range(2))
        if not a3["all_failure_ledgers_exhausted"]:
            raise AssertionError("Failed deliveries incorrectly refunded reservations")
        restarted_at = time.perf_counter()
        target = collector.start()
        stub = client(target)
        a3["recovery_probe"] = health(stub, True)
        a3["restart_to_serving_ms"] = (time.perf_counter() - restarted_at) * 1000
        a3["persisted_summary"] = summary(stub, 160)
        if a3["persisted_summary"] != a2["summary"]:
            raise AssertionError("A3 persisted noisy/estimated marginals changed across restart")
        a3["reopened_exhausted"] = report_batch(target, "a3", 2, ["ALLOW"] * 2)
        a3["after_no_replay"] = summary(stub, 160)
        a3["fresh_ledger_recovery"] = report_batch(target, "a3-recovery", 1, ["WARN"] * 8)
        a3["recovered_summary"] = summary(stub, 168)
        manifest["phases"]["A3_outage_recovery"] = a3
        save(output / "manifest.json", manifest)

        invalid = pb.TelemetryPacket(privacy_mechanism="invalid")
        try:
            stub.RecordTelemetry(invalid, timeout=2)
        except grpc.RpcError as error:
            code = error.code().name
        else:
            raise AssertionError("Invalid packet was accepted")
        if code != "INVALID_ARGUMENT":
            raise AssertionError("Invalid packet returned the wrong gRPC status")
        a4 = {"invalid_packet_status": code, "summary": summary(stub, 168)}
        collector.stop()
        stub = client(collector.start())
        a4["after_second_restart"] = summary(stub, 168)
        if a4["summary"] != a4["after_second_restart"]:
            raise AssertionError("A4 noisy/estimated marginals changed across restart")
        manifest["phases"]["A4_rejection_persistence"] = a4
        if counters["fixture_report_opportunities"] != 308:
            raise AssertionError("Frozen fixture opportunity count differs from 308")
        manifest["status"] = "complete"
    except Exception as error:
        manifest["status"] = "failed"
        manifest["failure"] = {"type": type(error).__name__, "message": str(error)[:500]}
        raise
    finally:
        for reporter in reporters:
            reporter.close()
        for channel in channels:
            channel.close()
        try:
            collector.stop()
        except Exception as error:
            manifest["status"] = "failed"
            manifest["cleanup_failure"] = type(error).__name__
        manifest["lifecycle"] = collector.lifecycle
        manifest["collector_reaped"] = collector.process is None
        manifest["reporter_threads_stopped"] = all(not reporter._thread.is_alive() for reporter in reporters)
        if not manifest["collector_reaped"] or not manifest["reporter_threads_stopped"]:
            manifest["status"] = "failed"
        manifest["timings"] = {"report_call_ms": quantiles(all_report_ms),
            "summary_rpc_ms": quantiles(summary_ms), "health_rpc_ms": quantiles(health_ms),
            "batch_drain_ms": quantiles(drains)}
        manifest["counters"] = counters
        manifest["final_source_hashes"] = {name: sha(ROOT / name) for name in source_hashes}
        if manifest["final_source_hashes"] != source_hashes or sha(args.protocol) != manifest["protocol_sha256"]:
            manifest["status"] = "failed"
            manifest["source_or_protocol_changed"] = True
        logging.shutdown()
        manifest["reporter_failure_log_count"] = (output / "reporter.log").read_text().count("telemetry submission failed")
        if manifest["status"] == "complete" and manifest["reporter_failure_log_count"] != 16:
            manifest["status"] = "failed"
            manifest["failure"] = {"type": "failure_log_count_mismatch"}
        manifest["artifact_hashes"] = {str(path.relative_to(output)): sha(path)
            for path in output.rglob("*") if path.is_file() and path.name != "manifest.json"}
        save(output / "manifest.json", manifest)
    return 0 if manifest["status"] == "complete" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--database", type=Path)
    parser.add_argument("--ready", type=Path)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    if args.serve:
        return serve(args)
    if args.output is None or args.protocol is None:
        parser.error("--protocol and --output are required for the controller")
    return study(args)


if __name__ == "__main__":
    raise SystemExit(main())
