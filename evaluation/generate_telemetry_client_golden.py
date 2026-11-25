"""Golden fixture of the telemetry reporter for the Rust client (RUST-S18, stage 18).

``extension/client-runtime/src/telemetry/privacy.py`` and ``event_emitter.py`` run unmodified. Only the gRPC edges are
replaced by in-process stubs (``grpc``, ``privoke_service.stack_connection.grpc_channel`` and the generated
``privoke.v1`` modules), so the oracle needs nothing beyond the standard library. The operating-system random source
(``random._urandom``, what ``random.SystemRandom`` reads) is replaced by a recorded byte stream, so every draw, every
byte consumed and every decision is reproducible and the Rust crate can be fed the same bytes.

Records, for the Rust crate ``privoke-telemetry-client``:

* ``kernel``: binary64 truthful and other probabilities for a grid of (epsilon, domain size);
* ``grr``: single draws (boundary draws at the threshold and random draws), with the exact bytes consumed;
* ``reports``: ``randomize_report`` draws over the five real domains, and the rejected inputs with their messages;
* ``ledger``: scenario scripts (caps, reopen, UTC day and rollback, invalid rows, corruption, outage and recovery)
  with each operation's outcome and the final ledger rows;
* ``events``: the true values ``StructuredEventEmitter`` derives from an analysis, and complete packets;
* ``reporter``: ``TelemetryReporter`` scenarios (budget cap and order, delivery failures, queue overflow, ledger
  outage and recovery, failed build) with the per-report outcomes and the delivered packets;
* ``config``: ``validate_privacy_config`` accept and reject cases.

Host run, read-only on every environment (standard library only)::

    python evaluation/generate_telemetry_client_golden.py \
        --out rust/crates/privoke-telemetry-client/tests/fixtures/golden.json \
        --ledger-out rust/crates/privoke-telemetry-client/tests/fixtures/python_written_ledger.sqlite3

The output is deterministic: running it twice yields identical bytes (the interpreter version is recorded).
"""

from __future__ import annotations

import argparse
import enum
import hashlib
import json
import logging
import math
import os
import queue
import random
import sqlite3
import struct
import sys
import tempfile
import threading
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
CLIENT = REPO / "extension" / "client-runtime"
TELEMETRY = CLIENT / "src" / "telemetry"
SEED = b"privoke-telemetry-client-golden-v1"


# --- stand-ins for the gRPC edges ---------------------------------------------------------------------------------


class StatusCode(enum.Enum):
    UNAVAILABLE = "unavailable"
    DEADLINE_EXCEEDED = "deadline"
    INTERNAL = "internal"


class RpcError(Exception):
    def __init__(self, code: StatusCode):
        super().__init__(code.name)
        self._code = code

    def code(self) -> StatusCode:
        return self._code


class Packet:
    """The generated ``TelemetryPacket``: keyword construction, attribute access."""

    FIELDS = (
        "time_bucket", "action", "primary_category", "risk_bucket", "model_version",
        "privacy_mechanism", "privacy_epsilon",
    )

    def __init__(self, **fields):
        self.__dict__.update(fields)


def install_stubs() -> None:
    grpc = types.ModuleType("grpc")
    grpc.RpcError = RpcError
    grpc.StatusCode = StatusCode
    sys.modules["grpc"] = grpc
    service = types.ModuleType("privoke_service")
    service.__path__ = []
    stack = types.ModuleType("privoke_service.stack_connection")
    stack.grpc_channel = lambda *args, **kwargs: None
    service.stack_connection = stack
    sys.modules["privoke_service"] = service
    sys.modules["privoke_service.stack_connection"] = stack
    root = types.ModuleType("privoke")
    root.__path__ = []
    version = types.ModuleType("privoke.v1")
    version.__path__ = []
    pb2 = types.ModuleType("privoke.v1.telemetry_pb2")
    pb2.TelemetryPacket = Packet
    pb2_grpc = types.ModuleType("privoke.v1.telemetry_pb2_grpc")
    pb2_grpc.TelemetryServiceStub = object
    version.telemetry_pb2 = pb2
    version.telemetry_pb2_grpc = pb2_grpc
    root.v1 = version
    sys.modules.update({
        "privoke": root,
        "privoke.v1": version,
        "privoke.v1.telemetry_pb2": pb2,
        "privoke.v1.telemetry_pb2_grpc": pb2_grpc,
    })


def load_client():
    install_stubs()
    sys.path.insert(0, str(CLIENT))
    from src.telemetry import event_emitter, privacy  # noqa: PLC0415 (stubs first)

    return event_emitter, privacy


# --- deterministic inputs -------------------------------------------------------------------------------------------


def det_bytes(label: str, length: int) -> bytes:
    """``length`` bytes of a SHA-256 counter stream keyed by ``label``."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(SEED + label.encode() + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:length])


class Det:
    """Deterministic choices (not ``random``: its algorithms are not part of the oracle)."""

    def __init__(self, label: str):
        self._label = label
        self._counter = 0

    def below(self, n: int) -> int:
        value = int.from_bytes(det_bytes(f"{self._label}/{self._counter}", 8), "big")
        self._counter += 1
        return value % n


class Exhausted(Exception):
    pass


class Stream:
    """Replacement for ``os.urandom`` that serves a fixed byte string and counts what is read."""

    def __init__(self, data: bytes = b"", failure: Exception | None = None):
        self.data = data
        self.position = 0
        self.failure = failure

    def urandom(self, n: int) -> bytes:
        if self.failure is not None:
            raise self.failure
        if self.position + n > len(self.data):
            raise Exhausted(f"stream exhausted at {self.position} reading {n}")
        chunk = self.data[self.position:self.position + n]
        self.position += n
        return chunk


def patched_stream(stream: Stream):
    return mock.patch.object(random, "_urandom", stream.urandom)


def fbits(value: float) -> str:
    return struct.pack(">d", value).hex()


def fhex_repr(value: float) -> dict:
    return {"bits": fbits(value), "repr": repr(value)}


# --- kernel and GRR -----------------------------------------------------------------------------------------------


EPSILON_GRID = (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.75, 1.0, 1.25, 1.5, 1.7, 2.0)
DOMAIN_SIZES = (2, 3, 4, 6, 11)


def synthetic_domain(size: int) -> list[str]:
    return [f"v{index}" for index in range(size)]


def kernel_section(privacy) -> dict:
    cells = []
    for epsilon in EPSILON_GRID:
        for size in DOMAIN_SIZES:
            domain = synthetic_domain(size)
            probabilities = privacy.grr_probabilities(domain[0], domain, epsilon)
            cells.append({
                "epsilon": fhex_repr(epsilon),
                "size": size,
                "truthful": fhex_repr(probabilities[domain[0]]),
                "other": fhex_repr(probabilities[domain[1]]),
            })
    # The per-dimension epsilons of every supported event epsilon over the five real domains.
    per_dimension = []
    for event_epsilon in (0.5, 0.6, 0.75, 1.0, 1.3, 1.5, 2.0):
        for name, domain in privacy.DOMAINS.items():
            epsilon = event_epsilon / len(privacy.DIMENSIONS)
            probabilities = privacy.grr_probabilities(domain[0], list(domain), epsilon)
            per_dimension.append({
                "event_epsilon": fhex_repr(event_epsilon),
                "dimension": name,
                "epsilon": fhex_repr(epsilon),
                "truthful": fhex_repr(probabilities[domain[0]]),
                "other": fhex_repr(probabilities[domain[1]]),
            })
    return {"grid": cells, "per_dimension": per_dimension}


def run_grr(privacy, domain, value, epsilon, data: bytes) -> dict:
    stream = Stream(data)
    with patched_stream(stream):
        try:
            output = privacy.generalized_randomized_response(value, domain, epsilon, rng=random.SystemRandom())
            error = None
        except ValueError as exc:
            output, error = None, {"class": "ValueError", "message": str(exc)}
    case = {
        "domain": list(domain),
        "value": value,
        "epsilon": fhex_repr(epsilon),
        "bytes": data[: stream.position].hex(),
        "output": output,
    }
    if error:
        case["error"] = error
    return case


def grr_section(privacy) -> dict:
    cases = []
    # Boundary draws: J = ceil(p * 2**53) grid points are truthful (J/2**53 < p), so the draw J-1 is truthful and J is not.
    for size in DOMAIN_SIZES:
        for epsilon in (0.1, 0.3, 0.7, 1.0, 2.0):
            domain = synthetic_domain(size)
            p = privacy.grr_probabilities(domain[0], domain, epsilon)[domain[0]]
            count = math.ceil(p * (1 << 53))
            for label, j in (("zero", 0), ("below", count - 1), ("at", count), ("above", count + 1), ("max", (1 << 53) - 1)):
                # The 7-byte read keeps the top 53 bits; the low three bits are noise that must not matter.
                noise = int.from_bytes(det_bytes(f"noise/{size}/{epsilon}/{label}", 1), "big") & 7
                word = ((j << 3) | noise).to_bytes(7, "big")
                filler = det_bytes(f"boundary/{size}/{epsilon}/{label}", 16)
                case = run_grr(privacy, domain, domain[1 % size], epsilon, word + filler)
                case["boundary"] = {"draw_count": j, "label": label}
                cases.append(case)
    det = Det("grr")
    domains = {name: list(domain) for name, domain in privacy.DOMAINS.items()}
    domains.update({f"synthetic{size}": synthetic_domain(size) for size in DOMAIN_SIZES})
    names = sorted(domains)
    for index in range(360):
        name = names[det.below(len(names))]
        domain = domains[name]
        value = domain[det.below(len(domain))]
        epsilon = EPSILON_GRID[det.below(len(EPSILON_GRID))]
        cases.append(run_grr(privacy, domain, value, epsilon, det_bytes(f"grr-bytes/{index}", 96)))
    errors = []
    for domain, value, epsilon in (
        ([], "x", 1.0), (["only"], "only", 1.0), (["same", "same"], "same", 1.0), (["a", "b"], "missing", 1.0),
        (["a", "b"], "a", 0.0), (["a", "b"], "a", -1.0), (["a", "b"], "a", math.nan), (["a", "b"], "a", math.inf),
    ):
        errors.append(run_grr(privacy, domain, value, epsilon, b""))
    return {"cases": cases, "errors": errors}


VALUE_KINDS = ("action", "risk_bucket", "primary_category", "model_version", "time_bucket")


def report_section(privacy) -> dict:
    det = Det("reports")
    cases = []
    for index in range(160):
        epsilon = (0.5, 0.6, 0.75, 1.0, 1.3, 1.5, 2.0)[det.below(7)]
        values = {name: privacy.DOMAINS[name][det.below(len(privacy.DOMAINS[name]))] for name in privacy.DIMENSIONS}
        stream = Stream(det_bytes(f"report-bytes/{index}", 512))
        with patched_stream(stream):
            output = privacy.randomize_report(values, epsilon, rng=random.SystemRandom())
        cases.append({
            "epsilon": fhex_repr(epsilon),
            "values": values,
            "bytes": stream.data[: stream.position].hex(),
            "output": output,
        })
    complete = {name: privacy.DOMAINS[name][0] for name in privacy.DIMENSIONS}
    invalid = []
    for label, values, epsilon in (
        ("missing_dimension", {"action": "ALLOW"}, 1.0),
        ("extra_dimension", {**complete, "extra": "x"}, 1.0),
        ("epsilon_low", complete, 0.49),
        ("epsilon_high", complete, 2.01),
        ("epsilon_nan", complete, math.nan),
        ("epsilon_micros", complete, 0.5000001),
        ("value_outside_domain", {**complete, "action": "DENY"}, 1.0),
    ):
        try:
            privacy.randomize_report(values, epsilon, rng=random.SystemRandom())
            raise AssertionError(label)
        except ValueError as exc:
            invalid.append({
                "label": label, "values": values, "epsilon": fhex_repr(epsilon),
                "error": {"class": "ValueError", "message": str(exc)},
            })
    return {"cases": cases, "invalid": invalid}


def config_section(privacy) -> list:
    cases = []
    pairs = [
        (0.5, 0.5), (1.0, 8.0), (2.0, 8.0), (0.49, 1.0), (2.01, 8.0), (math.nan, 8.0), (math.inf, 8.0),
        (1.0, 0.99), (1.0, 8.01), (1.0, math.nan), (1.0, math.inf), (0.5000001, 1.0), (1.0, 1.0000001),
        (0.500000, 8.0), (0.5000000999, 1.0), (1.0, 7.9999999), (0.7, 0.7), (2.0, 2.0), (-1.0, 8.0),
    ]
    for event_epsilon, daily_epsilon in pairs:
        try:
            privacy.validate_privacy_config(event_epsilon, daily_epsilon)
            outcome = {"ok": True}
        except ValueError as exc:
            outcome = {"ok": False, "message": str(exc)}
        cases.append({"event": fhex_repr(event_epsilon), "daily": fhex_repr(daily_epsilon), **outcome})
    return cases


# --- ledger ------------------------------------------------------------------------------------------------------


def when(spec):
    year, month, day, hour, minute, offset_minutes = spec
    return datetime(year, month, day, hour, minute, tzinfo=timezone(timedelta(minutes=offset_minutes)))


def ledger_rows(path: Path):
    if not path.exists():
        return None
    try:
        connection = sqlite3.connect(path)
        try:
            return [[row[0], fbits(float(row[1]))] for row in connection.execute(
                "SELECT utc_day, epsilon_spent FROM daily_budget ORDER BY singleton")]
        finally:
            connection.close()
    except sqlite3.Error:
        return "unreadable"


def schema_sql(path: Path):
    connection = sqlite3.connect(path)
    try:
        return connection.execute("SELECT sql FROM sqlite_master WHERE name = 'daily_budget'").fetchone()[0]
    finally:
        connection.close()


D2026 = (2026, 1, 1, 23, 50, 0)


def day(year, month, dom, hour=12, minute=0, offset=0):
    return [year, month, dom, hour, minute, offset]


def reserve_op(epsilon, spec):
    return {"op": "reserve", "epsilon": fhex_repr(epsilon), "now": spec}


LEDGER_SCENARIOS = [
    {
        "name": "default_cap_persists_and_resets_on_utc_day",
        "daily": 8.0,
        "ops": (
            [reserve_op(1.0, list(D2026)) for _ in range(8)]
            + [reserve_op(1.0, list(D2026)), {"op": "new"}, reserve_op(1.0, list(D2026)),
               reserve_op(1.0, day(2026, 1, 2, 0, 10))]
        ),
    },
    {
        "name": "half_epsilon_cap_and_tolerance",
        "daily": 8.0,
        "ops": [reserve_op(0.5, day(2026, 6, 1)) for _ in range(17)] + [reserve_op(2.0, day(2026, 6, 1)),
                                                                          reserve_op(0.6, day(2026, 6, 2))],
    },
    {
        "name": "binary64_accumulation_of_six_tenths",
        "daily": 8.0,
        "ops": [reserve_op(0.6, day(2026, 6, 1)) for _ in range(15)],
    },
    {
        "name": "binary64_accumulation_of_odd_micros",
        "daily": 3.0,
        "ops": [reserve_op(0.7, day(2026, 6, 1)) for _ in range(6)] + [reserve_op(0.500001, day(2026, 6, 1))
                                                                       for _ in range(6)],
    },
    {
        "name": "utc_conversion_and_same_day_order",
        "daily": 1.0,
        "ops": [
            reserve_op(0.5, day(2026, 3, 1, 0, 15, 0)),
            reserve_op(0.5, day(2026, 3, 1, 23, 59, 0)),
            reserve_op(0.5, day(2026, 3, 2, 5, 30, 330)),
            reserve_op(0.5, day(2026, 3, 1, 15, 30, -840)),
            reserve_op(0.5, day(2026, 3, 2, 9, 0, 0)),
            reserve_op(0.5, day(2026, 3, 2, 8, 59, 0)),
        ],
    },
    {
        "name": "clock_rollback_fails_closed",
        "daily": 1.0,
        "ops": [
            reserve_op(1.0, day(2026, 3, 1, 0, 15)),
            reserve_op(0.5, day(2026, 2, 28, 15, 30, 840)),
            reserve_op(0.5, day(2026, 3, 1, 0, 20)),
            reserve_op(0.5, day(2025, 12, 31, 23, 59)),
            reserve_op(0.5, day(2026, 3, 2, 0, 0)),
        ],
    },
    {
        "name": "calendar_rollovers_and_string_order",
        "daily": 1.0,
        "ops": [
            reserve_op(1.0, day(2027, 12, 31, 23, 59)),
            reserve_op(1.0, day(2028, 1, 1, 0, 0)),
            reserve_op(1.0, day(2028, 2, 28, 23, 0)),
            reserve_op(1.0, day(2028, 2, 29, 0, 0)),
            reserve_op(1.0, day(2028, 3, 1, 0, 0)),
            reserve_op(1.0, day(2999, 12, 31, 0, 0)),
            reserve_op(1.0, day(9999, 12, 31, 23, 0)),
        ],
    },
    {
        "name": "year_below_1000_is_zero_padded",
        "daily": 1.0,
        "ops": [reserve_op(1.0, day(999, 12, 31, 12)), reserve_op(1.0, day(1000, 1, 1, 12)),
                reserve_op(0.5, day(999, 12, 31, 12))],
    },
    {
        "name": "epsilon_above_daily_cap_is_denied_without_touching_the_ledger",
        "daily": 1.0,
        "ops": [reserve_op(2.0, day(2026, 3, 1)), {"op": "exists"}, reserve_op(1.0, day(2026, 3, 1)), {"op": "exists"}],
    },
    {
        "name": "invalid_reservation_epsilon_is_rejected_before_any_io",
        "daily": 8.0,
        "ops": [
            reserve_op(0.49, day(2026, 3, 1)), reserve_op(2.01, day(2026, 3, 1)), reserve_op(math.nan, day(2026, 3, 1)),
            reserve_op(math.inf, day(2026, 3, 1)), reserve_op(0.5000001, day(2026, 3, 1)),
            reserve_op(0.0, day(2026, 3, 1)), reserve_op(-1.0, day(2026, 3, 1)), {"op": "exists"},
        ],
    },
    {
        "name": "corrupt_ledger_fails_closed_and_recovers_when_removed",
        "daily": 1.0,
        "ops": [
            {"op": "write_bytes", "hex": b"not a sqlite database".hex()},
            reserve_op(1.0, day(2026, 3, 1)),
            reserve_op(1.0, day(2026, 3, 1)),
            {"op": "remove_file"},
            reserve_op(1.0, day(2026, 3, 1)),
            reserve_op(1.0, day(2026, 3, 1)),
        ],
    },
    {
        "name": "unavailable_parent_fails_closed_and_recovers",
        "daily": 1.0,
        "ops": [
            reserve_op(0.5, day(2026, 3, 1)),
            {"op": "block_parent"},
            reserve_op(0.5, day(2026, 3, 1)),
            reserve_op(0.5, day(2026, 3, 1)),
            {"op": "unblock_parent"},
            reserve_op(0.5, day(2026, 3, 1)),
            reserve_op(0.5, day(2026, 3, 1)),
        ],
    },
    {
        "name": "invalid_ledger_contents_fail_closed",
        "daily": 4.0,
        "ops": [
            reserve_op(1.0, day(2026, 3, 1)),
            {"op": "sql", "statements": ["UPDATE daily_budget SET epsilon_spent = -1.0"]},
            reserve_op(1.0, day(2026, 3, 1)),
            {"op": "sql", "statements": ["UPDATE daily_budget SET epsilon_spent = 5.0"]},
            reserve_op(1.0, day(2026, 3, 1)),
            {"op": "sql", "statements": ["UPDATE daily_budget SET epsilon_spent = 4.0"]},
            reserve_op(1.0, day(2026, 3, 1)),
            {"op": "sql", "statements": ["UPDATE daily_budget SET epsilon_spent = 3.0, utc_day = '2026-3-1'"]},
            reserve_op(1.0, day(2026, 3, 1)),
            {"op": "sql", "statements": ["UPDATE daily_budget SET utc_day = '20260301'"]},
            reserve_op(1.0, day(2026, 3, 1)),
            {"op": "sql", "statements": ["UPDATE daily_budget SET utc_day = '0000-01-01'"]},
            reserve_op(1.0, day(2026, 3, 1)),
            {"op": "sql", "statements": ["UPDATE daily_budget SET utc_day = '2026-02-30'"]},
            reserve_op(1.0, day(2026, 3, 1)),
            {"op": "sql", "statements": ["UPDATE daily_budget SET utc_day = ''"]},
            reserve_op(1.0, day(2026, 3, 1)),
            {"op": "sql", "statements": ["UPDATE daily_budget SET utc_day = '2026-02-28', epsilon_spent = 4.0"]},
            reserve_op(1.0, day(2026, 3, 1)),
            reserve_op(4.0, day(2026, 3, 1)),
        ],
    },
    {
        "name": "ledger_without_a_row_is_initialised_and_foreign_table_is_left_alone",
        "daily": 2.0,
        "ops": [
            {"op": "sql", "statements": [
                "CREATE TABLE daily_budget (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), "
                "utc_day TEXT NOT NULL, epsilon_spent REAL NOT NULL)",
                "CREATE TABLE other (x INTEGER)", "INSERT INTO other VALUES (7)",
            ]},
            reserve_op(1.0, day(2026, 3, 1)),
            reserve_op(1.0, day(2026, 3, 1)),
            reserve_op(1.0, day(2026, 3, 1)),
        ],
    },
    {
        "name": "integer_valued_spent_is_read_as_a_float",
        "daily": 3.0,
        "ops": [
            reserve_op(1.0, day(2026, 3, 1)),
            {"op": "sql", "statements": ["UPDATE daily_budget SET epsilon_spent = 2"]},
            reserve_op(1.0, day(2026, 3, 1)),
            reserve_op(0.5, day(2026, 3, 1)),
        ],
    },
]


def run_ledger_scenario(privacy, scenario) -> dict:
    results = []
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        path = root / "state" / "ledger.sqlite3"
        budget = privacy.DailyPrivacyBudget(path, scenario["daily"])
        blocked = False
        for op in scenario["ops"]:
            kind = op["op"]
            if kind == "reserve":
                epsilon = struct.unpack(">d", bytes.fromhex(op["epsilon"]["bits"]))[0]
                now = when(op["now"])
                try:
                    results.append({"result": bool(budget.reserve(epsilon, now=now))})
                except (ValueError, RuntimeError) as exc:
                    results.append({"error": {"class": type(exc).__name__, "message": str(exc)}})
            elif kind == "new":
                budget = privacy.DailyPrivacyBudget(path, scenario["daily"])
                results.append({"ok": True})
            elif kind == "exists":
                results.append({"exists": path.exists()})
            elif kind == "write_bytes":
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(bytes.fromhex(op["hex"]))
                results.append({"ok": True})
            elif kind == "remove_file":
                path.unlink()
                results.append({"ok": True})
            elif kind == "sql":
                path.parent.mkdir(parents=True, exist_ok=True)
                connection = sqlite3.connect(path)
                try:
                    for statement in op["statements"]:
                        connection.execute(statement)
                    connection.commit()
                finally:
                    connection.close()
                results.append({"ok": True})
            elif kind == "block_parent":
                # Move the directory away and put a file where it was.
                path.parent.rename(root / "state-moved")
                (root / "state").write_text("x", encoding="utf-8")
                blocked = True
                results.append({"ok": True})
            elif kind == "unblock_parent":
                (root / "state").unlink()
                (root / "state-moved").rename(root / "state")
                blocked = False
                results.append({"ok": True})
            else:
                raise AssertionError(kind)
        rows = None if blocked else ledger_rows(path)
        schema = schema_sql(path) if path.exists() and rows not in (None, "unreadable") else None
    return {
        "name": scenario["name"], "daily": fhex_repr(scenario["daily"]), "ops": scenario["ops"],
        "results": results, "rows": rows, "schema": schema,
    }


def concurrent_ledger(privacy) -> dict:
    fixed = datetime(2026, 4, 2, 12, tzinfo=timezone.utc)
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "ledger.sqlite3"
        outcomes = []
        lock = threading.Lock()

        def reserve(_):
            outcome = privacy.DailyPrivacyBudget(path, 8.0).reserve(1.0, now=fixed)
            with lock:
                outcomes.append(outcome)

        threads = [threading.Thread(target=reserve, args=(index,)) for index in range(24)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len(outcomes) == 24, "a reservation thread failed"
        return {"threads": 24, "daily": 8.0, "epsilon": 1.0, "accepted": sum(outcomes),
                "next_denied": not privacy.DailyPrivacyBudget(path, 8.0).reserve(1.0, now=fixed)}


def ledger_fixture_file(privacy, target: Path) -> dict:
    """A ledger written by the Python implementation: day 2026-01-01 with 3.0 spent."""
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target.unlink()
    budget = privacy.DailyPrivacyBudget(target, 8.0)
    now = datetime(2026, 1, 1, 10, tzinfo=timezone.utc)
    for _ in range(3):
        assert budget.reserve(1.0, now=now)
    return {"day": "2026-01-01", "spent": fhex_repr(3.0), "daily": fhex_repr(8.0),
            "sha256": hashlib.sha256(target.read_bytes()).hexdigest()}


# --- events -------------------------------------------------------------------------------------------------------


def analysis_of(case):
    result = case["result"]
    if result is None:
        return SimpleNamespace(action=SimpleNamespace(name=case["action"]), result=None)
    classification = result["classification"]
    if classification is not None:
        classification = SimpleNamespace(
            sensitivity=lambda sensitivity=classification["sensitivity"]: SimpleNamespace(name=sensitivity),
            categories=lambda names=tuple(classification["categories"]): [SimpleNamespace(name=n) for n in names],
        )
    metadata = {} if result["model_version"] is None else {"model_version": result["model_version"]}
    return SimpleNamespace(action=SimpleNamespace(name=case["action"]),
                           result=SimpleNamespace(classification=classification, metadata=metadata))


def fixed_clock(event_emitter, hour: int, minute: int = 17):
    class Fixed(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 3, 5, hour, minute, 41, tzinfo=tz)

    return mock.patch.object(event_emitter, "datetime", Fixed)


ACTIONS = ("ALLOW", "WARN", "BLOCK", "UNKNOWN", "")
SENSITIVITIES = (None, "S0", "S1", "S2", "S3", "S9")
CATEGORY_SETS = (
    [], ["CHILD"], ["HEALTH", "CHILD"], ["THIRD_PARTY", "POLITICS"], ["RELIGION", "LOCATION", "IDENTITY"],
    ["PRIVATE_NEW_CATEGORY"], ["FINANCIAL", "PRIVATE_NEW_CATEGORY"], ["SEXUAL", "CRIMINAL", "HEALTH"],
    ["NONE"], ["CHILD", "CHILD"],
)
MODEL_VERSIONS = (None, "", "v0.3.0", "v0.3.0+train.17", "v0.3.0+train.", "+train.1", "v9.9.9+train.500000", "OTHER",
                  "v0.3.0+train.1+train.2", "V0.3.0", " v0.3.0")


def event_cases(event_emitter) -> list:
    det = Det("events")
    cases = []
    for index in range(160):
        action = ACTIONS[det.below(len(ACTIONS))]
        sensitivity = SENSITIVITIES[det.below(len(SENSITIVITIES))]
        if det.below(10) == 0:
            result = None
        else:
            classification = None if sensitivity is None else {
                "sensitivity": sensitivity, "categories": CATEGORY_SETS[det.below(len(CATEGORY_SETS))]}
            result = {"classification": classification, "model_version": MODEL_VERSIONS[det.below(len(MODEL_VERSIONS))]}
        cases.append({"action": action, "result": result, "hour": det.below(24)})
    # Every hour and every action for the plain case, so the time buckets are all covered.
    for hour in range(24):
        for action in ("ALLOW", "WARN", "BLOCK"):
            cases.append({"action": action, "result": {"classification": None, "model_version": "v0.3.0"}, "hour": hour})
    out = []
    for case in cases:
        observed = {}

        def identity(values, epsilon, observed=observed):
            observed["values"] = dict(values)
            observed["epsilon"] = epsilon
            return dict(values)

        with fixed_clock(event_emitter, case["hour"]), mock.patch.object(event_emitter, "randomize_report", identity):
            packet = event_emitter.StructuredEventEmitter().build_packet(analysis_of(case))
        out.append({**case, "true_values": observed["values"], "epsilon": fhex_repr(observed["epsilon"]),
                    "packet": packet_json(packet)})
    return out


def packet_json(packet) -> dict:
    return {
        "time_bucket": packet.time_bucket, "action": packet.action, "primary_category": packet.primary_category,
        "risk_bucket": packet.risk_bucket, "model_version": packet.model_version,
        "privacy_mechanism": packet.privacy_mechanism, "privacy_epsilon": fhex_repr(packet.privacy_epsilon),
    }


def packet_cases(event_emitter) -> list:
    det = Det("packets")
    out = []
    for index in range(40):
        epsilon = (0.5, 0.75, 1.0, 1.5, 2.0)[det.below(5)]
        case = {
            "action": ACTIONS[det.below(3)],
            "result": {
                "classification": {"sensitivity": SENSITIVITIES[1 + det.below(4)],
                                   "categories": CATEGORY_SETS[det.below(len(CATEGORY_SETS))]},
                "model_version": MODEL_VERSIONS[2 + det.below(3)],
            },
            "hour": det.below(24),
        }
        stream = Stream(det_bytes(f"packet-bytes/{index}", 512))
        with fixed_clock(event_emitter, case["hour"]), patched_stream(stream):
            packet = event_emitter.StructuredEventEmitter().build_packet(analysis_of(case), epsilon)
        out.append({**case, "epsilon": fhex_repr(epsilon), "bytes": stream.data[: stream.position].hex(),
                    "packet": packet_json(packet)})
    return out


# --- reporter -----------------------------------------------------------------------------------------------------


class Capture(logging.Handler):
    def __init__(self):
        super().__init__(logging.INFO)
        self.records: list[tuple[str, str, str]] = []

    def emit(self, record):
        self.records.append((record.levelname, record.getMessage(), threading.current_thread().name))


class Channel:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def analysis_for(action: str):
    return analysis_of({"action": action, "result": {"classification": None, "model_version": "v0.3.0"}})


def run_reporter(event_emitter, privacy, *, name, event_epsilon, daily_epsilon, actions, script, queue_size=1024,
                 block_first=False, blocked_ledger=None, unblock_after=None, failing_entropy=False, stream_bytes=4096):
    """Run one scenario. ``script`` lists the delivery outcome of each packet in order (ok, rejected, rpc, error)."""
    capture = Capture()
    root_logger = logging.getLogger()
    root_logger.addHandler(capture)
    previous_level = root_logger.level
    root_logger.setLevel(logging.INFO)
    sent: list = []
    release = threading.Event()
    entered = threading.Event()
    script_queue = list(script)

    class Stub:
        def RecordTelemetry(self, packet, timeout):
            sent.append(packet)
            entered.set()
            if block_first and len(sent) == 1:
                release.wait(10)
            outcome = script_queue.pop(0) if script_queue else "ok"
            if outcome == "ok":
                return SimpleNamespace(accepted=True)
            if outcome == "rejected":
                return SimpleNamespace(accepted=False)
            if outcome == "rpc":
                raise RpcError(StatusCode.UNAVAILABLE)
            if outcome == "rpc_deadline":
                raise RpcError(StatusCode.DEADLINE_EXCEEDED)
            raise RuntimeError("boom")

    stream = Stream(det_bytes(f"reporter/{name}", stream_bytes),
                    failure=OSError("entropy unavailable") if failing_entropy else None)
    per_report: list = []
    caller = threading.current_thread().name
    spent_after = None
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        path = root / "state" / "ledger.sqlite3"
        if blocked_ledger:
            (root / "state").write_text("x", encoding="utf-8")
        with mock.patch.object(event_emitter, "grpc_channel", return_value=Channel()), \
                mock.patch.object(event_emitter.telemetry_pb2_grpc, "TelemetryServiceStub", return_value=Stub()), \
                fixed_clock(event_emitter, 13), patched_stream(stream):
            reporter = event_emitter.TelemetryReporter(
                target="unused:50055", event_epsilon=event_epsilon, daily_epsilon=daily_epsilon,
                ledger_path=str(path), queue_size=queue_size)
            try:
                for index, action in enumerate(actions):
                    if unblock_after is not None and index == unblock_after:
                        (root / "state").unlink()
                    if block_first and index == 1:
                        assert entered.wait(10), "the worker never took the first packet"
                    before = len(capture.records)
                    reporter.report(analysis_for(action))
                    # The worker logs delivery outcomes concurrently; only this thread's lines belong to the call.
                    new = [message for _, message, thread in capture.records[before:] if thread == caller]
                    per_report.append(new[0] if new else None)
                release.set()
                reporter._queue.join()
            finally:
                reporter.close(timeout_seconds=10.0)
        if path.exists():
            rows = ledger_rows(path)
            spent_after = rows[0][1] if rows and rows != "unreadable" else None
    root_logger.removeHandler(capture)
    root_logger.setLevel(previous_level)
    delivery = [message for _, message, thread in capture.records if thread == "privoke-telemetry-reporter"]
    return {
        "name": name,
        "event_epsilon": fhex_repr(event_epsilon),
        "daily_epsilon": fhex_repr(daily_epsilon),
        "queue_size": queue_size,
        "actions": list(actions),
        "script": list(script),
        "block_first": block_first,
        "blocked_ledger": bool(blocked_ledger),
        "unblock_after": unblock_after,
        "failing_entropy": failing_entropy,
        "stream": stream.data[: stream.position].hex(),
        "per_report_log": per_report,
        "delivery_log": delivery,
        "sent": [packet_json(packet) for packet in sent],
        "spent_after": spent_after,
    }


def reporter_section(event_emitter, privacy) -> list:
    actions = ("ALLOW", "WARN", "BLOCK", "ALLOW", "BLOCK", "WARN")
    return [
        run_reporter(event_emitter, privacy, name="budget_cap_and_fifo_order", event_epsilon=0.5, daily_epsilon=2.0,
                     actions=actions, script=[]),
        run_reporter(event_emitter, privacy, name="delivery_failures_do_not_refund", event_epsilon=1.0,
                     daily_epsilon=8.0, actions=("ALLOW", "WARN", "BLOCK", "ALLOW", "WARN", "BLOCK", "ALLOW"),
                     script=["rpc", "error", "rejected", "rpc_deadline", "ok", "ok", "ok"]),
        run_reporter(event_emitter, privacy, name="queue_overflow_is_not_refunded", event_epsilon=1.0,
                     daily_epsilon=8.0, actions=("ALLOW", "WARN", "BLOCK", "ALLOW"), script=[], queue_size=1,
                     block_first=True),
        run_reporter(event_emitter, privacy, name="ledger_outage_suppresses_then_recovers", event_epsilon=1.0,
                     daily_epsilon=8.0, actions=("ALLOW", "WARN", "BLOCK", "ALLOW"), script=[], blocked_ledger=True,
                     unblock_after=2),
        run_reporter(event_emitter, privacy, name="failed_build_is_not_refunded", event_epsilon=0.5,
                     daily_epsilon=0.5, actions=("ALLOW", "WARN"), script=[], failing_entropy=True),
    ]


# --- driver -------------------------------------------------------------------------------------------------------


def sha256_lf(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def build(ledger_out: Path | None) -> dict:
    event_emitter, privacy = load_client()
    document = {
        "schema": 1,
        "oracle": {
            "python": sys.version.split()[0],
            "privacy_py_sha256_lf": sha256_lf(TELEMETRY / "privacy.py"),
            "event_emitter_py_sha256_lf": sha256_lf(TELEMETRY / "event_emitter.py"),
            "random_source": "random.SystemRandom reading random._urandom, replaced by a recorded byte stream",
            "sqlite": sqlite3.sqlite_version,
        },
        "constants": {
            "mechanism": privacy.MECHANISM,
            "dimensions": list(privacy.DIMENSIONS),
            "domains": {name: list(values) for name, values in privacy.DOMAINS.items()},
        },
        "kernel": kernel_section(privacy),
        "grr": grr_section(privacy),
        "reports": report_section(privacy),
        "config": config_section(privacy),
        "ledger": {
            "scenarios": [run_ledger_scenario(privacy, scenario) for scenario in LEDGER_SCENARIOS],
            "concurrent": concurrent_ledger(privacy),
        },
        "events": {"true_values": event_cases(event_emitter), "packets": packet_cases(event_emitter)},
        "reporter": reporter_section(event_emitter, privacy),
    }
    if ledger_out is not None:
        document["ledger"]["python_written"] = ledger_fixture_file(privacy, ledger_out)
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--ledger-out", type=Path, default=None, help="where to write the Python-written ledger file")
    arguments = parser.parse_args(argv)
    document = build(arguments.ledger_out)
    arguments.out.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(document, indent=1, sort_keys=True, ensure_ascii=True) + "\n"
    arguments.out.write_bytes(text.encode("utf-8"))
    print(f"wrote {arguments.out} ({len(text)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
