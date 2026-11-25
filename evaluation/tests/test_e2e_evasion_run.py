"""Orchestration test for ``e2e_evasion.py run`` with every external piece faked: no browser, no runtime, no ports.

Checks that the run holds the host lock, refuses an empty layer list before starting anything,
records browsers that did not run with a reason, aborts on a layer mismatch, writes ids-only rows,
and stops everything it started. Real browsers are exercised only by Stage 13b-2.
"""

import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "evaluation")]

import e2e_evasion as e2e  # noqa: E402
from test_e2e_evasion import FakeDriver, FakeReceiver, FakeTap, item  # noqa: E402


class FakeProcess:
    pid = 4242

    def poll(self):
        return None


class World:
    """Shared state the faked classes use to find each other."""

    def __init__(self, plan, lock_path):
        self.plan, self.lock_path = plan, lock_path
        self.tap = self.receiver = self.supervisor = self.driver = None
        self.lock_seen_during_sends = []
        self.started = []
        self.stopped = []
        self.launches = 0


def install(world):
    class BaseSupervisor:
        def __init__(self, python, log_path):
            self.python, self.log_path, self.process = python, Path(log_path), None
            world.supervisor = self

        def stop(self, wait=True):
            world.stopped.append("supervisor")
            self.process = None

    class HeldPort:
        def __init__(self, port):
            world.started.append(f"decoy:{port}")

        def close(self):
            world.stopped.append("decoy")

    xp = types.ModuleType("cross_platform_study")
    xp.BROWSERS = {
        "chrome": {"label": "Google Chrome", "family": "chromium", "dist": "dist", "exe": [sys.executable]},
        "edge": {"label": "Microsoft Edge", "family": "chromium", "dist": "dist", "exe": [str(Path(tempfile.gettempdir()) / "no-such-edge.exe")]},
        "firefox": {"label": "Mozilla Firefox", "family": "firefox", "dist": "dist-firefox", "exe": [sys.executable]},
    }
    xp.Supervisor, xp.HeldPort = BaseSupervisor, HeldPort
    xp.wait_for = lambda predicate, timeout, interval=0.5: True
    xp.file_version = lambda exe: "1.0"
    xp.tree_hash = lambda directory: {"manifest.json": "x"}
    xp.listener_pid = lambda port: None
    xp.outbound_connections = lambda pids: []
    xp.git = lambda *args: "abc123" if args[0] == "rev-parse" else ""
    xp.SUPERVISOR_MAIN = Path("unused/supervisor/main.py")

    class Receiver(FakeReceiver):
        def __init__(self, cert, key, port):
            super().__init__()
            self.captures, self.foreign_hosts = [], []
            world.receiver = self

        def start(self):
            world.started.append("receiver")

        def stop(self):
            world.stopped.append("receiver")

        def unattributed(self):
            return []

    receiver_module = types.ModuleType("cross_platform_receiver")
    receiver_module.Receiver = Receiver
    receiver_module.generate_certificate = lambda directory, openssl="openssl": (Path("c.pem"), Path("k.pem"), "spki")

    class Tap(FakeTap):
        def __init__(self, upstream, listen, log_path=None):
            super().__init__()
            world.tap = self

        def start(self):
            world.started.append("tap")

        def stop(self):
            world.stopped.append("tap")

    class Driver:
        def __init__(self, node):
            world.driver = self
            self.inner = FakeDriver(world.tap, world.receiver, world.plan)

        def request(self, op, timeout=None, **fields):
            if op == "launch":
                world.launches += 1
                return {"ok": True, "product": "Fake/1"}
            if op == "send":
                world.lock_seen_during_sends.append(world.lock_path.exists())
                return self.inner.request(op, timeout, **fields)
            if op == "foreign":
                return {"measured": True, "requests": []}
            return {"ok": True}

        def close(self):
            world.stopped.append("driver")

    def fake_start(supervisor, xp_module, env):
        supervisor.process = FakeProcess()
        world.started.append("supervisor")

    return xp, receiver_module, Tap, Driver, fake_start


class RunOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.local = self.tmp / "local"
        self.out = self.local / "s13b" / "run"
        self.fake_root = self.tmp / "repo"
        (self.fake_root / "extension" / "dist").mkdir(parents=True)
        (self.fake_root / "extension" / "dist" / "manifest.json").write_text("{}", encoding="utf-8")
        self.lock_path = self.local / "s13-host.lock"
        items = []
        for seed in ("a", "b"):
            items += [item(seed, "baseline", f"base {seed}"), item(seed, "v1", f"variant one {seed}"),
                      item(seed, "v2", f"variant two {seed}", applicable=False)]
        self.items = items
        self.run_set = self.tmp / "run_set.jsonl"
        self.run_set.write_text("\n".join(json.dumps(i) for i in items) + "\n", encoding="utf-8")
        self.args = SimpleNamespace(run_set=str(self.run_set), out=str(self.out), runtime_python=sys.executable,
                                    browsers="chrome,edge,firefox", layers="regex,ner,semantic", pilot=False, stage="13b-2",
                                    runtime_env=[], receiver_port=443, openssl="openssl", workdir=str(self.tmp / "work"),
                                    max_consecutive_errors=10)

    def do_run(self, plan=None, args=None, preflight_seconds=None):
        world = World(plan or (lambda text: {}), self.lock_path)
        xp, receiver_module, tap, driver, fake_start = install(world)
        original = e2e.preflight
        patches = [
            mock.patch.dict(os.environ, {"S13_LOCAL_INPUTS_ROOT": str(self.local)}),
            mock.patch.dict(sys.modules, {"cross_platform_study": xp, "cross_platform_receiver": receiver_module}),
            mock.patch.object(e2e, "BridgeTap", tap), mock.patch.object(e2e, "E2EDriver", driver),
            mock.patch.object(e2e, "start_supervisor", fake_start), mock.patch.object(e2e, "_port_open", return_value=False),
            mock.patch.object(e2e, "ROOT", self.fake_root),
            mock.patch.object(e2e.subprocess, "run", return_value=SimpleNamespace(stdout="v0")),
            mock.patch.object(e2e.time, "sleep", lambda s: None),
        ]
        if preflight_seconds is not None:
            patches.append(mock.patch.object(e2e, "preflight", lambda d, t, e: original(d, t, e, seconds=preflight_seconds, pause=0)))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        error = None
        try:
            code = e2e.execute_run(args or self.args)
        except Exception as exc:  # noqa: BLE001 - the tests assert on the type
            code, error = None, exc
        return world, code, error

    def meta(self, name="run_meta.json"):
        return json.loads((self.out / name).read_text(encoding="utf-8"))

    def test_a_clean_run_records_every_browser_and_stops_everything_it_started(self):
        world, code, error = self.do_run()
        self.assertIsNone(error)
        self.assertEqual(code, 0)
        meta = self.meta()
        statuses = {b["key"]: b for b in meta["browsers"]}
        self.assertEqual(statuses["chrome"]["status"], "run")
        self.assertEqual(statuses["chrome"]["rows_written"], 4)
        self.assertEqual(statuses["edge"]["status"], "not_run")
        self.assertIn("not installed", statuses["edge"]["reason"])
        self.assertEqual(statuses["firefox"]["status"], "not_run")
        self.assertIn("extension build missing", statuses["firefox"]["reason"])
        self.assertTrue(all(b["headless"] and not b["attended"] for b in meta["browsers"]))
        self.assertEqual(meta["layers"], ["regex", "ner", "semantic"])
        self.assertEqual(meta["host_guard"]["outside_lookups"], 0)
        self.assertEqual(meta["leftover_ports_after_cleanup"], [])
        self.assertEqual(meta["scope_label"], e2e.SCOPE_LABEL)
        self.assertEqual(meta["template_sha256"], e2e.lf_sha256(e2e.e2etx.template_file()))
        rows = e2e.read_jsonl(self.out / "rows_chrome.jsonl")
        self.assertEqual([(r["seed_id"], r["variant"]) for r in rows],
                         [("a", "baseline"), ("a", "v1"), ("b", "baseline"), ("b", "v1")])
        self.assertTrue(all(r["scope_label"] == e2e.SCOPE_LABEL and not r["attended"] for r in rows))
        for row in rows:
            for forbidden in ("text", "prompt", "body", "notes"):
                self.assertNotIn(forbidden, row)
        self.assertFalse(self.lock_path.exists(), "the host lock is released")
        self.assertTrue(world.lock_seen_during_sends and all(world.lock_seen_during_sends), "the lock is held while sending")
        for started in ("receiver", "tap", "supervisor"):
            self.assertIn(started, world.started)
        for stopped in ("receiver", "tap", "supervisor", "decoy", "driver"):
            self.assertIn(stopped, world.stopped)

    def test_an_empty_layer_list_is_refused_before_anything_starts(self):
        args = SimpleNamespace(**dict(vars(self.args), layers=""))
        world, code, error = self.do_run(args=args)
        self.assertIsInstance(error, e2e.LayerConfigError)
        self.assertEqual(world.started, [])
        self.assertFalse(self.lock_path.exists())

    def test_a_held_host_lock_refuses_the_run_without_starting_services(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path.write_text('{"stage": "13e", "pid": 1}', encoding="utf-8")
        world, code, error = self.do_run()
        self.assertIsInstance(error, e2e.HostLockHeld)
        self.assertEqual(world.started, [])
        self.assertTrue(self.lock_path.exists(), "a lock this run does not own is left alone")

    def test_a_dropped_semantic_layer_stops_the_run_at_the_preflight(self):
        world, code, error = self.do_run(plan=lambda text: {"requested": (2, 3)}, preflight_seconds=0.0)
        self.assertIsInstance(error, e2e.RunAborted)
        self.assertIn("LayerMismatchError", str(error))
        meta = self.meta()
        self.assertIn("LayerMismatchError", meta["aborted"])
        self.assertEqual(next(b for b in meta["browsers"] if b["key"] == "chrome")["status"], "aborted")
        self.assertFalse((self.out / "rows_chrome.jsonl").exists())
        self.assertFalse(self.lock_path.exists())
        for stopped in ("receiver", "tap", "supervisor", "decoy", "driver"):
            self.assertIn(stopped, world.stopped)

    def test_a_mismatch_in_the_middle_of_the_run_keeps_earlier_rows_and_aborts(self):
        world, code, error = self.do_run(plan=lambda text: {"requested": (2, 3)} if "variant one a" in text else {})
        self.assertIsInstance(error, e2e.RunAborted)
        rows = e2e.read_jsonl(self.out / "rows_chrome.jsonl")
        self.assertEqual([(r["seed_id"], r["variant"]) for r in rows], [("a", "baseline")])
        self.assertIn("LayerMismatchError", self.meta()["aborted"])
        self.assertFalse(self.lock_path.exists())
        self.assertIn("driver", world.stopped)

    def test_the_pilot_sends_only_its_first_items_and_writes_pilot_meta(self):
        args = SimpleNamespace(**dict(vars(self.args), pilot=True, out=str(self.local / "s13b" / "pilot")))
        world, code, error = self.do_run(args=args)
        self.assertIsNone(error)
        self.assertTrue((self.local / "s13b" / "pilot" / "pilot_meta.json").is_file())
        self.assertEqual(len(e2e.read_jsonl(self.local / "s13b" / "pilot" / "rows_chrome.jsonl")), 4)

    def test_output_outside_the_ignored_directory_is_refused(self):
        args = SimpleNamespace(**dict(vars(self.args), out=str(self.tmp / "elsewhere")))
        world, code, error = self.do_run(args=args)
        self.assertIsInstance(error, e2e.HarnessError)
        self.assertEqual(world.started, [])


if __name__ == "__main__":
    unittest.main()
