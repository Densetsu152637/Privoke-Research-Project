#!/usr/bin/env python3
"""Focused tests for race-safe process identity sampling."""

import importlib.util
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import traceback
import unittest
from types import SimpleNamespace
from unittest.mock import patch


SOURCE = Path(__file__).with_name("installed-browser-resources.py")
SPEC = importlib.util.spec_from_file_location("installed_browser_resources", SOURCE)
assert SPEC and SPEC.loader
try:
    import psutil  # noqa: F401
except ImportError:
    # Identity parsing itself is stdlib-only; the sampler's process walk needs psutil.
    stub = types.ModuleType("psutil")
    stub.pid_exists = lambda _pid: False
    stub.process_iter = lambda *_args, **_kwargs: []
    stub.Process = lambda _pid: None
    class Error(Exception):
        pass

    class NoSuchProcess(Error):
        pass

    stub.Error = Error
    stub.NoSuchProcess = NoSuchProcess
    sys.modules["psutil"] = stub
RESOURCES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RESOURCES)


def stat_line(start_ticks: int) -> str:
    # Fields following the final ')' begin with stat field 3; starttime is field 22.
    fields = ["S"] + ["0"] * 18 + [str(start_ticks)]
    return f"123 (browser (renderer)) {' '.join(fields)}"


class StartTicksTests(unittest.TestCase):
    def test_reads_start_ticks_after_process_name_with_parentheses(self):
        self.assertEqual(
            RESOURCES._start_ticks(123, read_stat=lambda _pid: stat_line(9876), pid_exists=lambda _pid: True),
            9876,
        )

    def test_absent_proc_entry_is_reported_as_a_vanished_process(self):
        def missing(_pid):
            raise FileNotFoundError("/proc/123/stat")

        self.assertIsNone(RESOURCES._start_ticks(123, read_stat=missing, pid_exists=lambda _pid: False))

    def test_live_but_unreadable_process_identity_fails_closed(self):
        def missing(_pid):
            raise FileNotFoundError("/proc/123/stat")

        with self.assertRaisesRegex(RuntimeError, "PID remained live"):
            RESOURCES._start_ticks(123, read_stat=missing, pid_exists=lambda _pid: True)

    def test_malformed_process_stat_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "valid start-tick identity"):
            RESOURCES._start_ticks(123, read_stat=lambda _pid: "123 (broken) S", pid_exists=lambda _pid: True)

    def test_stat_rejects_mismatched_pid_and_negative_ticks(self):
        with self.assertRaisesRegex(RuntimeError, "valid start-tick identity"):
            RESOURCES._process_stat_identity(123, read_stat=lambda _pid: stat_line(9876).replace("123 ", "124 ", 1))
        negative = stat_line(-1)
        with self.assertRaisesRegex(RuntimeError, "valid start-tick identity"):
            RESOURCES._process_stat_identity(123, read_stat=lambda _pid: negative)
        with self.assertRaisesRegex(RuntimeError, "PID is invalid"):
            RESOURCES._process_stat_identity(0, read_stat=lambda _pid: stat_line(1))


class SamplerTerminalDiagnosticTests(unittest.TestCase):
    def test_private_sidecar_contains_only_safe_exception_identity_and_bounded_frames(self):
        try:
            raise RuntimeError("synthetic private exception text")
        except RuntimeError as error:
            payload = RESOURCES._terminal_diagnostic_payload("error", 7, error)
        encoded = json.dumps(payload, ensure_ascii=True)
        self.assertEqual(payload["exception_type"], "RuntimeError")
        self.assertEqual(payload["samples_written"], 7)
        self.assertNotIn("synthetic private exception text", encoded)
        self.assertLessEqual(len(payload["frames"]), 12)

        frame = traceback.FrameSummary("private\nsecret.py", 2, "bad\nfunction")
        self.assertEqual(RESOURCES._safe_terminal_frame(frame), {
            "file": "<unavailable>", "function": "<unavailable>", "line": 2,
        })

    def test_terminal_sidecar_is_exclusive_and_does_not_serialize_exception_message(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "terminal.json"
            try:
                raise RuntimeError("secret-sentinel-text")
            except RuntimeError as error:
                payload = RESOURCES._terminal_diagnostic_payload("error", 0, error)
            RESOURCES._write_terminal_diagnostic(path, payload)
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn("secret-sentinel-text", raw)
            self.assertEqual(json.loads(raw), payload)
            with self.assertRaises(FileExistsError):
                RESOURCES._write_terminal_diagnostic(path, payload)


class SamplerDiagnosticTests(unittest.TestCase):
    def test_error_sidecar_keeps_only_class_and_bounded_traceback_identity(self):
        secret = "synthetic prompt payload must never appear"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "samples.jsonl"
            diagnostic = Path(str(output) + ".terminal.json")
            argv = ["sampler", "--output", str(output), "--interval-ms", "100",
                    "--terminal-diagnostic", str(diagnostic),
                    "--source-revision", "a" * 40, "--protocol-sha256", "b" * 64]

            def fail(_output, _interval, progress, *_bindings):
                progress["samples_written"] = 7
                raise RuntimeError(secret)

            with patch.object(sys, "argv", argv), patch.object(RESOURCES, "sample", side_effect=fail):
                self.assertEqual(RESOURCES.main(), 1)
            raw = diagnostic.read_text(encoding="utf-8")
            payload = __import__("json").loads(raw)
            self.assertNotIn(secret, raw)
            self.assertEqual(payload["status"], "error")
            self.assertEqual(payload["samples_written"], 7)
            self.assertEqual(payload["exception_type"], "RuntimeError")
            self.assertLessEqual(len(payload["frames"]), 12)
            self.assertTrue(all(set(frame) == {"file", "function", "line"} for frame in payload["frames"]))
            self.assertTrue(all("/" not in frame["file"] and "\\" not in frame["file"] for frame in payload["frames"]))

    def test_stopped_sidecar_is_exclusive_and_records_count(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "samples.jsonl"
            diagnostic = Path(str(output) + ".terminal.json")
            argv = ["sampler", "--output", str(output), "--interval-ms", "100",
                    "--terminal-diagnostic", str(diagnostic),
                    "--source-revision", "a" * 40, "--protocol-sha256", "b" * 64]

            def stop(_output, _interval, progress, *_bindings):
                progress["samples_written"] = 4

            with patch.object(sys, "argv", argv), patch.object(RESOURCES, "sample", side_effect=stop):
                self.assertEqual(RESOURCES.main(), 0)
            payload = __import__("json").loads(diagnostic.read_text(encoding="utf-8"))
            self.assertEqual(payload, {
                "schema_version": 1, "status": "stopped", "samples_written": 4,
                "exception_type": None, "frames": [],
            })
            with self.assertRaises(FileExistsError):
                RESOURCES._write_terminal_diagnostic(diagnostic, payload)


class ProcessSamplingTests(unittest.TestCase):
    @staticmethod
    def processes(pid, *, root=False, chromium_child=False, fresh_create_time=1.0, parent_pids=None):
        command = ("chromium --user-data-dir=/tmp/profile-1" if root else
                   "chromium --type=renderer" if chromium_child else
                   "python /runtime/extension/client-runtime/src/grpc_main.py")
        old = SimpleNamespace(
            pid=pid,
            info={"pid": pid, "ppid": 1,
                  "cmdline": ["python", "/old/extension/client-runtime/src/grpc_main.py"]
                  if not root and not chromium_child else command.split(),
                  "create_time": 1.0,
                  "memory_info": SimpleNamespace(rss=999999),
                  "cpu_times": SimpleNamespace(user=99, system=99)},
            cmdline=lambda: command.split(),
        )
        fresh_command = command
        ppid_calls = iter(parent_pids or [1, 1])
        fresh = SimpleNamespace(
            pid=pid,
            create_time=lambda: fresh_create_time,
            is_running=lambda: True,
            cmdline=lambda: fresh_command.split(),
            ppid=lambda: next(ppid_calls),
            memory_info=lambda: SimpleNamespace(rss=1234),
            cpu_times=lambda: SimpleNamespace(user=0.3, system=0.2),
        )
        return old, fresh

    def test_rows_use_fresh_metrics_between_matching_stat_identities(self):
        old, fresh = self.processes(321)
        with patch.object(RESOURCES.psutil, "process_iter", return_value=[old]), \
             patch.object(RESOURCES.psutil, "Process", return_value=fresh), \
             patch.object(RESOURCES, "_browser_process_ids", return_value=(set(), set())), \
             patch.object(RESOURCES, "_process_stat_identity", side_effect=[
                 ("S", 75), ("S", 4), ("S", 75), ("S", 4),
             ]), \
             patch.object(RESOURCES, "_pss_bytes", return_value=None):
            rows, races = RESOURCES._processes()
        self.assertEqual(races, {})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["start_ticks"], 75)
        self.assertEqual(rows[0]["rss_bytes"], 1234)
        self.assertEqual(rows[0]["cpu_seconds"], 0.5)
        self.assertEqual(rows[0]["parent_start_ticks"], 4)
        self.assertEqual(rows[0]["command_sha256"], hashlib.sha256(
            b"python /runtime/extension/client-runtime/src/grpc_main.py").hexdigest())

    def test_browser_roots_use_exact_profile_argument_and_exclude_child_types(self):
        profile = Path("/tmp/profile-1")
        spaced_profile = Path("/tmp/browser profiles/profile 2")
        root_argv = ["/usr/bin/chromium", f"--user-data-dir={profile}"]
        child_argv = ["/usr/bin/chromium", "--type=renderer", f"--user-data-dir={profile}"]
        paired_argv = ["/usr/bin/chrome", "--user-data-dir", str(spaced_profile)]
        prefix_collision_argv = ["/usr/bin/chromium", "--user-data-dir=/tmp/profile-10"]
        with patch.object(RESOURCES, "_browser_profiles", return_value=[profile, spaced_profile]):
            self.assertTrue(RESOURCES._browser_match(root_argv))
            self.assertTrue(RESOURCES._browser_match(paired_argv))
            self.assertFalse(RESOURCES._browser_match(child_argv))
            self.assertFalse(RESOURCES._browser_match(prefix_collision_argv))

    def test_browser_process_ids_use_only_main_profile_process_as_root(self):
        profile = Path("/tmp/browser profiles/profile-1")
        root_argv = ["/usr/bin/chromium", "--user-data-dir", str(profile)]
        renderer_argv = ["/usr/bin/chromium", "--type=renderer", f"--user-data-dir={profile}"]
        utility_argv = ["/usr/bin/chromium", "--type=utility", f"--user-data-dir={profile}"]
        renderer = SimpleNamespace(pid=22, info={"pid": 22, "cmdline": renderer_argv},
                                   cmdline=lambda: renderer_argv, children=lambda recursive: [])
        utility = SimpleNamespace(pid=23, info={"pid": 23, "cmdline": utility_argv},
                                  cmdline=lambda: utility_argv, children=lambda recursive: [])
        root = SimpleNamespace(pid=21, info={"cmdline": root_argv}, cmdline=lambda: root_argv,
                               children=lambda recursive: [renderer, utility])
        with patch.object(RESOURCES, "_browser_profiles", return_value=[profile]):
            roots, included = RESOURCES._browser_process_ids([root, renderer, utility])
        self.assertEqual(roots, {21})
        self.assertEqual(included, {21, 22, 23})

    def test_discovery_does_not_swallow_unrelated_fixture_attribute_errors(self):
        process = SimpleNamespace(pid=21, cmdline=lambda: ["/usr/bin/chromium"])
        with self.assertRaises(AttributeError):
            RESOURCES._browser_process_ids([process])

    def test_cached_root_argv_survives_fresh_cmdline_disappearance_in_discovery(self):
        profile = Path("/tmp/browser profiles/profile-1")
        root_argv = ["/usr/bin/chromium", "--user-data-dir", str(profile)]

        def vanished_cmdline():
            raise RESOURCES.psutil.NoSuchProcess(21)

        root = SimpleNamespace(
            pid=21,
            info={"pid": 21, "ppid": 1, "cmdline": root_argv},
            cmdline=vanished_cmdline,
            children=lambda recursive: [],
        )
        with patch.object(RESOURCES, "_browser_profiles", return_value=[profile]):
            roots, included = RESOURCES._browser_process_ids([root])
        self.assertEqual(roots, {21})
        self.assertEqual(included, {21})

    def test_exiting_included_chromium_child_is_dropped_but_root_is_sampled(self):
        profile = Path("/tmp/browser profiles/profile-1")
        root_argv = ["/usr/bin/chromium", "--user-data-dir", str(profile)]
        child_argv = ["/usr/bin/chromium", "--type=renderer", f"--user-data-dir={profile}"]

        def old_process(pid, argv, children=()):
            return SimpleNamespace(
                pid=pid,
                info={"pid": pid, "ppid": 100 + pid, "cmdline": argv,
                      "create_time": float(pid), "memory_info": SimpleNamespace(rss=999999),
                      "cpu_times": SimpleNamespace(user=99, system=99)},
                cmdline=lambda: argv,
                children=lambda recursive: list(children),
            )

        root = old_process(21, root_argv)
        child = old_process(22, child_argv)
        fresh_root = SimpleNamespace(
            create_time=lambda: 21.0, is_running=lambda: True, cmdline=lambda: root_argv,
            ppid=lambda: 1, memory_info=lambda: SimpleNamespace(rss=1234),
            cpu_times=lambda: SimpleNamespace(user=0.3, system=0.2),
        )
        root.children = lambda recursive: [child]
        with patch.object(RESOURCES, "_browser_profiles", return_value=[profile]), \
             patch.object(RESOURCES.psutil, "process_iter", return_value=[root, child]), \
             patch.object(RESOURCES.psutil, "Process", return_value=fresh_root), \
             patch.object(RESOURCES, "_process_stat_identity", side_effect=[
                 ("S", 210), ("S", 101), ("S", 210), ("S", 101), None,
             ]), \
             patch.object(RESOURCES, "_pss_bytes", return_value=None):
            rows, races = RESOURCES._processes()
        self.assertEqual([row["pid"] for row in rows], [21])
        self.assertEqual(races, {"chromium": 1})

    def test_exiting_exact_profile_root_remains_fatal(self):
        profile = Path("/tmp/profile-1")
        root_argv = ["/usr/bin/chromium", f"--user-data-dir={profile}"]
        old_root = SimpleNamespace(
            pid=21,
            info={"pid": 21, "ppid": 1, "cmdline": root_argv, "create_time": 21.0},
            cmdline=lambda: root_argv,
            children=lambda recursive: [],
        )
        with patch.object(RESOURCES, "_browser_profiles", return_value=[profile]), \
             patch.object(RESOURCES.psutil, "process_iter", return_value=[old_root]), \
             patch.object(RESOURCES, "_process_stat_identity", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "PID exited before stat snapshot"):
                RESOURCES._processes()

    def test_fresh_root_cmdline_disappearance_remains_fatal_from_cached_identity(self):
        profile = Path("/tmp/profile-1")
        root_argv = ["/usr/bin/chromium", f"--user-data-dir={profile}"]
        old_root = SimpleNamespace(
            pid=21,
            info={"pid": 21, "ppid": 1, "cmdline": root_argv, "create_time": 21.0},
            cmdline=lambda: root_argv,
            children=lambda recursive: [],
        )

        def vanished_cmdline():
            raise RESOURCES.psutil.NoSuchProcess(21)

        fresh_root = SimpleNamespace(
            create_time=lambda: 21.0, is_running=lambda: True, cmdline=vanished_cmdline,
        )
        with patch.object(RESOURCES, "_browser_profiles", return_value=[profile]), \
             patch.object(RESOURCES.psutil, "process_iter", return_value=[old_root]), \
             patch.object(RESOURCES.psutil, "Process", return_value=fresh_root), \
             patch.object(RESOURCES, "_process_stat_identity", return_value=("S", 210)):
            with self.assertRaisesRegex(RuntimeError, "process vanished during fresh reads"):
                RESOURCES._processes()

    def test_fresh_root_cmdline_access_denial_is_not_dropped(self):
        profile = Path("/tmp/profile-1")
        root_argv = ["/usr/bin/chromium", f"--user-data-dir={profile}"]
        old_root = SimpleNamespace(
            pid=21,
            info={"pid": 21, "ppid": 1, "cmdline": root_argv, "create_time": 21.0},
            cmdline=lambda: root_argv,
            children=lambda recursive: [],
        )

        def denied_cmdline():
            raise PermissionError("synthetic unreadable process command")

        fresh_root = SimpleNamespace(
            create_time=lambda: 21.0, is_running=lambda: True, cmdline=denied_cmdline,
        )
        with patch.object(RESOURCES, "_browser_profiles", return_value=[profile]), \
             patch.object(RESOURCES.psutil, "process_iter", return_value=[old_root]), \
             patch.object(RESOURCES.psutil, "Process", return_value=fresh_root), \
             patch.object(RESOURCES, "_process_stat_identity", return_value=("S", 210)):
            with self.assertRaisesRegex(PermissionError, "synthetic unreadable process command"):
                RESOURCES._processes()

    def test_metrics_are_discarded_if_identity_changes_during_sampling(self):
        old, fresh = self.processes(654)
        with patch.object(RESOURCES.psutil, "process_iter", return_value=[old]), \
             patch.object(RESOURCES.psutil, "Process", return_value=fresh), \
             patch.object(RESOURCES, "_browser_process_ids", return_value=(set(), set())), \
             patch.object(RESOURCES, "_process_stat_identity", side_effect=[
                 ("S", 75), ("S", 4), ("R", 76),
             ]):
            with self.assertRaisesRegex(RuntimeError, "exited or changed start ticks"):
                RESOURCES._processes()

    def test_parent_identity_is_null_when_child_reparents_during_metric_read(self):
        old, fresh = self.processes(654, parent_pids=[11, 12])
        with patch.object(RESOURCES.psutil, "process_iter", return_value=[old]), \
             patch.object(RESOURCES.psutil, "Process", return_value=fresh), \
             patch.object(RESOURCES, "_browser_process_ids", return_value=(set(), set())), \
             patch.object(RESOURCES, "_process_stat_identity", side_effect=[
                 ("S", 75), ("S", 4), ("S", 75), ("S", 6),
             ]), \
             patch.object(RESOURCES, "_pss_bytes", return_value=None):
            rows, _ = RESOURCES._processes()
        self.assertEqual(rows[0]["ppid"], 11)
        self.assertIsNone(rows[0]["parent_start_ticks"])

    def test_parent_identity_is_null_when_parent_pid_is_reused(self):
        old, fresh = self.processes(654, parent_pids=[11, 11])
        with patch.object(RESOURCES.psutil, "process_iter", return_value=[old]), \
             patch.object(RESOURCES.psutil, "Process", return_value=fresh), \
             patch.object(RESOURCES, "_browser_process_ids", return_value=(set(), set())), \
             patch.object(RESOURCES, "_process_stat_identity", side_effect=[
                 ("S", 75), ("S", 4), ("S", 75), ("S", 5),
             ]), \
             patch.object(RESOURCES, "_pss_bytes", return_value=None):
            rows, _ = RESOURCES._processes()
        self.assertEqual(rows[0]["ppid"], 11)
        self.assertIsNone(rows[0]["parent_start_ticks"])

    def test_pid_reuse_during_enumeration_drops_only_a_confirmed_child(self):
        old, fresh = self.processes(321, chromium_child=True, fresh_create_time=2.0)
        with patch.object(RESOURCES.psutil, "process_iter", return_value=[old]), \
             patch.object(RESOURCES.psutil, "Process", return_value=fresh), \
             patch.object(RESOURCES, "_browser_process_ids", return_value=(set(), {321})), \
             patch.object(RESOURCES, "_process_stat_identity", return_value=("S", 100)):
            rows, races = RESOURCES._processes()
        self.assertEqual(rows, [])
        self.assertEqual(races, {"chromium": 1})

    def test_confirmed_exit_before_stat_drops_only_a_chromium_child(self):
        old, fresh = self.processes(321, chromium_child=True)
        with patch.object(RESOURCES.psutil, "process_iter", return_value=[old]), \
             patch.object(RESOURCES.psutil, "Process", return_value=fresh), \
             patch.object(RESOURCES, "_browser_process_ids", return_value=(set(), {321})), \
             patch.object(RESOURCES, "_process_stat_identity", return_value=None):
            rows, races = RESOURCES._processes()
        self.assertEqual(rows, [])
        self.assertEqual(races, {"chromium": 1})

    def test_pid_reuse_never_drops_the_profile_root_or_required_service(self):
        old_root, fresh_root = self.processes(321, root=True, fresh_create_time=2.0)
        with patch.object(RESOURCES.psutil, "process_iter", return_value=[old_root]), \
             patch.object(RESOURCES.psutil, "Process", return_value=fresh_root), \
             patch.object(RESOURCES, "_browser_process_ids", return_value=({321}, {321})), \
             patch.object(RESOURCES, "_process_stat_identity", return_value=("S", 100)), \
             patch.object(RESOURCES, "_browser_match", return_value=True):
            with self.assertRaisesRegex(RuntimeError, "PID was reused"):
                RESOURCES._processes()

        with patch.object(RESOURCES.psutil, "process_iter", return_value=[old_root]), \
             patch.object(RESOURCES, "_browser_process_ids", return_value=({321}, {321})), \
             patch.object(RESOURCES, "_process_stat_identity", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "PID exited before stat snapshot"):
                RESOURCES._processes()

        old_service, fresh_service = self.processes(654, fresh_create_time=2.0)
        with patch.object(RESOURCES.psutil, "process_iter", return_value=[old_service]), \
             patch.object(RESOURCES.psutil, "Process", return_value=fresh_service), \
             patch.object(RESOURCES, "_browser_process_ids", return_value=(set(), set())), \
             patch.object(RESOURCES, "_process_stat_identity", return_value=("S", 100)):
            with self.assertRaisesRegex(RuntimeError, "PID was reused"):
                RESOURCES._processes()


class StartupTransitionTests(unittest.TestCase):
    def identities(self):
        supervisor = {"pid": 123, "start_ticks": 200, "command_sha256": "a" * 64}
        predecessor = {"pid": 321, "start_ticks": 300, "command_sha256": "b" * 64,
                       "parent_pid": 123, "parent_start_ticks": 200}
        return supervisor, predecessor

    def record(self, kind, supervisor, predecessor, **extra):
        return {"schema_version": 1, "type": kind, "transition_id": "c" * 32,
                "session_id": "01-fetch-allow-r1", "expires_at_ns": RESOURCES.time.monotonic_ns() + 60_000_000_000,
                "predecessor": predecessor, "supervisor": supervisor,
                "source_revision": "d" * 40, "protocol_sha256": "e" * 64, **extra}

    def test_three_control_records_are_bound_and_one_shot(self):
        supervisor, predecessor = self.identities()
        successor = {"pid": 322, "start_ticks": 400, "command_sha256": "b" * 64,
                     "parent_pid": 123, "parent_start_ticks": 200}
        transition = RESOURCES.StartupTransition()
        transition.last_rows = [
            {"role": "supervisor_bridge", **supervisor},
            {"role": "detector", "pid": predecessor["pid"], "start_ticks": predecessor["start_ticks"],
             "command_sha256": predecessor["command_sha256"], "ppid": predecessor["parent_pid"],
             "parent_start_ticks": predecessor["parent_start_ticks"]},
        ]
        transition._validate_live_predecessor = lambda: None
        transition._validate_live_successor = lambda _identity: None
        prepare = self.record("prepare", supervisor, predecessor)
        dispatch = {**prepare, "type": "dispatch", "operation": "cloud_to_local_startup"}
        commit = {**prepare, "type": "commit", "successor": successor}
        output = io.StringIO()
        with patch.object(RESOURCES.sys, "stdout", output):
            transition._accept(prepare)
            transition._accept(dispatch)
            transition.retired = True
            transition.successor = successor
            transition._accept(commit)
        acknowledgements = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([item["sequence"] for item in acknowledgements], ["prepare", "dispatch", "commit"])
        self.assertEqual(acknowledgements[-1]["successor"], {"pid": 322, "start_ticks": 400})
        with patch.object(RESOURCES.sys, "stdout", io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "sequence is invalid|fields are invalid"):
                transition._accept(self.record("dispatch", supervisor, predecessor,
                                               operation="cloud_to_local_startup"))

    def test_control_records_must_match_sampler_source_and_protocol(self):
        supervisor, predecessor = self.identities()
        transition = RESOURCES.StartupTransition("d" * 40, "e" * 64)
        transition._validate_live_predecessor = lambda: None
        record = self.record("prepare", supervisor, predecessor)
        record["source_revision"] = "f" * 40
        with patch.object(RESOURCES.sys, "stdout", io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "source binding"):
                transition._accept(record)

    def test_actual_process_walk_allows_only_authorized_exact_predecessor_exit(self):
        supervisor, predecessor = self.identities()
        transition = RESOURCES.StartupTransition()
        transition.phase = "dispatched"
        transition.record = {"predecessor": predecessor, "supervisor": supervisor,
                            "transition_id": "c" * 32, "expires_at_ns": RESOURCES.time.monotonic_ns() + 60_000_000_000}
        process = SimpleNamespace(info={"pid": 321, "ppid": 123,
            "cmdline": ["python", "extension/client-runtime/src/grpc_main.py"],
            "create_time": 1.0, "memory_info": None, "cpu_times": None})
        with patch.object(RESOURCES.psutil, "process_iter", return_value=[process]), \
             patch.object(RESOURCES, "_browser_process_ids", return_value=(set(), set())), \
             patch.object(RESOURCES, "_process_stat_identity", return_value=None):
            rows, races = RESOURCES._processes(transition)
        self.assertEqual(rows, [])
        self.assertEqual(races, {})
        self.assertTrue(transition.retired)
        self.assertEqual(transition.events[0]["type"], "predecessor_retired")

        transition = RESOURCES.StartupTransition()
        transition.phase = "dispatched"
        transition.record = {"predecessor": {**predecessor, "pid": 322},
                            "supervisor": supervisor, "transition_id": "c" * 32,
                            "expires_at_ns": RESOURCES.time.monotonic_ns() + 60_000_000_000}
        with patch.object(RESOURCES.psutil, "process_iter", return_value=[process]), \
             patch.object(RESOURCES, "_browser_process_ids", return_value=(set(), set())), \
             patch.object(RESOURCES, "_process_stat_identity", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "identity changed during resource sampling"):
                RESOURCES._processes(transition)

    def test_predecessor_reuse_or_live_state_is_not_authorized(self):
        supervisor, predecessor = self.identities()
        transition = RESOURCES.StartupTransition()
        transition.phase = "dispatched"
        transition.record = {"predecessor": predecessor, "supervisor": supervisor,
            "transition_id": "c" * 32, "expires_at_ns": RESOURCES.time.monotonic_ns() + 60_000_000_000}
        self.assertFalse(transition.allow_predecessor_retirement("detector", 321, ("S", 300), "live"))
        self.assertFalse(transition.allow_predecessor_retirement("detector", 321, ("Z", 301), "reused"))
        self.assertFalse(transition.allow_predecessor_retirement("detector", 322, None, "other PID"))
        self.assertFalse(transition.retired)
        self.assertTrue(transition.allow_predecessor_retirement("detector", 321, ("Z", 300), "terminal"))

    def test_observe_rejects_multiple_successors_even_under_transition(self):
        supervisor, predecessor = self.identities()
        transition = RESOURCES.StartupTransition()
        transition.phase = "dispatched"
        transition.retired = True
        transition.record = {"predecessor": predecessor, "supervisor": supervisor,
            "transition_id": "c" * 32, "expires_at_ns": RESOURCES.time.monotonic_ns() + 60_000_000_000}
        def row(pid, ticks):
            return {"role": "detector", "pid": pid, "start_ticks": ticks,
                    "command_sha256": "b" * 64, "ppid": 123, "parent_start_ticks": 200}
        rows = [{"role": "supervisor_bridge", **supervisor}, row(322, 400), row(323, 500)]
        with patch.object(RESOURCES, "_process_stat_identity", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "unexpected detector successor"):
                transition.observe(rows)

    def test_observed_successor_may_not_disappear_before_commit(self):
        supervisor, predecessor = self.identities()
        transition = RESOURCES.StartupTransition()
        transition.phase = "dispatched"
        transition.retired = True
        transition.record = {"predecessor": predecessor, "supervisor": supervisor,
            "transition_id": "c" * 32, "expires_at_ns": RESOURCES.time.monotonic_ns() + 60_000_000_000}
        final = {"role": "detector", "pid": 322, "start_ticks": 400,
                 "command_sha256": predecessor["command_sha256"], "ppid": 123, "parent_start_ticks": 200}
        with patch.object(RESOURCES, "_process_stat_identity", return_value=None):
            transition.observe([{"role": "supervisor_bridge", **supervisor}, final])
            with self.assertRaisesRegex(RuntimeError, "successor disappeared"):
                transition.observe([{"role": "supervisor_bridge", **supervisor}])


if __name__ == "__main__":
    unittest.main()
