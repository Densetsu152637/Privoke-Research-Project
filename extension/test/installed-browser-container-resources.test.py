import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("collector", Path(__file__).with_name("installed-browser-container-resources.py"))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
IDENTITY = {"membership_sha256": "a" * 64, "mount_sha256": "e" * 64, "namespace_inode": 123, "files": [{"device": 1, "inode": n} for n in range(3)]}


class CollectorTests(unittest.TestCase):
    def run_loop(self, values, times=None, cpus=None):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "rows"
            progress = {"samples_written": 0}
            reader = iter(values)
            times = times or [1_000_000_000 + n * 100_000_000 for n in range(len(values))]
            clock = iter(value for end in times for value in (end - 1, end))
            cpu = iter(cpus or range(len(values)))
            sleeps = []
            c.collect(output, "b" * 40, "c" * 64, progress, read=lambda: next(reader),
                      clock=lambda: next(clock), cpu_clock=lambda: next(cpu),
                      sleep=sleeps.append, stopped=lambda: progress["samples_written"] == len(values) - 1)
            return [json.loads(s) for s in output.read_text().splitlines()], sleeps

    def test_real_loop_retains_whole_cgroup_counters_and_no_catchup(self):
        rows, sleeps = self.run_loop([(IDENTITY, 10, 500), (IDENTITY, 20, 450), (IDENTITY, 30, 600)],
                                    [1_000_000_000, 1_400_000_000, 1_500_000_000])
        self.assertEqual(len(rows), 3)
        self.assertEqual(sleeps, [0.1, 0.1])
        self.assertEqual([r["final_observation"] for r in rows], [False, False, True])
        self.assertEqual(rows[2]["memory_current_bytes"], 600)
        self.assertNotIn("roles", rows[0])

    def test_loop_rejects_counter_reset(self):
        with self.assertRaisesRegex(RuntimeError, "counter_decreased"):
            self.run_loop([(IDENTITY, 10, 1), (IDENTITY, 9, 1)])

    def test_loop_rejects_observer_counter_reset(self):
        with self.assertRaisesRegex(RuntimeError, "counter_decreased"):
            self.run_loop([(IDENTITY, 10, 1), (IDENTITY, 11, 1)], cpus=[2, 1])

    def test_loop_rejects_membership_or_file_identity_change(self):
        for change in [{**IDENTITY, "membership_sha256": "d" * 64}, {**IDENTITY, "files": [{"device": 3, "inode": 1}]}]:
            with self.subTest(change=change), self.assertRaisesRegex(RuntimeError, "identity_changed"):
                self.run_loop([(IDENTITY, 10, 1), (change, 11, 1)])

    def test_loop_rejects_duplicate_and_reversed_times(self):
        for end in [1_000_000_000, 999_999_999]:
            with self.subTest(end=end), self.assertRaisesRegex(RuntimeError, "nonpositive_sample_time"):
                self.run_loop([(IDENTITY, 10, 1), (IDENTITY, 11, 1)], [1_000_000_000, end])

    def test_all_positive_gaps_retained_with_final_read_bracketing(self):
        rows, sleeps = self.run_loop([(IDENTITY, 1, 2), (IDENTITY, 2, 3)], [1_000_000_000, 5_000_000_000])
        self.assertEqual(rows[-1]["read_started_monotonic_ns"], 4_999_999_999)
        self.assertEqual(rows[-1]["sample_monotonic_ns"], 5_000_000_000)
        self.assertTrue(rows[-1]["final_observation"])
        self.assertEqual(sleeps, [0.1])

    def test_signal_during_read_requires_another_read_started_after_stop(self):
        with tempfile.TemporaryDirectory() as temp:
            progress = {"samples_written": 0}
            stopping = False
            clocks = iter([90, 110, 120, 130])
            def read():
                nonlocal stopping
                stopping = True  # Stop arrives during first read, whose start preceded endBoundary100.
                return IDENTITY, 1, 2
            output = Path(temp) / "rows"
            c.collect(output, "b" * 40, "c" * 64, progress, read=read, clock=lambda: next(clocks),
                      cpu_clock=lambda: 1, sleep=lambda _: None, stopped=lambda: stopping)
            rows = [json.loads(s) for s in output.read_text().splitlines()]
            self.assertEqual([r["final_observation"] for r in rows], [False, True])
            self.assertGreater(rows[-1]["read_started_monotonic_ns"], 100)
            self.assertEqual(progress["samples_written"], 2)

    def test_actual_loop_retains_rejected_observation_and_closed_diagnostic(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "rows"
            progress = {"samples_written": 0}
            reads = iter([(IDENTITY, 10, 1), (IDENTITY, 9, 1)])
            clocks = iter([100, 101, 200, 201])
            try:
                c.collect(output, "b" * 40, "c" * 64, progress, read=lambda: next(reads),
                          clock=lambda: next(clocks), cpu_clock=lambda: 1, sleep=lambda _: None,
                          stopped=lambda: progress["samples_written"] > 0)
                self.fail("reset accepted")
            except c.ObservationFailure as error:
                diagnostic = c.terminal("error", progress["samples_written"], error)
            rows = [json.loads(s) for s in output.read_text().splitlines()]
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[-1]["cpu_usage_usec"], 9)
            self.assertEqual(diagnostic["samples_written"], 2)
            self.assertEqual(diagnostic["observation_failure"]["reason"], "counter_decreased")
            self.assertEqual(diagnostic["observation_failure"]["current"]["sample_monotonic_ns"], 201)
            self.assertNotIn("command", json.dumps(diagnostic))

    def test_loop_rejects_bad_counters(self):
        for value in [-1, 1.5, True, 2**53, float("nan")]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.run_loop([(IDENTITY, value, 1)])

    def test_actual_reader_requires_counters_and_tracks_inode(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "membership").write_bytes(b"0::/\n")
            (root / "mountinfo").write_text(f"12 1 0:1 / {root.as_posix().replace(" ", chr(92) + "040")} ro - cgroup2 cgroup rw\n")
            (root / "namespace").write_text("fixture")
            (root / "cpu.stat").write_text("usage_usec 17\nuser_usec 12\nsystem_usec 5\n")
            (root / "memory.current").write_text("900\n")
            identity, cpu, memory = c.read_cgroup(root, root / "membership", root / "mountinfo", root / "namespace")
            self.assertEqual((cpu, memory), (17, 900))
            self.assertEqual(len(identity["files"]), 3)
            for text in ["user_usec 12\n", "usage_usec -1\n", "usage_usec 1\nusage_usec 2\n", "usage_usec nan\n"]:
                (root / "cpu.stat").write_text(text)
                with self.assertRaises((ValueError, KeyError)):
                    c.read_cgroup(root, root / "membership", root / "mountinfo", root / "namespace")
            (root / "memory.current").unlink()
            with self.assertRaises(FileNotFoundError):
                c.read_cgroup(root, root / "membership", root / "mountinfo", root / "namespace")

    def test_actual_reader_rejects_foreign_membership_and_ancestor_mount(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "membership").write_bytes(b"0::/foreign\n")
            (root / "mountinfo").write_text(f"12 1 0:1 / {root.as_posix().replace(" ", chr(92) + "040")} ro - cgroup2 cgroup rw\n")
            with self.assertRaisesRegex(RuntimeError, "membership"):
                c.read_cgroup(root, root / "membership", root / "mountinfo", root / "namespace")
            (root / "membership").write_bytes(b"0::/\n")
            for mount in [f"12 1 0:1 /ancestor {root.as_posix().replace(" ", chr(92) + "040")} ro - cgroup2 cgroup rw\n",
                          f"12 1 0:1 / {root.as_posix().replace(" ", chr(92) + "040")} ro - ext4 disk rw\n", ""]:
                (root / "mountinfo").write_text(mount)
                with self.assertRaisesRegex(RuntimeError, "mount"):
                    c.read_cgroup(root, root / "membership", root / "mountinfo", root / "namespace")

    def test_failure_terminal_contains_no_exception_message(self):
        try:
            raise RuntimeError("SECRET-COMMAND")
        except RuntimeError as error:
            payload = c.terminal("error", 3, error)
        self.assertNotIn("SECRET", json.dumps(payload))
        self.assertEqual(payload["exception_type"], "RuntimeError")
        self.assertEqual(c.terminal("stopped", 3)["frames"], [])


if __name__ == "__main__":
    unittest.main()
