#!/usr/bin/env python3
"""Focused tests for race-safe process identity sampling."""

import importlib.util
from pathlib import Path
import sys
import types
import unittest


SOURCE = Path(__file__).with_name("installed-browser-resources.py")
SPEC = importlib.util.spec_from_file_location("installed_browser_resources", SOURCE)
assert SPEC and SPEC.loader
try:
    import psutil  # noqa: F401
except ImportError:
    # Identity parsing itself is stdlib-only; the sampler's process walk needs psutil.
    stub = types.ModuleType("psutil")
    stub.pid_exists = lambda _pid: False
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


if __name__ == "__main__":
    unittest.main()
