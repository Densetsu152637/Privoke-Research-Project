"""Mechanics tests for the W4 native-transport study support (evaluation/w4_transport.py).

No browser and no runtime is started. The registry, process and port observations are exercised on synthetic rows.
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "evaluation")]

import w4_transport as w4  # noqa: E402

EXE = Path(r"C:\build\privoke-supervisor.exe")


def row(pid, parent, name, path=None, command=""):
    return {"ProcessId": pid, "ParentProcessId": parent, "Name": name, "ExecutablePath": path, "CommandLine": command}


class TransportSupportTests(unittest.TestCase):
    def test_chromium_extension_id_matches_the_pinned_identity(self):
        identities = json.loads((ROOT / "extension" / "extension-identities.json").read_text(encoding="utf8"))
        self.assertEqual(w4.chromium_extension_id(identities["chromium_public_key"]), identities["chromium_extension_id"])

    def test_the_host_name_is_not_the_python_launchers(self):
        self.assertEqual(w4.HOST_NAME, "org.privoke.runtime_controller")
        self.assertNotEqual(w4.HOST_NAME, "org.privoke.runtime_launcher")

    def test_controller_tree_and_workers_are_found_and_unrelated_processes_are_not(self):
        rows = [
            row(1, 0, "chrome.exe", r"C:\chrome.exe"),
            row(10, 1, "privoke-supervisor.exe", str(EXE)),
            row(11, 10, "python.exe", r"C:\venv\python.exe", "python worker_shim.py --runtime-root x"),
            row(12, 11, "python.exe", r"C:\py\python.exe", "python worker_shim.py --runtime-root x"),
            row(20, 1, "other.exe", r"C:\other.exe"),
            row(30, 0, "python.exe", r"C:\py\python.exe", "python unrelated.py"),
        ]
        found = {entry["pid"] for entry in w4.privoke_processes(EXE, rows)}
        self.assertEqual(found, {10, 11, 12})

    def test_a_shim_whose_controller_is_gone_is_still_an_orphan(self):
        rows = [row(40, 0, "python.exe", r"C:\py\python.exe", "python .../worker_shim.py --runtime-root x")]
        self.assertEqual([entry["pid"] for entry in w4.privoke_processes(EXE, rows)], [40])
        self.assertEqual(w4.privoke_processes(EXE, [row(1, 0, "chrome.exe", r"C:\chrome.exe")]), [])

    def test_descendants_follow_parent_links_transitively(self):
        rows = [row(2, 1, "a"), row(3, 2, "b"), row(4, 3, "c"), row(5, 9, "d")]
        self.assertEqual(w4.descendants(rows, {1}), {1, 2, 3, 4})

    def test_latency_summary_and_verdict(self):
        summary = w4.latency_summary([10.0, 20.0, 30.0, 40.0, 100.0])
        self.assertEqual((summary["count"], summary["median_ms"], summary["min_ms"], summary["max_ms"]), (5, 30.0, 10.0, 100.0))
        self.assertEqual(w4.latency_summary([]), {"count": 0})
        within = w4.spread_verdict([55.0, 59.0, 60.0], [58.0, 61.0, 57.0])
        self.assertTrue(within["within_recorded_spread"])
        self.assertEqual(within["baseline_run_spread_ms"], [55.0, 60.0])
        slower = w4.spread_verdict([55.0, 59.0, 60.0], [75.0, 80.0, 70.0])
        self.assertFalse(slower["within_recorded_spread"])
        self.assertEqual(slower["delta_ms"], 16.0)
        faster = w4.spread_verdict([55.0, 59.0, 60.0], [20.0, 21.0, 22.0])
        self.assertTrue(faster["within_recorded_spread"], "a lower latency is not a regression")


if __name__ == "__main__":
    unittest.main()
