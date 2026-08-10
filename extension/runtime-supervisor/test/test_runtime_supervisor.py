from __future__ import annotations

import unittest
from subprocess import CompletedProcess
from pathlib import Path
import sys


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from src.runtime_supervisor import RuntimeProcessSupervisor


class FakeProcess:
    def __init__(self, pid: int = 4242) -> None:
        self.pid = pid
        self.return_code = None
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.return_code

    def terminate(self) -> None:
        self.terminated = True
        self.return_code = 0

    def kill(self) -> None:
        self.killed = True
        self.return_code = -9

    def wait(self, timeout=None):
        return self.return_code


class RuntimeProcessSupervisorTests(unittest.TestCase):
    def test_default_child_is_the_sibling_client_runtime(self) -> None:
        supervisor = RuntimeProcessSupervisor(environment={})

        self.assertEqual(
            Path(supervisor.command[1]).resolve(),
            (
                PACKAGE_ROOT.parent / "client-runtime" / "src" / "grpc_main.py"
            ).resolve(),
        )

        self.assertEqual(
            Path(supervisor.dependency_check_command[1]).resolve(),
            (PACKAGE_ROOT.parent / "client-runtime" / "src" / "dependency_check.py").resolve(),
        )

    def test_explicit_runtime_python_overrides_interpreter_discovery(self) -> None:
        supervisor = RuntimeProcessSupervisor(
            environment={"PRIVOKE_RUNTIME_PYTHON": "managed-python"}
        )

        self.assertEqual(supervisor.command[0], "managed-python")
        self.assertEqual(
            supervisor.dependency_check_command[0],
            "managed-python",
        )

    def test_starts_and_stops_the_runtime_child(self) -> None:
        process = FakeProcess()
        supervisor = RuntimeProcessSupervisor(
            command=("runtime",),
            environment={},
            process_factory=lambda *args, **kwargs: process,
        )
        supervisor._wait_until_ready = lambda child: True

        running = supervisor.start()
        self.assertTrue(running.enabled)
        self.assertEqual(running.status, "RUNNING")
        self.assertEqual(running.process_id, 4242)

        stopped = supervisor.stop()
        self.assertFalse(stopped.enabled)
        self.assertEqual(stopped.status, "STOPPED")
        self.assertTrue(process.terminated)

    def test_cleans_up_a_child_that_never_becomes_ready(self) -> None:
        process = FakeProcess()
        supervisor = RuntimeProcessSupervisor(
            command=("runtime",),
            environment={},
            process_factory=lambda *args, **kwargs: process,
        )
        supervisor._wait_until_ready = lambda child: False

        status = supervisor.start()

        self.assertFalse(status.enabled)
        self.assertTrue(process.terminated)
        self.assertIn("did not listen", status.message)

    def test_does_not_launch_runtime_when_required_dependencies_are_missing(self) -> None:
        launches = []
        supervisor = RuntimeProcessSupervisor(
            environment={},
            process_factory=lambda *args, **kwargs: launches.append(args),
            dependency_check_factory=lambda *args, **kwargs: CompletedProcess(
                args[0],
                1,
                stdout="",
                stderr="ModuleNotFoundError: No module named 'presidio_analyzer'\n",
            ),
        )

        status = supervisor.start()

        self.assertFalse(status.enabled)
        self.assertEqual(launches, [])
        self.assertIn("presidio_analyzer", status.message)


if __name__ == "__main__":
    unittest.main()
