from __future__ import annotations

import unittest
from subprocess import CompletedProcess
from pathlib import Path
import sys
from unittest.mock import patch


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
    def test_switching_stack_restarts_owned_child_and_preserves_loopback(self) -> None:
        processes = []
        def factory(*args, **kwargs):
            process = FakeProcess(len(processes) + 1)
            processes.append((process, dict(kwargs["env"])))
            return process

        supervisor = RuntimeProcessSupervisor(command=["test-runtime"], environment={}, process_factory=factory)
        with patch.object(supervisor, "_runtime_port_is_open", return_value=False), patch.object(supervisor, "_wait_until_ready", return_value=True):
            supervisor.set_enabled(True, False)
            supervisor.set_enabled(True, True)
            self.assertTrue(processes[0][0].terminated)
            self.assertEqual(processes[1][1]["PRIVOKE_USE_LOCAL_STACK"], "true")
            self.assertEqual(processes[1][1]["PRIVOKE_GRPC_HOST"], "127.0.0.1")
            self.assertEqual(processes[1][1]["PRIVOKE_GRPC_PORT"], "50057")
            supervisor.set_enabled(True, True)
            self.assertEqual(len(processes), 2)
            supervisor.set_enabled(False, False)
            self.assertTrue(processes[1][0].terminated)
            self.assertEqual(supervisor.environment["PRIVOKE_USE_LOCAL_STACK"], "false")

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
        self.assertEqual(supervisor.runtime_port, 50057)
        self.assertEqual(supervisor.environment["PRIVOKE_GRPC_PORT"], "50057")
        self.assertEqual(supervisor.environment["PRIVOKE_GRPC_HOST"], "127.0.0.1")

    def test_forces_runtime_to_loopback(self) -> None:
        supervisor = RuntimeProcessSupervisor(
            environment={"PRIVOKE_GRPC_HOST": "0.0.0.0"}
        )

        self.assertEqual(supervisor.environment["PRIVOKE_GRPC_HOST"], "127.0.0.1")

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
        supervisor._runtime_port_is_open = lambda: False
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
        supervisor._runtime_port_is_open = lambda: False
        supervisor._wait_until_ready = lambda child: False

        status = supervisor.start()

        self.assertFalse(status.enabled)
        self.assertTrue(process.terminated)
        self.assertIn("did not listen", status.message)

    def test_does_not_claim_an_unmanaged_process_as_its_runtime(self) -> None:
        launches = []
        supervisor = RuntimeProcessSupervisor(
            command=("runtime",),
            environment={},
            process_factory=lambda *args, **kwargs: launches.append(args),
        )
        supervisor._runtime_port_is_open = lambda: True

        status = supervisor.start()

        self.assertFalse(status.enabled)
        self.assertEqual(launches, [])
        self.assertIn("not owned by this supervisor", status.message)

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
        supervisor._runtime_port_is_open = lambda: False

        status = supervisor.start()

        self.assertFalse(status.enabled)
        self.assertEqual(launches, [])
        self.assertIn("presidio_analyzer", status.message)


if __name__ == "__main__":
    unittest.main()
