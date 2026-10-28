from __future__ import annotations

import os
import socket
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
    def setUp(self) -> None:
        # These lifecycle tests use fake processes; exercise real platform
        # termination separately below, without passing fake PIDs to taskkill.
        termination = patch.object(RuntimeProcessSupervisor, "_terminate_process", side_effect=lambda process: process.terminate())
        termination.start()
        self.addCleanup(termination.stop)

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


@unittest.skipUnless(os.name == "nt", "Windows venv process-tree regression")
class WindowsRuntimeProcessTests(unittest.TestCase):
    def test_stopping_venv_runtime_releases_port_and_allows_restart(self) -> None:
        runtime_python = Path(__file__).resolve().parents[2] / "client-runtime" / ".venv" / "Scripts" / "python.exe"
        if not runtime_python.is_file():
            self.skipTest("Local Windows runtime virtual environment is unavailable")
        with socket.socket() as port_socket:
            port_socket.bind(("127.0.0.1", 0))
            port = port_socket.getsockname()[1]
        command = (
            str(runtime_python), "-c",
            "import socket,time; s=socket.socket(); "
            f"s.bind(('127.0.0.1',{port})); s.listen(); time.sleep(60)",
        )
        supervisor = RuntimeProcessSupervisor(command=command, runtime_port=port, environment=dict(os.environ))
        try:
            for _ in range(3):
                self.assertTrue(supervisor.start().enabled)
                self.assertTrue(supervisor._runtime_port_is_open())
                self.assertFalse(supervisor.stop().enabled)
                self.assertFalse(supervisor._runtime_port_is_open(), "Detector outlived its venv launcher")
        finally:
            supervisor.stop()

    def test_failed_tree_termination_does_not_report_stopped(self) -> None:
        supervisor = RuntimeProcessSupervisor(command=("runtime",), environment={})
        process = FakeProcess()
        supervisor._process = process
        with patch("src.runtime_supervisor.subprocess.run", return_value=CompletedProcess([], 1)):
            with self.assertRaisesRegex(RuntimeError, "process tree"):
                supervisor.stop()
        self.assertIs(supervisor._process, process)
        self.assertTrue(supervisor.status().enabled)

    def test_partial_tree_failure_is_not_ignored_when_launcher_exits(self) -> None:
        supervisor = RuntimeProcessSupervisor(command=("runtime",), environment={})
        process = FakeProcess()
        def partial_failure(*args, **kwargs):
            process.return_code = 0
            return CompletedProcess(args[0], 1)
        with patch("src.runtime_supervisor.subprocess.run", side_effect=partial_failure):
            with self.assertRaisesRegex(RuntimeError, "process tree"):
                supervisor._terminate_process(process)


if __name__ == "__main__":
    unittest.main()
