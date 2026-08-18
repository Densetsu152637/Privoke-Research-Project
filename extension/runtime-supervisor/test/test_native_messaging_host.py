from __future__ import annotations

from io import BytesIO
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from src import native_messaging_host


class NativeMessagingHostTests(unittest.TestCase):
    def test_rejects_unsupported_actions(self) -> None:
        response = native_messaging_host.handle_message({"action": "run_arbitrary_command"})

        self.assertFalse(response["ok"])
        self.assertIn("Unsupported", response["message"])

    @patch.object(native_messaging_host, "ensure_supervisor")
    def test_accepts_only_the_fixed_supervisor_action(self, ensure_supervisor) -> None:
        ensure_supervisor.return_value = {"ok": True, "started": True}

        response = native_messaging_host.handle_message({"action": "ensure_supervisor"})

        self.assertEqual(response, {"ok": True, "started": True})
        ensure_supervisor.assert_called_once_with()

    def test_native_message_framing_round_trip(self) -> None:
        request = json.dumps({"action": "invalid"}).encode("utf-8")
        input_stream = BytesIO(struct.pack("=I", len(request)) + request)
        output_stream = BytesIO()

        native_messaging_host.serve(input_stream, output_stream)

        output_stream.seek(0)
        length = struct.unpack("=I", output_stream.read(4))[0]
        response = json.loads(output_stream.read(length))
        self.assertFalse(response["ok"])

    @patch.object(native_messaging_host, "_port_is_open")
    def test_does_not_spawn_when_bridge_is_already_open(self, port_is_open) -> None:
        port_is_open.return_value = True

        response = native_messaging_host.ensure_supervisor()

        self.assertTrue(response["ok"])
        self.assertFalse(response["started"])

    @unittest.skipUnless(os.name == "nt", "Windows process flag regression test")
    @patch.object(native_messaging_host, "_port_is_open")
    @patch.object(native_messaging_host.subprocess, "Popen")
    def test_windows_supervisor_starts_without_a_console_window(
        self,
        popen: MagicMock,
        port_is_open: MagicMock,
    ) -> None:
        process = popen.return_value
        process.pid = 1234
        port_is_open.side_effect = [False, False, True]

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            supervisor_main = root / "extension" / "runtime-supervisor" / "src" / "main.py"
            python_executable = root / "extension" / "client-runtime" / ".venv" / "Scripts" / "python.exe"
            supervisor_main.parent.mkdir(parents=True)
            python_executable.parent.mkdir(parents=True)
            supervisor_main.touch()
            python_executable.touch()

            with (
                patch.object(native_messaging_host, "repository_root", return_value=root),
                patch.object(native_messaging_host, "_log_path", return_value=root / "supervisor.log"),
            ):
                response = native_messaging_host.ensure_supervisor(timeout_seconds=0.1)

        self.assertTrue(response["ok"])
        creation_flags = popen.call_args.kwargs["creationflags"]
        self.assertTrue(creation_flags & subprocess.CREATE_NO_WINDOW)
        self.assertFalse(creation_flags & subprocess.DETACHED_PROCESS)


if __name__ == "__main__":
    unittest.main()
