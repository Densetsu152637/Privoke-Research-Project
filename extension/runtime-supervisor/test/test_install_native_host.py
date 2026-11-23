"""The native-host installers pass PRIVOKE_PRETRAINED_CONTEXT_DIR to the host.

The browser starts the native host with a clean environment, so the encoder asset directory known when the installer
runs has to be stored in the launcher. The POSIX installer is run for real in a scratch home (Linux only, where its
install root is `$XDG_DATA_HOME/privoke/native-host`); the Windows installer and its launcher are checked as text, since
PowerShell and the C# compiler are not available to this suite.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
INSTALLER = SCRIPTS / "install-native-host.sh"
VARIABLE = "PRIVOKE_PRETRAINED_CONTEXT_DIR"


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("sh"), "the POSIX installer layout under test is Linux's")
class PosixInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = Path(tempfile.mkdtemp(prefix="privoke-installer-"))
        self.addCleanup(shutil.rmtree, self.scratch, ignore_errors=True)
        # The installer only checks that the supervisor binary exists; it is never run.
        self.binary = self.scratch / "privoke-supervisor"
        self.binary.write_text("#!/bin/sh\n", encoding="utf-8")

    def install(self, **extra: str) -> subprocess.CompletedProcess[str]:
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.scratch / "home"),
            "XDG_CONFIG_HOME": str(self.scratch / "config"),
            "XDG_DATA_HOME": str(self.scratch / "data"),
            "PRIVOKE_SUPERVISOR_BINARY": str(self.binary),
            **extra,
        }
        return subprocess.run(["sh", str(INSTALLER), "chromium"], env=environment, capture_output=True, text=True, check=False)

    def launcher(self) -> str:
        return (self.scratch / "data" / "privoke" / "native-host" / "privoke-native-host").read_text(encoding="utf-8")

    def test_the_launcher_exports_the_encoder_directory_when_it_is_set(self) -> None:
        assets = self.scratch / "assets"
        assets.mkdir()
        result = self.install(**{VARIABLE: str(assets)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"export {VARIABLE}='{assets}'\n", self.launcher())
        self.assertIn("export PRIVOKE_REPOSITORY_ROOT=", self.launcher())

    def test_the_launcher_carries_none_when_it_is_unset(self) -> None:
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(VARIABLE, self.launcher())

    def test_a_quote_in_the_directory_name_cannot_end_the_quoting(self) -> None:
        assets = self.scratch / "it's assets"
        assets.mkdir()
        self.assertEqual(self.install(**{VARIABLE: str(assets)}).returncode, 0)
        self.assertIn(f"export {VARIABLE}='{str(assets).replace(chr(39), chr(39) + chr(92) + chr(39) + chr(39))}'\n", self.launcher())

    def test_a_relative_path_or_a_missing_directory_is_refused_before_anything_is_installed(self) -> None:
        for value in ("assets", str(self.scratch / "missing")):
            result = self.install(**{VARIABLE: value})
            self.assertNotEqual(result.returncode, 0, value)
            self.assertIn(VARIABLE, result.stderr)
        self.assertFalse((self.scratch / "data").exists(), "a refused installation must not write the launcher")


class WindowsInstallerTests(unittest.TestCase):
    def test_the_installer_stores_the_directory_as_the_launchers_fourth_line(self) -> None:
        script = (SCRIPTS / "install-native-host.ps1").read_text(encoding="utf-8")
        self.assertIn("[string]$PretrainedContextDir = $env:" + VARIABLE, script)
        self.assertIn("-PathType Container", script)
        self.assertIn("$pretrainedContextPath", script)

    def test_the_launcher_sets_the_variable_from_a_fourth_config_line_and_still_takes_three(self) -> None:
        launcher = (SCRIPTS / "native-host-launcher.cs").read_text(encoding="utf-8")
        self.assertIn("config.Length != 3 && config.Length != 4", launcher)
        self.assertIn('EnvironmentVariables["' + VARIABLE + '"] = config[3]', launcher)


if __name__ == "__main__":
    unittest.main()
