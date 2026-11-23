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

    def test_the_launcher_refreshes_the_standard_model_by_default_and_honours_the_environment(self) -> None:
        # V3-R7: the Rust controller keeps the V3 models fresh; the browser's clean environment is why the launcher stores it.
        self.assertEqual(self.install().returncode, 0)
        self.assertIn("export V3_PACKAGE_REFRESH_MODELS='privoke-v3-balanced'\n", self.launcher())
        self.assertNotIn("V3_PACKAGE_REFRESH_SECONDS", self.launcher())
        self.assertEqual(self.install(V3_PACKAGE_REFRESH_MODELS="privoke-v3-efficient,privoke-v3-quality", V3_PACKAGE_REFRESH_SECONDS="900").returncode, 0)
        self.assertIn("export V3_PACKAGE_REFRESH_MODELS='privoke-v3-efficient,privoke-v3-quality'\n", self.launcher())
        self.assertIn("export V3_PACKAGE_REFRESH_SECONDS='900'\n", self.launcher())
        self.assertEqual(self.install(V3_PACKAGE_REFRESH_MODELS="").returncode, 0)
        self.assertNotIn("V3_PACKAGE_REFRESH_MODELS", self.launcher(), "an empty value starts no refresh loop")

    def test_a_malformed_refresh_setting_is_refused(self) -> None:
        for extra in ({"V3_PACKAGE_REFRESH_MODELS": "privoke-v3-balanced; rm -rf /"}, {"V3_PACKAGE_REFRESH_SECONDS": "soon"}):
            result = self.install(**extra)
            self.assertNotEqual(result.returncode, 0, extra)
            self.assertIn("V3_PACKAGE_REFRESH", result.stderr)

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
        self.assertIn("config.Length < 3 || config.Length > 5", launcher)
        self.assertIn('EnvironmentVariables["' + VARIABLE + '"] = config[3]', launcher)
        # The fifth line (V3-R7): the models the Rust controller keeps fresh.
        self.assertIn('EnvironmentVariables["V3_PACKAGE_REFRESH_MODELS"] = config[4]', launcher)

    def test_the_installer_stores_the_refresh_models_as_the_launchers_fifth_line(self) -> None:
        script = (SCRIPTS / "install-native-host.ps1").read_text(encoding="utf-8")
        self.assertIn("[string]$RefreshModels", script)
        self.assertIn("privoke-v3-balanced", script)
        self.assertIn("$useRustHost -and $RefreshModels", script)


if __name__ == "__main__":
    unittest.main()
