"""Stage 6: the telemetry emitter delivers over mutual TLS with the shared reporter credential.

The receiver is a stand-in for the stage 4 Rust telemetry service (RecordTelemetry and Health, reporter identity only).
The check against the real service is pending stage 4. Certificates are issued at test time by ``privoke-pki``.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PACKAGE_ROOT.parents[1]
for path in (PACKAGE_ROOT, PACKAGE_ROOT / "generated", REPO_ROOT / "shared/python"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from src.telemetry import event_emitter

# The fixture lives beside the shared tests; load it by path so that directory never joins sys.path (it holds
# test modules whose names collide with this suite's).
_spec = importlib.util.spec_from_file_location("privoke_mtls_pki", REPO_ROOT / "shared/python/tests/mtls_pki.py")
_fixture = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _fixture
_spec.loader.exec_module(_fixture)
PkiFixture, TelemetryStandIn, locate_pki_tool = _fixture.PkiFixture, _fixture.TelemetryStandIn, _fixture.locate_pki_tool

TOOL = locate_pki_tool()


def _analysis():
    return SimpleNamespace(
        action=SimpleNamespace(name="ALLOW"),
        result=SimpleNamespace(classification=None, metadata={"model_version": "v0.3.0"}),
    )


@unittest.skipIf(TOOL is None, "privoke-pki is not built and cargo is unavailable")
class TelemetryMutualTlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = PkiFixture(TOOL)
        cls.addClassCleanup(cls.pki.close)
        cls.service = cls.pki.service("fuzzer", "runtime")

    def setUp(self):
        self.receiver = TelemetryStandIn(self.pki.server_environment())
        self.addCleanup(self.receiver.stop)
        # The target is a loopback stand-in; treat it as the remote cloud address so the production TLS path runs.
        patcher = patch("privoke_service.stack_connection.is_loopback_target", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _send(self, environment: dict[str, str], expected: int) -> None:
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, environment, clear=False):
            reporter = event_emitter.TelemetryReporter(
                target=self.receiver.target,
                event_epsilon=0.5,
                daily_epsilon=2.0,
                ledger_path=str(Path(temporary) / "ledger.sqlite3"),
                timeout_seconds=5.0,
            )
            try:
                reporter.report(_analysis())
                reporter._queue.join()
            finally:
                reporter.close()
        deadline = time.monotonic() + 3
        while len(self.receiver.packets) < expected and time.monotonic() < deadline:
            time.sleep(0.05)

    def test_packet_is_delivered_with_the_reporter_credential(self):
        environment = self.pki.client_environment(self.pki.reporter_cert, self.pki.reporter_key, prefix="PRIVOKE_TELEMETRY_TLS")
        # An installation identity is also configured; it must not be the one presented to telemetry.
        environment.update(PRIVOKE_TLS_CERT_FILE=str(self.service[0]), PRIVOKE_TLS_KEY_FILE=str(self.service[1]))
        self._send(environment, expected=1)
        self.assertEqual(len(self.receiver.packets), 1)
        self.assertEqual(self.receiver.packets[0].privacy_epsilon, 0.5)

    def test_the_installation_certificate_is_not_a_substitute_for_the_reporter_credential(self):
        environment = self.pki.client_environment(*self.service)
        for name in ("PRIVOKE_TELEMETRY_TLS_CERT_FILE", "PRIVOKE_TELEMETRY_TLS_KEY_FILE"):
            os.environ.pop(name, None)
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, environment, clear=False):
            with self.assertRaisesRegex(ValueError, "PRIVOKE_TELEMETRY_TLS_CERT_FILE"):
                event_emitter.TelemetryReporter(
                    target=self.receiver.target, ledger_path=str(Path(temporary) / "ledger.sqlite3")
                )

    def test_a_non_reporter_certificate_is_refused_by_the_receiver(self):
        environment = self.pki.client_environment(*self.service, prefix="PRIVOKE_TELEMETRY_TLS")
        self._send(environment, expected=1)
        self.assertEqual(self.receiver.packets, [])


if __name__ == "__main__":
    unittest.main()
