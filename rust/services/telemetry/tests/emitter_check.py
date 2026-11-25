"""Drive the real Python telemetry emitter against a telemetry service over mutual TLS (stage 6 check, stage 4 target).

The emitter is ``extension/client-runtime/src/telemetry/event_emitter.py`` and is used unmodified: it opens its channel
with ``grpc_channel(target, credential="reporter")`` and so presents only ``PRIVOKE_TELEMETRY_TLS_CERT_FILE`` and
``PRIVOKE_TELEMETRY_TLS_KEY_FILE``. Certificates are issued at test time by the Rust test that runs this script; nothing
here is committed key material. Run from the host Python environment (``AGENTS.md``): the Rust test passes the
interpreter, the generated protobuf directory and the paths as arguments.

Exit status: 0 when every report was accepted (mode ``deliver``) or refused with PERMISSION_DENIED (mode ``refused``,
for a credential that is not the reporter's), 1 otherwise. The last line of stdout is a JSON summary.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPOSITORY = Path(__file__).resolve().parents[4]
PACKAGE_ROOT = REPOSITORY / "extension" / "client-runtime"


class Collector(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def analysis(action: str):
    return SimpleNamespace(
        action=SimpleNamespace(name=action),
        result=SimpleNamespace(classification=None, metadata={"model_version": "v0.3.0"}),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--cert", required=True, help="credential presented as the telemetry credential")
    parser.add_argument("--key", required=True)
    parser.add_argument("--ca", required=True, help="server CA bundle")
    parser.add_argument("--generated", required=True, help="directory holding the generated privoke/v1 protobuf modules")
    parser.add_argument("--reports", type=int, default=4)
    parser.add_argument("--mode", choices=("deliver", "refused"), default="deliver")
    arguments = parser.parse_args()

    for path in (PACKAGE_ROOT, Path(arguments.generated), REPOSITORY / "shared" / "python"):
        sys.path.insert(0, str(path))
    from src.telemetry import event_emitter  # noqa: PLC0415 (the path must be set first)

    environment = {
        "PRIVOKE_TELEMETRY_TLS_CERT_FILE": arguments.cert,
        "PRIVOKE_TELEMETRY_TLS_KEY_FILE": arguments.key,
        "PRIVOKE_TLS_CA_FILE": arguments.ca,
    }
    collector = Collector()
    logging.getLogger().addHandler(collector)
    logging.getLogger().setLevel(logging.WARNING)
    actions = ("ALLOW", "WARN", "BLOCK", "ALLOW")
    # The target is a loopback address; treat it as the remote cloud address so that the production TLS path runs.
    with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, environment, clear=False), patch(
        "privoke_service.stack_connection.is_loopback_target", return_value=False
    ):
        reporter = event_emitter.TelemetryReporter(
            target=arguments.target,
            event_epsilon=0.5,
            daily_epsilon=2.0,
            ledger_path=str(Path(temporary) / "ledger.sqlite3"),
            timeout_seconds=10.0,
        )
        try:
            for index in range(arguments.reports):
                reporter.report(analysis(actions[index % len(actions)]))
            reporter._queue.join()  # noqa: SLF001 (wait for delivery, as the stage 6 test does)
        finally:
            reporter.close(timeout_seconds=10.0)

    failures = [message for message in collector.messages if "submission failed" in message]
    denied = [message for message in failures if "PERMISSION_DENIED" in message]
    summary = {
        "mode": arguments.mode,
        "reports": arguments.reports,
        "submission_failures": len(failures),
        "permission_denied": len(denied),
        "other_warnings": [m for m in collector.messages if m not in failures and "rejected" in m],
    }
    print(json.dumps(summary))
    if arguments.mode == "deliver":
        return 0 if not failures and not summary["other_warnings"] else 1
    return 0 if len(denied) == arguments.reports else 1


if __name__ == "__main__":
    raise SystemExit(main())
