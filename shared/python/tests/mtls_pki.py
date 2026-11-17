"""Certificates for mutual-TLS tests, generated at test time with the real ``privoke-pki`` tool.

Nothing here is committed as a key or certificate: every run issues a fresh private PKI in a temporary directory,
using the same certificate profile (URI SAN, clientAuth EKU) the Rust servers enforce.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RUST = ROOT / "rust"
_SUFFIX = ".exe" if os.name == "nt" else ""


def locate_pki_tool() -> Path | None:
    """The ``privoke-pki`` binary: PRIVOKE_PKI_BIN, the workspace build, or one built now with cargo."""
    explicit = os.environ.get("PRIVOKE_PKI_BIN", "").strip()
    if explicit:
        return Path(explicit) if Path(explicit).is_file() else None
    binary = RUST / "target" / "debug" / f"privoke-pki{_SUFFIX}"
    if not binary.is_file() and shutil.which("cargo"):
        subprocess.run(["cargo", "build", "-p", "privoke-pki", "--locked"], cwd=RUST, check=False, capture_output=True)
    return binary if binary.is_file() else None


class PkiFixture:
    """A client CA, a server CA, a server certificate and issued principals."""

    def __init__(self, tool: Path, server_names=("localhost", "127.0.0.1")):
        self.tool = tool
        self._directory = tempfile.TemporaryDirectory(prefix="privoke-mtls-")
        self.root = Path(self._directory.name)
        self.client_ca = self.root / "ca" / "client"
        self.server_ca = self.root / "ca" / "server"
        self.registry = self.root / "registry.toml"
        self._run("init-ca", "--dir", self.client_ca, "--name", "test-client-ca")
        self._run("init-ca", "--dir", self.server_ca, "--name", "test-server-ca")
        arguments = ["issue-server", "--ca-dir", self.server_ca, "--out-dir", self.root / "server"]
        for name in server_names:
            arguments += ["--dns", name]
        self._run(*arguments)
        self._run("issue-reporter", "--ca-dir", self.client_ca)
        self.client_ca_pem = self.client_ca / "ca.crt"
        self.server_ca_pem = self.server_ca / "ca.crt"
        self.server_cert = self.root / "server" / "server.crt"
        self.server_key = self.root / "server" / "server.key"
        self.reporter_cert = self.client_ca / "reporter" / "reporter.crt"
        self.reporter_key = self.client_ca / "reporter" / "reporter.key"

    def close(self) -> None:
        self._directory.cleanup()

    def _run(self, *arguments) -> None:
        result = subprocess.run([str(self.tool), *map(str, arguments)], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(f"privoke-pki {arguments[0]} failed: {result.stderr.strip()}")

    def service(self, name: str, role: str) -> tuple[Path, Path]:
        """Issue a service certificate and register it; returns (certificate, key)."""
        out = self.root / "service" / name
        self._run("sign-service", "--ca-dir", self.client_ca, "--name", name, "--role", role, "--out-dir", out, "--registry", self.registry)
        return out / f"{name}.crt", out / f"{name}.key"

    @staticmethod
    def urn(service: str) -> str:
        return f"urn:privoke:service:{service}"

    def client_environment(self, cert: Path, key: Path, prefix: str = "PRIVOKE_TLS") -> dict[str, str]:
        return {f"{prefix}_CERT_FILE": str(cert), f"{prefix}_KEY_FILE": str(key), "PRIVOKE_TLS_CA_FILE": str(self.server_ca_pem)}

    def server_environment(self, allowed: str = "", **extra: str) -> dict[str, str]:
        environment = {
            "PRIVOKE_SERVER_TLS_CERT_FILE": str(self.server_cert),
            "PRIVOKE_SERVER_TLS_KEY_FILE": str(self.server_key),
            "PRIVOKE_SERVER_TLS_CLIENT_CA_FILE": str(self.client_ca_pem),
        }
        if allowed:
            environment["PRIVOKE_SERVER_ALLOWED_IDENTITIES"] = allowed
        environment.update(extra)
        return environment


class TelemetryStandIn:
    """Minimal mutual-TLS stand-in for the stage 4 Rust telemetry service.

    It implements ``RecordTelemetry`` and ``Health`` with the contract the emitter relies on: a packet from the shared
    reporter credential is accepted and counted, and every other identity gets ``PERMISSION_DENIED``. The real service
    check is pending stage 4.
    """

    def __init__(self, environment: dict[str, str], host: str = "127.0.0.1"):
        from concurrent import futures

        from privoke.v1 import telemetry_pb2, telemetry_pb2_grpc
        from privoke_service.stack_connection import bind_server, build_server

        self.packets: list = []
        outer = self

        class Servicer(telemetry_pb2_grpc.TelemetryServiceServicer):
            def RecordTelemetry(self, request, context):
                outer.packets.append(request)
                return telemetry_pb2.RecordTelemetryResponse(accepted=True, message="")

            def Health(self, request, context):
                return telemetry_pb2.TelemetryHealthResponse(service="telemetry-service", status="SERVING")

        environment = {"PRIVOKE_SERVER_ALLOWED_IDENTITIES": "urn:privoke:reporter", **environment}
        self.server = build_server(futures.ThreadPoolExecutor(max_workers=2), environment=environment)
        telemetry_pb2_grpc.add_TelemetryServiceServicer_to_server(Servicer(), self.server)
        self.port = bind_server(self.server, host, 0, environment=environment)
        self.server.start()
        self.target = f"{host}:{self.port}"

    def stop(self) -> None:
        self.server.stop(0).wait()
