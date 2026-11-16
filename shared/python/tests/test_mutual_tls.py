"""Stage 6: mutual TLS for the Python servers, split cloud targets and the telemetry credential.

Certificates are issued at test time by ``privoke-pki`` into a temporary directory; none is committed.
"""
from __future__ import annotations

import importlib.util
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "extension/client-runtime/generated"))

import grpc

from mtls_pki import PkiFixture, TelemetryStandIn, locate_pki_tool
from privoke_service.stack_connection import (
    PeerIdentityGuard,
    bind_server,
    build_server,
    grpc_channel,
    load_runtime_environment,
    server_credentials,
    service_channel,
    stack_target,
)

PKI = None
TOOL = locate_pki_tool()


def setUpModule():
    global PKI
    if TOOL is not None:
        PKI = PkiFixture(TOOL)


def tearDownModule():
    if PKI is not None:
        PKI.close()


def health(target, environment, *, credential="installation"):
    from privoke.v1 import telemetry_pb2, telemetry_pb2_grpc

    with grpc_channel(target, environment=environment, tls=True, credential=credential) as channel:
        return telemetry_pb2_grpc.TelemetryServiceStub(channel).Health(telemetry_pb2.TelemetryHealthRequest(), timeout=5)


class NoPkiTests(unittest.TestCase):
    """Policy that needs no certificate."""

    def test_plaintext_is_refused_on_non_loopback_addresses_and_allowed_on_loopback(self):
        # R6: a server on the Compose network (non-loopback bind) without TLS configuration does not start.
        for host in ("0.0.0.0", "[::]", "client-runtime", "10.1.2.3"):
            server = build_server(_executor())
            with self.subTest(host=host), self.assertRaisesRegex(ValueError, "Refusing plaintext"):
                bind_server(server, host, 0, environment={"PRIVOKE_STACK_MODE": "internal"})
        for host in ("127.0.0.1", "localhost", "[::1]"):
            server = build_server(_executor())
            with self.subTest(host=host):
                self.assertGreater(bind_server(server, host, 0, environment={}), 0)

    def test_insecure_opt_out_is_internal_mode_only_and_explicit(self):
        flag = "PRIVOKE_ALLOW_INSECURE_INTERNAL_PLAINTEXT"
        with self.assertRaisesRegex(ValueError, "Refusing plaintext"):
            bind_server(build_server(_executor()), "0.0.0.0", 0, environment={flag: "true"})
        server = build_server(_executor())
        self.assertGreater(bind_server(server, "0.0.0.0", 0, environment={flag: "true", "PRIVOKE_STACK_MODE": "internal"}), 0)

    def test_partial_server_tls_settings_are_an_error(self):
        with self.assertRaisesRegex(ValueError, "PRIVOKE_SERVER_TLS_KEY_FILE"):
            server_credentials({"PRIVOKE_SERVER_TLS_CERT_FILE": "a", "PRIVOKE_SERVER_TLS_CLIENT_CA_FILE": "b"})
        self.assertIsNone(server_credentials({}))

    def test_x16_internal_mode_plaintext_to_non_loopback_target_is_refused(self):
        env = {"PRIVOKE_STACK_MODE": "internal"}
        with patch("grpc.insecure_channel") as insecure, self.assertRaisesRegex(ValueError, "PRIVOKE_TLS_CERT_FILE"):
            grpc_channel("model-streaming-service:50051", environment=env)
        insecure.assert_not_called()
        # Loopback in internal mode is the workstation boundary and stays plaintext.
        with patch("grpc.insecure_channel") as insecure:
            grpc_channel("127.0.0.1:50051", environment=env)
            insecure.assert_called_once()

    def test_x16_explicit_internal_opt_out_is_the_only_plaintext_path(self):
        env = {"PRIVOKE_STACK_MODE": "internal", "PRIVOKE_ALLOW_INSECURE_INTERNAL_PLAINTEXT": "true"}
        with patch("grpc.insecure_channel") as insecure:
            grpc_channel("model-streaming-service:50051", environment=env)
            insecure.assert_called_once()
        with self.assertRaisesRegex(ValueError, "PRIVOKE_TLS_CERT_FILE"):
            grpc_channel("stack.example.com:443", environment={"PRIVOKE_ALLOW_INSECURE_INTERNAL_PLAINTEXT": "true"})

    def test_cloud_model_and_telemetry_targets_are_separate(self):
        cloud = {"PRIVOKE_CLOUD_TARGET": "stack.example.com:443"}
        self.assertEqual(stack_target("MODEL_STREAMING", cloud), "stack.example.com:443")
        # Telemetry has its own port and credential: no fallback to the shared target.
        self.assertEqual(stack_target("TELEMETRY", cloud), "")
        split = {**cloud, "PRIVOKE_CLOUD_MODEL_TARGET": "stack.example.com:8000", "PRIVOKE_CLOUD_TELEMETRY_TARGET": "stack.example.com:8443"}
        self.assertEqual(stack_target("MODEL_STREAMING", split), "stack.example.com:8000")
        self.assertEqual(stack_target("TELEMETRY", split), "stack.example.com:8443")
        self.assertEqual(stack_target("TELEMETRY", {"PRIVOKE_CLOUD_TELEMETRY_TARGET": "t.example.com:8443"}), "t.example.com:8443")
        local = {**split, "PRIVOKE_USE_LOCAL_STACK": "true"}
        self.assertEqual(stack_target("MODEL_STREAMING", local), "127.0.0.1:50051")
        self.assertEqual(stack_target("TELEMETRY", local), "127.0.0.1:50055")

    def test_telemetry_channel_presents_only_the_reporter_credential(self):
        with tempfile.TemporaryDirectory() as directory:
            env = {"PRIVOKE_TLS_CA_FILE": _file(directory, "ca", b"root-ca")}
            for name, content in (
                ("PRIVOKE_TLS_CERT_FILE", b"installation-cert"),
                ("PRIVOKE_TLS_KEY_FILE", b"installation-key"),
            ):
                env[name] = _file(directory, name, content)
            # An installation certificate must never be offered to the telemetry server (it would be linkable).
            with self.assertRaisesRegex(ValueError, "PRIVOKE_TELEMETRY_TLS_CERT_FILE"):
                grpc_channel("telemetry.example.com:8443", environment=env, credential="reporter")
            env["PRIVOKE_TELEMETRY_TLS_CERT_FILE"] = _file(directory, "rc", b"reporter-cert")
            env["PRIVOKE_TELEMETRY_TLS_KEY_FILE"] = _file(directory, "rk", b"reporter-key")
            with patch("grpc.ssl_channel_credentials") as credentials, patch("grpc.secure_channel") as secure:
                grpc_channel("telemetry.example.com:8443", environment=env, credential="reporter")
                credentials.assert_called_once_with(root_certificates=b"root-ca", private_key=b"reporter-key", certificate_chain=b"reporter-cert")
                secure.assert_called_once()
            with self.assertRaisesRegex(ValueError, "credential"):
                grpc_channel("telemetry.example.com:8443", environment=env, credential="other")

    @unittest.skipIf(importlib.util.find_spec("dotenv") is None, "python-dotenv is not installed in this host environment")
    def test_env_file_resolves_relative_telemetry_credential_paths(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            root = Path(directory)
            (root / ".env").write_text(
                "PRIVOKE_TELEMETRY_TLS_CERT_FILE=secrets/reporter.crt\nPRIVOKE_TELEMETRY_TLS_KEY_FILE=secrets/reporter.key\n",
                encoding="utf-8",
            )
            load_runtime_environment(root)
            self.assertEqual(Path(os.environ["PRIVOKE_TELEMETRY_TLS_CERT_FILE"]), (root / "secrets/reporter.crt").resolve())
            self.assertEqual(Path(os.environ["PRIVOKE_TELEMETRY_TLS_KEY_FILE"]), (root / "secrets/reporter.key").resolve())

    def test_server_with_tls_refuses_to_start_without_an_identity_allow_list(self):
        with self.assertRaisesRegex(ValueError, "PRIVOKE_SERVER_ALLOWED_IDENTITIES"):
            PeerIdentityGuard()
        with self.assertRaisesRegex(ValueError, "PRIVOKE_SERVER_ALLOWED_IDENTITIES"):
            PeerIdentityGuard(registry_path="registry.toml")  # a registry without roles admits nobody

    def test_service_channel_uses_plaintext_without_an_identity_and_warns_for_non_loopback(self):
        with patch("grpc.insecure_channel") as insecure, self.assertLogs("privoke_service.stack_connection", logging.WARNING):
            service_channel("client-runtime:50054", environment={})
        insecure.assert_called_once()
        with patch("grpc.insecure_channel") as insecure:
            service_channel("127.0.0.1:50054", environment={})
            insecure.assert_called_once()


@unittest.skipIf(TOOL is None, "privoke-pki is not built and cargo is unavailable")
class MutualTlsTests(unittest.TestCase):
    def setUp(self):
        self.runtime = TelemetryStandIn(PKI.server_environment("urn:privoke:service:fuzzer"))
        self.addCleanup(self.runtime.stop)
        self.fuzzer = PKI.service("fuzzer", "runtime")
        self.intruder = PKI.service("intruder", "publisher")

    def env_for(self, credential):
        return PKI.client_environment(*credential)

    def test_allowed_service_certificate_is_accepted(self):
        response = health(self.runtime.target, self.env_for(self.fuzzer))
        self.assertEqual((response.service, response.status), ("telemetry-service", "SERVING"))

    def test_r6_plaintext_call_to_a_tls_server_is_refused(self):
        from privoke.v1 import telemetry_pb2, telemetry_pb2_grpc

        with grpc.insecure_channel(self.runtime.target) as channel, self.assertRaises(grpc.RpcError) as caught:
            telemetry_pb2_grpc.TelemetryServiceStub(channel).Health(telemetry_pb2.TelemetryHealthRequest(), timeout=5)
        self.assertEqual(caught.exception.code(), grpc.StatusCode.UNAVAILABLE)

    def test_a_tls_client_without_a_certificate_is_refused(self):
        from privoke.v1 import telemetry_pb2, telemetry_pb2_grpc

        credentials = grpc.ssl_channel_credentials(root_certificates=PKI.server_ca_pem.read_bytes())
        with grpc.secure_channel(self.runtime.target, credentials) as channel, self.assertRaises(grpc.RpcError) as caught:
            telemetry_pb2_grpc.TelemetryServiceStub(channel).Health(telemetry_pb2.TelemetryHealthRequest(), timeout=5)
        self.assertEqual(caught.exception.code(), grpc.StatusCode.UNAVAILABLE)

    def test_a_valid_certificate_for_another_identity_gets_permission_denied(self):
        with self.assertRaises(grpc.RpcError) as caught:
            health(self.runtime.target, self.env_for(self.intruder))
        self.assertEqual(caught.exception.code(), grpc.StatusCode.PERMISSION_DENIED)

    def test_a_certificate_from_another_ca_is_refused_at_the_handshake(self):
        other = PkiFixture(TOOL)
        self.addCleanup(other.close)
        stranger = other.service("fuzzer", "runtime")
        env = {**PKI.client_environment(*stranger)}
        with self.assertRaises(grpc.RpcError) as caught:
            health(self.runtime.target, env)
        self.assertEqual(caught.exception.code(), grpc.StatusCode.UNAVAILABLE)

    def test_a_client_that_does_not_trust_the_server_ca_is_refused(self):
        env = {**self.env_for(self.fuzzer), "PRIVOKE_TLS_CA_FILE": str(PKI.client_ca_pem)}
        with self.assertRaises(grpc.RpcError) as caught:
            health(self.runtime.target, env)
        self.assertEqual(caught.exception.code(), grpc.StatusCode.UNAVAILABLE)

    def test_registry_deny_list_and_role_admission_apply_without_restart(self):
        registry = Path(PKI.root) / "python-registry.toml"
        registry.write_text(PKI.registry.read_text(encoding="utf-8"), encoding="utf-8")
        environment = PKI.server_environment(
            "", PRIVOKE_SERVER_REGISTRY_FILE=str(registry), PRIVOKE_SERVER_ALLOWED_ROLES="runtime"
        )
        server = TelemetryStandIn({**environment, "PRIVOKE_SERVER_ALLOWED_IDENTITIES": ""})
        self.addCleanup(server.stop)
        # The fuzzer is a registered runtime-role service; the intruder is a publisher.
        self.assertEqual(health(server.target, self.env_for(self.fuzzer)).status, "SERVING")
        with self.assertRaises(grpc.RpcError) as caught:
            health(server.target, self.env_for(self.intruder))
        self.assertEqual(caught.exception.code(), grpc.StatusCode.PERMISSION_DENIED)
        # A deny entry takes effect on the next call over a new connection.
        registry.write_text(
            registry.read_text(encoding="utf-8") + f'\n[[deny]]\nurn = "urn:privoke:service:fuzzer"\nreason = "test"\n',
            encoding="utf-8",
        )
        with self.assertRaises(grpc.RpcError) as caught:
            health(server.target, self.env_for(self.fuzzer))
        self.assertEqual(caught.exception.code(), grpc.StatusCode.PERMISSION_DENIED)
        # A broken edit keeps the previous registry (the deny entry stays in force).
        registry.write_text("not = [valid", encoding="utf-8")
        with self.assertRaises(grpc.RpcError) as caught:
            health(server.target, self.env_for(self.fuzzer))
        self.assertEqual(caught.exception.code(), grpc.StatusCode.PERMISSION_DENIED)

    def test_an_invalid_registry_at_startup_refuses_to_start(self):
        bad = Path(PKI.root) / "bad-registry.toml"
        bad.write_text("version = 2\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "registry"):
            PeerIdentityGuard(["urn:privoke:service:fuzzer"], registry_path=bad)

    def test_the_fuzzer_service_channel_uses_its_service_certificate(self):
        with service_channel(self.runtime.target, environment=self.env_for(self.fuzzer)) as channel:
            from privoke.v1 import telemetry_pb2, telemetry_pb2_grpc

            response = telemetry_pb2_grpc.TelemetryServiceStub(channel).Health(telemetry_pb2.TelemetryHealthRequest(), timeout=5)
        self.assertEqual(response.status, "SERVING")

    def test_healthcheck_probes_a_tls_server_with_the_service_identity(self):
        import grpc_healthcheck

        generated = Path(__file__).resolve().parents[3] / "extension/client-runtime/generated"
        environment = {**PKI.server_environment("urn:privoke:service:fuzzer"), **self.env_for(self.fuzzer)}
        with patch.dict(os.environ, environment):
            grpc_healthcheck.check_health("telemetry-service", self.runtime.target, generated)
        with patch.dict(os.environ, {**environment, "PRIVOKE_TLS_CERT_FILE": str(self.intruder[0]), "PRIVOKE_TLS_KEY_FILE": str(self.intruder[1])}):
            with self.assertRaises(grpc.RpcError):
                grpc_healthcheck.check_health("telemetry-service", self.runtime.target, generated)


def _file(directory, name, content):
    path = Path(directory) / name
    path.write_bytes(content)
    return str(path)


def _executor():
    from concurrent import futures

    return futures.ThreadPoolExecutor(max_workers=1)


if __name__ == "__main__":
    unittest.main()
