from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from privoke_service.stack_connection import grpc_channel, load_runtime_environment, stack_target, use_local_stack


class StackConnectionTests(unittest.TestCase):
    def test_cloud_is_default_and_missing_configuration_does_not_fall_back(self):
        self.assertFalse(use_local_stack({}))
        self.assertEqual(stack_target("MODEL_STREAMING", {}), "")
        with self.assertRaisesRegex(ValueError, "PRIVOKE_CLOUD_TARGET"):
            grpc_channel("", environment={})

    def test_both_services_switch_together_without_cloud_credentials(self):
        cloud = {"PRIVOKE_CLOUD_TARGET": "stack.example.com:443"}
        for service, port in (("MODEL_STREAMING", 50051), ("TELEMETRY", 50055)):
            self.assertEqual(stack_target(service, cloud), "stack.example.com:443")
            self.assertEqual(stack_target(service, {**cloud, "PRIVOKE_USE_LOCAL_STACK": "true"}), f"127.0.0.1:{port}")

    def test_internal_mode_preserves_compose_routing(self):
        env = {"PRIVOKE_STACK_MODE": "internal", "MODEL_STREAMING_TARGET": "model-streaming-service:50051"}
        self.assertEqual(stack_target("MODEL_STREAMING", env), env["MODEL_STREAMING_TARGET"])
        with patch("grpc.insecure_channel") as channel:
            grpc_channel(env["MODEL_STREAMING_TARGET"], environment=env)
            channel.assert_called_once_with(env["MODEL_STREAMING_TARGET"], options=())

    def test_cloud_requires_client_identity(self):
        with self.assertRaisesRegex(ValueError, "PRIVOKE_TLS_CERT_FILE"):
            grpc_channel("stack.example.com:443", environment={})

    def test_cloud_channel_uses_verified_tls_and_client_certificate(self):
        with tempfile.TemporaryDirectory() as directory:
            env = {}
            for variable, content in (("PRIVOKE_TLS_CERT_FILE", b"certificate"), ("PRIVOKE_TLS_KEY_FILE", b"private-key"), ("PRIVOKE_TLS_CA_FILE", b"root-ca")):
                path = Path(directory) / variable
                path.write_bytes(content)
                env[variable] = str(path)
            with patch("grpc.ssl_channel_credentials") as credentials, patch("grpc.secure_channel") as secure, patch("grpc.insecure_channel") as insecure:
                grpc_channel("stack.example.com:443", environment=env)
                credentials.assert_called_once_with(root_certificates=b"root-ca", private_key=b"private-key", certificate_chain=b"certificate")
                secure.assert_called_once_with("stack.example.com:443", credentials.return_value, options=())
                insecure.assert_not_called()

    def test_env_file_is_loaded_without_cwd_search_or_overriding_process_environment(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"PRIVOKE_CLOUD_TARGET": "override.example:443"}, clear=True):
            root = Path(directory)
            (root / ".env").write_text("PRIVOKE_CLOUD_TARGET=ignored.example:443\nPRIVOKE_TLS_KEY_FILE=secrets/client.key\nOPENAI_API_KEY=literal-${NO_EXPANSION}\n", encoding="utf-8")
            load_runtime_environment(root)
            self.assertEqual(os.environ["PRIVOKE_CLOUD_TARGET"], "override.example:443")
            self.assertEqual(Path(os.environ["PRIVOKE_TLS_KEY_FILE"]), root / "secrets/client.key")
            self.assertEqual(os.environ["OPENAI_API_KEY"], "literal-${NO_EXPANSION}")

    def test_explicit_env_file_supports_installed_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "private.env"
            config.write_text("PRIVOKE_USE_LOCAL_STACK=true\n", encoding="utf-8")
            with patch.dict(os.environ, {"PRIVOKE_ENV_FILE": str(config)}, clear=True):
                load_runtime_environment(Path(directory) / "package")
                self.assertTrue(use_local_stack())

    def test_malformed_hidden_setting_is_rejected(self):
        with self.assertRaises(ValueError):
            use_local_stack({"PRIVOKE_USE_LOCAL_STACK": "maybe"})


if __name__ == "__main__":
    unittest.main()
