"""Validate Compose entry points without starting services or detector tests."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(shutil.which("docker"), "Docker Compose CLI is unavailable")
class ComposeDefaultsTests(unittest.TestCase):
    def render(self, *files: str) -> dict:
        environment = {key: value for key, value in os.environ.items()
                       if key not in {"COMPOSE_FILE", "COMPOSE_PROFILES"}}
        command = ["docker", "compose", "--profile", "*"]
        for file in files:
            command.extend(["-f", file])
        result = subprocess.run(
            command + ["config", "--no-interpolate", "--no-env-resolution", "--format", "json"],
            cwd=ROOT, env=environment, capture_output=True, text=True, check=True, timeout=30,
        )
        return json.loads(result.stdout)

    def test_default_selects_development_images_and_loopback_ports(self) -> None:
        config = self.render()
        for name, port in (("model-streaming-service", 50051), ("param-update-service", 50052),
                           ("privoke-fuzzer", 50053), ("client-runtime", 50054), ("telemetry-service", 50055)):
            with self.subTest(service=name):
                service = config["services"][name]
                self.assertEqual(service["build"]["target"], "development")
                self.assertTrue(service["image"].endswith(f"-{name}-dev"))
                self.assertFalse(service["read_only"])
                self.assertEqual(service["restart"], "no")
                self.assertTrue(any(binding["target"] == port and binding["host_ip"] == "127.0.0.1"
                                    and binding["published"] == str(port) for binding in service["ports"]))

    def test_explicit_production_preserves_hardening_and_internal_ports(self) -> None:
        config = self.render("docker-compose.prod.yml")
        for name, service in config["services"].items():
            if name == "storage-permissions":
                continue
            with self.subTest(service=name):
                self.assertNotIn("ports", service)
                self.assertNotIn("target", service["build"])
                self.assertTrue(service["read_only"])
                self.assertEqual(service["restart"], "unless-stopped")
                self.assertIn("ALL", service["cap_drop"])

    def test_research_overlays_explicitly_retain_production(self) -> None:
        config = self.render("docker-compose.prod.yml", "evaluation/compose.tests.yml", "evaluation/compose.presence.yml")
        for name in ("client-runtime", "presence-update-service", "presence-fuzzer"):
            with self.subTest(service=name):
                service = config["services"][name]
                self.assertNotIn("target", service["build"])
                self.assertTrue(service["read_only"])


if __name__ == "__main__":
    unittest.main()
