"""Validate Compose entry points without starting services or detector tests."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
LOOPBACK_DEFAULT = re.compile(r"127\.0\.0\.1:\d+|\$\{[A-Z_]+:-127\.0\.0\.1:\d+\}")
TLS_FLAGS = ("--cert=", "--key=", "--client-ca=", "--crl=", "--registry=")
ONE_SHOT = {"model-seed"}
PUBLIC = {"model-streaming-service": 50443, "telemetry-service": 58443}
INTERNAL = {50051, 50052, 50055, 50171, 50172}
V3_TRAINING = {"param-update-service", "v3-runtime", "v3-fuzzer"}
ANALYSIS = {"analysis-service", "analysis-model-streaming"}


def bindings(service: dict) -> list[tuple[str, int]]:
    """(host side, container port) for each published port, from either rendering Compose may produce."""
    result = []
    for entry in service.get("ports", []):
        if isinstance(entry, dict):
            result.append((f"{entry['host_ip']}:{entry['published']}", int(entry["target"])))
        else:
            host, _, target = entry.rpartition(":")
            result.append((host, int(target)))
    return result


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

    def test_default_publishes_the_rust_services_on_loopback_only(self) -> None:
        config = self.render()
        expected = {"model-streaming-service": {50443, 50051}, "telemetry-service": {58443, 50055},
                    "param-update-service": {50052}, "v3-fuzzer": {50172}, "v3-runtime": {50171}}
        for name, ports in expected.items():
            with self.subTest(service=name):
                service = config["services"][name]
                self.assertNotIn("target", service["build"])
                self.assertTrue(service["read_only"])
                self.assertEqual(service["restart"], "no")
                published = bindings(service)
                self.assertEqual({target for _, target in published}, ports)
                for host, _ in published:
                    self.assertRegex(host, LOOPBACK_DEFAULT)
        for name in ("analysis-service", "analysis-model-streaming"):
            with self.subTest(service=name):
                self.assertEqual(bindings(config["services"][name]), [])

    def test_explicit_production_is_hardened_mutual_tls_with_two_public_ports(self) -> None:
        config = self.render("docker-compose.prod.yml")
        self.assertEqual(
            set(config["services"]),
            {"model-seed", "model-streaming-service", "telemetry-service", "param-update-service", "v3-runtime", "v3-fuzzer",
             "analysis-model-streaming", "analysis-service"},
        )
        for name, service in config["services"].items():
            with self.subTest(service=name):
                self.assertNotIn("target", service["build"] if "build" in service else {})
                self.assertTrue(service["read_only"])
                self.assertIn("ALL", service["cap_drop"])
                self.assertIn("no-new-privileges:true", service["security_opt"])
                self.assertEqual(service["restart"], "no" if name in ONE_SHOT else "unless-stopped")
                published = bindings(service)
                if name in PUBLIC:
                    # Published on loopback unless the operator says otherwise; never an internal listener.
                    self.assertEqual([target for _, target in published], [PUBLIC[name]])
                    self.assertRegex(published[0][0], LOOPBACK_DEFAULT)
                else:
                    self.assertEqual(published, [])
                self.assertFalse(INTERNAL & {target for _, target in published})
                if name in {"model-streaming-service", "telemetry-service", "param-update-service", "v3-runtime", "v3-fuzzer",
                            "analysis-model-streaming", "analysis-service"}:
                    command = service["command"]
                    for flag in TLS_FLAGS:
                        self.assertTrue(any(item.startswith(flag) for item in command), (name, flag))
        for network in ("training", "analysis-fuzzer", "analysis-models"):
            self.assertTrue(config["networks"][network]["internal"])
        # The V3 routine-training stack (stage V3-R7): behind the V3 profile only, the fuzzer and the runtime on the internal
        # network alone (no route out, no published port), V1 training and the V1 fuzzer gone, the store and the published tree
        # shared with model-streaming, and every secret or staged input a mount rather than an image layer.
        for name in V3_TRAINING:
            self.assertEqual(config["services"][name]["profiles"], ["v3-training"], name)
        for name in ANALYSIS:
            self.assertEqual(config["services"][name]["profiles"], ["legacy-analysis"], name)
        for name in ("v3-runtime", "v3-fuzzer"):
            self.assertEqual(set(config["services"][name]["networks"]), {"training"}, name)
        self.assertEqual(set(config["services"]["param-update-service"]["networks"]), {"default", "training"})
        update = config["services"]["param-update-service"]["environment"]
        for key in ("V3_STORE", "V3_PINNED", "V3_PUBLISH_ROOT", "V3_PUBLICATION_KEY_FILE", "V3_PUBLICATION_KEY_ID", "V3_DRIFT_BOUNDS",
                    "V3_RETENTION_ROOT", "V3_RETENTION_BANK", "V3_POLICY_FILE", "V3_SOURCE_ROOT", "V3_TIERS", "FUZZER_TARGET"):
            self.assertIn(key, update, key)
        for key in ("MODEL_ID", "MODEL_ARTIFACT_PATH", "FUZZER_TRAIN_UNDERLYING"):
            self.assertNotIn(key, update, f"{key} is the V1 training model")
        self.assertEqual(update["FUZZER_TARGET"], "v3-fuzzer:50172")
        self.assertEqual(config["services"]["v3-fuzzer"]["environment"]["V3_MODE"], "routine")
        streaming = config["services"]["model-streaming-service"]["environment"]
        self.assertEqual((streaming["V3_STORE"], streaming["V3_PUBLISH_ROOT"]), ("/v3-store", "/v3-published"))
        for name in ("param-update-service", "v3-runtime", "v3-fuzzer"):
            for mount in config["services"][name]["volumes"]:
                if mount["target"] in {"/v3-source", "/v3-originals", "/model-releases", "/v3-retention-bank",
                                       "/run/privoke/v3-publication.key"}:
                    self.assertTrue(mount["read_only"], (name, mount["target"]))
        # The quarantined analysis service has no route out: only internal networks, no capabilities, bounded resources.
        analysis = config["services"]["analysis-service"]
        self.assertEqual(set(analysis["networks"]), {"analysis-fuzzer", "analysis-models"})
        for limit in ("mem_limit", "pids_limit", "cpus"):
            self.assertIn(limit, analysis)

    def test_no_deployment_file_has_a_proxy_or_a_plaintext_opt_out(self) -> None:
        self.assertFalse((ROOT / "deploy/gce/nginx.conf").exists())
        for file in ("docker-compose.yml", "docker-compose.prod.yml", "docker-compose.gpu.yml", "deploy/gce/compose.yml"):
            with self.subTest(file=file):
                text = (ROOT / file).read_text(encoding="utf-8").lower()
                self.assertNotIn("nginx", text)
                self.assertNotIn("allow_insecure", text)
        deploy = self.render("deploy/gce/compose.yml")
        self.assertNotIn("ingress", deploy["services"])
        # The deployment carries the same services except the quarantined V1 analysis service, which only the oracle checks use.
        self.assertEqual(set(deploy["services"]), set(self.render("docker-compose.prod.yml")["services"]) - ANALYSIS)
        self.assertFalse(ANALYSIS & set(deploy["services"]))
        self.assertTrue(deploy["networks"]["training"]["internal"])
        for name, service in deploy["services"].items():
            with self.subTest(service=name):
                self.assertNotIn("build", service)
                self.assertTrue({target for _, target in bindings(service)} <= set(PUBLIC.values()))

    def test_research_overlays_explicitly_retain_the_legacy_stack(self) -> None:
        # The historical study stacks were recorded on the Python and Go services, which now live in the retired
        # docker-compose.legacy.yml (the former production file, unchanged).
        config = self.render("docker-compose.legacy.yml", "evaluation/compose.tests.yml", "evaluation/compose.presence.yml")
        for name in ("client-runtime", "presence-update-service", "presence-fuzzer"):
            with self.subTest(service=name):
                service = config["services"][name]
                self.assertNotIn("target", service["build"])
                self.assertTrue(service["read_only"])


if __name__ == "__main__":
    unittest.main()
