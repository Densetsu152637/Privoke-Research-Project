from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "run_external_pii_study", ROOT / "evaluation/run-external-pii-study.py")
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)

from privoke_model.artifact import artifact_checksum


def fixture_artifact(model_id: str) -> dict:
    path = ROOT / "shared/python/tests/fixtures/presence-efficient.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    profile = model_id.removeprefix("privoke-presence-")
    value["model_id"] = model_id
    value["config"]["profile"] = profile
    limits = {"efficient": 2000, "balanced": 8000, "quality": 16000}
    for branch in value["config"]["branches"].values():
        branch["max_features"] = limits[profile]
    value["checksum"] = artifact_checksum({key: item for key, item in value.items() if key != "checksum"})
    return value


class FakeBackend:
    def __init__(self, catalog: dict[str, bytes], *, install_error: bool = False,
                 restore_error: bool = False):
        self.catalog = dict(catalog)
        self.install_error = install_error
        self.restore_error = restore_error
        self.restore_calls = []

    def read_raw(self, model_id):
        return self.catalog[model_id]

    def restore_exact(self, model_id, raw):
        self.restore_calls.append(model_id)
        if self.restore_error and model_id == "privoke-presence-balanced":
            raise OSError("fake restore failure")
        self.catalog[model_id] = raw

    def install(self, artifact):
        model_id = artifact["model_id"]
        self.catalog[model_id] = json.dumps(artifact, sort_keys=True).encode("utf-8")
        if self.install_error:
            raise RuntimeError("fake partial install failure")

    @staticmethod
    def identity(artifact):
        return {"model_id": artifact["model_id"]}

    def wait_identity(self, expected):
        return None


class ExternalPresenceRunnerTests(unittest.TestCase):
    def setUp(self):
        self.artifacts = {model_id: fixture_artifact(model_id) for model_id in runner.MODEL_IDS.values()}
        self.artifacts["privoke-balanced"] = json.loads(
            (ROOT / "models/privoke-balanced.json").read_text(encoding="utf-8"))
        self.raw = {model_id: (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
                    for model_id, value in self.artifacts.items()}
        self.temp = tempfile.TemporaryDirectory()
        self.output = Path(self.temp.name) / "study"

    def tearDown(self):
        self.temp.cleanup()

    def test_restores_byte_exact_models_after_rpc_failure(self):
        backend = FakeBackend(self.raw)
        before = {key: hashlib.sha256(value).hexdigest() for key, value in self.raw.items()}

        def fail_rpc():
            backend.install(fixture_artifact("privoke-presence-balanced"))
            raise RuntimeError("simulated scorer failure")

        with patch.object(runner, "BALANCED_CHECKSUM", self.artifacts["privoke-balanced"]["checksum"]):
            self.output.mkdir(parents=True)
            manifest = {}
            with self.assertRaisesRegex(RuntimeError, "scorer failure"):
                with runner.protected_catalog(backend, self.output, manifest):
                    fail_rpc()
        after = {key: hashlib.sha256(value).hexdigest() for key, value in backend.catalog.items()}
        self.assertEqual(after, before)
        self.assertTrue(manifest["restoration_verified"])
        self.assertEqual(set(backend.restore_calls), set(runner.MODEL_IDS.values()))
        backup = self.output / "private-backups/privoke-presence-balanced.json.base64"
        self.assertEqual(base64_decode(backup.read_bytes()), self.raw["privoke-presence-balanced"])

    def test_restores_partial_install_failure_in_finally(self):
        backend = FakeBackend(self.raw, install_error=True)
        before = dict(self.raw)
        with patch.object(runner, "BALANCED_CHECKSUM", self.artifacts["privoke-balanced"]["checksum"]):
            self.output.mkdir(parents=True)
            manifest = {}
            with self.assertRaisesRegex(RuntimeError, "partial install"):
                with runner.protected_catalog(backend, self.output, manifest):
                    backend.install(fixture_artifact("privoke-presence-efficient"))
            self.assertTrue(manifest["restoration_verified"])
        self.assertEqual(backend.catalog, before)

    def test_restoration_failure_is_retained_and_reported(self):
        backend = FakeBackend(self.raw, restore_error=True)
        with patch.object(runner, "BALANCED_CHECKSUM", self.artifacts["privoke-balanced"]["checksum"]):
            self.output.mkdir(parents=True)
            manifest = {}
            with self.assertRaisesRegex(RuntimeError, "restoration failed"):
                with runner.protected_catalog(backend, self.output, manifest):
                    pass
        self.assertFalse(manifest["restoration_verified"])
        self.assertEqual(manifest["restoration_failures"][0]["model_id"], "privoke-presence-balanced")

    def test_fixed_plan_contains_only_whitelisted_presence_rows(self):
        plan = runner.fixed_plan()
        self.assertEqual(len(plan), 18)
        self.assertEqual({item[0] for item in plan}, set(runner.PROFILES))
        self.assertEqual({item[1] for item in plan}, set(runner.CONTROLS))
        self.assertEqual({item[2] for item in plan}, set(runner.PARTITIONS))
        self.assertNotIn("development", runner.PARTITIONS)
        self.assertNotIn("final", runner.PARTITIONS)

    def test_current_revision_reads_this_checkout_with_scoped_safe_directory(self):
        observed = runner.current_revision()
        self.assertRegex(observed, r"^[0-9a-f]{40,64}$")

    def test_paths_outside_results_and_nonwhitelist_ids_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "evaluation/results"):
            runner.result_path(Path(self.temp.name))
        with self.assertRaisesRegex(ValueError, "whitelist"):
            runner.validate_catalog_artifact(self.raw["privoke-balanced"], "privoke-presence-unknown")


def base64_decode(value: bytes) -> bytes:
    import base64
    return base64.b64decode(value, validate=True)


if __name__ == "__main__":
    unittest.main()
