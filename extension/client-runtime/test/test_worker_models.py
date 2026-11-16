"""The worker's read-only model provider against the stage 0 model-streaming corpus."""
from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

from src import worker_main
from worker_harness import LEGACY_MODEL_ROOT, REPOSITORY_ROOT, V3_MODEL_ID, v3_model_root

CORPUS = REPOSITORY_ROOT / "tests" / "conformance" / "model_streaming.json"


class LegacySnapshotMatchesGoServiceTests(unittest.TestCase):
    def test_snapshot_equals_what_the_go_streaming_service_serves(self):
        corpus = json.loads(CORPUS.read_text())["legacy"]
        provider = worker_main.LocalModelProvider([LEGACY_MODEL_ROOT])
        for model_id, recorded in corpus.items():
            with self.subTest(model_id):
                recorded = recorded["get_model_parameters"]
                snapshot = provider.fetch(model_id)
                self.assertEqual((snapshot.model_id, snapshot.version, snapshot.generated_at_unix),
                                 (recorded["model_id"], recorded["version"], recorded["generated_at_unix"]))
                wire_metadata = {key: value for key, value in recorded["metadata"].items()
                                 if key not in ("served_by", "consumer_id")}
                self.assertEqual(dict(snapshot.metadata), wire_metadata)
                self.assertEqual([item["name"] for item in recorded["parameters"]], sorted(snapshot.parameters))
                for item in recorded["parameters"]:
                    values = snapshot.parameters[item["name"]]
                    self.assertEqual(list(snapshot.shapes[item["name"]]), item["shape"])
                    self.assertEqual(len(values), item["values"])
                    self.assertEqual(hashlib.sha256(struct.pack(f"<{len(values)}f", *values)).hexdigest(),
                                     item["values_sha256_f32le"])


class ProviderBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.provider = worker_main.LocalModelProvider([LEGACY_MODEL_ROOT])

    def test_identifiers_cannot_escape_the_model_roots(self):
        for model_id in ("../privoke-balanced", "..\\privoke-balanced", "a/b", "", "latest.json/../x", " privoke-balanced"):
            with self.subTest(model_id=model_id):
                with self.assertRaises(ValueError):
                    self.provider.fetch(model_id)

    def test_latest_needs_an_explicit_target(self):
        with self.assertRaisesRegex(ValueError, "latest"):
            self.provider.fetch("latest")
        pinned = worker_main.LocalModelProvider([LEGACY_MODEL_ROOT], latest_model_id="privoke-balanced")
        self.assertEqual(pinned.fetch("latest").model_id, "privoke-balanced")

    def test_missing_model_and_non_directory_root_fail(self):
        with self.assertRaisesRegex(ValueError, "not available"):
            self.provider.fetch("privoke-absent")
        with self.assertRaises(ValueError):
            worker_main.LocalModelProvider([LEGACY_MODEL_ROOT / "privoke-balanced.json"])

    def test_scratch_presence_and_pretrained_context_are_refused(self):
        from privoke_model.scratch_presence import SCRATCH_PRESENCE_MODEL_IDS
        with tempfile.TemporaryDirectory() as directory:
            source = json.loads((LEGACY_MODEL_ROOT / "privoke-balanced.json").read_text())
            scratch_id = sorted(SCRATCH_PRESENCE_MODEL_IDS)[0]
            (Path(directory) / f"{scratch_id}.json").write_text(json.dumps({**source, "model_id": scratch_id}))
            with self.assertRaises(ValueError):
                worker_main.LocalModelProvider([directory]).fetch(scratch_id)

    def test_a_tampered_artifact_is_rejected_by_the_artifact_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            source = json.loads((LEGACY_MODEL_ROOT / "privoke-balanced.json").read_text())
            first = next(iter(source["parameters"]))
            source["parameters"][first]["values"][0] += 1.0
            (Path(directory) / "privoke-balanced.json").write_text(json.dumps(source))
            with self.assertRaises(Exception):
                worker_main.LocalModelProvider([directory]).fetch("privoke-balanced")

    def test_pinned_v3_package_loads_and_is_verified_once(self):
        root = v3_model_root()
        if root is None:
            self.skipTest("pretrained-V3 standard release is not available in this checkout")
        provider = worker_main.LocalModelProvider([root])
        package = provider.fetch(V3_MODEL_ID)
        self.assertEqual(package.model_id, V3_MODEL_ID)
        self.assertIs(provider.fetch(V3_MODEL_ID), package)


class OfflineRuntimeTests(unittest.TestCase):
    def test_network_helpers_fail_once_the_offline_runtime_is_installed(self):
        from src.LLM.privoke import parameter_stream
        saved_fetch, saved_channel = parameter_stream.ModelParameterStreamer.fetch, parameter_stream.grpc_channel
        try:
            worker_main._install_offline_runtime(worker_main.LocalModelProvider([LEGACY_MODEL_ROOT]))
            with self.assertRaisesRegex(RuntimeError, "no network"):
                parameter_stream.grpc_channel("127.0.0.1:50051")
            snapshot = parameter_stream.ModelParameterStreamer(model_id="privoke-balanced", target="x:1").fetch()
            self.assertEqual(snapshot.model_id, "privoke-balanced")
        finally:
            parameter_stream.ModelParameterStreamer.fetch = saved_fetch
            parameter_stream.grpc_channel = saved_channel


if __name__ == "__main__":
    unittest.main()
