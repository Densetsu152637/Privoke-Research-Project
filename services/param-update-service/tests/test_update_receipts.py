import json
import shutil
import sqlite3
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "app", ROOT / "generated", ROOT.parents[1] / "shared/python"):
    sys.path.insert(0, str(path))

from privoke.v1 import parameters_pb2
from server import ParamUpdateService
from receipts import UpdateReceipts


class Context:
    def abort(self, code, message):
        raise RuntimeError(f"{code}: {message}")


class UpdateReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.artifact = self.directory / "model.json"
        shutil.copyfile(ROOT.parents[1] / "models/privoke-baseline.json", self.artifact)
        self.audit = self.directory / "updates.jsonl"
        self.initial = json.loads(self.artifact.read_text())
        self.request = parameters_pb2.ParameterUpdateRequest(
            source_id="fuzzer", model_id="privoke-baseline", base_version=self.initial["version"],
            gradients=[parameters_pb2.Parameter(name="head.sensitivity.bias", shape=[4], values=[0, 0, 0, 0.01])],
            metadata={"request_id": "cycle-1", "request_source_id": "experiment", "training_request_fingerprint": "intent-1", "generated_prompt_count": "8"},
        )

    def service(self):
        return ParamUpdateService(self.audit, "privoke-baseline", model_artifact_path=self.artifact)

    def lookup(self, fingerprint="intent-1"):
        return self.service().GetParameterUpdateStatus(parameters_pb2.ParameterUpdateStatusRequest(
            source_id="fuzzer", request_id="cycle-1", request_source_id="experiment", model_id="privoke-baseline", request_fingerprint=fingerprint,
        ), Context())

    def test_duplicate_update_and_restart_preserve_original_outcome(self):
        first = self.service().SubmitParameterUpdate(self.request, Context())
        published = self.artifact.read_bytes()
        second = self.service().SubmitParameterUpdate(self.request, Context())
        self.assertEqual(second.applied_version, first.applied_version)
        self.assertEqual(self.artifact.read_bytes(), published)
        self.assertEqual(len(self.audit.read_text().splitlines()), 1)
        status = self.lookup()
        self.assertTrue(status.found)
        self.assertEqual(status.ack.applied_version, first.applied_version)
        self.assertEqual(status.prompts_generated, 8)

    def test_conflicting_reuse_is_rejected_without_another_update(self):
        self.service().SubmitParameterUpdate(self.request, Context())
        published = self.artifact.read_bytes()
        self.request.gradients[0].values[3] = 0.02
        with self.assertRaisesRegex(RuntimeError, "different parameter update"):
            self.service().SubmitParameterUpdate(self.request, Context())
        with self.assertRaisesRegex(RuntimeError, "different training request"):
            self.lookup("changed-intent")
        self.assertEqual(self.artifact.read_bytes(), published)

    def test_model_commit_recovers_after_receipt_database_failure(self):
        with patch("receipts.UpdateReceipts.put", side_effect=sqlite3.OperationalError("simulated interrupted commit")):
            with self.assertRaisesRegex(RuntimeError, "persistence failed"):
                self.service().SubmitParameterUpdate(self.request, Context())
        published = self.artifact.read_bytes()
        status = self.lookup()
        self.assertTrue(status.found)
        replay = self.service().SubmitParameterUpdate(self.request, Context())
        self.assertEqual(replay.applied_version, status.ack.applied_version)
        self.assertEqual(self.artifact.read_bytes(), published)

    def test_concurrent_services_commit_the_same_request_once(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(lambda _: self.service().SubmitParameterUpdate(self.request, Context()), range(2)))
        self.assertEqual(responses[0].applied_version, responses[1].applied_version)
        self.assertEqual(len(self.audit.read_text().splitlines()), 1)

    def test_recovery_is_durable_before_another_interrupted_publication(self):
        with patch("receipts.UpdateReceipts.put", side_effect=sqlite3.OperationalError("first interruption")):
            with self.assertRaises(RuntimeError):
                self.service().SubmitParameterUpdate(self.request, Context())
        first_version = json.loads(self.artifact.read_text())["version"]
        second = parameters_pb2.ParameterUpdateRequest()
        second.CopyFrom(self.request)
        second.base_version = first_version
        second.metadata["request_id"] = "cycle-2"
        original_put = UpdateReceipts.put

        def fail_new_receipt(store, receipt):
            if receipt["base_version"] == first_version:
                raise sqlite3.OperationalError("second interruption")
            return original_put(store, receipt)

        with patch.object(UpdateReceipts, "put", new=fail_new_receipt):
            with self.assertRaises(RuntimeError):
                self.service().SubmitParameterUpdate(second, Context())
        self.assertEqual(self.lookup().ack.applied_version, first_version)
        self.assertEqual(self.service().SubmitParameterUpdate(second, Context()).applied_version, json.loads(self.artifact.read_text())["version"])

    def test_anonymous_update_cannot_erase_a_pending_receipt(self):
        with patch("receipts.UpdateReceipts.put", side_effect=sqlite3.OperationalError("interruption")):
            with self.assertRaises(RuntimeError):
                self.service().SubmitParameterUpdate(self.request, Context())
        first_version = json.loads(self.artifact.read_text())["version"]
        anonymous = parameters_pb2.ParameterUpdateRequest()
        anonymous.CopyFrom(self.request)
        anonymous.base_version = first_version
        anonymous.metadata.clear()
        self.service().SubmitParameterUpdate(anonymous, Context())
        self.assertEqual(self.lookup().ack.applied_version, first_version)
