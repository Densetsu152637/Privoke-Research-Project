import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "app", ROOT / "generated", ROOT.parents[1] / "shared/python"):
    sys.path.insert(0, str(path))
import grpc
from fuzzer_requests import FuzzerRequestConfig, request_fuzzer_loop
from training_cycles import TrainingCycles
from privoke.v1 import parameters_pb2 as pb


class Rejection(grpc.RpcError):
    def code(self):
        return grpc.StatusCode.FAILED_PRECONDITION


class DualTrainingCycleTests(unittest.TestCase):
    def test_terminal_partial_next_periodic_cycle_gets_new_ids_and_seed(self):
        journal=TrainingCycles(self.config.state_path)
        self.addCleanup(journal.close)
        first=journal.reserve(self.config)
        first["stages"]["heads"].update(state="accepted",applied_version="S1")
        first["stages"]["full_encoder"]["state"]="rejected"
        first.update(state="partial",finished_at=100.)
        journal.save(first)
        with patch("training_cycles.time.time",return_value=200.):
            second=journal.reserve(replace(self.config,interval_seconds=50))
        self.assertEqual(second["seed"],first["seed"]+1)
        self.assertNotEqual(second["cycle_id"],first["cycle_id"])

    def test_completed_restart_respects_remaining_cadence_and_explicit_new_payload(self):
        journal=TrainingCycles(self.config.state_path)
        self.addCleanup(journal.close)
        record=journal.reserve(self.config)
        record.update(state="complete",finished_at=100.)
        journal.save(record)
        with patch("training_cycles.time.time",return_value=110.):
            self.assertEqual(journal.reserve(replace(self.config,interval_seconds=50))["cycle_id"],record["cycle_id"])
        different=journal.reserve(replace(self.config,prompt_count=64))
        self.assertNotEqual(different["cycle_id"],record["cycle_id"])

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.config = FuzzerRequestConfig("unused", 32, "privoke-balanced", "updater", 60, 0, 0, 0, 2, 42,
                                         state_path=str(Path(self.temporary.name) / "cycles.sqlite3"))

    def response(self, version, base="v0"):
        return pb.FuzzerTrainingResponse(accepted=True, model_id="privoke-balanced", base_version=base,
                                         applied_version=version, prompts_generated=32)

    def record(self):
        with closing(sqlite3.connect(self.config.state_path)) as connection:
            return json.loads(connection.execute("SELECT record FROM cycles ORDER BY sequence DESC LIMIT 1").fetchone()[0])

    def test_head_then_full_fresh_base_persisted_requests_and_completed_restart_no_calls(self):
        with patch("fuzzer_requests.request_fuzzer_training", side_effect=[self.response("S1"), self.response("S2", "S1")]) as rpc:
            request_fuzzer_loop(self.config)
        self.assertEqual([c.kwargs["training_scope"] for c in rpc.call_args_list], ["heads", "full_encoder"])
        self.assertEqual(rpc.call_args_list[1].kwargs["expected_base_version"], "S1")
        record = self.record()
        self.assertEqual(record["state"], "complete")
        self.assertNotEqual(record["stages"]["heads"]["request_id"], record["stages"]["full_encoder"]["request_id"])
        request = pb.FuzzerTrainingRequest.FromString(bytes.fromhex(record["stages"]["full_encoder"]["request_protobuf_hex"]))
        self.assertEqual(request.metadata["expected_base_version"], "S1")
        self.assertEqual(request.seed, 42)
        with patch("fuzzer_requests.request_fuzzer_training") as rpc:
            request_fuzzer_loop(self.config)
        rpc.assert_not_called()

    def test_pending_full_resumes_on_restart_without_recalling_head_even_if_transport_changes(self):
        with patch("fuzzer_requests.request_fuzzer_training", side_effect=[self.response("S1"), RuntimeError("lost ack"), RuntimeError("offline")]):
            request_fuzzer_loop(self.config)
        before = self.record()
        self.assertEqual(before["state"], "pending")
        with patch("fuzzer_requests.request_fuzzer_training", return_value=self.response("S2", "S1")) as rpc:
            request_fuzzer_loop(replace(self.config, target="new-target", timeout_seconds=90))
        self.assertEqual(rpc.call_count, 1)
        self.assertEqual(rpc.call_args.kwargs["training_scope"], "full_encoder")
        self.assertEqual(rpc.call_args.kwargs["training_request_id"], before["stages"]["full_encoder"]["request_id"])

    def test_lost_head_ack_retries_identical_identity_and_seed(self):
        with patch("fuzzer_requests.request_fuzzer_training", side_effect=[RuntimeError("lost"), self.response("S1"), self.response("S2", "S1")]) as rpc:
            request_fuzzer_loop(self.config)
        self.assertEqual(rpc.call_args_list[0].kwargs, rpc.call_args_list[1].kwargs)
        self.assertEqual(rpc.call_args_list[0].args[0].seed, rpc.call_args_list[1].args[0].seed)

    def test_terminal_full_safety_rejection_retains_head_and_reports_partial(self):
        with patch("fuzzer_requests.request_fuzzer_training", side_effect=[self.response("S1"), Rejection()]) as rpc:
            request_fuzzer_loop(self.config)
        record = self.record()
        self.assertEqual(record["state"], "partial")
        self.assertEqual(record["stages"]["heads"]["state"], "accepted")
        self.assertEqual(record["stages"]["full_encoder"]["state"], "rejected")
        with patch("fuzzer_requests.request_fuzzer_training") as rpc:
            request_fuzzer_loop(self.config)
        rpc.assert_not_called()

    def test_pending_config_conflict_fails_closed_zero_disables_both(self):
        with patch("fuzzer_requests.request_fuzzer_training", side_effect=RuntimeError("offline")):
            request_fuzzer_loop(self.config)
        with self.assertRaisesRegex(ValueError, "different training settings"):
            request_fuzzer_loop(replace(self.config, prompt_count=64))
        with patch("fuzzer_requests.request_fuzzer_training") as rpc:
            request_fuzzer_loop(replace(self.config, prompt_count=0))
        rpc.assert_not_called()
