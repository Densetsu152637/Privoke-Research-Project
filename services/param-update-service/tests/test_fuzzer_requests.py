"""Automatic cycle cadence, exploration seeds, and replay-safe retries."""
from __future__ import annotations

import os
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import grpc

SERVICE_ROOT = Path(__file__).resolve().parents[1]
for path in (SERVICE_ROOT / "app", SERVICE_ROOT / "generated"):
    sys.path.insert(0, str(path))

from fuzzer_requests import (
    FuzzerRequestConfig,
    request_fuzzer_loop,
    request_fuzzer_training,
    start_fuzzer_requester,
)
from privoke.v1 import parameters_pb2 as pb, parameters_pb2_grpc as rpc


class StopLoop(Exception):
    """Stop an otherwise periodic worker after the observed cycles."""


def configuration(**changes):
    return replace(FuzzerRequestConfig(
        target="fuzzer:50053", prompt_count=32, model_id="privoke-balanced",
        source_id="param-update-service", timeout_seconds=60,
        interval_seconds=3600, initial_delay_seconds=0, retry_seconds=2,
        max_attempts=2, seed=1337,
    ), **changes)


def accepted_response():
    return SimpleNamespace(accepted=True, model_id="privoke-balanced",
                           applied_version="v1+train.1", prompts_generated=32)


class AutomaticFuzzerRequestTests(unittest.TestCase):
    def test_explicit_sampler_seed_stays_stable_across_periodic_cycles(self):
        config = configuration(curriculum_sampler_policy="seeded_family_v1", curriculum_sampler_seed=42)
        config.validate()
        with patch("fuzzer_requests.request_fuzzer_training", side_effect=(accepted_response(), StopLoop())) as train, patch("fuzzer_requests.time.sleep"):
            with self.assertRaises(StopLoop):
                request_fuzzer_loop(config)
        self.assertEqual([call.args[0].curriculum_sampler_seed for call in train.call_args_list], [42, 42])
        self.assertEqual([call.args[0].seed for call in train.call_args_list], [1337, 1338])

    def test_sampler_environment_validation_and_rpc_metadata(self):
        with patch.dict(os.environ, {"FUZZER_CURRICULUM_SAMPLER_POLICY": "seeded_family_v1", "FUZZER_CURRICULUM_SAMPLER_SEED": "44"}, clear=True):
            config = FuzzerRequestConfig.from_env()
        for candidate in (configuration(curriculum_sampler_policy="bad"), configuration(curriculum_sampler_seed=42),
                          configuration(curriculum_sampler_policy="seeded_family_v1", curriculum_sampler_seed=-1),
                          configuration(curriculum_sampler_policy="seeded_family_v1", curriculum_sampler_seed=2**32)):
            with self.assertRaises(ValueError):
                candidate.validate()
        for candidate, metadata in ((configuration(), {"initiator": "param-update-service"}),
                                    (config, {"initiator": "param-update-service", "curriculum_sampler_policy": "seeded_family_v1", "curriculum_sampler_seed": "44"})):
            with patch("fuzzer_requests.grpc.insecure_channel"), patch("fuzzer_requests.parameters_pb2_grpc.FuzzerServiceStub") as stub:
                request_fuzzer_training(candidate, "cycle")
            self.assertEqual(dict(stub.return_value.RunTrainingCycle.call_args.args[0].metadata), metadata)

    def test_default_environment_starts_periodic_training(self):
        with patch.dict(os.environ, {}, clear=True):
            config = FuzzerRequestConfig.from_env()
        self.assertEqual(config.prompt_count, 32)
        self.assertEqual(config.interval_seconds, 3600)
        with patch("fuzzer_requests.threading.Thread") as thread:
            start_fuzzer_requester(config)
        thread.return_value.start.assert_called_once()

    def test_zero_prompt_count_opts_out(self):
        with patch.dict(os.environ, {"FUZZER_PROMPT_COUNT": "0"}, clear=True):
            config = FuzzerRequestConfig.from_env()
        with patch("fuzzer_requests.threading.Thread") as thread:
            start_fuzzer_requester(config)
        thread.assert_not_called()

    def test_new_cycles_have_new_identities_and_seeds(self):
        with patch("fuzzer_requests.request_fuzzer_training", side_effect=(
            accepted_response(), accepted_response(), StopLoop(),
        )) as train, patch("fuzzer_requests.time.sleep") as sleep:
            with self.assertRaises(StopLoop):
                request_fuzzer_loop(configuration())
        calls = train.call_args_list
        self.assertEqual([call.args[0].seed for call in calls], [1337, 1338, 1339])
        self.assertEqual(len({call.kwargs["training_request_id"] for call in calls}), 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [3600, 3600])

    def test_exhausted_cycle_waits_then_explores_a_new_batch(self):
        with patch("fuzzer_requests.request_fuzzer_training", side_effect=(
            RuntimeError("unavailable"), RuntimeError("unavailable"),
            accepted_response(), StopLoop(),
        )) as train, patch("fuzzer_requests.time.sleep") as sleep:
            with self.assertRaises(StopLoop):
                request_fuzzer_loop(configuration())
        first, retry, following, _ = train.call_args_list
        self.assertEqual(first.kwargs["training_request_id"], retry.kwargs["training_request_id"])
        self.assertEqual(first.args[0].seed, retry.args[0].seed)
        self.assertNotEqual(retry.kwargs["training_request_id"], following.kwargs["training_request_id"])
        self.assertEqual(following.args[0].seed, 1338)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [2, 3600, 3600])

    def test_one_shot_stops_after_success_or_bounded_failures(self):
        for effects, expected_attempts in (([accepted_response()], 1),
                                            ([RuntimeError("failed")] * 2, 2)):
            with self.subTest(attempts=expected_attempts):
                with patch("fuzzer_requests.request_fuzzer_training", side_effect=effects) as train, \
                     patch("fuzzer_requests.time.sleep"):
                    request_fuzzer_loop(configuration(interval_seconds=0))
                self.assertEqual(train.call_count, expected_attempts)

    def test_rejected_response_is_a_failed_attempt(self):
        with patch("fuzzer_requests.request_fuzzer_training", return_value=SimpleNamespace(accepted=False)) as train, \
             patch("fuzzer_requests.time.sleep") as sleep:
            request_fuzzer_loop(configuration(interval_seconds=0))
        self.assertEqual(train.call_count, 2)
        sleep.assert_called_once_with(2)

    def test_seed_wrap_avoids_the_omitted_seed_sentinel(self):
        with patch("fuzzer_requests.request_fuzzer_training", side_effect=(
            accepted_response(), StopLoop(),
        )) as train, patch("fuzzer_requests.time.sleep"):
            with self.assertRaises(StopLoop):
                request_fuzzer_loop(configuration(seed=0xFFFFFFFF))
        self.assertEqual(train.call_args_list[1].args[0].seed, 1)
        for seed in (-1, 0x100000000):
            with self.subTest(seed=seed), self.assertRaisesRegex(ValueError, "32-bit"):
                configuration(seed=seed).validate()

    def test_rpc_sends_the_cycle_seed_and_identity(self):
        with patch("fuzzer_requests.grpc.insecure_channel"), \
             patch("fuzzer_requests.parameters_pb2_grpc.FuzzerServiceStub") as stub:
            request_fuzzer_training(configuration(seed=1338), "cycle-2")
        request = stub.return_value.RunTrainingCycle.call_args.args[0]
        self.assertEqual((request.request_id, request.seed, request.prompt_count),
                         ("cycle-2", 1338, 32))

    def test_default_periodic_loop_reaches_a_real_fuzzer_rpc(self):
        requests = []

        class Fuzzer(rpc.FuzzerServiceServicer):
            def RunTrainingCycle(self, request, context):
                requests.append(request)
                return pb.FuzzerTrainingResponse(
                    accepted=True, model_id=request.model_id,
                    applied_version=f"v1+train.{len(requests)}",
                    prompts_generated=request.prompt_count,
                )

        server = grpc.server(ThreadPoolExecutor(max_workers=1))
        rpc.add_FuzzerServiceServicer_to_server(Fuzzer(), server)
        port = server.add_insecure_port("127.0.0.1:0")
        server.start()
        self.addCleanup(lambda: server.stop(0).wait())
        with patch.dict(os.environ, {}, clear=True):
            config = replace(FuzzerRequestConfig.from_env(),
                             target=f"127.0.0.1:{port}", initial_delay_seconds=0)
        with patch("fuzzer_requests.time.sleep", side_effect=(None, StopLoop())) as sleep:
            with self.assertRaises(StopLoop):
                request_fuzzer_loop(config)
        self.assertEqual([request.seed for request in requests], [1337, 1338])
        self.assertEqual([request.prompt_count for request in requests], [32, 32])
        self.assertNotEqual(requests[0].request_id, requests[1].request_id)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [3600, 3600])


if __name__ == "__main__":
    unittest.main()
