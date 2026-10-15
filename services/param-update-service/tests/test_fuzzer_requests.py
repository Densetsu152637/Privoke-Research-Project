"""Automatic configuration and actual request construction contracts."""
import os
import sys
import unittest
from pathlib import Path
from dataclasses import replace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
for path in (ROOT / "app",ROOT / "generated",ROOT.parents[1] / "shared/python"):
    sys.path.insert(0,str(path))
from fuzzer_requests import FuzzerRequestConfig, request_fuzzer_training, start_fuzzer_requester


def configuration(**changes):
    return replace(FuzzerRequestConfig("fuzzer:50053",32,"privoke-balanced","updater",60,3600,0,2,2,1337),**changes)


class AutomaticFuzzerRequestTests(unittest.TestCase):
    def test_default_environment_enables_both_periodic_stages(self):
        with patch.dict(os.environ,{},clear=True): config=FuzzerRequestConfig.from_env()
        self.assertTrue(config.train_underlying)
        self.assertEqual(config.prompt_count,32)
        self.assertEqual(config.interval_seconds,3600)
        self.assertEqual(config.state_path,"/data/training-cycles.sqlite3")
        with patch("fuzzer_requests.threading.Thread") as thread: start_fuzzer_requester(config)
        thread.return_value.start.assert_called_once()

    def test_zero_prompt_count_disables_both_without_opening_journal(self):
        with patch("fuzzer_requests.threading.Thread") as thread:
            start_fuzzer_requester(configuration(prompt_count=0))
        thread.assert_not_called()

    def test_sampler_seed_and_limits_validate(self):
        for changes in ({"seed":-1},{"seed":2**32},{"prompt_count":-1},{"max_attempts":0},
                        {"curriculum_sampler_policy":"bad"},{"curriculum_sampler_seed":42},
                        {"curriculum_sampler_policy":"seeded_family_v1","curriculum_sampler_seed":2**32}):
            with self.subTest(changes=changes),self.assertRaises(ValueError): configuration(**changes).validate()
        configuration(curriculum_sampler_policy="seeded_family_v1",curriculum_sampler_seed=42).validate()

    def test_rpc_routes_both_endpoints_with_exact_ids_seed_and_expected_prior_base(self):
        for stage,method in (("heads","RunTrainingCycle"),("full_encoder","RunUnderlyingTrainingCycle")):
            with patch("fuzzer_requests.grpc.insecure_channel"),patch("fuzzer_requests.parameters_pb2_grpc.FuzzerServiceStub") as stub:
                request_fuzzer_training(configuration(seed=1338),"cycle-2-"+stage,training_scope=stage,
                                        expected_base_version="S1" if stage=="full_encoder" else None)
            request=getattr(stub.return_value,method).call_args.args[0]
            self.assertEqual((request.request_id,request.seed,request.prompt_count),("cycle-2-"+stage,1338,32))
            self.assertEqual(request.metadata["require_full_capability"],"true")
            if stage=="full_encoder": self.assertEqual(request.metadata["expected_base_version"],"S1")

    def test_explicit_head_only_opt_out_preserves_standalone_request_contract(self):
        with patch("fuzzer_requests.grpc.insecure_channel"),patch("fuzzer_requests.parameters_pb2_grpc.FuzzerServiceStub") as stub:
            request_fuzzer_training(configuration(train_underlying=False),"head")
        self.assertEqual(dict(stub.return_value.RunTrainingCycle.call_args.args[0].metadata),{"initiator":"param-update-service"})

    def test_sampler_environment_reaches_both_requests(self):
        config=configuration(curriculum_sampler_policy="seeded_family_v1",curriculum_sampler_seed=44)
        with patch("fuzzer_requests.grpc.insecure_channel"),patch("fuzzer_requests.parameters_pb2_grpc.FuzzerServiceStub") as stub:
            request_fuzzer_training(config,"full",training_scope="full_encoder")
        metadata=stub.return_value.RunUnderlyingTrainingCycle.call_args.args[0].metadata
        self.assertEqual(metadata["curriculum_sampler_policy"],"seeded_family_v1")
        self.assertEqual(metadata["curriculum_sampler_seed"],"44")
