"""FULL rate selection preserves runtime execution and durable request contracts."""
import base64
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SERVICE = Path(__file__).resolve().parents[1]
for path in (SERVICE / "src", SERVICE / "generated", SERVICE.parents[1] / "shared/python"):
    sys.path.insert(0, str(path))

from config import FuzzerConfig
from fuzzer_service import FuzzerTrainingService
from privoke.v1 import parameters_pb2, runtime_pb2
from test_dual_runtime_contract import contract
from test_underlying_cycle import Aborted, Context
from training.types import BatchTrainingExample


def config(**environment):
    with patch.dict(os.environ, environment, clear=True):
        return FuzzerConfig.from_env()


class UnderlyingLearningRateTests(unittest.TestCase):
    def test_default_and_unset_override_follow_existing_rate_for_all_stages(self):
        for environment, expected in (({}, .03), ({"FUZZ_TRAINING_LEARNING_RATE": ".02"}, .02)):
            selected = config(**environment)
            self.assertIsNone(selected.underlying_training_learning_rate)
            self.assertEqual(selected.batch_training_config(42).learning_rate, expected)
            self.assertEqual(selected.batch_training_config(42, training_scope="full_encoder").learning_rate, expected)
            self.assertEqual(selected.presence_training_config(42).learning_rate, expected)

    def test_override_changes_full_only_and_retains_other_training_settings(self):
        selected = config(FUZZ_UNDERLYING_TRAINING_LEARNING_RATE=".003")
        head = selected.batch_training_config(42)
        full = selected.batch_training_config(42, training_scope="full_encoder")
        self.assertEqual(head.learning_rate, .03)
        self.assertEqual(selected.presence_training_config(42).learning_rate, .03)
        self.assertEqual(full, replace(head, learning_rate=.003))

    def test_invalid_override_rejected_at_configuration_boundary(self):
        for value in ("0", "-0.003", "nan", "inf", "-inf", "", "invalid"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "FUZZ_UNDERLYING_TRAINING_LEARNING_RATE"):
                config(FUZZ_UNDERLYING_TRAINING_LEARNING_RATE=value)

    def test_service_sends_selected_rate_to_actual_semantic_rpc_without_rescaling_deltas(self):
        for override in (None, ".003"):
            selected = config(MODEL_ID="privoke-balanced", FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE="0",
                              **({"FUZZ_UNDERLYING_TRAINING_LEARNING_RATE": override} if override else {}))
            for scope, rpc in (("heads", "ComputeSemanticGradients"), ("full_encoder", "ComputeUnderlyingModelGradients")):
                request, response = contract(scope)
                response.gradients[0].values[0] = .01

                def compute(sent, **kwargs):
                    response.metadata["learning_rate"] = str(sent.learning_rate)
                    return response

                with self.subTest(override=override, scope=scope), \
                     patch("runtime_client.grpc.insecure_channel"), \
                     patch("runtime_client.runtime_pb2_grpc.PrivokeRuntimeServiceStub") as stub:
                    getattr(stub.return_value, rpc).side_effect = compute
                    update = FuzzerTrainingService(selected)._train(
                        request.model_id, [BatchTrainingExample("synthetic train")],
                        [BatchTrainingExample("synthetic heldout")], 42, Context(),
                        training_scope=scope, request_id="req", require_full_capability=True)
                    sent = getattr(stub.return_value, rpc).call_args.args[0]
                expected = .003 if override and scope == "full_encoder" else .03
                self.assertEqual(sent.learning_rate, expected)
                self.assertEqual(sent.max_gradient, .05)
                self.assertEqual(list(sent.layers), [runtime_pb2.DETECTION_LAYER_SEMANTIC])
                self.assertEqual(update.metadata["learning_rate"], str(expected))
                self.assertEqual(update.gradients[response.gradients[0].name][0], response.gradients[0].values[0])
                evidence = update.execution_evidence
                self.assertEqual(base64.b64decode(evidence["request_protobuf_base64"]), sent.SerializeToString(deterministic=True))
                self.assertEqual([e["phase"] for e in evidence["executions"]],
                                 ["training", "base_heldout", "candidate_heldout"])
                self.assertTrue(all(e["layer"] == runtime_pb2.DETECTION_LAYER_SEMANTIC and e["status"] == "ok"
                                    for e in evidence["executions"]))

    def test_full_receipt_recovery_binds_rate_and_preserves_legacy_default_fingerprint(self):
        request = parameters_pb2.FuzzerTrainingRequest(request_id="same", source_id="study",
            model_id="privoke-balanced", prompt_count=8, seed=42,
            metadata={"require_full_capability": "true"})
        status = parameters_pb2.ParameterUpdateStatus(found=True, base_version="v1", prompts_generated=8,
            ack=parameters_pb2.ParameterUpdateAck(accepted=True, model_id=request.model_id, applied_version="v2"))
        default = config(MODEL_ID=request.model_id, FUZZ_CONTEXTUAL_SAMPLING_STRATEGY="legacy_random_v1")
        override = replace(default, underlying_training_learning_rate=.003)
        # Exercise both the procedural and curriculum effective-settings branches.
        for curriculum in (None, SimpleNamespace(curriculum_id="fixture", manifest_sha256="a" * 64)):
            with self.subTest(curriculum=bool(curriculum)), tempfile.TemporaryDirectory() as directory, \
                 patch.dict(os.environ, {"PRIVOKE_FUZZER_DUMP_DIR": directory}), \
                 patch("fuzzer_service.load_curriculum", return_value=curriculum):
                if curriculum:
                    default = replace(default, curriculum_manifest_path="fixture", curriculum_state_path=str(Path(directory) / "cursor.sqlite3"))
                    override = replace(override, curriculum_manifest_path="fixture", curriculum_state_path=default.curriculum_state_path)
                service = FuzzerTrainingService(default)
                with patch.object(service, "_previous_update_for_fingerprint", return_value=status) as lookup, \
                     patch.object(service, "_train") as train:
                    self.assertTrue(service.RunUnderlyingTrainingCycle(request, Context()).accepted)
                    scoped, _, _, fingerprint = lookup.call_args.args
                    if not curriculum:
                        legacy_settings = {"training": asdict(default.batch_training_config(42)),
                            "scope": "full_encoder", "prompt_count": 8, "heldout_count": 16,
                            "minimum_exact_match_rate": 0.0, "dataset_sha256": "bundled_synthetic_generator_v1"}
                        legacy = hashlib.sha256(json.dumps([scoped.SerializeToString(deterministic=True).hex(), legacy_settings],
                            sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                        self.assertEqual(fingerprint, legacy)
                    # Explicit equal rate has identical effective settings and can recover the receipt.
                    same_rate = FuzzerTrainingService(replace(default, underlying_training_learning_rate=.03))
                    with patch.object(same_rate, "_previous_update_for_fingerprint", return_value=status) as replay:
                        self.assertEqual(same_rate.RunUnderlyingTrainingCycle(request, Context()).metadata["replayed"], "true")
                    self.assertEqual(replay.call_args.args[3], fingerprint)
                    train.assert_not_called()
                changed = FuzzerTrainingService(override)
                with patch.object(changed, "_previous_update_for_fingerprint") as lookup, patch.object(changed, "_train") as train:
                    with self.assertRaisesRegex(Aborted, "different effective training settings"):
                        changed.RunUnderlyingTrainingCycle(request, Context())
                lookup.assert_not_called()
                train.assert_not_called()
