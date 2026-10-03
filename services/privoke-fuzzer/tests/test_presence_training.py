from __future__ import annotations

import json
import math
import sys
import tempfile
import unittest
from unittest.mock import MagicMock
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import grpc

SERVICE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVICE_ROOT.parents[1]
for path in (SERVICE_ROOT / "src", SERVICE_ROOT / "generated", REPO_ROOT / "shared/python"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from fuzzer_service import (
    FuzzerTrainingService,
    _presence_training_request_fingerprint,
    _training_request_fingerprint,
    validate_presence_training_request,
    validate_presence_training_update,
)
from privoke_model.training_data import training_text_key
from privoke.v1 import parameters_pb2
from prompt_generation.presence import PresenceExample, generate_presence_training_partition, load_presence_dataset
from runtime_client import PrivokeRuntimeClient, RuntimeAnalysisError
from privoke.v1 import runtime_pb2
from training.types import BatchTrainingUpdate


def _metrics():
    return {
        "examples": 4.0,
        "average_loss": 0.62,
        "exact_match_rate": 0.75,
        "heldout_examples": 4.0,
        "heldout_present_examples": 2.0,
        "heldout_absent_examples": 2.0,
        "candidate_heldout_examples": 4.0,
        "candidate_heldout_present_examples": 2.0,
        "candidate_heldout_absent_examples": 2.0,
        "heldout_exact_match_rate": 0.75,
        "heldout_present_recall": 0.5,
        "heldout_absent_specificity": 1.0,
        "candidate_heldout_exact_match_rate": 0.75,
        "candidate_heldout_present_recall": 0.5,
        "candidate_heldout_absent_specificity": 1.0,
    }


def _update(metrics=None):
    return BatchTrainingUpdate(
        model_id="privoke-presence-balanced", base_version="v1",
        gradients={"head.presence.bias": (0.01,)},
        parameter_shapes={"head.presence.bias": (1,)},
        metrics=_metrics() if metrics is None else metrics, metadata={
            "presence_profile": "balanced", "presence_release": "r1",
            "parameter_fingerprint": "abc",
        },
    )


class PresencePartitionTests(unittest.TestCase):
    def _dataset(self, path, each=8):
        rows = []
        for label in (False, True):
            for index in range(each):
                base_text = f"{'Sensitive' if label else 'Ordinary'} unique document {0 if index == each - 1 else index}"
                rows.append({
                    "id": f"{'p' if label else 'a'}-{index}",
                    "text": base_text,
                    "sensitive": label,
                    "group_id": f"{'p' if label else 'a'}-group-{index}",
                })
                rows.append({
                    "id": f"{'p' if label else 'a'}-{index}-sibling",
                    "text": f"{'Sensitive' if label else 'Ordinary'} sibling document {index}",
                    "sensitive": label,
                    "group_id": f"{'p' if label else 'a'}-group-{index}",
                })
        path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
        return path

    def test_partition_is_deterministic_group_and_normalized_text_disjoint(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._dataset(Path(directory) / "curriculum.jsonl")
            train, heldout = generate_presence_training_partition(4, 4, 42, path)
            train2, heldout2 = generate_presence_training_partition(4, 4, 42, path)
            self.assertEqual(train, train2)
            self.assertEqual(heldout, heldout2)
            self.assertEqual({row.sensitive for row in heldout}, {False, True})
            self.assertEqual({row.sensitive for row in train}, {False, True})
            self.assertFalse({row.group_id for row in train} & {row.group_id for row in heldout})
            self.assertFalse({training_text_key(row.text) for row in train} &
                             {training_text_key(row.text) for row in heldout})

    def test_loader_rejects_non_boolean_and_missing_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.jsonl"
            path.write_text(json.dumps({"id": "x", "text": "test", "sensitive": 1, "group_id": "g"}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "strict booleans"):
                load_presence_dataset(path)
            path.write_text(json.dumps({"id": "x", "text": "test", "sensitive": True}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "group_id"):
                load_presence_dataset(path)

    def test_sampler_fails_when_group_separation_is_insufficient(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._dataset(Path(directory) / "small.jsonl", each=2)
            with self.assertRaisesRegex(ValueError, "Presence dataset cannot supply"):
                generate_presence_training_partition(2, 4, 7, path)


class PresenceGuardAndReplayTests(unittest.TestCase):
    def test_presence_guard_requires_finite_consistent_counts_and_strata(self):
        validate_presence_training_update(_update(), minimum_exact_match_rate=0.5)
        cases = []
        missing = _metrics(); missing.pop("heldout_present_examples"); cases.append(missing)
        inconsistent = _metrics(); inconsistent["heldout_examples"] = 5; cases.append(inconsistent)
        candidate_counts = _metrics(); candidate_counts["candidate_heldout_present_examples"] = 1; cases.append(candidate_counts)
        impossible_fraction = _metrics(); impossible_fraction["heldout_present_recall"] = 0.6; cases.append(impossible_fraction)
        inconsistent_exact = _metrics(); inconsistent_exact["heldout_exact_match_rate"] = 0.5; cases.append(inconsistent_exact)
        inconsistent_train = _metrics(); inconsistent_train["examples"] = 3
        nonfinite = _metrics(); nonfinite["candidate_heldout_absent_specificity"] = math.nan; cases.append(nonfinite)
        missing_loss = _metrics(); missing_loss.pop("average_loss"); cases.append(missing_loss)
        for metrics in cases:
            with self.subTest(metrics=metrics):
                with self.assertRaises(ValueError):
                    validate_presence_training_update(_update(metrics), minimum_exact_match_rate=0.0)
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_presence_training_update(
                _update(inconsistent_train), minimum_exact_match_rate=0.0,
                expected_examples=4,
            )

    def test_presence_guard_rejects_any_stratum_or_exact_match_regression(self):
        for name in ("candidate_heldout_exact_match_rate", "candidate_heldout_present_recall",
                     "candidate_heldout_absent_specificity"):
            metrics = _metrics()
            if name == "candidate_heldout_exact_match_rate":
                metrics[name] = 0.5
                metrics["candidate_heldout_present_recall"] = 0.0
            elif name == "candidate_heldout_present_recall":
                metrics[name] = 0.0
                metrics["candidate_heldout_exact_match_rate"] = 0.5
            else:
                metrics[name] = 0.5
                metrics["candidate_heldout_exact_match_rate"] = 0.5
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "worse"):
                validate_presence_training_update(_update(metrics), minimum_exact_match_rate=0.0)

    def test_presence_request_requires_explicit_configured_model(self):
        request = parameters_pb2.FuzzerTrainingRequest(
            request_id="r", source_id="evaluation", model_id="privoke-presence-balanced", prompt_count=4
        )
        validate_presence_training_request(request, "privoke-presence-balanced")
        request.model_id = ""
        with self.assertRaisesRegex(ValueError, "model_id"):
            validate_presence_training_request(request, "privoke-presence-balanced")

    def test_task_salt_separates_contextual_and_presence_replay_fingerprints(self):
        request = parameters_pb2.FuzzerTrainingRequest(
            request_id="same-id", source_id="evaluation", model_id="privoke-presence-balanced", prompt_count=4
        )
        self.assertNotEqual(_presence_training_request_fingerprint(request), _training_request_fingerprint(request))
        self.assertEqual(len(_presence_training_request_fingerprint(request)), 64)

    def test_status_unavailable_aborts_without_training(self):
        config = SimpleNamespace(
            model_id="privoke-balanced", presence_model_id="privoke-presence-balanced",
            max_concurrent_cycles=1, max_prompt_count=256, seed=42,
            heldout_prompt_count=4, presence_dataset_path="unused", prompt_dataset_path=None,
            minimum_exact_match_rate=0.0,
            param_update_target="updates:50052", timeout_seconds=1.0, fuzzer_id="fuzzer",
        )
        service = FuzzerTrainingService(config)
        request = parameters_pb2.FuzzerTrainingRequest(
            request_id="r", source_id="test", model_id="privoke-presence-balanced", prompt_count=4
        )

        class Aborted(Exception):
            pass

        class Context:
            def abort(self, code, message):
                self.code = code
                raise Aborted(message)

        context = Context()
        class Offline(grpc.RpcError):
            def code(self):
                return grpc.StatusCode.UNAVAILABLE

        with patch("fuzzer_service.grpc.insecure_channel", side_effect=Offline("offline")), \
             patch.object(service, "_train_presence") as train:
            # Exercise the public mapping path where status errors are translated to UNAVAILABLE.
            with self.assertRaises(Aborted):
                service._run_presence_training_cycle(request, context)
        train.assert_not_called()

    def test_reused_request_id_with_other_task_is_a_conflict(self):
        config = SimpleNamespace(
            param_update_target="updates:50052", timeout_seconds=1.0,
            fuzzer_id="fuzzer", max_concurrent_cycles=1,
        )
        service = FuzzerTrainingService(config)
        request = parameters_pb2.FuzzerTrainingRequest(
            request_id="shared-id", source_id="evaluation",
            model_id="privoke-presence-balanced", prompt_count=4,
        )
        channel = MagicMock()
        channel.__enter__.return_value = channel
        stub = MagicMock()

        class AlreadyExists(grpc.RpcError):
            def code(self):
                return grpc.StatusCode.ALREADY_EXISTS

        stub.GetParameterUpdateStatus.side_effect = AlreadyExists("fingerprint conflict")

        class Context:
            def abort(self, code, message):
                self.code, self.message = code, message
                raise RuntimeError(message)

        context = Context()
        with patch("fuzzer_service.grpc.insecure_channel", return_value=channel), \
             patch("fuzzer_service.parameters_pb2_grpc.ParamUpdateServiceStub", return_value=stub):
            with self.assertRaisesRegex(RuntimeError, "different training request"):
                service._previous_update_for_fingerprint(
                    request, SimpleNamespace(model_id=request.model_id), context,
                    _presence_training_request_fingerprint(request),
                )
        self.assertEqual(context.code, grpc.StatusCode.ALREADY_EXISTS)

    def test_update_metadata_keeps_task_identity_and_never_contains_text(self):
        config = SimpleNamespace(
            param_update_target="updates:50052", fuzzer_id="fuzzer", timeout_seconds=1.0,
            max_concurrent_cycles=1,
        )
        service = FuzzerTrainingService(config)
        request = parameters_pb2.FuzzerTrainingRequest(
            request_id="metadata", source_id="evaluation",
            model_id="privoke-presence-balanced", prompt_count=2,
        )
        cycle = SimpleNamespace(requested_prompt_count=2)
        fingerprint = _presence_training_request_fingerprint(request)
        ack = object()
        with patch("fuzzer_service.emit_training_update", return_value=ack) as emit:
            result = service._submit_presence_update(
                request, cycle, _update(), 2, fingerprint, SimpleNamespace()
            )
        self.assertIs(result, ack)
        metadata = emit.call_args.kwargs["extra_metadata"]
        self.assertEqual(metadata["task"], "annotation_presence")
        self.assertEqual(metadata["training_pipeline"], "client_runtime_presence_gradients")
        self.assertEqual(metadata["training_request_fingerprint"], fingerprint)
        self.assertNotIn("text", metadata)

    def test_replay_skips_presence_training_and_publication(self):
        config = SimpleNamespace(
            model_id="privoke-balanced", presence_model_id="privoke-presence-balanced",
            max_concurrent_cycles=1, max_prompt_count=256, seed=42,
        )
        service = FuzzerTrainingService(config)
        previous = parameters_pb2.ParameterUpdateStatus(
            found=True,
            ack=parameters_pb2.ParameterUpdateAck(accepted=True, model_id="privoke-presence-balanced", applied_version="v1+1"),
            base_version="v1", prompts_generated=4,
        )
        request = parameters_pb2.FuzzerTrainingRequest(
            request_id="replay", source_id="test", model_id="privoke-presence-balanced", prompt_count=4
        )
        with patch.object(service, "_previous_update_for_fingerprint", return_value=previous), \
             patch.object(service, "_train_presence") as train, patch.object(service, "_submit_presence_update") as submit:
            response = service._run_presence_training_cycle(request, None)
        self.assertTrue(response.accepted)
        self.assertEqual(response.metadata["replayed"], "true")
        train.assert_not_called()
        submit.assert_not_called()

    def test_cycle_caps_count_and_submits_task_salted_fingerprint_without_text(self):
        config = SimpleNamespace(
            model_id="privoke-balanced", presence_model_id="privoke-presence-balanced",
            max_concurrent_cycles=1, max_prompt_count=4, seed=42,
            heldout_prompt_count=4, presence_dataset_path="curriculum.jsonl",
            prompt_dataset_path=None, minimum_exact_match_rate=0.0,
            privoke_runtime_target="runtime:50054", timeout_seconds=1.0,
            param_update_target="updates:50052", fuzzer_id="fuzzer",
            batch_training_config=lambda seed: object(),
        )
        service = FuzzerTrainingService(config)
        request = parameters_pb2.FuzzerTrainingRequest(
            request_id="bounded", source_id="evaluation",
            model_id="privoke-presence-balanced", prompt_count=12,
        )
        training_rows = [PresenceExample(f"training prompt {index}", bool(index % 2), f"id-{index}", f"group-{index}")
                         for index in range(4)]
        heldout_rows = [PresenceExample(f"heldout prompt {index}", bool(index % 2), f"hid-{index}", f"heldout-group-{index}")
                        for index in range(4)]
        ack = parameters_pb2.ParameterUpdateAck(
            accepted=True, model_id="privoke-presence-balanced", applied_version="v1+train.1", message="ok"
        )

        class Context:
            def is_active(self):
                return True

            def abort(self, code, message):
                raise AssertionError((code, message))

        update = _update()
        with patch.object(service, "_previous_update_for_fingerprint",
                          return_value=parameters_pb2.ParameterUpdateStatus(found=False)) as status, \
             patch("fuzzer_service.generate_presence_training_partition",
                   return_value=(training_rows, heldout_rows)) as partition, \
             patch.object(service, "_train_presence", return_value=update), \
             patch.object(service, "_submit_presence_update", return_value=ack) as submit:
            response = service._run_presence_training_cycle(request, Context())
        self.assertEqual(response.prompts_generated, 4)
        partition.assert_called_once_with(4, 4, 42, "curriculum.jsonl")
        fingerprint = _presence_training_request_fingerprint(request)
        self.assertEqual(status.call_args.args[3], fingerprint)
        self.assertEqual(submit.call_args.args[4], fingerprint)
        self.assertNotIn("secret prompt", str(submit.call_args.args[2].metadata))

    def test_cycle_rejects_sampler_count_mismatch_before_runtime_call(self):
        config = SimpleNamespace(
            model_id="privoke-balanced", presence_model_id="privoke-presence-balanced",
            max_concurrent_cycles=1, max_prompt_count=4, seed=42,
            heldout_prompt_count=4, presence_dataset_path="curriculum.jsonl",
            minimum_exact_match_rate=0.0,
        )
        service = FuzzerTrainingService(config)
        request = parameters_pb2.FuzzerTrainingRequest(
            request_id="bad-partition", source_id="evaluation",
            model_id="privoke-presence-balanced", prompt_count=4,
        )

        class Aborted(Exception):
            pass

        class Context:
            code = None

            def abort(self, code, message):
                self.code = code
                raise Aborted(message)

        context = Context()
        with patch.object(service, "_previous_update_for_fingerprint",
                          return_value=parameters_pb2.ParameterUpdateStatus(found=False)), \
             patch("fuzzer_service.generate_presence_training_partition",
                   return_value=([PresenceExample("one", True, "id", "group")],
                                 [PresenceExample("heldout", False, "hid", "heldout-group")])) as partition, \
             patch.object(service, "_train_presence") as train:
            with self.assertRaisesRegex(Aborted, "counts that do not match"):
                service._run_presence_training_cycle(request, context)
        self.assertEqual(context.code, grpc.StatusCode.FAILED_PRECONDITION)
        partition.assert_called_once()
        train.assert_not_called()


class PresenceRuntimeClientTests(unittest.TestCase):
    def test_runtime_receives_binary_presence_labels_and_preserves_release_metadata(self):
        response = runtime_pb2.ComputePresenceGradientsResponse(
            model_id="privoke-presence-balanced", base_version="r1",
            gradients=[runtime_pb2.RuntimeParameterDelta(
                name="head.presence.bias", values=[0.01], shape=[1]
            )],
            metrics={"examples": 2.0},
            metadata={"profile": "balanced", "release": "r1", "parameter_fingerprint": "fp"},
        )
        stub = MagicMock()
        stub.ComputePresenceGradients.return_value = response
        channel = MagicMock()
        channel.__enter__.return_value = channel
        with patch("runtime_client.grpc.insecure_channel", return_value=channel), \
             patch("runtime_client.runtime_pb2_grpc.PrivokeRuntimeServiceStub", return_value=stub):
            result = PrivokeRuntimeClient("runtime:50054").compute_presence_gradients(
                [PresenceExample("present", True, "p", "pg"),
                 PresenceExample("absent", False, "a", "ag")],
                model_id="privoke-presence-balanced", learning_rate=0.03,
                max_gradient=0.05, request_id="cycle-1",
            )
        request = stub.ComputePresenceGradients.call_args.args[0]
        self.assertEqual(request.examples[0].target, runtime_pb2.ANNOTATION_PRESENCE_PRESENT)
        self.assertEqual(request.examples[1].target, runtime_pb2.ANNOTATION_PRESENCE_ABSENT)
        self.assertEqual([example.group_id for example in request.examples], ["pg", "ag"])
        self.assertEqual(request.request_id, "cycle-1")
        self.assertEqual(result["metadata"]["parameter_fingerprint"], "fp")
        self.assertEqual(set(result["gradients"]), {"head.presence.bias"})

    def test_runtime_rejects_non_presence_gradient_and_non_boolean_target(self):
        example = PresenceExample("text", True, "id", "group")
        with self.assertRaisesRegex(ValueError, "strict booleans"):
            PrivokeRuntimeClient("unused").compute_presence_gradients(
                [PresenceExample("text", 1, "id", "group")], model_id="m",
                learning_rate=0.1, max_gradient=0.1,
            )
        response = runtime_pb2.ComputePresenceGradientsResponse(
            model_id="m", base_version="v1",
            gradients=[runtime_pb2.RuntimeParameterDelta(name="head.sensitivity.bias", values=[0.1], shape=[1])],
        )
        stub = MagicMock()
        stub.ComputePresenceGradients.return_value = response
        channel = MagicMock()
        channel.__enter__.return_value = channel
        with patch("runtime_client.grpc.insecure_channel", return_value=channel), \
             patch("runtime_client.runtime_pb2_grpc.PrivokeRuntimeServiceStub", return_value=stub):
            with self.assertRaisesRegex(RuntimeAnalysisError, "non-presence"):
                PrivokeRuntimeClient("runtime:50054").compute_presence_gradients(
                    [example], model_id="m", learning_rate=0.1, max_gradient=0.1,
                )


if __name__ == "__main__":
    unittest.main()
