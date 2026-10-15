"""Analytic manufactured tensors/fake semantic backends; zero real model calls."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from types import SimpleNamespace
import os
import hashlib
import json
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

import numpy as np
from src import pipeline
from src.classification import Classification, ClassificationResult
from src.LLM.privoke.reference_preparation import ReferenceBinding, bind_reference, current_binding
from src.LLM.privoke.sensitive_retention_training import safety_rows, margin_and_gap
from src.LLM.privoke.supervised_training import supervised_last_block_deltas
from src.LLM.privoke.training import SemanticTrainingExample, compute_underlying_model_gradients
from privoke_model import sensitive_retention as contract


class RetentionConfigPreflightTests(unittest.TestCase):
    """Pure config/count preflight; no model arithmetic, RPC or guard payloads."""

    @staticmethod
    def config():
        # Metadata-only fixture from sealed quality before/terminal snapshots.
        return {"category_labels": ["HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL", "SEXUAL",
                "CHILD", "LOCATION", "IDENTITY", "THIRD_PARTY"], "category_threshold": .38,
            "hidden_size": 32, "intermediate_size": 64, "max_tokens": 256, "num_attention_heads": 4,
            "num_layers": 3, "sensitivity_labels": ["S0", "S1", "S2", "S3"],
            "visibility_labels": ["P0", "P1", "P2", "P3", "P4", "PU"], "vocab_size": 768}

    @classmethod
    def formats(cls):
        config = cls.config()
        compact = json.dumps(config, sort_keys=True, separators=(",", ":"))
        # The updater's indent=2 artifact write nests config one level deep;
        # Go RawMessage returns precisely this substring, including whitespace.
        artifact = json.dumps({"config": config}, indent=2, sort_keys=True)
        start = artifact.index('"config": ') + len('"config": ')
        _, end = json.JSONDecoder().raw_decode(artifact, start)
        return compact, artifact[start:end]

    def run_preflight(self, config, *, policy, main=64, guard=16):
        from src.LLM.privoke import training as runtime_training
        from src.LLM.privoke import sensitive_retention_training as retention_runtime
        release = SimpleNamespace(manifest={"teacher": {"config": self.config()}})
        snapshot = SimpleNamespace(metadata={"model_config": config, contract.MANIFEST_KEY: "a" * 64})
        runtime_model = SimpleNamespace(snapshot=snapshot)  # Deliberately has no model/backend.
        cache = SimpleNamespace(model_for_training=lambda streamer: runtime_model)
        example = SemanticTrainingExample("manufactured config/count fixture", None, 1.)
        admission = {"expected_optimizer": policy, "expected_training_scope": "full_encoder"}
        with patch.object(retention_runtime, "load_runtime_release", return_value=release), \
             patch.object(contract, "validate_admission"), patch.object(contract, "validate_release"), \
             patch("privoke_model.full_adam.validate_admission", return_value=False), \
             patch("src.LLM.privoke.full_adam_training.preflight"), \
             patch.object(runtime_training, "ModelParameterStreamer", return_value=object()), \
             patch.object(runtime_training, "GLOBAL_STREAMED_MODEL_CACHE", cache), \
             patch.object(runtime_training, "normalize_text", side_effect=lambda text: text), \
             patch.object(runtime_training, "_validate_heldout_examples"), \
             patch.object(runtime_training, "validate_backtracking_policy", side_effect=RuntimeError("config preflight reached")) as sentinel:
            try:
                compute_underlying_model_gradients((example,) * main, model_id="privoke-quality",
                    learning_rate=.003, max_gradient=.05, heldout_examples=(example,) * guard, admission=admission)
            except ValueError:
                sentinel.assert_not_called()
                raise

    def test_sealed_compact_and_pretty_formats_pass_real_preflight_both_policies(self):
        from src.LLM.privoke.sensitive_retention_training import validate_current_config
        compact, pretty = self.formats()
        self.assertEqual((len(compact.encode()), len(pretty.encode())), (362, 580))
        self.assertEqual(hashlib.sha256(compact.encode()).hexdigest(),
            "469e31844ce0ca37d1cdff1a5466b0a900c46c19a077f5c5c84da410e7dd7266")
        self.assertEqual(hashlib.sha256(pretty.encode()).hexdigest(),
            "0d55e7a97f9cdcabaf1706b4711554c8839f130f6b73130d351dee7501bd0d4f")
        self.assertNotEqual(pretty, compact)  # The old raw-string predicate rejects this real format.
        for policy in (contract.GATE_POLICY, contract.HINGE_POLICY):
            for value in (compact, pretty):
                with self.subTest(policy=policy, format=len(value)):
                    self.assertIsNone(validate_current_config(value, self.config()))
                    with self.assertRaisesRegex(RuntimeError, "config preflight reached"):
                        self.run_preflight(value, policy=policy)

    def test_missing_added_changed_and_numeric_type_configs_fail_before_sentinel(self):
        compact, _ = self.formats()
        missing = self.config(); missing.pop("hidden_size")
        added = {**self.config(), "unexpected": 0}
        changed = {**self.config(), "category_threshold": .39}
        changed_type = {**self.config(), "num_layers": 3.0}
        for policy in (contract.GATE_POLICY, contract.HINGE_POLICY):
            for value in (None, 42, json.dumps(missing), json.dumps(added), json.dumps(changed), json.dumps(changed_type),
                    compact.replace('"num_layers":3', '"num_layers":true')):
                with self.subTest(policy=policy, value=value):
                    with self.assertRaisesRegex(ValueError, "Retention CURRENT config/main64/guard16"):
                        self.run_preflight(value, policy=policy)

    def test_malformed_duplicate_nonobject_and_nonfinite_configs_fail_before_sentinel(self):
        compact, _ = self.formats()
        invalid = ("{", "[]", "null", "true", "32", '"object"',
            compact[:-1] + ',"num_layers":3}', '{"nested":{"key":1,"key":1}}',
            '{"nested":[NaN]}', '{"nested":{"value":Infinity}}', '{"nested":[-Infinity]}',
            '{"nested":[1e999]}')
        for policy in (contract.GATE_POLICY, contract.HINGE_POLICY):
            for value in invalid:
                with self.subTest(policy=policy, value=value):
                    with self.assertRaisesRegex(ValueError, "Retention CURRENT config/main64/guard16"):
                        self.run_preflight(value, policy=policy)

    def test_json_types_are_not_python_bool_int_or_int_float_equality(self):
        from src.LLM.privoke.sensitive_retention_training import validate_current_config
        for current, teacher in (('{"value":true}', {"value": 1}), ('{"value":1}', {"value": True}),
                ('{"value":1.0}', {"value": 1}), ('{"value":1}', {"value": 1.0}),
                ('{"nested":[true]}', {"nested": [1]}), ('{"nested":[1]}', {"nested": [1.0]})):
            with self.subTest(current=current, teacher=teacher):
                with self.assertRaises(ValueError):
                    validate_current_config(current, teacher)
        for current, teacher in (('{"nested":[NaN]}', {"nested": [float("nan")]}),
                ('{"nested":[1e999]}', {"nested": [float("inf")]})):
            with self.assertRaises(ValueError):
                validate_current_config(current, teacher)

    def test_wrong_main_and_guard_counts_still_fail_before_sentinel(self):
        _, pretty = self.formats()
        for policy in (contract.GATE_POLICY, contract.HINGE_POLICY):
            for main, guard in ((63, 16), (65, 16), (64, 15), (64, 17)):
                with self.subTest(policy=policy, main=main, guard=guard):
                    with self.assertRaisesRegex(ValueError, "Retention CURRENT config/main64/guard16"):
                        self.run_preflight(pretty, policy=policy, main=main, guard=guard)


def fake_model(sensitivity=(0., 0., 0., 2.), category=None):
    """One-dimensional manufactured head fixture with an identity fake encoder."""
    config = SimpleNamespace(sensitivity_labels=("S0", "S1", "S2", "S3"),
        visibility_labels=("P0", "P1", "P2", "P3", "P4", "PU"),
        category_labels=("HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL", "SEXUAL", "CHILD", "LOCATION", "IDENTITY", "THIRD_PARTY"),
        category_threshold=.5, num_layers=1, readout="legacy_pool_v1")
    parameters = {"token_embedding": np.zeros((2, 1), dtype=np.float32),
                  "position_embedding": np.zeros((1, 1), dtype=np.float32)}
    for head, labels in (("sensitivity", config.sensitivity_labels), ("visibility", config.visibility_labels), ("category", config.category_labels)):
        parameters[f"head.{head}.weight"] = np.zeros((1, len(labels)), dtype=np.float32)
        parameters[f"head.{head}.bias"] = np.asarray(sensitivity if head == "sensitivity" else
            (category or [-2.] * len(labels)) if head == "category" else [0.] * len(labels), dtype=np.float32)
    return SimpleNamespace(config=config, parameters=parameters, token_ids=lambda text: np.asarray([1]),
        prediction_logits=lambda prediction, task: np.asarray(prediction.pooled, dtype=np.float32)
            @ parameters[f"head.{task}.weight"] + parameters[f"head.{task}.bias"],
        _layer_prefix=lambda layer: "", _torch_encoder_block=lambda hidden, mask, prefix, torch, p: hidden)


class RetentionRuntimeTests(unittest.TestCase):
    def test_untrusted_reference_header_rejects_before_sidecar_or_current_model_access(self):
        example = SemanticTrainingExample("manufactured", Classification(3 | 16 | 32), 1.)
        admission = {"expected_optimizer": contract.GATE_POLICY,
            "expected_retention_manifest_sha256": "d" * 64}
        with patch.dict(os.environ, {"PRIVOKE_RETENTION_MANIFEST_SHA256": "e" * 64}), \
             patch.object(contract, "load_release") as load, \
             patch("src.LLM.privoke.training.ModelParameterStreamer") as streamer, \
             self.assertRaisesRegex(ValueError, "trusted configured"):
            compute_underlying_model_gradients((example,), model_id="privoke-quality", learning_rate=.003,
                max_gradient=.05, heldout_examples=(example,), admission=admission)
        load.assert_not_called(); streamer.assert_not_called()

    def test_reference_preparer_uses_actual_analyze_handler_and_same_fake_prediction_once_per_row(self):
        from src.LLM.privoke.reference_preparation import prepare_references
        root = Path(__file__).resolve().parents[3]
        bank = (root / "evaluation/results/iterative_fuzzer_20261011/train-sensitive-retention/approved-train-bank.json").read_bytes()
        teacher = {"profile": "quality", "model_id": "privoke-quality", "version": "manufactured",
            "parameter_fingerprint": "a" * 64, "checksum": "b" * 64}
        artifact = {"model_id": teacher["model_id"], "version": teacher["version"], "checksum": teacher["checksum"],
            "architecture": "manufactured", "config": {}, "metadata": {},
            "parameters": {"manufactured": {"values": [.1], "shape": [1], "trainable": True}}}
        calls, output = [], []
        def constructor(snapshot, *, prediction_observer):
            from privoke_model.artifact import float32
            self.assertEqual(snapshot.parameters, {"manufactured": (float32(.1),)})
            self.assertEqual(snapshot.shapes, {"manufactured": (1,)})
            def classify(text):
                calls.append(text)
                prediction_observer(SimpleNamespace(sensitivity="S3", visibility="P3", categories=("HEALTH",),
                    confidence=.9, pooled=[0.]))
                return [ClassificationResult(Classification(3 | 16 | 32), text, "manufactured", confidence=.9)]
            snapshot = SimpleNamespace(model_id=teacher["model_id"], version=teacher["version"],
                fingerprint=teacher["parameter_fingerprint"], metadata={"artifact_checksum": teacher["checksum"]})
            return SimpleNamespace(snapshot=snapshot, model=fake_model(), classify=classify)
        with patch.object(contract, "teacher_identity", return_value=teacher), \
             patch.object(contract, "load_original_artifact", return_value=artifact), \
             patch("src.LLM.privoke.streamed_model.StreamedTransformerPrivacyModel", side_effect=constructor), \
             patch.object(pipeline, "_detector_for", side_effect=AssertionError("current stream forbidden")):
            references, identity = prepare_references(bank, "manufactured.json", "quality", output=output.append)
        self.assertEqual(identity, teacher)
        self.assertEqual(len(calls), 200)
        self.assertEqual(sum(r["status"] == "attempted" for r in output), 200)
        self.assertEqual(sum(r["status"] == "completed" for r in output), 200)
        self.assertTrue(all(r["layers"] == [4] for r in output))
        self.assertEqual(len(contract.parse_canonical(references)["rows"]), 200)
        self.assertIsNone(current_binding())

    def test_actual_original_protobuf_snapshot_identity_and_authority_all_three_profiles(self):
        from privoke.v1 import parameters_pb2
        from privoke_model.fingerprint import parameter_fingerprint
        from src.LLM.privoke.parameter_stream import ParameterSnapshot
        root = Path(__file__).resolve().parents[3]
        for profile in ("quality", "balanced", "efficient"):
            with self.subTest(profile=profile):
                path = (Path(os.environ["SR01_ORIGINAL_DIR"]) / ("privoke-" + profile + ".json")
                    if "SR01_ORIGINAL_DIR" in os.environ else
                    root / "evaluation/results/iterative_fuzzer_20261011/block01" / profile / "catalog" / ("privoke-" + profile + ".json"))
                artifact = contract.load_original_artifact(path, profile)
                teacher = contract.teacher_identity(path, profile)
                wire, raw, shapes = {}, {}, {}
                for name, tensor in artifact["parameters"].items():
                    message = parameters_pb2.Parameter(name=name, values=tensor["values"], shape=tensor["shape"])
                    restored = parameters_pb2.Parameter.FromString(message.SerializeToString(deterministic=True))
                    wire[name], raw[name], shapes[name] = tuple(restored.values), tuple(tensor["values"]), tuple(restored.shape)
                self.assertEqual(contract.original_effective_parameters(artifact), wire)
                self.assertNotEqual(parameter_fingerprint(raw, shapes), teacher["parameter_fingerprint"])
                snapshot = ParameterSnapshot(teacher["model_id"], teacher["version"], 0, wire, shapes,
                    {"artifact_checksum": teacher["checksum"]})
                self.assertEqual(snapshot.fingerprint, teacher["parameter_fingerprint"])
                model = SimpleNamespace(snapshot=snapshot)
                binding = ReferenceBinding(model, teacher, str(path))
                binding.validate_request(("semantic",), teacher["model_id"], None)
                # Raw-value snapshots, changed identity and forged checksums remain rejected.
                for parameters, version, checksum in ((raw, teacher["version"], teacher["checksum"]),
                        (wire, "changed", teacher["checksum"]), (wire, teacher["version"], "f" * 64)):
                    model.snapshot = ParameterSnapshot(teacher["model_id"], version, 0, parameters, shapes,
                        {"artifact_checksum": checksum})
                    with self.assertRaises(ValueError):
                        binding.validate_request(("semantic",), teacher["model_id"], None)
                model.snapshot = snapshot
                with self.assertRaises(ValueError):
                    binding.validate_request((), teacher["model_id"], None)
                with self.assertRaises(ValueError):
                    ReferenceBinding(model, {**teacher, "checksum": "f" * 64}, str(path)).validate_request(
                        ("semantic",), teacher["model_id"], None)

    def test_unchanged_parity_branch_reachable_with_protobuf_identity_using_only_stubbed_backends(self):
        """Actual branch/partial trace, with model, gradient and Adam all replaced."""
        import json
        from privoke.v1 import parameters_pb2
        from privoke_model.fingerprint import parameter_fingerprint
        from src.LLM.privoke import full_adam_training as driver
        root = Path(__file__).resolve().parents[3]
        path = (Path(os.environ["SR01_ORIGINAL_DIR"]) / "privoke-balanced.json"
            if "SR01_ORIGINAL_DIR" in os.environ else
            root / "evaluation/results/iterative_fuzzer_20261011/block01/balanced/catalog/privoke-balanced.json")
        artifact = contract.load_original_artifact(path, "balanced")
        teacher = contract.teacher_identity(path, "balanced")
        wire = {n: tuple(parameters_pb2.Parameter(values=t["values"]).values) for n, t in artifact["parameters"].items()}
        raw = {n: tuple(t["values"]) for n, t in artifact["parameters"].items()}
        shapes = {n: tuple(t["shape"]) for n, t in artifact["parameters"].items()}
        zeros = {n: (0.,) * len(v) for n, v in wire.items()}
        fake = SimpleNamespace(config=SimpleNamespace(num_layers=1), reject_overlength=True,
            _torch_encoder_block=lambda *args: self.fail("encoder execution forbidden"))
        def gradient_stub(*args, **kwargs):
            if "retention_diagnostics" in kwargs:
                kwargs["retention_diagnostics"].update(active_rows=0, maximum_hinge=0., maximum_scaled_original_difference=3.25)
            return zeros, 0.
        def branch(original_fingerprint):
            with patch.object(driver, "preflight"), \
                 patch.object(driver, "TinyTransformerModel", return_value=fake), \
                 patch.object(driver, "adam_step", return_value=(zeros, wire, 0)), \
                 patch("src.LLM.privoke.supervised_training.supervised_last_block_deltas", side_effect=gradient_stub), \
                 self.assertRaises(driver.FullAdamFailure) as raised:
                driver.fit(fake, wire, shapes, (object(),), cancel_check=unittest.mock.Mock(side_effect=(True, False)),
                    retention=((object(),), (1.,), original_fingerprint))
            steps = json.loads(raised.exception.training_metadata["original_train_retention_partial_work_v1"])["steps"]
            self.assertEqual(len(steps), 1)
            return steps[0]["original_state_parity_scaled_error"]
        self.assertIsNone(branch(parameter_fingerprint(raw, shapes)))  # Old ORIGINAL identity cannot reach parity.
        self.assertEqual(branch(teacher["parameter_fingerprint"]), 3.25)  # Manufactured diagnostic, not measured parity.

    def test_decoder_aligned_float32_margin_threshold_equality_and_severity_tie(self):
        prediction = SimpleNamespace(pooled=[0.])
        self.assertEqual(margin_and_gap(fake_model((0., 0., 0., 0.), [0.] * 10), prediction), (0., 0.))
        self.assertEqual(margin_and_gap(fake_model((0., 1., 1., -2.), [-2.] * 10), prediction), (1., 0.))
        self.assertEqual(margin_and_gap(fake_model((0., -1., -1., -1.), [2.] + [-2.] * 9), prediction)[0], 2.)

    def test_wrong_category_positive_margin_cannot_hide_severity_and_rounded_action_loss(self):
        source = {"id": "manufactured-train", "packed_classification": 3 | 16 | 32}
        original = {"packed": source["packed_classification"], "confidence": .9, "margin": 2.}
        release = SimpleNamespace(eligible=((source, original),))
        # High wrong-category score keeps the union margin positive, but S1 loses the severity/action floor.
        prediction = SimpleNamespace(sensitivity="S1", visibility="P3", categories=("POLITICS",), confidence=.9, pooled=[0.])
        rows = safety_rows(release, [prediction], fake_model((0., 1., 0., 0.), [-2., 2.] + [-2.] * 8))
        self.assertGreater(rows[0]["candidate_margin"], 0)
        self.assertTrue(rows[0]["violation"])
        prediction.sensitivity = "S3"; prediction.categories = ("HEALTH",)
        prediction.confidence = .4994
        self.assertTrue(safety_rows(release, [prediction], fake_model())[0]["violation"])
        prediction.confidence = .4996  # Production round to .500 restores the original BLOCK action.
        self.assertFalse(safety_rows(release, [prediction], fake_model())[0]["violation"])
        # No artificial teacher>=gold eligibility: a lower original S1/action floor is retained as-is.
        original["packed"] = 1 | 16 | 32
        original["confidence"] = .9
        prediction.sensitivity = "S1"; prediction.confidence = .9
        self.assertFalse(safety_rows(release, [prediction], fake_model())[0]["violation"])

    def test_independent_unweighted_hinge_normalization_unequal_row_counts(self):
        model = fake_model()
        target = Classification(3 | 16 | 32)
        examples = tuple(SemanticTrainingExample("manufactured", target, 1.) for _ in range(3))
        direction, loss = supervised_last_block_deltas(model, examples, set(model.parameters),
            objective=contract.HINGE_OBJECTIVE, retention_margins=(3., 3., 3.))
        single, single_loss = supervised_last_block_deltas(model, examples[:1], set(model.parameters),
            objective=contract.HINGE_OBJECTIVE, retention_margins=(3.,))
        self.assertAlmostEqual(loss, 1.)
        self.assertAlmostEqual(single_loss, loss)
        np.testing.assert_allclose(direction["head.sensitivity.bias"], [ -1., 0., 0., 1.], atol=1e-6)
        for name in direction:
            np.testing.assert_allclose(direction[name], single[name], atol=1e-6)
        diagnostic = {}
        _, exact_zero = supervised_last_block_deltas(model, examples[:1], set(model.parameters),
            objective=contract.HINGE_OBJECTIVE, retention_margins=(2.,), retention_diagnostics=diagnostic)
        self.assertEqual(exact_zero, 0.)
        self.assertEqual(diagnostic["active_rows"], 0)
        self.assertEqual(diagnostic["maximum_scaled_original_difference"], 0.)

    def test_scoped_reference_actual_dispatch_crosses_pool_and_never_leaks(self):
        teacher = {"profile": "quality", "model_id": "privoke-quality", "version": "manufactured",
                   "parameter_fingerprint": "a" * 64, "checksum": "b" * 64}
        calls = []
        snapshot = SimpleNamespace(model_id=teacher["model_id"], version=teacher["version"],
            fingerprint=teacher["parameter_fingerprint"], metadata={"artifact_checksum": teacher["checksum"]})
        def classify(text):
            calls.append((text, threading.get_ident()))
            return [ClassificationResult(Classification(3 | 16 | 32), text, "manufactured", confidence=.9)]
        model = SimpleNamespace(snapshot=snapshot, classify=classify)
        binding = ReferenceBinding(model, teacher, "manufactured-original.json")
        with patch.object(contract, "teacher_identity", return_value=teacher), patch.object(pipeline, "_detector_for", side_effect=AssertionError("current stream forbidden")):
            with bind_reference(binding):
                actual = pipeline.analyse_text("manufactured input", layers=("semantic",), semantic_model_id="privoke-quality")
                self.assertEqual(len(actual.layers), 1)
                self.assertEqual((actual.layers[0].layer, actual.layers[0].status), ("semantic", "ok"))
                self.assertEqual(actual.layers[0].semantic_model_identity["parameter_fingerprint"], "a" * 64)
                self.assertEqual(len(calls), 1)
                self.assertNotEqual(calls[0][1], threading.get_ident())
                for layers, model_id in ((None, "privoke-quality"), ((), "privoke-quality"), (("regex", "semantic"), "privoke-quality"), (("semantic",), "privoke-balanced")):
                    with self.assertRaises(ValueError):
                        pipeline.analyse_text("manufactured", layers=layers, semantic_model_id=model_id)
            self.assertIsNone(current_binding())
        with patch.object(pipeline, "_detector_for", return_value=lambda text: []) as default:
            pipeline.analyse_text("default following reference", layers=("semantic",), semantic_model_id="privoke-quality")
            default.assert_called_once()

    def test_reference_context_resets_after_failure_and_isolated_callers(self):
        teachers = [{"profile": "quality", "model_id": "privoke-quality", "version": str(i),
                     "parameter_fingerprint": str(i) * 64, "checksum": "b" * 64} for i in (1, 2)]
        def task(teacher):
            snapshot = SimpleNamespace(model_id=teacher["model_id"], version=teacher["version"],
                fingerprint=teacher["parameter_fingerprint"], metadata={"artifact_checksum": teacher["checksum"]})
            binding = ReferenceBinding(SimpleNamespace(snapshot=snapshot, classify=lambda text: []), teacher, teacher["version"])
            with bind_reference(binding):
                result = pipeline.analyse_text("manufactured", layers=("semantic",), semantic_model_id="privoke-quality")
            self.assertIsNone(current_binding())
            return result.layers[0].semantic_model_identity["model_version"]
        with patch.object(contract, "teacher_identity", side_effect=lambda path, profile: teachers[int(path) - 1]):
            with ThreadPoolExecutor(max_workers=2) as pool:
                self.assertEqual(list(pool.map(task, teachers)), ["1", "2"])
            with self.assertRaises(RuntimeError):
                with bind_reference(object()):
                    raise RuntimeError("manufactured failure")
            self.assertIsNone(current_binding())


if __name__ == "__main__":
    unittest.main()
