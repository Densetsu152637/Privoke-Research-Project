"""Independent numeric oracles, protocol barriers and runtime parity fixtures."""
import copy
import math
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

os.environ["PRIVOKE_MODEL_DEVICE"] = "cpu"
import numpy as np
from privoke_eval import pretrained_context_study as study
from privoke.v1 import runtime_pb2 as RP


class PretrainedStudyTests(unittest.TestCase):
    def test_fixture_action_eligibility_null_and_warn_block_membership(self):
        row = {"ambiguous": True, "allowed_actions": None}
        self.assertEqual(study.fixture_action(row, "WARN"), {"action_eligible": False, "allowed_actions": None, "action_correct": None})
        row = {"ambiguous": False, "allowed_actions": ["WARN", "BLOCK"]}
        self.assertTrue(study.fixture_action(row, "WARN")["action_correct"])
        self.assertTrue(study.fixture_action(row, "BLOCK")["action_correct"])
        self.assertFalse(study.fixture_action(row, "ALLOW")["action_correct"])
        for invalid in (None, [], "WARN", ["REJECT"], ["WARN", "WARN"], [{}]):
            with self.assertRaises(ValueError):
                study.fixture_action({"ambiguous": False, "allowed_actions": invalid}, "WARN")

    def test_fixture_all_rows_retained_and_runtime_error_not_clean(self):
        data = [{"ambiguous": i < 7, "allowed_actions": None if i < 7 else ["WARN", "BLOCK"]} for i in range(48)]
        predictions = [{"id": str(i), "status": "ok", "quantitative": not row["ambiguous"],
            "sensitivity_correct": True, "visibility": "P3", **study.fixture_action(row, "WARN")} for i, row in enumerate(data)]
        summary = study.fixture_summary(data, predictions)
        self.assertEqual((summary["loaded_rows"], summary["ambiguous_exclusions"], summary["action_denominator"]), (48, 7, 41))
        self.assertTrue(all(p["action_correct"] is None for p in predictions[:7]))
        predictions[-1] = {"id": "47", "status": "error", "error": "runtime failed"}
        summary = study.fixture_summary(data, predictions)
        self.assertEqual(summary["runtime_errors"], 1)
        self.assertEqual(summary["action_denominator"], 40)
        self.assertEqual(summary["expected_action_eligible"], 41)
        self.assertEqual(summary["coverage"], 47 / 48)

    def amendment_fixture(self, root):
        original = {name: "original" for name in study.SECONDARY_CHANGED_PATHS}
        original["extension/client-runtime/src/model.py"] = "runtime"
        current = {**original, **{name: "amended" for name in study.SECONDARY_CHANGED_PATHS}}
        study.write(root / "eligibility.json", {"assets": {"directory": str(root), "backbone_sha256": "asset", "tokenizer_sha256": "asset"}})
        study.write(root / "freeze.json", {"source_revision": "original-revision", "sources": original,
            "eligibility_sha256": study.sha(root / "eligibility.json")})
        selections = []
        for arm in study.ARMS:
            for seed in study.SEEDS:
                directory = root / f"{arm}-{seed}"; directory.mkdir()
                study.write(directory / "artifact.json", {"head": arm, "seed": seed})
                study.write(directory / "selection.json", {"arm": arm, "seed": seed, "steps": 2000,
                    "freeze_sha256": study.sha(root / "freeze.json"),
                    "selected": {"artifact": "artifact.json", "artifact_sha256": study.sha(directory / "artifact.json")}})
                selections.append({"file": f"{arm}-{seed}/selection.json", "sha256": study.sha(directory / "selection.json")})
        study.write(root / "selection-commitment.json", {"freeze_sha256": study.sha(root / "freeze.json"), "selections": selections})
        amendment = {"schema_version": 1, "status": "accepted", "scope": "secondary-only", "amendment_id": "fixture-action-v1",
            "freeze_sha256": study.sha(root / "freeze.json"), "selection_commitment_sha256": study.sha(root / "selection-commitment.json"),
            "frozen_runtime_source_revision": "original-revision", "controller_revision": "amended-revision",
            "permitted_changed_paths": sorted(study.SECONDARY_CHANGED_PATHS),
            "amended_source_hashes": {name: current[name] for name in study.SECONDARY_CHANGED_PATHS},
            "reason": "Null ambiguous fixture action repair", "review_evidence": ["controlled test"], "test_evidence": ["controlled test"]}
        study.write(root / "amendment.json", amendment)
        return current, amendment

    def test_secondary_amendment_binds_scope_sources_selections_and_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            current, amendment = self.amendment_fixture(root)
            def fake_sha(path):
                return "asset" if Path(path).name in {"model.onnx", "tokenizer.json"} else real_sha(path)
            real_sha = study.sha
            def fake_git(*args):
                return "amended-revision" if args[0] == "rev-parse" else "\n".join(sorted(study.SECONDARY_CHANGED_PATHS))
            with patch.object(study, "source_inventory", return_value=current), patch.object(study, "verify_prepared"), patch.object(study, "git", side_effect=fake_git), patch.object(study, "sha", side_effect=fake_sha):
                self.assertEqual(study.verify_secondary_amendment(root, root / "amendment.json"), amendment)
                with self.assertRaisesRegex(ValueError, "Source/eligibility freeze changed"):
                    study.verify_freeze(root)
                current["extension/client-runtime/src/model.py"] = "changed-runtime"
                with self.assertRaisesRegex(ValueError, "Unlisted"):
                    study.verify_secondary_amendment(root, root / "amendment.json")
                current["extension/client-runtime/src/model.py"] = "runtime"
                for field, bad in (("scope", "fit"), ("controller_revision", "wrong-revision"), ("frozen_runtime_source_revision", "wrong-runtime")):
                    mutated = {**amendment, field: bad}; study.write(root / "amendment.json", mutated)
                    with self.assertRaises(ValueError):
                        study.verify_secondary_amendment(root, root / "amendment.json")
                study.write(root / "amendment.json", amendment)
                receipt_path = root / "random-42/selection.json"
                receipt = study.read(receipt_path)
                study.write(receipt_path, {**receipt, "steps": 1999})
                with self.assertRaisesRegex(ValueError, "artifact/receipt"):
                    study.verify_secondary_amendment(root, root / "amendment.json")
                study.write(receipt_path, receipt)
                study.write(root / "random-42/artifact.json", {"head": "mutated"})
                with self.assertRaisesRegex(ValueError, "artifact/receipt"):
                    study.verify_secondary_amendment(root, root / "amendment.json")

    def test_reuse_only_hash_bound_complete_random42_development(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "secondary-random-42.json"
            identity = {"model_id": "privoke-balanced", "artifact_checksum": "selected"}
            block = {"summary": {"loaded_samples": 502, "evaluated_samples": 502, "runtime_errors": 0},
                     "predictions": [{"id": str(i), "status": "ok"} for i in range(502)]}
            receipt = {"status": "failed", "identity": identity, "endpoints": {"development_presence": block}}
            study.write(path, receipt)
            amendment = {"development_reuse": {"path": str(path.resolve()), "receipt_sha256": study.sha(path),
                "block_sha256": study.sha256(study.canonical_json(block).encode())}}
            self.assertEqual(study.reuse_completed_development(path, amendment, "random", 42, identity), block)
            with self.assertRaises(ValueError):
                study.reuse_completed_development(path, amendment, "random", 43, identity)
            with self.assertRaises(ValueError):
                study.reuse_completed_development(path, amendment, "random", 42, {"artifact_checksum": "other"})
            receipt["endpoints"]["development_presence"]["predictions"].pop()
            study.write(path, receipt)
            with self.assertRaises(ValueError):
                study.reuse_completed_development(path, amendment, "random", 42, identity)

    def test_original_balanced_identity_matches_protobuf_float32_wire_values(self):
        from privoke.v1 import parameters_pb2 as PP
        from src.LLM.privoke.parameter_stream import ParameterSnapshot
        artifact = study.load_artifact(study.ROOT / "models/privoke-balanced.json")
        message = PP.ModelParametersResponse(model_id=artifact["model_id"], version=artifact["version"],
            generated_at_unix=artifact["generated_at_unix"], metadata={"artifact_checksum": artifact["checksum"]})
        for name, tensor in artifact["parameters"].items():
            message.parameters.add(name=name, values=tensor["values"], shape=tensor["shape"])
        wire = PP.ModelParametersResponse.FromString(message.SerializeToString())
        parameters = {p.name: list(p.values) for p in wire.parameters}
        shapes = {p.name: list(p.shape) for p in wire.parameters}
        raw = study.parameter_fingerprint({n: t["values"] for n, t in artifact["parameters"].items()}, shapes)
        wire_fingerprint = study.parameter_fingerprint(parameters, shapes)
        # This fixture must exercise the original defect, rather than already
        # float32-exact candidate head arrays that would conceal it.
        self.assertNotEqual(raw, wire_fingerprint)
        actual = study.artifact_identity(artifact)
        self.assertEqual(actual["parameter_fingerprint"], wire_fingerprint)
        snapshot = ParameterSnapshot(wire.model_id, wire.version, wire.generated_at_unix, parameters, shapes, dict(wire.metadata))
        self.assertEqual(actual["parameter_fingerprint"], snapshot.fingerprint)
        self.assertEqual(actual["artifact_checksum"], artifact["checksum"])
        self.assertEqual(actual["model_version"], artifact["version"])
        changed = copy.deepcopy(artifact)
        name = next(iter(changed["parameters"]))
        changed["parameters"][name]["values"][0] += .125
        self.assertNotEqual(study.artifact_identity(changed)["parameter_fingerprint"], wire_fingerprint)

    def test_combined_loss_gradients_against_finite_differences(self):
        x = np.array([[.2, -.3], [.8, .5]], dtype=np.float64)
        parameters = study.initialize(2, 42)
        truth = {"sensitivity": np.array([1, 3]), "visibility": np.array([0, 5]),
                 "category": np.array([[1] + [0] * 9, [0, 1] + [0] * 8])}
        _, gradients = study.loss_gradients(x, truth, parameters)
        for name, values in parameters.items():
            for index in (tuple(0 for _ in values.shape), tuple(v - 1 for v in values.shape)):
                before = values[index]
                values[index] = before + 1e-6
                plus, _ = study.loss_gradients(x, truth, parameters)
                values[index] = before - 1e-6
                minus, _ = study.loss_gradients(x, truth, parameters)
                values[index] = before
                self.assertAlmostEqual((plus - minus) / 2e-6, gradients[name][index], places=7)

    def test_adam_clipping_coupled_decay_and_moments_against_scalar_reference(self):
        parameters = {"weight": np.array([2., -3.])}
        optimizer = study.Adam(parameters)
        expected, m, v = [2., -3.], [0., 0.], [0., 0.]
        for step, gradients in enumerate(([3., 4.], [-.2, .1]), 1):
            norm = math.sqrt(sum(g * g for g in gradients))
            scale = min(1., 1. / (norm + 1e-12))
            for i in range(2):
                g = gradients[i] * scale + .0001 * expected[i]
                m[i] = .9 * m[i] + .1 * g
                v[i] = .999 * v[i] + .001 * g * g
                expected[i] -= .01 * (m[i] / (1 - .9 ** step)) / (math.sqrt(v[i] / (1 - .999 ** step)) + 1e-8)
            optimizer.step(parameters, {"weight": np.array(gradients)})
            np.testing.assert_allclose(parameters["weight"], expected, rtol=0, atol=1e-14)

    def test_fit_and_assessment_stop_before_rows_without_commitments(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(study, "rows", side_effect=AssertionError("premature dataset access")):
                with self.assertRaises(FileNotFoundError):
                    study.fit(SimpleNamespace(output=root))
                with patch.object(study, "verify_freeze", return_value=({}, {})):
                    with self.assertRaises(FileNotFoundError):
                        study.evaluate(SimpleNamespace(output=root))

    def test_checkpoint_rule_joint_then_overall_then_earlier(self):
        values = [{"epoch": 25, "nonS0_joint_correct": 40, "overall_joint_correct": 80},
                  {"epoch": 50, "nonS0_joint_correct": 41, "overall_joint_correct": 70},
                  {"epoch": 75, "nonS0_joint_correct": 41, "overall_joint_correct": 71},
                  {"epoch": 100, "nonS0_joint_correct": 41, "overall_joint_correct": 71}]
        self.assertEqual(max(values, key=study.checkpoint_key)["epoch"], 75)

    def test_joint_gain_boundary_and_public_serious_action_veto(self):
        data = study.resource_tools.render(study.read(study.RESOURCE))["assessment"]
        perfect = [{"id": row["id"], "target": row["classification"], "classification": copy.deepcopy(row["classification"]),
                    "required_action": row["allowed_actions"][0], "action": row["allowed_actions"][0]} for row in data]
        baseline = copy.deepcopy(perfect)
        serious = [i for i, p in enumerate(baseline) if p["target"]["sensitivity"] in {"S2", "S3"}]
        mild = [i for i, p in enumerate(baseline) if p["target"]["sensitivity"] == "S1"]
        for i in serious[:8] + mild[:2]:
            baseline[i]["classification"]["visibility"] = "P0" if baseline[i]["target"]["visibility"] != "P0" else "P1"
        result = study.paired_qualification(baseline, perfect)
        self.assertEqual(result["joint_gains_cases"], {"nonS0": 10, "serious": 8})
        self.assertTrue(result["both_primary_gains"])
        self.assertTrue(result["veto_clear"])
        candidate = copy.deepcopy(perfect)
        public = next(i for i in serious if candidate[i]["target"]["visibility"] == "P0" and candidate[i]["required_action"] == "BLOCK")
        candidate[public]["action"] = "WARN"
        result = study.paired_qualification(baseline, candidate)
        self.assertFalse(result["veto_clear"])
        self.assertEqual(len(result["serious_action_harms"]), 1)
        self.assertEqual(result["private_serious_action_harms"], [])

    def test_specificity_veto_counts_two_false_positives_as_more_than_two_pp(self):
        data = study.resource_tools.render(study.read(study.RESOURCE))["assessment"]
        before = [{"id": r["id"], "target": r["classification"], "classification": copy.deepcopy(r["classification"]),
                   "required_action": r["allowed_actions"][0], "action": r["allowed_actions"][0]} for r in data]
        after = copy.deepcopy(before)
        clean = [i for i, p in enumerate(after) if p["target"]["sensitivity"] == "S0"]
        after[clean[0]]["classification"]["categories"] = ["HEALTH"]
        self.assertTrue(study.paired_qualification(before, after)["veto_clear"])
        after[clean[1]]["classification"]["categories"] = ["HEALTH"]
        self.assertFalse(study.paired_qualification(before, after)["veto_clear"])

    def test_partial_selection_manifest_rejected_before_assessment(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            study.write(root / "selection-commitment.json", {"freeze_sha256": "frozen", "selections": [{}] * 5})
            with patch.object(study, "verify_freeze"), patch.object(study, "sha", return_value="frozen"), patch.object(study, "rows", side_effect=AssertionError("assessment read")):
                with self.assertRaisesRegex(ValueError, "six"):
                    study.selection_barrier(root)

    def test_empty_semantic_response_requires_used_pretrained_identity_and_no_gate(self):
        identity = {"model_id": "privoke-pretrained-context-minilm", "model_version": "fixture-v1",
                    "artifact_checksum": "a" * 64, "parameter_fingerprint": "b" * 64}
        response = RP.AnalyzePromptResponse(request_id="probe", action="ALLOW")
        response.classification.sensitivity = "S0"
        response.classification.visibility = "PU"
        response.layers.add(layer=RP.DETECTION_LAYER_SEMANTIC, status="ok")
        response.metadata.update({"privoke.pretrained_context." + k: v for k, v in
            {**identity, "backbone_sha256": study.BACKBONE_SHA256, "tokenizer_sha256": study.TOKENIZER_SHA256}.items()})
        study.validate_response(response, "probe", identity, True)
        response.metadata["privoke.pretrained_context.model_version"] = "wrong"
        with self.assertRaises(ValueError):
            study.validate_response(response, "probe", identity, True)
        response.metadata["privoke.pretrained_context.model_version"] = "fixture-v1"
        response.layers[0].semantic_presence_gate.model_id = "gate"
        with self.assertRaises(ValueError):
            study.validate_response(response, "probe", identity, True)

    def test_serialized_head_parity_and_actual_confidence_policy(self):
        from src.LLM.privoke.parameter_stream import ParameterSnapshot
        from src.LLM.privoke.pretrained_context_model import StreamedPretrainedContextModel
        from src.pipeline import strongest_result
        class Encoder:
            def encode_normalized(self, text):
                return np.ones(384, dtype=np.float32) / np.sqrt(np.float32(384))
        encoder = Encoder()
        parameters = study.initialize(384, 42)
        for values in parameters.values():
            values[:] = 0
        parameters["head.sensitivity.bias"][3] = .1
        parameters["head.category.bias"][:] = -5
        for bias, expected_action in ((.1, "WARN"), (4., "BLOCK")):
            parameters["head.sensitivity.bias"][3] = bias
            artifact = study.export_artifact("pretrained", parameters, {}, 42, 25, 100)
            features = np.stack([encoder.encode_normalized("x")])
            self.assertLessEqual(study.parity([{"text": "x"}], features, artifact, encoder), 1e-5)
            snapshot = ParameterSnapshot(artifact["model_id"], artifact["version"], 100,
                {n: t["values"] for n, t in artifact["parameters"].items()}, {n: t["shape"] for n, t in artifact["parameters"].items()},
                {"architecture": artifact["architecture"], "artifact_checksum": artifact["checksum"], "trainable_parameters": "",
                 "model_config": study.canonical_json(artifact["config"])})
            wrapper = StreamedPretrainedContextModel(snapshot, encoder)
            _, action = strongest_result(wrapper.classify("x"))
            self.assertEqual(action.name, expected_action)
