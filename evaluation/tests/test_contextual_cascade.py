"""Independent projections, trace guards and frozen cascade phase tests."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("cascade", ROOT / "evaluation/evaluate-contextual-cascade.py")
CASCADE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CASCADE)


def outcome(positive, action=None):
    return {"classification": {"sensitivity": "S2" if positive else "S0", "visibility": "PU", "categories": []},
            "action": action or ("WARN" if positive else "ALLOW"), "allowed": not positive,
            "masked_text": "", "evidence": {}, "elapsed_ms": 1.0, "error": "", "layers": []}


def row(row_id, truth, probability, *, rule_positive=False, semantic_positive=True):
    return {"id": row_id, "group_id": "fixture:" + row_id, "expected_has_pii": truth,
            "ordinary": outcome(rule_positive or semantic_positive), "nonsemantic": outcome(rule_positive),
            "gated": outcome(rule_positive or semantic_positive), "trace": {"probability": probability}}


SEMANTIC = {"model_id": "privoke-balanced", "model_version": "v0.3.0",
            "artifact_checksum": "a" * 64, "parameter_fingerprint": "b" * 64}
PRESENCE = {"model_id": "privoke-presence-efficient", "model_version": "v1",
            "artifact_checksum": "c" * 64, "parameter_fingerprint": "d" * 64, "threshold": .3}


def triplet(probability=.4, threshold=0):
    result = {"classification": {"sensitivity": "S2", "categories": [], "visibility": "PU"},
              "metadata": dict(SEMANTIC)}
    ordinary = outcome(True)
    ordinary["layers"] = [{"layer": name, "status": "ok", "error": "", "results": []} for name in ("regex", "ner")]
    ordinary["layers"].append({"layer": "semantic", "status": "ok", "error": "", "results": [result]})
    gated = copy.deepcopy(ordinary)
    trace = {**{k: v for k, v in PRESENCE.items() if k != "threshold"}, "status": "applied",
             "probability": probability, "model_threshold": .3, "decision_threshold": threshold,
             "predicted_label": "present" if probability >= threshold else "absent",
             "semantic_results": [result], "error": ""}
    trace.update({"contextual_" + k: v for k, v in SEMANTIC.items()})
    gated["layers"][-1]["semantic_presence_gate"] = trace
    if probability < threshold:
        gated.update({k: v for k, v in outcome(False).items() if k != "layers"})
        gated["layers"][-1]["results"] = []
    nonsemantic = outcome(False)
    nonsemantic["layers"] = copy.deepcopy(ordinary["layers"][:2])
    return ordinary, gated, nonsemantic


def regex_shortcut(threshold=0):
    """Wire shape emitted by the producer's regex-first BLOCK shortcut."""
    reason = "Skipped after regex returned BLOCK."
    ordinary = outcome(True, "BLOCK")
    ordinary["classification"]["sensitivity"] = "S3"
    ordinary["layers"] = [{"layer": "regex", "status": "ok", "error": "",
                           "results": [{"action": "BLOCK", "classification": ordinary["classification"], "metadata": {}}]},
                          {"layer": "ner", "status": "skipped", "error": reason, "results": []},
                          {"layer": "semantic", "status": "skipped", "error": reason, "results": []}]
    gated = copy.deepcopy(ordinary)
    gated["layers"][-1]["semantic_presence_gate"] = {"status": "not_run", "model_id": PRESENCE["model_id"],
        "decision_threshold": threshold, "error": reason, "semantic_results": [], "predicted_label": "unspecified"}
    return ordinary, gated


class CascadeTests(unittest.TestCase):
    def test_optional_aggregate_evidence_can_be_absent_on_both_outputs(self):
        ordinary, gated, nonsemantic = triplet()
        del ordinary["evidence"]
        del gated["evidence"]
        self.assertIsNone(CASCADE.summary(ordinary)["evidence"])
        self.assertEqual(CASCADE.summary(ordinary), CASCADE.summary(gated))
        CASCADE.verify_triplet(ordinary, gated, nonsemantic, {"semantic": SEMANTIC, "presence": PRESENCE})

    def test_present_aggregate_evidence_remains_part_of_parity(self):
        ordinary, gated, nonsemantic = triplet()
        del ordinary["evidence"]
        self.assertNotEqual(CASCADE.summary(ordinary), CASCADE.summary(gated))
        with self.assertRaises(ValueError):
            CASCADE.verify_triplet(ordinary, gated, nonsemantic, {"semantic": SEMANTIC, "presence": PRESENCE})
        ordinary["evidence"] = {"action": "WARN"}
        gated["evidence"] = {"action": "BLOCK"}
        self.assertNotEqual(CASCADE.summary(ordinary), CASCADE.summary(gated))

    def test_optional_evidence_does_not_default_required_aggregate_fields(self):
        for key in ("classification", "action", "allowed", "masked_text"):
            with self.subTest(key=key):
                payload = outcome(False)
                del payload[key]
                with self.assertRaises(KeyError):
                    CASCADE.summary(payload)

    def test_contextual_identity_matches_float32_transport_with_framed_tensors(self):
        artifact = {"model_id": "privoke-balanced", "version": "fixture", "checksum": "a" * 64,
                    "parameters": {"z.weight": {"values": [.1, -.3], "shape": [1, 2]},
                                   "a.bias": {"values": [1.00000001], "shape": [1]}}}
        transported = [[name, tensor["shape"],
                        [struct.unpack("!f", struct.pack("!f", value))[0] for value in tensor["values"]]]
                       for name, tensor in sorted(artifact["parameters"].items())]
        expected = hashlib.sha256(json.dumps(transported, separators=(",", ":"),
                                            ensure_ascii=False, allow_nan=False).encode()).hexdigest()
        raw = CASCADE.parameter_fingerprint(
            {name: tensor["values"] for name, tensor in artifact["parameters"].items()},
            {name: tensor["shape"] for name, tensor in artifact["parameters"].items()})
        self.assertNotEqual(expected, raw)
        self.assertEqual(CASCADE.contextual_identity(artifact), {
            "model_id": "privoke-balanced", "model_version": "fixture", "artifact_checksum": "a" * 64,
            "parameter_fingerprint": expected})
        self.assertEqual(artifact["parameters"]["a.bias"]["values"], [1.00000001])

    def test_contextual_identity_keeps_tensor_shape_and_name_binding(self):
        artifact = {"model_id": "fixture", "version": "v1", "checksum": "a" * 64,
                    "parameters": {"head": {"values": [.1, .2], "shape": [1, 2]}}}
        expected = CASCADE.contextual_identity(artifact)["parameter_fingerprint"]
        reshaped = copy.deepcopy(artifact)
        reshaped["parameters"]["head"]["shape"] = [2, 1]
        renamed = copy.deepcopy(artifact)
        renamed["parameters"]["other"] = renamed["parameters"].pop("head")
        for changed in (reshaped, renamed):
            self.assertNotEqual(CASCADE.contextual_identity(changed)["parameter_fingerprint"], expected)

    def test_threshold_projection_preserves_rule_actions(self):
        value = row("a", True, .1, rule_positive=True)
        self.assertEqual(CASCADE.project(value, .9), value["nonsemantic"])
        self.assertTrue(CASCADE.detection(CASCADE.project(value, .9)))

    def test_calibration_handles_ge_boundary_and_highest_threshold_tie(self):
        values = [row("positive", True, .8), row("negative", False, .2)]
        result = CASCADE.calibrate(values)
        self.assertEqual(result["chosen"]["threshold"], .8)
        self.assertEqual(result["chosen"]["metrics"]["recall"], 1)
        self.assertEqual(result["chosen"]["metrics"]["specificity"], 1)
        self.assertIn(math_next(.2), [x["threshold"] for x in result["candidates"]])

    def test_calibration_floor_can_be_infeasible(self):
        values = [row("positive", True, .8, semantic_positive=False), row("negative", False, .2)]
        result = CASCADE.calibrate(values)
        self.assertEqual(result["status"], "ineligible")
        self.assertIsNone(result["chosen"])
        self.assertTrue(result["candidates"])

    def test_skip_gate_has_no_projected_effect(self):
        value = row("short", True, .1)
        value["trace"] = None
        self.assertIs(CASCADE.project(value, 1), value["ordinary"])

    def test_binary_proxy_is_separate_from_action(self):
        value = outcome(True, "ALLOW")
        self.assertTrue(CASCADE.detection(value))
        self.assertEqual(value["action"], "ALLOW")

    def test_paired_report_exposes_losses_and_transitions(self):
        values = [row("private", True, .1), row("public", False, .2)]
        report = CASCADE.paired_report(values, lambda r: CASCADE.project(r, .5))
        self.assertEqual(report["lost_detection_ids"], ["private", "public"])
        self.assertEqual(report["action_transitions"], {"WARN->ALLOW": 2})

    def test_projection_suppression_uses_projection_threshold_not_gate_zero_label(self):
        value = row("private", True, .1)
        value["trace"]["predicted_label"] = "present"
        report = CASCADE.paired_report([value], lambda r: CASCADE.project(r, .5), projection_threshold=.5)
        self.assertEqual(report["lost_detection_ids"], ["private"])
        self.assertEqual(report["suppressed_semantic_ids"], ["private"])
        self.assertEqual(report["actual_trace_absent_ids"], [])
        zero = CASCADE.paired_report([value], lambda r: CASCADE.project(r, 0), projection_threshold=0)
        one = CASCADE.paired_report([value], lambda r: CASCADE.project(r, 1), projection_threshold=1)
        self.assertEqual(zero["suppressed_semantic_ids"], [])
        self.assertEqual(one["suppressed_semantic_ids"], ["private"])
        value["trace"]["probability"] = 1
        boundary = CASCADE.paired_report([value], lambda r: CASCADE.project(r, 1), projection_threshold=1)
        self.assertEqual(boundary["suppressed_semantic_ids"], [])

    def test_legitimate_regex_block_not_run_preserves_documented_reason(self):
        ordinary, gated = regex_shortcut(.7)
        self.assertIsNone(CASCADE.verify_live(ordinary, gated, {"semantic": SEMANTIC, "presence": PRESENCE}, .7))
        gated["layers"][-1]["semantic_presence_gate"]["error"] = ""
        with self.assertRaisesRegex(ValueError, "NOT_RUN"):
            CASCADE.verify_live(ordinary, gated, {"semantic": SEMANTIC, "presence": PRESENCE}, .7)

    def test_skip_cannot_hide_semantic_execution_or_tampered_gate_request(self):
        ordinary, gated, _ = triplet()
        gated["layers"][-1].update({"status": "skipped", "results": []})
        gated["layers"][-1]["semantic_presence_gate"] = {"status": "not_run", "model_id": "wrong",
            "decision_threshold": .9, "error": "hidden failure", "semantic_results": [], "predicted_label": "unspecified"}
        with self.assertRaisesRegex(ValueError, "execution statuses"):
            CASCADE.verify_live(ordinary, gated, {"semantic": SEMANTIC, "presence": PRESENCE}, 0)
        for field, value in (("model_id", "wrong"), ("decision_threshold", .8), ("error", "different reason"),
                             ("predicted_label", "present"), ("probability", 0), ("model_threshold", .3),
                             ("model_version", "invented")):
            ordinary, gated = regex_shortcut(.7)
            gated["layers"][-1]["semantic_presence_gate"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "NOT_RUN"):
                CASCADE.verify_live(ordinary, gated, {"semantic": SEMANTIC, "presence": PRESENCE}, .7)
        ordinary, gated = regex_shortcut(.7)
        ordinary["action"] = gated["action"] = "ALLOW"
        with self.assertRaisesRegex(ValueError, "NOT_RUN"):
            CASCADE.verify_live(ordinary, gated, {"semantic": SEMANTIC, "presence": PRESENCE}, .7)

    def test_selected_validation_rejects_trace_presence_change_even_with_same_decision(self):
        previous = row("private", True, .4)
        current = copy.deepcopy(previous)
        CASCADE.verify_selected_validation(current, previous, 0)
        current["trace"] = None
        with self.assertRaisesRegex(ValueError, "trace execution"):
            CASCADE.verify_selected_validation(current, previous, 0)
        previous["trace"] = None
        current["trace"] = {"probability": .4}
        with self.assertRaisesRegex(ValueError, "trace execution"):
            CASCADE.verify_selected_validation(current, previous, 0)
        current["trace"] = None
        CASCADE.verify_selected_validation(current, previous, 0)

    def test_selected_validation_rejects_changed_probability_under_same_decision(self):
        previous = row("private", True, .4)
        current = copy.deepcopy(previous)
        current["trace"]["probability"] = .41
        with self.assertRaisesRegex(ValueError, "probability changed"):
            CASCADE.verify_selected_validation(current, previous, 0)

    def test_zero_gate_and_raw_semantic_parity(self):
        ordinary, gated, rules = triplet()
        CASCADE.verify_triplet(ordinary, gated, rules, {"semantic": SEMANTIC, "presence": PRESENCE})
        gated["layers"][-1]["semantic_presence_gate"]["semantic_results"] = []
        with self.assertRaisesRegex(ValueError, "Raw semantic"):
            CASCADE.verify_triplet(ordinary, gated, rules, {"semantic": SEMANTIC, "presence": PRESENCE})

    def test_error_and_wrong_identity_are_never_calibration_evidence(self):
        ordinary, gated, _ = triplet()
        gated["layers"][-1]["semantic_presence_gate"]["artifact_checksum"] = "wrong"
        with self.assertRaisesRegex(ValueError, "identity"):
            CASCADE.verify_live(ordinary, gated, {"semantic": SEMANTIC, "presence": PRESENCE}, 0)
        ordinary["error"] = "semantic outage"
        with self.assertRaisesRegex(ValueError, "errors"):
            CASCADE.validate_payload(ordinary, SEMANTIC)

    def test_absent_drops_only_semantic_and_rejects_residual_contribution(self):
        ordinary, gated, _ = triplet(threshold=.5)
        CASCADE.verify_live(ordinary, gated, {"semantic": SEMANTIC, "presence": PRESENCE}, .5)
        gated["layers"][-1]["results"] = ordinary["layers"][-1]["results"]
        with self.assertRaisesRegex(ValueError, "retained semantic"):
            CASCADE.verify_live(ordinary, gated, {"semantic": SEMANTIC, "presence": PRESENCE}, .5)

    def test_request_explicit_zero_threshold_and_ordinary_omission(self):
        pb = SimpleNamespace(DETECTION_LAYER_REGEX=2, DETECTION_LAYER_NER=3, REGEX_EXECUTION_ORDER_FIRST=1,
                             SemanticPresenceGate=lambda **kwargs: kwargs, AnalyzePromptRequest=lambda **kwargs: kwargs)
        ordinary = CASCADE.request_for(pb, "test", "id", "privoke-balanced")
        self.assertNotIn("semantic_presence_gate", ordinary)
        gated = CASCADE.request_for(pb, "test", "id", "privoke-balanced", presence_id=PRESENCE["model_id"], threshold=0)
        self.assertEqual(gated["semantic_presence_gate"]["threshold"], 0)
        hinted = CASCADE.request_for(pb, "test", "id", "privoke-balanced", visibility_hint="P3")
        self.assertEqual(hinted["visibility_hint"], "P3")
        self.assertNotIn("visibility_hint", ordinary)
        with self.assertRaises(ValueError):
            CASCADE.request_for(pb, "test", "id", "privoke-balanced", visibility_hint="private")
        with self.assertRaises(ValueError):
            CASCADE.request_for(pb, "test", "id", "privoke-balanced", presence_id=PRESENCE["model_id"], threshold=float("nan"))

    def test_prior_phase_digest_and_confusion_tampering_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "collect-validation/original-efficient"
            directory.mkdir(parents=True)
            values = [row("p", True, .8), row("n", False, .2)]
            CASCADE.write(directory / "predictions.json", values)
            CASCADE.complete_report(directory, values, lambda r: r["gated"], {}, "original-efficient", "collect-validation")
            CASCADE.verified_rows(directory, values, {}, "original-efficient")
            report = CASCADE.read(directory / "report.json")
            report["metrics"]["tp"] = 0
            (directory / "report.json").write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "confusion"):
                CASCADE.verified_rows(directory, values, {}, "original-efficient")

    def test_development_cannot_start_without_frozen_all_six_choices(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "study"
            root.mkdir()
            CASCADE.write(root / "study-manifest.json", {"binding": {}})
            args = SimpleNamespace(study_root=root, phase="evaluate-development", validation_file=root / "v",
                                   control="original", profile="efficient")
            with patch.object(CASCADE, "inside_results", side_effect=lambda p: p), patch.object(CASCADE, "bind_inputs", return_value={}), patch.object(CASCADE, "dataset", return_value=[]):
                with self.assertRaises(FileNotFoundError):
                    CASCADE.run_stage(args, client_factory=lambda target: self.fail("No RPC before frozen choices"))

    def test_all_six_freeze_and_live_parity_are_required_before_development(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "study"
            reference = [{"id": "positive", "text": "fixture private", "group_id": "fixture:p", "expected_has_pii": True},
                         {"id": "negative", "text": "fixture public", "group_id": "fixture:n", "expected_has_pii": False}]
            binding = {"controls": {name: {"identity": SEMANTIC} for name in CASCADE.CONTROLS},
                       "presence": {name: {"identity": PRESENCE} for name in CASCADE.PROFILES}}
            calls = []
            class Client:
                def analyze(self, example, request_id, semantic_id, **kwargs):
                    calls.append((example["id"], kwargs))
                    ordinary, gated, nonsemantic = triplet(probability=.8 if example["expected_has_pii"] else .2,
                                                          threshold=kwargs.get("threshold", 0))
                    value = nonsemantic if kwargs.get("nonsemantic") else gated if "presence_id" in kwargs else ordinary
                    return value, copy.deepcopy(value)
                def close(self):
                    pass
            args = SimpleNamespace(study_root=root, target="fixture", validation_file=root / "validation",
                                   development_file=root / "development", phase="collect-validation")
            with patch.object(CASCADE, "inside_results", side_effect=lambda p: p), patch.object(CASCADE, "bind_inputs", return_value=binding), patch.object(CASCADE, "dataset", return_value=reference):
                for control in CASCADE.CONTROLS:
                    for profile in CASCADE.PROFILES:
                        args.control, args.profile = control, profile
                        CASCADE.run_stage(args, lambda target: Client())
                args.phase = "calibrate"
                CASCADE.run_stage(args, lambda target: self.fail("Calibration must not call runtime"))
                selected = CASCADE.read(root / "calibration/selection.json")
                self.assertEqual(set(selected["choices"]), set(CASCADE.PAIRS))
                self.assertTrue(all(x["chosen"]["threshold"] == .8 for x in selected["choices"].values()))
                args.phase = "evaluate-development"
                count_before = len(calls)
                with self.assertRaises(FileNotFoundError):
                    CASCADE.run_stage(args, lambda target: self.fail("Development before all-six parity"))
                self.assertEqual(len(calls), count_before)
                args.phase = "evaluate-validation"
                for control in CASCADE.CONTROLS:
                    for profile in CASCADE.PROFILES:
                        args.control, args.profile = control, profile
                        CASCADE.run_stage(args, lambda target: Client())
                args.phase = "evaluate-development"
                CASCADE.run_stage(args, lambda target: Client())
                self.assertEqual(CASCADE.read(root / args.phase / f"{args.control}-{args.profile}" / "report.json")["metrics"]["specificity"], 1)
                with self.assertRaises(FileExistsError):
                    CASCADE.run_stage(args, lambda target: self.fail("Refuse reused output"))


def math_next(value):
    import math
    return math.nextafter(value, math.inf)


if __name__ == "__main__":
    unittest.main()
