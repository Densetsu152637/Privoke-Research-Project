"""Synthetic-only checks for joint selection and paired bootstrap logic."""
from __future__ import annotations

import copy
import hashlib
import math
from pathlib import Path
import sys
import unittest

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evaluation"))
sys.path.insert(0, str(ROOT / "shared" / "python"))

from privoke_eval import in_house_study_analysis as analysis
from privoke_eval.in_house_study_contract import ARM_KEYS, ARMS


def sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def layer(status="ok", label="layer", reason=None):
    return {"status": status,
            "results_sha256": sha(label) if status == "ok" else None,
            "skip_reason": reason}


def outcome(detected: bool, *, label="outcome", block=False,
            sensitivity=None, categories=None):
    if sensitivity is None:
        sensitivity = "S2" if detected else "S0"
    if categories is None:
        categories = []
    if block:
        action = "BLOCK"
        layers = {
            "regex": layer(label=label + ":regex"),
            "ner": layer("skipped", reason=analysis.REGEX_BLOCK_REASON),
            "semantic": layer("skipped", reason=analysis.REGEX_BLOCK_REASON),
        }
    else:
        action = "ALLOW"
        layers = {
            "regex": layer(label=label + ":regex"),
            "ner": layer(label=label + ":ner"),
            "semantic": layer(label=label + ":semantic"),
        }
    return {
        "status": "complete", "error_count": 0,
        "classification": {
            "sensitivity": sensitivity, "visibility": "PU", "categories": list(categories),
        },
        "action": action, "allowed": not block,
        "masked_text_sha256": sha(label + ":mask"),
        "evidence_sha256": sha(label + ":evidence"),
        "layers": layers,
    }


def identity(arm: str, epoch: int):
    definition = ARMS[ARM_KEYS.index(arm)]
    version = "v1.0.0" if epoch == 0 else f"v1.0.0+epoch.{epoch}"
    return {
        "model_id": definition.model_id, "version": version,
        "artifact_sha256": sha(f"{arm}/{epoch}/file"),
        "artifact_checksum": sha(f"{arm}/{epoch}/checksum"),
        "parameter_fingerprint": sha(f"{arm}/{epoch}/params"),
    }


def row(row_index: int, truth: bool, *, ordinary_detect=True,
        nonsemantic_detect=None, probability=0.5, arm_identity=None,
        block=False):
    if nonsemantic_detect is None:
        nonsemantic_detect = truth
    ordinary = outcome(ordinary_detect, label=f"row-{row_index}-ordinary", block=block)
    gate_zero = copy.deepcopy(ordinary)
    nonsemantic = outcome(nonsemantic_detect, label=f"row-{row_index}-nonsemantic", block=block)
    nonsemantic["layers"]["regex"] = copy.deepcopy(ordinary["layers"]["regex"])
    nonsemantic["layers"]["ner"] = copy.deepcopy(ordinary["layers"]["ner"])
    nonsemantic["layers"]["semantic"] = {
        "status": "not_requested", "results_sha256": None,
        "skip_reason": analysis.NOT_REQUESTED_REASON,
    }
    if block:
        gate = {"status": "not_run", "identity": None, "probability": None,
                "predicted_present": None, "semantic_results_sha256": None}
    else:
        gate = {
            "status": "applied",
            "identity": {
                "model_id": arm_identity["model_id"],
                "model_version": arm_identity["version"],
                "artifact_checksum": arm_identity["artifact_checksum"],
                "parameter_fingerprint": arm_identity["parameter_fingerprint"],
            },
            "probability": float(probability), "predicted_present": probability >= 0.5,
            "semantic_results_sha256": ordinary["layers"]["semantic"]["results_sha256"],
        }
    return {
        "row_id_sha256": sha(f"row:{row_index}"),
        "group_id_sha256": sha(f"group:{row_index}"),
        "truth": truth, "ordinary": ordinary, "gate_zero": gate_zero,
        "nonsemantic": nonsemantic, "gate": gate,
    }


def validation_input(rows=4, positives=2, *, baseline_positive_predictions=None,
                     nonsemantic_positive_predictions=None,
                     one_arm_threshold_effect=False):
    if baseline_positive_predictions is None:
        baseline_positive_predictions = [True] * positives
    if nonsemantic_positive_predictions is None:
        nonsemantic_positive_predictions = [True] * positives
    control_hash = sha("shared-control-bindings")
    records = []
    for arm in ARM_KEYS:
        epochs = (0,) if arm in ("S0", "S1") else range(1, 6)
        checkpoints = []
        for epoch in epochs:
            identity_value = identity(arm, epoch)
            rows_data = []
            for index in range(rows):
                truth = index < positives
                ordinary_detect = baseline_positive_predictions[index] if truth else False
                nonsemantic_detect = nonsemantic_positive_predictions[index] if truth else False
                if not truth:
                    probability = 0.1
                elif one_arm_threshold_effect and arm == "B-F":
                    probability = 0.9 if index % 2 == 0 else 0.1
                else:
                    probability = 0.9
                rows_data.append(row(
                    index, truth, ordinary_detect=ordinary_detect,
                    nonsemantic_detect=nonsemantic_detect, probability=probability,
                    arm_identity=identity_value,
                ))
            checkpoints.append({"epoch": epoch, "identity": identity_value, "rows": rows_data})
        records.append({"arm": arm, "control_binding_sha256": control_hash,
                        "checkpoints": checkpoints})
    return {"schema_version": 1, "control_binding_sha256": control_hash, "arms": records}


def endpoint_input():
    rows = []
    for index in range(2000):
        truth = index < 1000
        group = index // 5
        rows.append({"row_id_sha256": sha(f"test:{index}"),
                     "group_id_sha256": sha(f"test-group:{group}"), "truth": truth})
    records = []
    for arm in ARM_KEYS:
        outcomes = []
        for index, row_value in enumerate(rows):
            predicted = row_value["truth"]
            if arm == "S1" and 1000 <= index < 1010:
                predicted = True
            elif arm == "B-F" and 1000 <= index < 1020:
                predicted = True
            # Even when action is ALLOW, S2 is a positive classification.
            outcomes.append({**row_value, "outcome": outcome(
                predicted, label=f"endpoint:{arm}:{index}",
                sensitivity="S2" if predicted else "S0",
            )})
        records.append({"arm": arm, "status": "complete", "error_count": 0,
                        "rows": outcomes})
    return {"schema_version": 1, "arms": records}


class JointSelectionTests(unittest.TestCase):
    def _internal(self, payload, *, recall_floor=0.9):
        return analysis._select_joint_validation(
            payload, expected_rows=4, positive_rows=2, recall_floor=recall_floor,
            min_components_per_class=0,
        )

    def test_full_fixed_validation_contract_selects_all_arms_and_keeps_candidate_table(self):
        result = analysis.select_joint_validation(validation_input(rows=2000, positives=1000))
        self.assertEqual(result["status"], "eligible")
        self.assertEqual(set(result["selections"]), set(ARM_KEYS))
        self.assertEqual(result["validation_rows"], 2000)
        self.assertFalse(result["test_authorized"])
        for arm, choice in result["selections"].items():
            self.assertEqual(choice["epoch"], 0 if arm in ("S0", "S1") else 1)
            self.assertEqual(choice["metrics"]["recall"], 1.0)
            thresholds = {candidate["threshold"] for candidate in result["candidate_tables"][arm]}
            self.assertIn(0.0, thresholds)
            self.assertIn(1.0, thresholds)
            self.assertTrue(any(candidate["reason"] for candidate in result["candidate_tables"][arm]))

    def test_joint_failure_withholds_every_selection_even_when_one_arm_can_pass(self):
        value = validation_input(
            baseline_positive_predictions=[True, False],
            nonsemantic_positive_predictions=[False, True],
            one_arm_threshold_effect=True,
        )
        # Ordinary and nonsemantic controls are shared. Only B-F's score ordering
        # lets one threshold retain both complementary positive findings.
        result = self._internal(value, recall_floor=0.9)
        self.assertEqual(result["status"], "ineligible")
        self.assertIsNone(result["selections"])
        self.assertIn("B-F", result["candidate_tables"])
        self.assertTrue(any(item["eligible"] for item in result["candidate_tables"]["B-F"]))
        self.assertFalse(any(item["eligible"] for item in result["candidate_tables"]["E-H"]))

    def test_earlier_epoch_and_threshold_ties_are_deterministic(self):
        value = validation_input()
        result = self._internal(value, recall_floor=0.5)
        self.assertEqual(result["status"], "eligible")
        self.assertEqual(result["selections"]["B-H"]["epoch"], 1)
        chosen = result["selections"]["B-H"]
        self.assertEqual(chosen["threshold"], 1.0)
        candidates = result["candidate_tables"]["B-H"]
        probabilities = [
            value["arms"][2]["checkpoints"][0]["rows"][0]["gate"]["probability"],
            float(np.nextafter(0.9, math.inf)),
        ]
        self.assertTrue(all(any(item["threshold"] == threshold for item in candidates)
                            for threshold in probabilities))

    def test_gate_zero_regex_block_is_fixed_not_run_not_a_negative_score(self):
        arm_identity = identity("S0", 0)
        item = row(0, True, arm_identity=arm_identity, block=True)
        validated = analysis._validate_row(item, arm_identity)
        self.assertEqual(validated["trace"], {"status": "not_run", "probability": None})
        self.assertTrue(analysis._detected(validated["ordinary"]))

    def test_detection_uses_classification_even_when_action_is_allow(self):
        value = outcome(False, sensitivity="S0", categories=["IDENTITY"])
        self.assertEqual(value["action"], "ALLOW")
        self.assertTrue(analysis._detected(analysis._validate_outcome(value)))

    def test_controls_identity_rows_threshold_and_checkpoint_inventory_fail_closed(self):
        mutations = []
        changed_binding = validation_input()
        changed_binding["arms"][1]["control_binding_sha256"] = sha("different")
        mutations.append(changed_binding)
        changed_control = validation_input()
        changed_control["arms"][3]["checkpoints"][0]["rows"][0]["nonsemantic"]["masked_text_sha256"] = sha("wrong")
        mutations.append(changed_control)
        changed_probability_identity = validation_input()
        changed_probability_identity["arms"][0]["checkpoints"][0]["rows"][0]["gate"]["identity"]["artifact_checksum"] = sha("wrong")
        mutations.append(changed_probability_identity)
        changed_truth_type = validation_input()
        changed_truth_type["arms"][0]["checkpoints"][0]["rows"][0]["truth"] = 1
        mutations.append(changed_truth_type)
        missing_checkpoint = validation_input()
        missing_checkpoint["arms"][2]["checkpoints"].pop()
        mutations.append(missing_checkpoint)
        duplicate_row = validation_input()
        duplicate_row["arms"][0]["checkpoints"][0]["rows"][1]["row_id_sha256"] = duplicate_row["arms"][0]["checkpoints"][0]["rows"][0]["row_id_sha256"]
        mutations.append(duplicate_row)
        for index, value in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(analysis.StudyAnalysisError):
                    self._internal(value)


class PairedEndpointTests(unittest.TestCase):
    def test_fixed_endpoint_metrics_and_shared_bootstrap_draws_cover_all_eight(self):
        result = analysis.analyze_paired_endpoint(endpoint_input())
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["rows"], 2000)
        self.assertEqual(set(result["arm_metrics"]), set(ARM_KEYS))
        self.assertEqual(result["arm_metrics"]["S0"]["tp"], 1000)
        contrasts = result["paired_component_bootstrap"]["contrasts"]
        self.assertAlmostEqual(contrasts["S1-S0"]["point_delta"]["specificity"], -0.01)
        self.assertAlmostEqual(contrasts["B-F-B-H"]["point_delta"]["specificity"], -0.02)
        self.assertTrue(contrasts["S1-S0"]["confirmatory_directional_contrast"])
        self.assertFalse(contrasts["E-F-E-H"]["confirmatory_directional_contrast"])
        self.assertFalse(result["test_authorized"])
        self.assertIsNone(result["retention_decision"])
        bootstrap = result["paired_component_bootstrap"]
        self.assertTrue(bootstrap["confirmatory_inference_eligible"])
        rng = np.random.default_rng(analysis.BOOTSTRAP_SEED)
        digest = hashlib.sha256()
        for _ in range(analysis.BOOTSTRAP_ITERATIONS):
            draw = rng.integers(0, result["component_count"], size=result["component_count"])
            digest.update(np.asarray(draw, dtype="<i8").tobytes())
        self.assertEqual(bootstrap["shared_component_draws_sha256"], digest.hexdigest())
        self.assertEqual(bootstrap["contrasts"]["S1-S0"]["valid_specificity_replicates"], 2000)

    def test_endpoint_counts_categories_and_sensitive_allow_as_detection(self):
        value = endpoint_input()
        row_value = value["arms"][0]["rows"][1000]
        row_value["outcome"]["classification"] = {
            "sensitivity": "S0", "visibility": "PU", "categories": ["IDENTITY"],
        }
        result = analysis.analyze_paired_endpoint(value)
        self.assertEqual(result["arm_metrics"]["S0"]["fp"], 1)

    def test_row_weighting_preserves_component_multiplicity_and_undefined_replicates(self):
        truth = np.asarray([True, True, False, False], dtype=np.bool_)
        predictions = np.tile(np.asarray([True, True, False, False], dtype=np.bool_), (8, 1))
        groups = np.asarray([0, 0, 1, 2], dtype=np.int64)
        confusion = analysis._resampled_confusions(truth, predictions, groups,
                                                   np.asarray([0, 0, 1], dtype=np.int64))
        self.assertIsNotNone(confusion)
        self.assertEqual(confusion[0]["positive_examples"], 4)
        self.assertEqual(confusion[0]["absent_examples"], 1)
        only_positive = analysis._resampled_confusions(
            truth, predictions, np.asarray([0, 1, 2, 3]), np.asarray([0, 1, 0, 1]),
        )
        self.assertIsNone(only_positive)

    def test_endpoint_join_error_count_prediction_and_group_truth_are_strict(self):
        mutations = []
        row_mismatch = endpoint_input()
        row_mismatch["arms"][1]["rows"][0]["row_id_sha256"] = sha("misaligned")
        mutations.append(row_mismatch)
        bad_error_count = endpoint_input()
        bad_error_count["arms"][0]["error_count"] = False
        mutations.append(bad_error_count)
        malformed_classification = endpoint_input()
        malformed_classification["arms"][2]["rows"][0]["outcome"]["classification"]["sensitivity"] = 1
        mutations.append(malformed_classification)
        mixed_group = endpoint_input()
        mixed_group["arms"][0]["rows"][0]["group_id_sha256"] = mixed_group["arms"][0]["rows"][1000]["group_id_sha256"]
        for value in (row_mismatch, bad_error_count, malformed_classification, mixed_group):
            with self.assertRaises(analysis.StudyAnalysisError):
                analysis.analyze_paired_endpoint(value)

    def test_small_fixture_replicates_report_undefined_class_draws(self):
        truth = [True, True, False, False]
        groups = [sha("p1"), sha("p2"), sha("n1"), sha("n2")]
        predictions = [list(truth) for _ in ARM_KEYS]
        result = analysis._paired_bootstrap(truth, groups, predictions, iterations=50, seed=14102026)
        self.assertGreater(result["undefined_class_replicates"], 0)
        self.assertEqual(result["valid_class_replicates"] + result["undefined_class_replicates"], 50)
        self.assertEqual(result["contrasts"]["B-F-B-H"]["specificity_interval_status"],
                         "insufficient_valid_replicates")


if __name__ == "__main__":
    unittest.main()
