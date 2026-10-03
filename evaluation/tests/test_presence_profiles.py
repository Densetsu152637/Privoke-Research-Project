"""Focused tests for the bounded sparse presence evaluation interface."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "shared/python"))
sys.path.insert(0, str(ROOT / "evaluation"))

from privoke_model.artifact import validate_artifact  # noqa: E402
from privoke_model.presence import PROFILE_MAX_FEATURES, SparsePresenceModel  # noqa: E402
from privoke_eval.presence_rpc import response_record, validate_response  # noqa: E402
from privoke_eval.presence_training import (  # noqa: E402
    binary_metrics,
    build_artifact,
    make_vectorizer,
    select_threshold,
    serialized_runtime_model,
)


def rows(prefix: str, count: int):
    output = []
    for index in range(count):
        present = index % 2 == 0
        topic = "personal identifier account" if present else "garden weather schedule"
        output.append({"id": f"{prefix}-{index}", "group_id": f"fixture:{prefix}-{index}",
                       "text": f"{topic} shared example number {index}",
                       "text_key": f"{topic} shared example number {index}",
                       "expected_has_pii": present})
    return output


class PresenceProfileTests(unittest.TestCase):
    def test_profile_vectorizer_limits_and_roundtrip_artifact(self):
        train = rows("train", 40)
        vectorizer = make_vectorizer("efficient")
        documents = [row["text"] for row in train]
        matrix = vectorizer.fit_transform(documents)
        self.assertEqual(matrix.shape[1], sum(len(branch.get_feature_names_out())
                                              for _, branch in vectorizer.transformer_list))
        for profile, limit in PROFILE_MAX_FEATURES.items():
            profile_vectorizer = make_vectorizer(profile)
            for _, branch in profile_vectorizer.transformer_list:
                self.assertEqual(branch.max_features, limit)
        from sklearn.linear_model import LogisticRegression
        model = LogisticRegression(C=1, class_weight="balanced", solver="lbfgs",
                                   max_iter=1000, tol=1e-4, random_state=7102026)
        model.fit(matrix, [int(row["expected_has_pii"]) for row in train])
        artifact = build_artifact(vectorizer, model, "efficient", 0.5,
                                  {"task": "annotation_presence", "profile": "efficient",
                                   "release_version": "v1.0.0", "training_revision": "0"})
        validate_artifact(artifact)
        serialized = json.loads(json.dumps(artifact, allow_nan=False))
        runtime = SparsePresenceModel.from_artifact(serialized)
        probabilities = [runtime.predict_probability(row["text"]) for row in train]
        self.assertTrue(all(0.0 <= value <= 1.0 for value in probabilities))
        self.assertEqual(runtime.profile, "efficient")
        trainable = {name: tensor["trainable"] for name, tensor in artifact["parameters"].items()}
        self.assertTrue(all(flag == name.startswith("head.presence.")
                            for name, flag in trainable.items()))
        self.assertEqual(sum(len(tensor["values"]) for tensor in artifact["parameters"].values()),
                         2 * runtime.feature_dimension + 1)

    def test_runtime_threshold_uses_specificity_then_recall_then_threshold(self):
        labels = [True, True, True, True, False, False, False, False]
        probabilities = [0.95, 0.80, 0.40, 0.20, 0.90, 0.35, 0.30, 0.10]
        threshold, metrics = select_threshold(labels, probabilities, 0.75)
        self.assertEqual(threshold, 0.4)
        self.assertEqual(metrics["recall"], 0.75)
        self.assertEqual(metrics["specificity"], 0.75)

    def test_absent_class_rates_are_null(self):
        metrics = binary_metrics([True, True], [0.9, 0.1], 0.5)
        self.assertEqual(metrics["recall"], 0.5)
        self.assertIsNone(metrics["specificity"])
        self.assertIsNone(metrics["balanced_accuracy"])

    def test_candidate_calibration_reloads_a_serialized_artifact(self):
        spec = importlib.util.spec_from_file_location(
            "fit_presence_profiles", ROOT / "evaluation/fit-presence-profiles.py")
        fit = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fit)
        train, validation = rows("train", 40), rows("validation", 20)
        vectorizer = make_vectorizer("efficient")
        matrix = vectorizer.fit_transform([row["text"] for row in train])
        input_hashes = {"manifest_sha256": "a" * 64,
                        "partition_sha256": {"train": "b" * 64, "validation": "c" * 64},
                        "locked_sha256": {"development": "d" * 64},
                        "bootstrap_source_sha256": "e" * 64}
        with tempfile.TemporaryDirectory() as directory:
            candidate = fit.fit_candidate(vectorizer, matrix, train, validation, "efficient", 1.0,
                                          "f" * 40, "1" * 64, input_hashes, Path(directory))
            self.assertTrue((Path(directory) / "C-1-calibration.json").is_file())
            saved = json.loads((Path(directory) / "C-1-calibration.json").read_text(encoding="utf-8"))
            validate_artifact(saved)
            self.assertTrue(candidate["converged"])
            self.assertEqual(candidate["artifact"]["metadata"]["profile"], "efficient")
            self.assertEqual(candidate["artifact"]["metadata"]["train_sha256"], "b" * 64)
            self.assertEqual(candidate["artifact"]["checksum"], candidate["artifact_identity"]["artifact_checksum"])
            self.assertEqual(len(candidate["validation_predictions"]), len(validation))

    def test_live_response_requires_exact_identity_probability_and_enum(self):
        identity = {"model_id": "privoke-presence-efficient", "model_version": "v1.0.0",
                    "artifact_checksum": "a" * 64, "parameter_fingerprint": "b" * 64,
                    "threshold": 0.5}
        response = Mock(request_id="request-1", error="", model_id=identity["model_id"],
                        model_version=identity["model_version"], probability=0.8, threshold=0.5,
                        predicted_label=2, artifact_checksum=identity["artifact_checksum"],
                        parameter_fingerprint=identity["parameter_fingerprint"], elapsed_ms=2.5)
        record = response_record(response)
        checked = validate_response(record, request_id="request-1", expected_identity=identity,
                                    present_enum=2, absent_enum=1, expected_probability=0.8)
        self.assertEqual(checked["predicted_label"], 2)
        for changes in ({"request_id": "other"}, {"model_version": "v1.0.1"},
                        {"parameter_fingerprint": "c" * 64}, {"threshold": 0.4},
                        {"predicted_label": 0}, {"probability": 0.7}):
            with self.subTest(changes=changes):
                broken = {**record, **changes}
                with self.assertRaises(ValueError):
                    validate_response(broken, request_id="request-1", expected_identity=identity,
                                      present_enum=2, absent_enum=1, expected_probability=0.8)
        errored = response_record(Mock(request_id="request-1", error="model unavailable"))
        with self.assertRaises(RuntimeError):
            validate_response(errored, request_id="request-1", expected_identity=identity,
                              present_enum=2, absent_enum=1)


if __name__ == "__main__":
    unittest.main()
