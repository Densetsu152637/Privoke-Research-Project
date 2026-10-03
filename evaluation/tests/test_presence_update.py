"""Provenance and immutability guards for independent presence update scoring."""
from __future__ import annotations

import copy
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "shared/python"))
sys.path.insert(0, str(ROOT / "evaluation"))

from sklearn.linear_model import LogisticRegression  # noqa: E402

from privoke_model.artifact import artifact_checksum, float32, validate_artifact  # noqa: E402
from privoke_model.fingerprint import parameter_fingerprint  # noqa: E402
from privoke_model.presence import PROFILE_MAX_FEATURES, SparsePresenceModel  # noqa: E402
from privoke_eval.presence_evidence import (  # noqa: E402
    artifact_identity, load_frozen_fit, sha256_file, validate_base_and_candidate,
    validate_retention_selection,
)
from privoke_eval.presence_training import build_artifact, make_vectorizer  # noqa: E402

REVISION, PROTOCOL = "a" * 40, "b" * 64


def fixture_rows(count=60):
    result = []
    for index in range(count):
        label = index % 2 == 0
        phrase = "email account private identifier" if label else "garden weather common sentence"
        result.append({"id": f"row-{index}", "group_id": f"source:{index}",
                       "text": f"{phrase} repeated token {index}", "expected_has_pii": label})
    return result


def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


class PresenceEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        train, validation = fixture_rows(), fixture_rows(20)
        self.hashes = {"manifest_sha256": "c" * 64,
            "partition_sha256": {"train": "d" * 64, "validation": "e" * 64},
            "locked_sha256": {"development": "f" * 64}}
        self.base_metrics = {"tp": 428, "fn": 47, "tn": 100, "fp": 393,
            "positive_examples": 475, "absent_examples": 493,
            "recall": 428 / 475, "specificity": 100 / 493}
        self.selections = {}
        for profile in ("efficient", "balanced", "quality"):
            vectorizer = make_vectorizer(profile)
            matrix = vectorizer.fit_transform([row["text"] for row in train])
            model = LogisticRegression(C=1, class_weight="balanced", solver="lbfgs",
                max_iter=1000, tol=1e-4, random_state=7102026).fit(
                    matrix, [int(row["expected_has_pii"]) for row in train])
            artifact = build_artifact(vectorizer, model, profile, 0.5, {
                "release_version": "v1.0.0", "task": "annotation_presence", "profile": profile,
                "source_revision": REVISION, "protocol_sha256": PROTOCOL,
                "prepared_manifest_sha256": self.hashes["manifest_sha256"],
                "train_sha256": self.hashes["partition_sha256"]["train"],
                "validation_sha256": self.hashes["partition_sha256"]["validation"],
                "locked_development_sha256": self.hashes["locked_sha256"]["development"]})
            relative = f"profiles/{profile}/artifact.json"
            artifact_path = self.root / relative
            write_json(artifact_path, artifact)
            selection = {"status": "selected", "profile": profile, "source_revision": REVISION,
                "protocol_sha256": PROTOCOL, "input_hashes": self.hashes,
                "selected_artifact_file": relative,
                "selected_artifact_sha256": sha256_file(artifact_path),
                "artifact_identity": artifact_identity(artifact), "selected_C": 1.0,
                "candidates": [{"C": 1.0, "converged": True,
                                "validation_metrics": self.base_metrics}]}
            selection_path = self.root / f"profiles/{profile}/selection.json"
            write_json(selection_path, selection)
            self.selections[profile] = selection
        self.manifest_path = self.root / "run-manifest.json"
        self.write_manifest()
        self.selection_path = self.root / "profiles/balanced/selection.json"
        self.fit = load_frozen_fit(self.selection_path, self.manifest_path,
                                   fit_source_revision=REVISION, protocol_sha256=PROTOCOL)
        self.base = self.fit["artifact"]
        self.base_path = self.fit["artifact_path"]

    def tearDown(self):
        self.temp.cleanup()

    def write_manifest(self):
        manifest = {"status": "complete", "source_revision": REVISION,
            "protocol_sha256": PROTOCOL, "selections_frozen_before_development_scoring": True,
            "profiles": self.selections}
        write_json(self.manifest_path, manifest)

    def test_all_frozen_profile_selections_and_artifacts_are_bound(self):
        self.assertEqual(set(self.fit["profiles"]), {"efficient", "balanced", "quality"})
        broken = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        broken["profiles"].pop("quality")
        write_json(self.manifest_path, broken)
        with self.assertRaises(ValueError):
            load_frozen_fit(self.selection_path, self.manifest_path,
                            fit_source_revision=REVISION, protocol_sha256=PROTOCOL)

    def test_candidate_must_keep_frozen_config_and_idf(self):
        candidate = copy.deepcopy(self.base)
        candidate["config"]["threshold"] = 0.4
        candidate["checksum"] = artifact_checksum({k: v for k, v in candidate.items() if k != "checksum"})
        with self.assertRaises(ValueError):
            validate_base_and_candidate(self.base, candidate, fit_record=self.fit,
                candidate_path=self.base_path, evidence=None)

    def test_candidate_update_requires_bound_accepted_receipt_and_fp32_identity(self):
        candidate = copy.deepcopy(self.base)
        name = next(key for key in candidate["parameters"] if key.startswith("head.presence.weight."))
        candidate["parameters"][name]["values"][0] = float32(candidate["parameters"][name]["values"][0] + 0.001)
        candidate["version"] = self.base["version"] + "+train.1"
        candidate["metadata"]["training_revision"] = "1"
        candidate["metadata"]["last_update_source"] = "fixture-source"
        candidate["checksum"] = artifact_checksum({k: v for k, v in candidate.items() if k != "checksum"})
        validate_artifact(candidate)
        candidate_path = self.root / "candidate.json"
        write_json(candidate_path, candidate)
        base_id, candidate_id = artifact_identity(self.base), artifact_identity(candidate)
        evidence = {"candidate_artifact_sha256": sha256_file(candidate_path),
            "candidate_artifact_checksum": candidate["checksum"], "request_fingerprint": "1" * 64,
            "request": {"request_id": "r1", "source_id": "s1", "model_id": self.base["model_id"],
                        "prompt_count": 256, "seed": 42},
            "response": {"accepted": True, "model_id": self.base["model_id"],
                "base_version": self.base["version"], "applied_version": candidate["version"],
                "prompts_generated": 256, "metadata": {"task": "annotation_presence",
                    "base_parameter_fingerprint": base_id["parameter_fingerprint"],
                    "candidate_parameter_fingerprint": candidate_id["parameter_fingerprint"]}},
            "receipt": {"found": True, "accepted": True, "model_id": self.base["model_id"],
                "base_version": self.base["version"], "applied_version": candidate["version"],
                "request_fingerprint": "1" * 64}}
        result = validate_base_and_candidate(self.base, candidate, fit_record=self.fit,
            candidate_path=candidate_path, evidence=evidence)
        self.assertTrue(result["changed"])
        updated_metrics = {"tp": 428, "fn": 47, "tn": 101, "fp": 392,
            "positive_examples": 475, "absent_examples": 493,
            "recall": 428 / 475, "specificity": 101 / 493}
        accepted = {"seed": 42, "status": "accepted", "accepted": True,
            "validation_metrics": updated_metrics, "artifact_sha256": sha256_file(candidate_path),
            "artifact_checksum": candidate["checksum"],
            "parameter_fingerprint": candidate_id["parameter_fingerprint"],
            "validation_report_sha256": "2" * 64}
        retention = {"status": "selected", "profile": "balanced", "source_revision": "c" * 40,
            "fit_source_revision": REVISION, "protocol_sha256": PROTOCOL,
            "fit_manifest_sha256": self.fit["manifest_sha256"],
            "base_artifact_sha256": self.fit["selection"]["selected_artifact_sha256"],
            "chosen_candidate_artifact_sha256": sha256_file(candidate_path),
            "chosen_artifact_checksum": candidate["checksum"],
            "chosen_parameter_fingerprint": candidate_id["parameter_fingerprint"],
            "chosen_validation_report_sha256": "2" * 64,
            "base_validation_report_sha256": "1" * 64,
            "validation_dataset_sha256": self.hashes["partition_sha256"]["validation"],
            "base_validation_metrics": self.base_metrics,
            "validation_metrics": updated_metrics, "chosen_seed": 42,
            "attempts": [accepted, {"seed": 43, "status": "rejected", "accepted": False},
                         {"seed": 44, "status": "failed", "accepted": False}]}
        validate_retention_selection(retention, candidate, candidate_path, self.fit,
                                     "c" * 40, PROTOCOL)
        corrupted = copy.deepcopy(evidence)
        corrupted["response"]["metadata"]["candidate_parameter_fingerprint"] = "2" * 64
        with self.assertRaises(ValueError):
            validate_base_and_candidate(self.base, candidate, fit_record=self.fit,
                candidate_path=candidate_path, evidence=corrupted)

    def test_retention_must_bind_candidate_and_all_fixed_seed_terminals(self):
        base_id = artifact_identity(self.base)
        base_metrics = self.base_metrics
        record = {"status": "selected", "profile": "balanced", "source_revision": "c" * 40,
            "fit_source_revision": REVISION, "protocol_sha256": PROTOCOL,
            "fit_manifest_sha256": self.fit["manifest_sha256"],
            "base_artifact_sha256": self.fit["selection"]["selected_artifact_sha256"],
            "chosen_candidate_artifact_sha256": self.fit["selection"]["selected_artifact_sha256"],
            "chosen_artifact_checksum": self.base["checksum"],
            "chosen_parameter_fingerprint": base_id["parameter_fingerprint"],
            "chosen_seed": None, "validation_metrics": base_metrics,
            "base_validation_metrics": base_metrics, "restoration_verified": True,
            "validation_dataset_sha256": self.hashes["partition_sha256"]["validation"],
            "base_validation_report_sha256": "1" * 64,
            "chosen_validation_report_sha256": "1" * 64,
            "attempts": [{"seed": seed, "status": "rejected", "accepted": False}
                         for seed in (42, 43, 44)]}
        validate_retention_selection(record, self.base, self.base_path, self.fit, "c" * 40, PROTOCOL)
        record["attempts"] = record["attempts"][:2]
        with self.assertRaises(ValueError):
            validate_retention_selection(record, self.base, self.base_path, self.fit, "c" * 40, PROTOCOL)

    def test_base_scorer_cli_validates_revision_and_dispatches_valid_arguments(self):
        spec = importlib.util.spec_from_file_location(
            "evaluate_presence_cli_smoke", ROOT / "evaluation/evaluate-presence.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        args = ["--artifact", "unused-artifact.json", "--selection", "unused-selection.json",
            "--fit-manifest", "unused-run-manifest.json", "--dataset-file", "development.jsonl",
            "--output", str(ROOT / "evaluation/results/cli-smoke"), "--source-revision", REVISION,
            "--fit-source-revision", "c" * 40, "--protocol-sha256", PROTOCOL]
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as invalid:
                module.main([*args[:args.index("--source-revision") + 1], "bad-revision",
                             *args[args.index("--source-revision") + 2:]])
        self.assertEqual(invalid.exception.code, 2)
        with patch.object(module, "run", return_value={
                "status": "complete", "rows": 502, "errors": []}) as run_mock:
            with contextlib.redirect_stdout(io.StringIO()):
                status = module.main(args)
        self.assertEqual(status, 0)
        self.assertEqual(run_mock.call_args.args[5], REVISION)
        self.assertEqual(run_mock.call_args.args[6], "c" * 40)
        self.assertEqual(run_mock.call_args.args[8], PROTOCOL)


if __name__ == "__main__":
    unittest.main()
