"""Study ownership, evidence, selection and failure checks without Docker."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "shared/python/tests"))
from test_presence import artifact_fixture
from privoke_model.artifact import apply_parameter_update, artifact_checksum, load_artifact, validate_artifact

SPEC = importlib.util.spec_from_file_location("presence_study", ROOT / "evaluation/run-presence-update-study.py")
STUDY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STUDY)
SOURCE = "a" * 40
PROTOCOL = "b" * 64
KEYS = {"one": (True, "fixture:1"), "two": (True, "fixture:2"),
        "three": (False, "fixture:3"), "four": (False, "fixture:4")}


def metric(recall=1, specificity=.5):
    return {"recall": recall, "specificity": specificity}


def response_metadata(base, candidate):
    return {"base_parameter_fingerprint": STUDY.identity(base)["parameter_fingerprint"],
            "candidate_parameter_fingerprint": STUDY.identity(candidate)["parameter_fingerprint"],
            "examples": "256", "heldout_examples": "32", "heldout_present_examples": "16", "heldout_absent_examples": "16",
            "exact_match_rate": ".8", "heldout_present_recall": ".8", "heldout_absent_specificity": ".8",
            "heldout_exact_match_rate": ".8", "candidate_heldout_present_recall": ".9",
            "candidate_heldout_absent_specificity": ".9", "candidate_heldout_exact_match_rate": ".9"}


class FakeBackend:
    def __init__(self, catalog):
        self.catalog = copy.deepcopy(catalog)
        self.installs, self.calls = [], []
        self.reject = False
        self.score_failure = False
        self.restore_failure = False
        self.uncertain = False
        self.receipt = None

    def read(self, model_id):
        return json.dumps(self.catalog[model_id]) if model_id in self.catalog else None

    def install(self, artifact):
        if self.restore_failure:
            raise OSError("restore blocked fixture")
        self.installs.append(copy.deepcopy(artifact))
        self.catalog[artifact["model_id"]] = copy.deepcopy(artifact)

    def configure(self, model_id):
        self.calls.append(("configure", model_id))

    def images(self):
        return {"runtime": "sha256:fixed-image"}

    def rpc(self, operation, request):
        self.calls.append((operation, request["seed"]))
        if operation == "receipt":
            return {"status": "rpc_error"} if self.uncertain else {"status": "receipt", "receipt": self.receipt or {"found": False}}
        if self.uncertain:
            return {"status": "rpc_error", "code": "DEADLINE_EXCEEDED"}
        if self.reject:
            self.receipt = None
            return {"status": "rpc_error", "code": "FAILED_PRECONDITION", "error": "binary regression"}
        base = self.catalog[request["model_id"]]
        candidate = apply_parameter_update(base, base_version=base["version"],
                                           deltas={"head.presence.bias": [.01]}, source_id="fixture")
        self.catalog[request["model_id"]] = candidate
        self.receipt = {"found": True, "accepted": True, "model_id": request["model_id"],
                        "base_version": base["version"], "applied_version": candidate["version"],
                        "prompts_generated": 256, "request_fingerprint": STUDY.request_fingerprint(request)}
        response = {"accepted": True, "model_id": request["model_id"], "base_version": base["version"],
                    "applied_version": candidate["version"], "prompts_generated": 256,
                    "metadata": response_metadata(base, candidate)}
        return {"status": "response", "response": response}

    def quiesce(self, request):
        self.calls.append(("quiesce", request["seed"]))
        return {"status": "rpc_error"} if self.uncertain else {"status": "receipt", "receipt": self.receipt or {"found": False}}

    def score(self, artifact_path, selection_path, dataset, output, *, phase, evidence=None, retention=None):
        if self.score_failure and phase == "candidate-validation":
            raise RuntimeError("scoring failed fixture")
        if phase == "selected-development" and not retention.exists():
            raise AssertionError("Development called before retention was persisted")
        artifact = load_artifact(artifact_path)
        model_identity = STUDY.identity(artifact)
        rows = []
        candidate = "+train." in artifact["version"]
        for index, (row_id, (truth, group)) in enumerate(KEYS.items()):
            predicted = truth or not candidate or index == 2
            rows.append({"id": row_id, "group_id": group, "expected_has_pii": truth,
                         "predicted_present": predicted, "probability": .9 if predicted else .1,
                         **model_identity})
        tp, tn, fp, fn = 2, int(candidate), 2 - int(candidate), 0
        metrics = {"tp": tp, "tn": tn, "fp": fp, "fn": fn, "recall": 1,
                   "specificity": tn / 2, "positive_examples": 2, "absent_examples": 2,
                   "balanced_accuracy": (1 + tn / 2) / 2}
        STUDY.write_exclusive(output / "predictions.json", {"rows": rows})
        STUDY.write_exclusive(output / "report.json", {"status": "complete", "errors": [],
                                                      "returned_identity": model_identity, "metrics": metrics})


class PresenceStudyTests(unittest.TestCase):
    def test_validation_only_retention_and_ties(self):
        attempts = [{"seed": seed, "status": "accepted", "validation_metrics": metric()}
                    for seed in STUDY.SEEDS]
        self.assertEqual(STUDY.choose_attempt(attempts, metric(specificity=.4))["seed"], 42)
        attempts[0]["validation_metrics"]["recall"] = .89
        attempts[1]["validation_metrics"]["specificity"] = .4
        self.assertEqual(STUDY.choose_attempt(attempts, metric(specificity=.4))["seed"], 44)
        attempts[2]["status"] = "rejected"
        self.assertIsNone(STUDY.choose_attempt(attempts, metric(specificity=.4)))
        with self.assertRaises(ValueError):
            STUDY.choose_attempt(attempts[:2], metric())

    def test_unscored_and_failed_remain_in_attempt_denominator(self):
        attempts = [{"seed": 42, "status": "accepted_unscored"},
                    {"seed": 43, "status": "failed"}, {"seed": 44, "status": "rejected"}]
        self.assertIsNone(STUDY.choose_attempt(attempts, metric()))
        attempts[0]["status"] = "started"
        with self.assertRaises(ValueError):
            STUDY.choose_attempt(attempts, metric())

    def test_request_bytes_match_generated_protobuf_semantics(self):
        try:
            from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
        except ImportError:
            self.skipTest("Optional host protobuf missing; root Docker supplies it.")
        descriptor = descriptor_pb2.FileDescriptorProto(name="fixture.proto", syntax="proto3")
        message = descriptor.message_type.add(name="FuzzerTrainingRequest")
        for number, name, kind in ((1, "request_id", 9), (2, "source_id", 9), (3, "model_id", 9),
                                   (4, "prompt_count", 13), (5, "seed", 13)):
            message.field.add(name=name, number=number, type=kind, label=1)
        pool = descriptor_pool.DescriptorPool()
        pool.Add(descriptor)
        cls = message_factory.GetMessageClass(pool.FindMessageTypeByName("FuzzerTrainingRequest"))
        request = {"request_id": "fixture-request", "source_id": STUDY.SOURCE_ID,
                   "model_id": "privoke-presence-balanced", "prompt_count": 256, "seed": 42}
        self.assertEqual(STUDY.request_bytes(request), cls(**request).SerializeToString(deterministic=True))

    def test_fingerprint_mismatch_blocks_candidate_evidence(self):
        base = artifact_fixture()
        request = {"request_id": "fixture", "source_id": STUDY.SOURCE_ID, "model_id": base["model_id"], "prompt_count": 256, "seed": 42}
        backend = FakeBackend({base["model_id"]: base})
        response = backend.rpc("cycle", request)["response"]
        candidate = backend.catalog[base["model_id"]]
        STUDY.validate_evidence(request, response, backend.receipt, base, candidate)
        response["metadata"]["candidate_parameter_fingerprint"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            STUDY.validate_evidence(request, response, backend.receipt, base, candidate)

    def test_exact_prediction_joins_reject_relabelled_and_changed_counts(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            artifact_path = directory / "artifact.json"
            artifact = artifact_fixture()
            STUDY.write_exclusive(artifact_path, artifact)
            backend = FakeBackend({})
            backend.score(artifact_path, None, None, directory / "score", phase="base-validation")
            STUDY.verified_metrics(directory / "score", KEYS, STUDY.identity(artifact))
            report = STUDY.json_read(directory / "score/report.json")
            report["metrics"]["tp"] = 1
            (directory / "score/report.json").write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "confusion"):
                STUDY.verified_metrics(directory / "score", KEYS, STUDY.identity(artifact))

    def test_refuses_reused_output_and_incomplete_fit(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(STUDY, "ROOT", Path(temporary)):
            root = Path(temporary) / "evaluation/results"
            root.mkdir(parents=True)
            existing = root / "existing"
            existing.mkdir()
            with self.assertRaises(FileExistsError):
                STUDY.result_path(existing, fresh=True)
            fit = root / "fit"
            fit.mkdir()
            STUDY.write_exclusive(fit / "run-manifest.json", {"status": "failed"})
            with self.assertRaisesRegex(ValueError, "completed"):
                STUDY.load_fit(fit, PROTOCOL)

    def test_complete_nine_attempts_and_selection_precedes_post_dev(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "study"
            output.mkdir()
            profiles = {}
            for profile in STUDY.PROFILES:
                artifact = artifact_fixture(profile)
                path = Path(temporary) / "fit" / profile / "artifact.json"
                STUDY.write_exclusive(path, artifact)
                profiles[profile] = {"artifact": artifact, "artifact_path": path,
                                     "selection_path": path.with_name("selection.json")}
            backend = FakeBackend({})
            manifest = {"profiles": {}, "retained_artifacts": {}, "fit_manifest_sha256": "c" * 64,
                        "source_revision": SOURCE, "fit_source_revision": SOURCE, "protocol_sha256": PROTOCOL}
            validation = Path(temporary) / "validation.jsonl"
            validation.write_text("fixture", encoding="utf-8")
            STUDY.execute_profiles(backend, profiles, output, manifest, KEYS, KEYS, validation, validation)
            attempts = [attempt for profile in manifest["profiles"].values() for attempt in profile["attempts"]]
            self.assertEqual(len(attempts), 9)
            self.assertTrue(all(item["status"] == "accepted" and item["restoration_verified"] for item in attempts))
            self.assertEqual([item["selection"]["chosen_seed"] for item in manifest["profiles"].values()], [42, 42, 42])
            self.assertNotIn("publication_pending", manifest)

    def test_unknown_publication_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / "efficient").mkdir()
            base = artifact_fixture()
            backend = FakeBackend({base["model_id"]: base})
            backend.uncertain = True
            manifest = {"profiles": {"efficient": {"attempts": []}}}
            with self.assertRaises(STUDY.PublicationUncertain):
                STUDY.execute_attempt(backend, {"artifact": base}, 42, output, manifest, KEYS, output / "unused")
            self.assertTrue(manifest["restoration_blocked"])
            self.assertIn("publication_pending", manifest)
            self.assertFalse(backend.installs)

    def test_scoring_error_after_known_commit_preserves_unscored_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / "efficient").mkdir()
            base = artifact_fixture()
            backend = FakeBackend({base["model_id"]: base})
            backend.score_failure = True
            manifest = {"profiles": {"efficient": {"attempts": []}}}
            attempt = STUDY.execute_attempt(backend, {"artifact": base, "selection_path": output / "selection"},
                                            42, output, manifest, KEYS, output / "unused")
            self.assertEqual(attempt["status"], "accepted_unscored")
            self.assertTrue(attempt["accepted"])
            self.assertNotIn("publication_pending", manifest)
            self.assertTrue((output / "efficient/seed42/artifact.json").is_file())

    def test_durable_rejected_receipt_is_terminal_without_quiescence(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / "efficient").mkdir()
            base = artifact_fixture()
            backend = FakeBackend({base["model_id"]: base})
            request = {"request_id": f"{output.name}-efficient-42", "source_id": STUDY.SOURCE_ID,
                       "model_id": base["model_id"], "prompt_count": 256, "seed": 42}
            backend.reject = True
            original_rpc = backend.rpc
            def durable_rpc(operation, actual):
                if operation == "receipt":
                    return {"status": "receipt", "receipt": {"found": True, "accepted": False,
                            "request_fingerprint": STUDY.request_fingerprint(request),
                            "model_id": base["model_id"], "base_version": base["version"], "applied_version": ""}}
                return original_rpc(operation, actual)
            manifest = {"profiles": {"efficient": {"attempts": []}}}
            with patch.object(backend, "rpc", side_effect=durable_rpc):
                attempt = STUDY.execute_attempt(backend, {"artifact": base}, 42, output, manifest, KEYS, output / "unused")
            self.assertEqual(attempt["status"], "rejected")
            self.assertNotIn("publication_pending", manifest)
            self.assertFalse(any(call[0] == "quiesce" for call in backend.calls))

    def test_committed_artifact_archive_failure_blocks_restoration(self):
        for failure in ("read", "write"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary)
                (output / "efficient").mkdir()
                base = artifact_fixture()
                backend = FakeBackend({base["model_id"]: base})
                manifest = {"profiles": {"efficient": {"attempts": []}}}
                original_write = STUDY.write_exclusive
                def archive_write(path, *args, **kwargs):
                    if failure == "write" and path.name == "artifact.json":
                        raise OSError("archive failed")
                    return original_write(path, *args, **kwargs)
                original_read = backend.read
                def archive_read(model_id):
                    if failure == "read":
                        raise OSError("candidate read failed")
                    return original_read(model_id)
                with patch.object(STUDY, "write_exclusive", side_effect=archive_write), patch.object(backend, "read", side_effect=archive_read):
                    with self.assertRaises(STUDY.PublicationUncertain):
                        STUDY.execute_attempt(backend, {"artifact": base}, 42, output, manifest, KEYS, output / "unused")
                self.assertTrue(manifest["restoration_blocked"])
                self.assertIn("publication_pending", manifest)
                self.assertTrue(manifest["profiles"]["efficient"]["attempts"][0]["accepted"])
                self.assertFalse(backend.installs)
                self.assertNotEqual(backend.catalog[base["model_id"]]["version"], base["version"])

    def test_cleanup_restores_after_operation_error_and_exposes_restore_failure(self):
        for fail_restore in (False, True):
            with tempfile.TemporaryDirectory() as temporary:
                balanced = {"schema_version": 1, "architecture": "privoke_tiny_transformer_v1",
                            "model_id": "privoke-balanced", "version": "v0.3.0+train.1",
                            "config": {"profile": "balanced"},
                            "parameters": {"head.sensitivity.bias": {
                                "shape": [4], "values": [0.0, 0.0, 0.0, 0.0], "trainable": True}}}
                balanced["checksum"] = artifact_checksum(balanced)
                validate_artifact(balanced)
                presence = artifact_fixture()
                backend = FakeBackend({"privoke-balanced": balanced, presence["model_id"]: presence})
                manifest = {"retained_artifacts": {}}
                with patch.object(STUDY, "BALANCED_CHECKSUM", balanced["checksum"]):
                    with self.assertRaisesRegex(RuntimeError, "restoration" if fail_restore else "operation failed"):
                        with STUDY.protected_catalog(backend, manifest, Path(temporary)):
                            backend.catalog[presence["model_id"]]["version"] = "changed"
                            backend.restore_failure = fail_restore
                            raise RuntimeError("operation failed")
                self.assertEqual(manifest["restoration_verified"], not fail_restore)
                self.assertEqual(manifest["operation_error"]["error"], "operation failed")
                if not fail_restore:
                    self.assertEqual(backend.catalog[presence["model_id"]], presence)


if __name__ == "__main__":
    unittest.main()
