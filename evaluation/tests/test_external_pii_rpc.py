from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location(
    "evaluate_external_pii", ROOT / "evaluate-external-pii.py")
assert SPEC is not None and SPEC.loader is not None
scorer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scorer)

sys_path = str(ROOT.parent / "shared/python")
if sys_path not in __import__("sys").path:
    __import__("sys").path.insert(0, sys_path)
from privoke_model.training_data import training_text_key


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def make_row(identifier: str, group: str, text: str, label: bool,
             **metadata) -> dict:
    return {"id": identifier, "group_id": group, "text": text,
            "text_key": training_text_key(text), "expected_has_pii": label,
            **metadata}


class FakeModel:
    def __init__(self, probability=0.75):
        self.probability = probability

    def predict_probability(self, text):
        return self.probability


class FakeRequest:
    def __init__(self, **values):
        self.__dict__.update(values)


class FakeStub:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.request = None
        self.timeout = None

    def DetectAnnotationPresence(self, request, timeout):
        self.request, self.timeout = request, timeout
        if self.error:
            raise self.error
        result = dict(self.response)
        result["request_id"] = request.request_id
        return SimpleNamespace(**result)


class ExternalPresenceRpcTests(unittest.TestCase):
    def test_generated_runtime_stubs_import_from_runtime_generated_directory(self):
        generated = scorer.ROOT / "extension/client-runtime/generated"
        if not (generated / "privoke/v1/runtime_pb2.py").is_file():
            if __import__("os").environ.get("PRIVOKE_EVAL_IN_CONTAINER") == "true":
                self.fail("Docker evaluator is missing generated privoke.v1 runtime protocol modules")
            self.skipTest("Docker image generates protocol modules; host checkout has no generated files")
        pb, grpc_pb = scorer.load_runtime_stubs()
        self.assertTrue(hasattr(pb, "DetectAnnotationPresenceRequest"))
        service = pb.DESCRIPTOR.services_by_name["PrivokeRuntimeService"]
        self.assertIn("DetectAnnotationPresence", {method.name for method in service.methods})
        self.assertTrue(hasattr(grpc_pb, "PrivokeRuntimeServiceStub"))
        self.assertIn(generated.as_posix(), __import__("sys").path)

    def test_setup_failure_reason_is_safe_and_specific_for_missing_module(self):
        exc = ModuleNotFoundError("No module named 'privoke'", name="privoke")
        self.assertEqual(scorer.safe_error_reason(exc), "missing_module:privoke")
        self.assertEqual(scorer.safe_error_reason(ImportError("private prompt must not be serialized")),
                         "import_error")

    def test_selection_profile_may_be_omitted_but_explicit_mismatch_is_rejected(self):
        self.assertTrue(scorer.selection_matches_profile({"status": "selected"}, "balanced"))
        self.assertTrue(scorer.selection_matches_profile({"profile": "balanced"}, "balanced"))
        self.assertFalse(scorer.selection_matches_profile({"profile": "efficient"}, "balanced"))
        self.assertFalse(scorer.selection_matches_profile({"profile": None}, "balanced"))

    def identity(self):
        return {"model_id": "privoke-presence-balanced",
                "model_version": "v1.0.0",
                "artifact_checksum": "checksum",
                "parameter_fingerprint": "fingerprint",
                "threshold": 0.6}

    def response(self, probability=0.75, threshold=0.6, label=2):
        return {"model_id": self.identity()["model_id"],
                "model_version": self.identity()["model_version"],
                "artifact_checksum": self.identity()["artifact_checksum"],
                "parameter_fingerprint": self.identity()["parameter_fingerprint"],
                "probability": probability, "threshold": threshold,
                "predicted_label": label, "elapsed_ms": 1.25, "error": ""}

    def test_score_row_uses_typed_rpc_timeout_and_never_returns_prompt(self):
        row = make_row("source-row-7", "nemotron-pii:uid", "private synthetic prompt", True,
                       source_family="nemotron-pii", expected_categories=["EMAIL"],
                       domain="health", document_format="email")
        stub = FakeStub(self.response())
        pb = SimpleNamespace(DetectAnnotationPresenceRequest=FakeRequest,
                             ANNOTATION_PRESENCE_PRESENT=2,
                             ANNOTATION_PRESENCE_ABSENT=1)
        record = scorer.score_row(stub, pb, FakeModel(),
                                  {"model_id": self.identity()["model_id"]},
                                  self.identity(), row, "opaque-request-1")
        self.assertEqual(stub.timeout, 120)
        self.assertEqual(stub.request.text, row["text"])
        self.assertEqual(record["request_sha256"], sha(row["text"].encode()))
        self.assertTrue(record["predicted_present"])
        self.assertNotIn(row["text"], json.dumps(record))
        self.assertNotIn(row["id"], json.dumps(record))
        self.assertNotIn(row["group_id"], json.dumps(record))

    def test_score_row_rejects_nonfinite_response_and_identity_mismatch(self):
        row = make_row("row", "family:group", "some text", True)
        pb = SimpleNamespace(DetectAnnotationPresenceRequest=FakeRequest,
                             ANNOTATION_PRESENCE_PRESENT=2,
                             ANNOTATION_PRESENCE_ABSENT=1)
        with self.assertRaisesRegex(ValueError, "probability"):
            scorer.score_row(FakeStub(self.response(probability=float("nan"))), pb,
                             FakeModel(), {"model_id": self.identity()["model_id"]},
                             self.identity(), row, "req-nan")
        bad = self.response()
        bad["parameter_fingerprint"] = "wrong"
        with self.assertRaisesRegex(ValueError, "parameter_fingerprint"):
            scorer.score_row(FakeStub(bad), pb, FakeModel(),
                             {"model_id": self.identity()["model_id"]},
                             self.identity(), row, "req-id")

    def test_prepared_manifest_hashes_and_allowlisted_partitions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            partition_rows = {
                "train": None,
                "validation": [make_row(f"v{i}", f"piimb:g{i}", f"validation row {i}", i % 2 == 1)
                               for i in range(968)],
                "nemotron_heldout": [make_row("n0", "nemotron-pii:g", "external positive", True)],
                "meddies_heldout": [],
            }
            filenames = {"train": "train.jsonl", "validation": "validation.jsonl",
                         "nemotron_heldout": "nemotron-heldout.jsonl",
                         "meddies_heldout": "meddies-heldout.jsonl"}
            hashes, counts = {}, {}
            for name, filename in filenames.items():
                if name == "train":
                    raw = b"train bytes\n"
                else:
                    raw = b"".join((json.dumps(row, sort_keys=True) + "\n").encode()
                                   for row in partition_rows[name])
                (root / filename).write_bytes(raw)
                hashes[name], counts[name] = sha(raw), (3 if name == "train" else len(partition_rows[name]))
            with patch.object(scorer, "EXPECTED_BASE_VALIDATION_SHA256", hashes["validation"]):
                manifest = {"status": "prepared", "schema_version": 1,
                            "source_revision": "a" * 40, "protocol_sha256": "b" * 64,
                            "partition_files": filenames, "partition_sha256": hashes,
                            "rows": counts, "prepared_reference": {
                                "train_sha256": "c" * 64,
                                "validation_sha256": hashes["validation"]}}
                (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
                loaded = scorer.validate_prepared(root, prepared_source_revision="a" * 40,
                                                  protocol_sha256="b" * 64)
                self.assertEqual(len(loaded["partition_rows"]["meddies_heldout"]), 0)
                self.assertEqual(len(loaded["partition_rows"]["validation"]), 968)
                manifest["partition_sha256"]["nemotron_heldout"] = "0" * 64
                (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "digest mismatch"):
                    scorer.validate_prepared(root, prepared_source_revision="a" * 40,
                                             protocol_sha256="b" * 64)

    def test_prepared_binding_requires_fit_recorded_source_and_exact_hashes(self):
        prepared_revision = "a" * 40
        prepared = {"manifest": {"source_revision": prepared_revision,
                                 "partition_sha256": {"train": "1" * 64}},
                    "manifest_sha256": "2" * 64}
        fit = {"prepared_source_revision": prepared_revision,
               "prepared_manifest_sha256": "2" * 64,
               "partition_sha256": {"train": "1" * 64}}
        self.assertEqual(scorer.bind_prepared_to_fit(prepared, fit), prepared_revision)
        fit["prepared_source_revision"] = "b" * 40
        with self.assertRaisesRegex(ValueError, "source revision or input digests"):
            scorer.bind_prepared_to_fit(prepared, fit)

    def test_prepared_rejects_path_escape_and_non_boolean_or_clean_source_target(self):
        with self.assertRaisesRegex(ValueError, "escapes"):
            scorer.confined_path(Path(tempfile.gettempdir()), "../outside.jsonl")
        row = make_row("n0", "nemotron-pii:g", "positive", False)
        with self.assertRaisesRegex(ValueError, "explicit-positive"):
            scorer.validate_row(row, partition="nemotron_heldout")
        row["expected_has_pii"] = 1
        with self.assertRaisesRegex(ValueError, "strict booleans"):
            scorer.validate_row(row, partition="validation")

    def test_profile_verifier_fails_closed_without_exact_three_profile_freeze(self):
        with self.assertRaisesRegex(ValueError, "exact three-profile"):
            scorer.verify_profile_bundle(
                {"manifest": {"status": "complete", "source_revision": "a" * 40,
                              "protocol_sha256": "b" * 64}, "profiles": {}},
                profile="balanced", fit_root=Path("."), source_revision="a" * 40,
                protocol_sha256="b" * 64, prepared={})

    def test_positive_only_metrics_have_null_specificity_and_exact_denominators(self):
        rows = [make_row("id", "meddies-pii:group", "clinical positive", True,
                         source="Meddies/meddies-pii", expected_categories=["medical_id"])]
        prediction = {"predicted_present": True, "group_id_sha256": "group-hash",
                      "word_count": 2, "source": "Meddies/meddies-pii",
                      "category": ["medical_id"], "document_format": "letter"}
        result = scorer.prediction_metrics(rows, [prediction])
        overall = result["overall"]
        self.assertEqual(overall["row_count"], 1)
        self.assertEqual(overall["positive_examples"], 1)
        self.assertEqual(overall["absent_examples"], 0)
        self.assertIsNone(overall["specificity"])
        self.assertEqual(overall["confidence_intervals_95"]["reason"],
                         "partition_lacks_both_label_strata")
        self.assertIn("medical_id", result["prompt_detection_recall_by_source_category"])

    def test_output_collision_is_rejected_before_any_input_read(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "already-used"
            output.mkdir()
            with self.assertRaises(FileExistsError):
                scorer.run(fit_root=Path("missing-fit"), prepared_root=Path("missing-prepared"),
                           baseline_fit_root=Path("missing-base"), profile="balanced",
                           control="expanded", partition="validation", output=output,
                           source_revision="a" * 40, fit_source_revision="b" * 40,
                           protocol_file=Path("missing-protocol"),
                           protocol_sha256="b" * 64, runtime_image_id="runtime@sha256:x",
                           evaluator_image_id="evaluator@sha256:y", target="runtime:50054")


if __name__ == "__main__":
    unittest.main()
