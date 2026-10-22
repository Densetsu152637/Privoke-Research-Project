"""Manufactured reference contracts; no teacher forwards or model construction."""
import copy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from privoke_model import sensitive_retention as retention
from privoke_model.full_adam import CONFIG, canonical
from privoke_model.contextual_training import training_policy_expectations, training_admission_metadata, parse_training_admission_metadata

ROOT = Path(__file__).resolve().parents[3]
BANK = ROOT / "evaluation/results/iterative_fuzzer_20261011/train-sensitive-retention/approved-train-bank.json"
# The approved bank lives under ignored local results; clean checkouts (CI) skip bank-backed contracts.
requires_bank = unittest.skipUnless(BANK.is_file(), "Approved TRAIN bank is local-only evaluation data.")


def manufactured_release():
    bank_payload = BANK.read_bytes()
    rows = retention.validate_bank(bank_payload)
    teacher = {"profile": "quality", "model_id": "privoke-quality", "version": "manufactured-original",
        "file_sha256": retention.TEACHER_SHA256["quality"], "checksum": "a" * 64,
        "parameter_fingerprint": "b" * 64, "inventory_fingerprint": "c" * 64, "config": {}}
    references = retention.canonical_bytes({"schema": 1, "teacher": teacher, "bank_sha256": retention.BANK_SHA256,
        "boundary": retention.BOUNDARY, "rows": [{"id": r["id"], "packed": r["packed_classification"],
            "confidence": .9, "margin": 2., "sensitivity_gap": 1., "eligible": True} for r in rows]})
    manifest = retention.canonical_bytes(retention.manifest_value(bank_payload, references, teacher))
    return retention.RetentionRelease(bank_payload, references, manifest, "manufactured-original.json"), teacher


def admission_metadata(policy, pin="d" * 64):
    return {"expected_contextual_training_optimizer": policy,
        "expected_contextual_training_objective": retention.OBJECTIVES[policy],
        "expected_contextual_candidate_eligibility": retention.ELIGIBILITY,
        "expected_full_projected_adam_config_v1": canonical(CONFIG),
        "expected_contextual_training_scope": "full_encoder",
        "expected_" + retention.MANIFEST_KEY: pin}


class RetentionContractTests(unittest.TestCase):
    def test_original_effective_values_are_float32_without_mutating_raw_artifact(self):
        from privoke_model.artifact import float32
        from privoke_model.fingerprint import parameter_fingerprint
        artifact = {"parameters": {"manufactured": {"values": [.1, -.3], "shape": [2]}}}
        before = copy.deepcopy(artifact)
        effective = retention.original_effective_parameters(artifact)
        self.assertEqual(effective, {"manufactured": (float32(.1), float32(-.3))})
        self.assertEqual(artifact, before)
        self.assertNotEqual(parameter_fingerprint(effective, {"manufactured": (2,)}),
            parameter_fingerprint({"manufactured": (.1, -.3)}, {"manufactured": (2,)}))
        artifact["parameters"]["manufactured"]["values"][0] = .2
        self.assertEqual(effective["manufactured"][0], float32(.1))

    @requires_bank
    def test_approved_bank_has_one_real_lf_and_rejects_text_target_metadata_reordering(self):
        payload = BANK.read_bytes()
        rows = retention.validate_bank(payload)
        self.assertTrue(payload.endswith(b"\n"))
        for key, value in (("text", "manufactured mutation"), ("packed_classification", 28), ("weight", 2)):
            changed = copy.deepcopy(rows); changed[0][key] = value
            with self.assertRaises(ValueError):
                retention.validate_bank(retention.canonical_bytes(changed))
        with self.assertRaises(ValueError):
            retention.validate_bank(payload[:-1] + b"LF")
        with self.assertRaises(ValueError):
            retention.validate_bank(retention.canonical_bytes(list(reversed(rows))))

    def test_schema4_is_additive_and_rejects_orphan_missing_conflicting_pins_and_head(self):
        for policy in retention.POLICIES:
            metadata = admission_metadata(policy)
            expected = training_policy_expectations(metadata)
            header = training_admission_metadata(expected)
            self.assertEqual(json.loads(header[0][1])["schema"], 4)
            self.assertEqual(parse_training_admission_metadata(header), expected)
            for key, value in (("expected_" + retention.MANIFEST_KEY, "wrong"),
                               ("expected_contextual_training_scope", "heads"),
                               ("expected_contextual_training_objective", retention.OBJECTIVES[next(p for p in retention.POLICIES if p != policy)])):
                with self.assertRaises(ValueError):
                    training_policy_expectations({**metadata, key: value})
        with self.assertRaises(ValueError):
            training_policy_expectations({"expected_" + retention.MANIFEST_KEY: "d" * 64})
        from privoke_model.full_adam import POLICY, ELIGIBILITY, OBJECTIVE
        old = training_policy_expectations({"expected_contextual_training_optimizer": POLICY,
            "expected_contextual_training_objective": OBJECTIVE, "expected_contextual_candidate_eligibility": ELIGIBILITY,
            "expected_contextual_training_scope": "full_encoder", "expected_full_projected_adam_config_v1": canonical(CONFIG)})
        self.assertEqual(json.loads(training_admission_metadata(old)[0][1])["schema"], 3)

    @requires_bank
    def test_reference_strict_boundaries_and_twenty_group_coverage(self):
        release, teacher = manufactured_release()
        bank = retention.validate_bank(release.bank_payload)
        for field, value in (("margin", retention.EPSILON), ("sensitivity_gap", retention.EPSILON), ("packed", 28)):
            refs = json.loads(release.reference_payload)
            refs["rows"][0][field] = value
            with self.assertRaises(ValueError):
                retention.validate_references(retention.canonical_bytes(refs), bank, teacher)
        refs = json.loads(release.reference_payload)
        group = bank[0]["metadata"]["group_id"]
        for source, row in zip(bank, refs["rows"]):
            if source["metadata"]["group_id"] == group:
                row.update(margin=0., eligible=False)
        with self.assertRaisesRegex(ValueError, "every20"):
            retention.validate_references(retention.canonical_bytes(refs), bank, teacher)

    @requires_bank
    def test_immutable_reference_baseline_and_profile_pins_before_any_model_access(self):
        release, teacher = manufactured_release()
        with patch.object(retention, "teacher_identity", return_value=teacher):
            retention.validate_release(release, model_id="privoke-quality", expected_sha256=release.sha256)
            for field, value in (("packed", 28), ("confidence", .499), ("margin", 1.9), ("eligible", False)):
                refs = json.loads(release.reference_payload); refs["rows"][0][field] = value
                with self.assertRaises(ValueError):
                    retention.validate_release(replace(release, reference_payload=retention.canonical_bytes(refs)))
            with self.assertRaises(ValueError):
                retention.validate_release(release, model_id="privoke-balanced")
            with self.assertRaises(ValueError):
                retention.validate_release(release, expected_sha256="f" * 64)
            with self.assertRaises(ValueError):
                retention.validate_release(replace(release, bank_payload=release.bank_payload.replace(b"train", b"wrong", 1)))

    def test_wrong_current_teacher_rejected_before_artifact_loader(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "current.json"; path.write_bytes(b"manufactured current teacher")
            with patch("privoke_model.artifact.load_artifact", side_effect=AssertionError("must not load wrong bytes")) as loader:
                with self.assertRaises(ValueError):
                    retention.teacher_identity(path, "quality")
                loader.assert_not_called()

    @requires_bank
    def test_recomputed_forged_baseline_manifest_does_not_replace_independent_trusted_pin(self):
        release, teacher = manufactured_release()
        refs = json.loads(release.reference_payload)
        refs["rows"][0]["margin"] = 1.5
        references = retention.canonical_bytes(refs)
        forged = replace(release, reference_payload=references,
            manifest_payload=retention.canonical_bytes(retention.manifest_value(release.bank_payload, references, teacher)))
        with patch.object(retention, "teacher_identity", return_value=teacher):
            # Preparation is self-consistent, but training cannot acquire its authority from that fact.
            retention.validate_release(forged, expected_sha256=forged.sha256)
            for trusted in (None, "wrong", release.sha256):
                with self.assertRaises(ValueError):
                    retention.validate_trusted_release(forged, model_id="privoke-quality", request_sha256=forged.sha256, trusted_sha256=trusted)
            retention.validate_trusted_release(release, model_id="privoke-quality", request_sha256=release.sha256, trusted_sha256=release.sha256)


if __name__ == "__main__":
    unittest.main()
