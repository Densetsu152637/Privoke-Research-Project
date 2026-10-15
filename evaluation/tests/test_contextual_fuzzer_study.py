"""Behavior checks for prospective data, selection and restoration boundaries."""
import copy
import importlib.util
from pathlib import Path
import unittest
import os
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

EVALUATION = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, EVALUATION / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREP = load("contextual_preparation", "prepare-contextual-fuzzer-study.py")
STUDY = load("contextual_study", "run-contextual-fuzzer-study.py")


def seed(text="Public blank outline", group="source:one", sensitivity="S0"):
    return {"template": text, "classification": {"sensitivity": sensitivity, "visibility": "PU", "categories": []}, "metadata": {"group_id": group, "example_id": group + "-row", "label_status": "provisional"}}


class PreparationTests(unittest.TestCase):
    def test_complete_targets_are_required(self):
        for field in ("sensitivity", "visibility", "categories"):
            row = seed()
            del row["classification"][field]
            with self.assertRaises(ValueError):
                PREP.strict_target(row)

    def test_unknown_category_and_missing_group_fail(self):
        for row in (seed(), seed()):
            row["classification"]["categories"] = ["HALLUCINATED"]
            with self.assertRaises(ValueError):
                PREP.strict_target(row)
        row = seed()
        del row["metadata"]["group_id"]
        with self.assertRaises(ValueError):
            PREP.strict_target(row)

    def test_whole_validation_group_is_excluded(self):
        public = [seed("Sibling A", "doc:heldout"), seed("Sibling B", "doc:heldout"), seed()]
        validation = [{"id": "unrelated-exact-id", "group_id": "doc:heldout", "text": "Different sentence"}]
        result, counts = PREP.prepare(public, validation, [], {"key_sets": {"groups": [], "ids": [], "texts": []}}, enforce_counts=False)
        self.assertEqual(counts["excluded_validation_rows"], 2)
        self.assertFalse(any(row["metadata"]["group_id"] == "doc:heldout" for row in result))

    def test_opaque_locked_text_collision_fails(self):
        row = seed()
        protected = PREP.opaque_exclusion_key("text_key", PREP.training_text_key(row["template"]))
        with self.assertRaises(ValueError):
            PREP.prepare([row], [], [], {"key_sets": {"groups": [], "ids": [], "texts": [protected]}}, enforce_counts=False)

    def test_fixture_text_is_never_training(self):
        row = seed()
        with self.assertRaises(ValueError):
            PREP.prepare([row], [], [{"text": row["template"], "family_id": "heldout"}], {"key_sets": {"groups": [], "ids": [], "texts": []}}, enforce_counts=False)

    def test_authored_families_keep_contrast_siblings_together(self):
        rows = PREP.authored_rows()
        groups = {}
        for row in rows:
            PREP.strict_target(row)
            groups.setdefault(row["metadata"]["group_id"], []).append(row)
        self.assertEqual(len(rows), 128)
        self.assertEqual(len(groups), 16)
        for family in groups.values():
            self.assertEqual(len(family), 8)
            self.assertEqual(sum(row["classification"]["sensitivity"] == "S0" for row in family), 4)


class StudyTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "Publication permissions require the Linux service platform")
    def test_raw_publication_preserves_bytes_and_cross_service_readability(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "model.json"
            raw = b'{"original":"bytes"}\r\n'
            subprocess.run([sys.executable, "-c", STUDY.RAW_PUBLICATION_CODE, str(path)], input=raw, check=True)
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)

    def test_guarded_publication_rejects_wrong_base_and_candidate(self):
        artifact = {"model_id": "balanced", "version": "v1", "checksum": "frozen", "parameters": {"head": {"shape": [1], "values": [0.0]}}}
        candidate = copy.deepcopy(artifact)
        candidate["parameters"]["head"]["values"] = [1.0]
        response = {"metadata": {"base_parameter_fingerprint": STUDY.training_value_fingerprint(artifact), "updated_parameter_fingerprint": STUDY.training_value_fingerprint(candidate)}}
        STUDY.verify_guarded_publication(artifact, candidate, response)
        with self.assertRaises(ValueError):
            STUDY.verify_guarded_publication(candidate, candidate, response)
        with self.assertRaises(ValueError):
            STUDY.verify_guarded_publication(artifact, artifact, response)
        self.assertNotEqual(STUDY.training_value_fingerprint(artifact), STUDY.artifact_identity(artifact)["parameter_fingerprint"])
        wrong_shape = copy.deepcopy(candidate)
        wrong_shape["parameters"]["head"]["shape"] = [1, 1]
        with self.assertRaises(ValueError):
            STUDY.verify_guarded_publication(artifact, wrong_shape, response)

    def test_measurement_endpoint_uses_frozen_scope_over_inherited_environment(self):
        args = SimpleNamespace(allow_product_pipeline=True, project_name="study")
        state = {"prefix": "scope-test", "prepared": "prepared", "runtime_target": "127.0.0.1:50054"}
        with patch.dict(STUDY.os.environ, {"PRIVOKE_RUNTIME_TARGET": "different.example:1234"}):
            driver = STUDY.Driver(args, state)
        self.assertEqual(driver.environment["PRIVOKE_RUNTIME_TARGET"], state["runtime_target"])

    def test_grid_has_54_unique_requests_with_paired_settings(self):
        planned = list(STUDY.attempts("safe-study"))
        self.assertEqual(len(planned), 54)
        self.assertEqual(len({r["request_id"] for r in planned}), 54)
        for profile in STUDY.PROFILES:
            self.assertEqual(sum(r["profile"] == profile for r in planned), 18)
        self.assertTrue(all(r["prompt_count"] == 256 and r["heldout_count"] == 16 and r["max_gradient"] == .05 and r["transforms"] == 0 for r in planned))

    def test_selection_requires_exact_floor_and_strict_gain(self):
        record = {"validation": {"pipeline": {"tp": 427, "tn": 200}}, "profile": "balanced", "strategy": "heads", "rate": .003, "seed": 42}
        self.assertIsNone(STUDY.candidate_key(record, {"tn": 100}))
        record["validation"]["pipeline"]["tp"] = 428
        self.assertIsNotNone(STUDY.candidate_key(record, {"tn": 100}))
        self.assertIsNone(STUDY.candidate_key(record, {"tn": 200}))

    def test_tie_prefers_lower_rate_seed_profile_and_heads(self):
        record = {"validation": {"pipeline": {"tp": 430, "tn": 200}}, "profile": "efficient", "strategy": "heads", "rate": .003, "seed": 42}
        preferred = STUDY.candidate_key(record, {"tn": 100})
        for field, value in (("rate", .01), ("seed", 1337), ("profile", "quality"), ("strategy", "last_block")):
            other = copy.deepcopy(record)
            other[field] = value
            self.assertGreater(preferred, STUDY.candidate_key(other, {"tn": 100}))

    def test_casewise_harms_cannot_cancel_improvements(self):
        cases = [{"case_id": "private-a", "ambiguous": False, "required_sensitive": True, "minimum_action": "BLOCK"}, {"case_id": "private-b", "ambiguous": False, "required_sensitive": True, "minimum_action": "BLOCK"}, {"case_id": "clean", "ambiguous": False, "required_sensitive": False, "minimum_action": "ALLOW", "expected_sensitivity": "S1"}]
        before = {"private-a": {"action": "BLOCK"}, "private-b": {"action": "ALLOW"}, "clean": {"action": "ALLOW"}}
        after = {"private-a": {"action": "WARN"}, "private-b": {"action": "BLOCK"}, "clean": {"action": "WARN"}}
        result = STUDY.fixture_gate(cases, before, after)
        self.assertFalse(result["passed"])
        self.assertEqual(result["private_action_losses"], ["private-a"])
        self.assertEqual(result["added_clean_interventions"], ["clean"])

    def test_ambiguous_cases_do_not_create_quantitative_failure(self):
        cases = [{"case_id": "ambiguous", "ambiguous": True, "required_sensitive": None}]
        self.assertTrue(STUDY.fixture_gate(cases, {"ambiguous": {"action": "BLOCK"}}, {"ambiguous": {"action": "ALLOW"}})["passed"])

    def test_restore_after_exception_preserves_exact_bytes(self):
        events, current = [], {"efficient": b"original\r\n", "balanced": b"original\n"}

        class FakeDriver:
            def stop_jobs(self):
                events.append("stop")

            def install_raw(self, profile, raw):
                events.append(profile)
                current[profile] = raw

            def restore_services(self):
                events.append("restore-services")

            def live(self, profile):
                return current[profile]

        backup = dict(current)
        with self.assertRaisesRegex(RuntimeError, "scoring failed"):
            with STUDY.restored_catalog(FakeDriver(), backup):
                current["balanced"] = b"candidate"
                raise RuntimeError("scoring failed")
        self.assertEqual(current, backup)
        self.assertEqual(events[0], "stop")

    def test_failed_quiescence_blocks_catalog_writes(self):
        class FakeDriver:
            def stop_jobs(self):
                raise STUDY.UnknownUpdateOutcome("busy")

            def install_raw(self, *_):
                raise AssertionError("unsafe restoration")

        with self.assertRaises(STUDY.UnknownUpdateOutcome):
            with STUDY.restored_catalog(FakeDriver(), {"balanced": b"original"}):
                pass

    def test_dataset_absent_class_rate_is_null(self):
        report = {"metadata": {"predictions": [{"group_id": "privy:x", "expected_has_pii": True, "detected_sensitive": True}]}}
        self.assertEqual(STUDY.by_dataset(report)["privy"]["recall"], 1)
        self.assertIsNone(STUDY.by_dataset(report)["privy"]["specificity"])

    def test_report_labels_ids_and_counts_are_verified(self):
        artifact = {"model_id": "privoke-efficient", "version": "v0.3.0", "checksum": "frozen", "parameters": {"head": {"shape": [1], "values": [0.0]}}}
        identity = STUDY.artifact_identity(artifact)
        reference = [{"id": "x", "expected_has_pii": True, "group_id": "doc:x"}]
        report = {"errors": [], "metrics": {"true_positives": 1, "true_negatives": 0, "false_positives": 0, "false_negatives": 0}, "metadata": {"predictions": [{"example_id": "local-jsonl:x", "expected_has_pii": True, "group_id": "doc:x", "detected_sensitive": True, "status": "ok", "layers": [{"layer": "DETECTION_LAYER_SEMANTIC", "status": "ok", "results": [{"metadata": identity}]}]}]}}
        self.assertEqual(STUDY.verified_report(report, reference, artifact)["tp"], 1)
        for field, value in (("example_id", "another"), ("expected_has_pii", False), ("group_id", "wrong")):
            changed = copy.deepcopy(report)
            changed["metadata"]["predictions"][0][field] = value
            with self.assertRaises(ValueError):
                STUDY.verified_report(changed, reference, artifact)
        changed = copy.deepcopy(report)
        changed["metrics"]["true_positives"] = 2
        with self.assertRaises(ValueError):
            STUDY.verified_report(changed, reference, artifact)

    def test_wrong_returned_model_identity_fails(self):
        artifact = {"model_id": "privoke-efficient", "version": "v0.3.0", "checksum": "frozen", "parameters": {"head": {"shape": [1], "values": [0.0]}}}
        reference = [{"id": "x", "expected_has_pii": False, "group_id": "doc:x"}]
        report = {"errors": [], "metadata": {"predictions": [{"example_id": "local-jsonl:x", "expected_has_pii": False, "group_id": "doc:x", "detected_sensitive": False, "status": "ok", "layers": [{"layer": "DETECTION_LAYER_SEMANTIC", "status": "ok", "results": [{"metadata": {"model_id": "privoke-quality"}}]}]}]}}
        with self.assertRaises(ValueError):
            STUDY.verified_report(report, reference, artifact)


if __name__ == "__main__":
    unittest.main()
