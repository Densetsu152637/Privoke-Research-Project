"""Known paired outcomes and tamper rejection for the independent audit."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

from privoke_eval.continual_fuzzer_study import paired_changes

SPEC = importlib.util.spec_from_file_location("long_audit", Path(__file__).resolve().parents[1] / "audit-long-fuzzer-study.py")
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class AuditTests(unittest.TestCase):
    def examples(self):
        before = [{"id": str(i), "group_id": str(i // 2), "expected_has_pii": bool(i % 2),
                   "detected_sensitive": bool(i % 3), "status": "ok"} for i in range(20)]
        after = copy.deepcopy(before)
        for i in (1, 4, 7, 11, 17):
            after[i]["detected_sensitive"] = not after[i]["detected_sensitive"]
        return before, after, paired_changes(before, after, iterations=80)

    def test_grouped_count_vectors_match_row_bootstrap(self):
        before, after, saved = self.examples()
        self.assertEqual(audit.verify_paired(before, list(reversed(after)), saved), 6)

    def test_tampered_interval_is_rejected(self):
        before, after, saved = self.examples()
        saved["changes"]["recall"]["interval_95"][0] += .01
        with self.assertRaisesRegex(ValueError, "interval differs"):
            audit.verify_paired(before, after, saved)

    def test_mismatched_pair_labels_are_rejected(self):
        before, after, saved = self.examples()
        after[0]["expected_has_pii"] = not after[0]["expected_has_pii"]
        with self.assertRaisesRegex(ValueError, "labels or groups"):
            audit.verify_paired(before, after, saved)

    def test_incomplete_endpoint_is_rejected(self):
        before, after, saved = self.examples()
        after[0]["status"] = "error"
        with self.assertRaisesRegex(ValueError, "endpoint errors"):
            audit.verify_paired(before, after, saved)

    def test_invalid_minimum_duration_rejected_before_access(self):
        for duration in (-1, float("nan"), float("inf")):
            with self.assertRaisesRegex(ValueError, "finite and nonnegative"):
                audit.audit(Path("not-accessed"), duration)

    def test_brief_run_cannot_satisfy_default_six_hour_requirement(self):
        with patch.object(audit, "read", return_value={"duration_seconds_per_profile": 36}):
            with self.assertRaisesRegex(ValueError, "shorter than the required"):
                audit.audit(Path("synthetic-output"))
