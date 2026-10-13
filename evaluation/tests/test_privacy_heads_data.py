"""Host-only data admission tests; no model weights or inference are loaded."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "evaluation"), str(ROOT / "services/privoke-fuzzer/src"),
               str(ROOT / "shared/python"), str(ROOT / "extension/client-runtime")]
from prompt_generation.privacy_heads_curriculum import (
    COUNTS, audit, audit_components, build, canonical, digest, fuzzer_training_examples, target, validate_resource,
)

SPEC = importlib.util.spec_from_file_location("privacy_heads_preparer", ROOT / "evaluation/prepare-privacy-heads-v3.py")
PREPARER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARER)


class PrivacyDataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.resource = json.loads((ROOT / PREPARER.RESOURCE).read_bytes())
        cls.pools = build(cls.resource)

    def test_reproducible_bytes_and_exact_composition(self):
        self.assertEqual(canonical(self.pools), canonical(build(copy.deepcopy(self.resource))))
        summary = audit(self.pools, self.resource)
        for split, expected in COUNTS.items():
            self.assertEqual(summary[split]["rows"], expected)
            self.assertEqual(summary[split]["families"], 140 if split == "train" else 35)
            self.assertEqual(summary[split]["sensitivity"]["S1"], 360 if split == "train" else 90)
            self.assertGreaterEqual(summary[split]["category_set_combinations"], 15)
            self.assertTrue(all(n == expected // 6 for n in summary[split]["visibility"].values()))

    def test_other_child_and_other_adult_health_closure(self):
        for rows in self.pools.values():
            for row in rows:
                if row["metadata"]["control"] != "actual_disclosure":
                    continue
                categories = row["classification"]["categories"]
                if row["metadata"]["subject_relationship"] == "other_child":
                    self.assertIn("CHILD", categories)
                    self.assertIn("THIRD_PARTY", categories)
                if row["metadata"]["subject_relationship"] == "other_adult":
                    self.assertIn("HEALTH", categories)
                    self.assertIn("THIRD_PARTY", categories)

    def test_single_category_enum_does_not_force_unrelated_closure(self):
        self.assertEqual(target("S2", "PU", ["CHILD"]).to_dict()["categories"], ["CHILD"])
        self.assertEqual(target("S2", "PU", ["THIRD_PARTY"]).to_dict()["categories"], ["THIRD_PARTY"])

    def test_auxiliary_is_mild_not_silent_clean_or_sensitive_domain(self):
        for rows in self.pools.values():
            mild = [r for r in rows if r["metadata"]["control"] == "mild_personal"]
            self.assertTrue(mild)
            self.assertTrue(all(r["classification"]["sensitivity"] == "S1"
                                and not r["classification"]["categories"]
                                and r["required_sensitive"] and r["allowed_actions"] == ["ALLOW"] for r in mild))

    def test_no_hints_and_all_truth_explicit(self):
        for rows in self.pools.values():
            for row in rows:
                self.assertNotIn("visibility_hint", row)
                self.assertEqual(row["packed"], row["packed_classification"])
                self.assertFalse(row["ambiguous"])
                self.assertTrue(row["context_truth_eligible"])
                self.assertTrue(row["metadata"]["visibility_evidence"])

    def test_family_predicate_duplicate_rejected_before_rendering(self):
        resource = copy.deepcopy(self.resource)
        resource["families"][-1]["fact"] = resource["families"][0]["fact"]
        with self.assertRaises(ValueError):
            build(resource)

    def test_split_entity_or_template_reuse_rejected(self):
        for field in ("entities", "variants"):
            resource = copy.deepcopy(self.resource)
            resource["splits"]["eval"][field][0] = resource["splits"]["train"][field][0]
            with self.assertRaises(ValueError):
                validate_resource(resource)

    def test_secondary_component_copy_and_amount_only_rewrite_rejected(self):
        for amount_only in (False, True):
            resource = copy.deepcopy(self.resource)
            train = next(f for f in resource["families"] if f["split"] == "train"
                         and f["primary_category"] == "CRIMINAL")
            heldout = next(f for f in resource["families"] if f["split"] == "eval")
            heldout["secondary"]["fact"] = train["secondary"]["fact"]
            if amount_only:
                heldout["secondary"]["fact"] = heldout["secondary"]["fact"].replace("80", "990")
            with self.assertRaises(ValueError):
                audit_components(resource)

    def test_coarse_credit_family_cannot_cross_splits(self):
        resource = copy.deepcopy(self.resource)
        heldout = next(f for f in resource["families"] if f["split"] == "eval")
        heldout["coarse_situation_id"] = "financial/loan_credit_obligation"
        with self.assertRaises(ValueError):
            audit_components(resource)

    def test_repaired_transaction_and_nonmedical_labels(self):
        families = {f["family_id"]: f for f in self.resource["families"]}
        for index in ("01", "11"):
            self.assertIn("FINANCIAL", families["PH3/train/politics/" + index]["categories"])
        self.assertNotIn("therapy", families["PH3/train/sexual/10"]["fact"])
        self.assertNotIn("counsell", families["PH3/validation/sexual/14"]["fact"])
        self.assertNotIn("counsell", families["PH3/validation/child/14"]["fact"])
        self.assertIn("vows", families["PH3/train/religion/11"]["fact"])

    def test_missing_or_changed_packed_target_rejected(self):
        for change in (lambda r: r["classification"].pop("visibility"),
                       lambda r: r.update(packed_classification=r["packed_classification"] ^ 1)):
            pools = copy.deepcopy(self.pools)
            change(pools["train"][0])
            with self.assertRaises(ValueError):
                audit(pools, self.resource)

    def test_valid_but_wrong_label_or_lineage_rejected(self):
        for change in (lambda r: r["metadata"].update(parent_id="PH3/eval/borrowed"),
                       lambda r: r.update(allowed_actions=["BLOCK"]),
                       lambda r: r.update(visibility_hint="P0"),
                       lambda r: r.update(text="Unrelated replacement text.")):
            pools = copy.deepcopy(self.pools)
            change(pools["validation"][0])
            with self.assertRaises(ValueError):
                audit(pools, self.resource)

    def test_duplicate_text_or_cross_split_family_rejected(self):
        pools = copy.deepcopy(self.pools)
        pools["eval"][0]["text"] = pools["train"][0]["text"]
        with self.assertRaises(ValueError):
            audit(pools, self.resource)

    def test_fuzzer_adapter_cannot_sample_validation_or_exhaust_pool(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rows.jsonl"
            path.write_bytes(b"".join(canonical(r) for r in self.pools["validation"][:4]))
            with self.assertRaises(ValueError):
                fuzzer_training_examples(path, 1, 42)
            path.write_bytes(b"".join(canonical(r) for r in self.pools["train"][:4]))
            with self.assertRaises(ValueError):
                fuzzer_training_examples(path, 5, 42)
            first = fuzzer_training_examples(path, 4, 42)
            second = fuzzer_training_examples(path, 4, 42)
            self.assertEqual([r.text for r in first], [r.text for r in second])
            self.assertEqual(len({r.text for r in first}), 4)

    def test_fuzzer_adapter_rejects_packed_only_and_conflicting_named_truth(self):
        for mutate in (lambda r: r["classification"].pop("visibility"),
                       lambda r: r.update(packed=r["packed"] ^ 1),
                       lambda r: r["classification"].update(sensitivity="S3")):
            with tempfile.TemporaryDirectory() as directory:
                row = copy.deepcopy(self.pools["train"][0])
                mutate(row)
                path = Path(directory) / "bad.jsonl"
                path.write_bytes(canonical(row))
                with self.assertRaises(ValueError):
                    fuzzer_training_examples(path, 1, 42)

    def test_native_tokenizers_and_smallest_v1_window(self):
        result = PREPARER.native_lengths(self.pools)
        self.assertFalse(result["inference_executed"])
        for values in result["splits"].values():
            self.assertLessEqual(values["v1_efficient"]["maximum"], 64)
            self.assertTrue(all(v["maximum"] <= v["cap"] for v in values.values()))

    def test_native_overlength_fails_without_trimming(self):
        pools = {split: list(rows[:1]) for split, rows in self.pools.items()}
        pools["train"] = [{**pools["train"][0], "text": "word " * 70}]
        with self.assertRaises(ValueError):
            PREPARER.native_lengths(pools)

    def test_historical_and_protected_exclusion_membership(self):
        proof = PREPARER.exclusion_audit(self.pools, self.resource)
        self.assertEqual(proof["exact_normalized_identity_transform_overlaps"], 0)
        self.assertFalse(proof["historical_final_payload_opened"])
        pools = {split: list(rows[:1]) for split, rows in self.pools.items()}
        prior = PREPARER.records((ROOT / PREPARER.HISTORICAL[2]).read_bytes())[0]
        pools["train"] = [{**pools["train"][0], "text": prior["template"]}]
        with self.assertRaises(ValueError):
            PREPARER.exclusion_audit(pools, self.resource)

    def test_component_matching_historical_substring_fails_even_with_new_whole_row(self):
        resource = copy.deepcopy(self.resource)
        resource["families"][0]["secondary"]["fact"] = "I am bisexual"
        with self.assertRaises(ValueError):
            PREPARER.exclusion_audit(self.pools, resource)

    def test_release_manifest_schema_and_source_bindings(self):
        manifest_path = ROOT / "evaluation/results/privacy_heads_v3_20261013/data/release-02/manifest.json"
        if not manifest_path.exists():
            self.skipTest("Local immutable release is not present; run host preparer for release check.")
        manifest = json.loads(manifest_path.read_bytes())
        self.assertEqual(manifest["schema"], 1)
        self.assertEqual(set(manifest["files"]), {"train", "validation", "fresh_eval"})
        for name, item in manifest["files"].items():
            payload = (manifest_path.parent / item["path"]).read_bytes()
            self.assertEqual(digest(payload), item["sha256"])
            rows = [json.loads(line) for line in payload.splitlines()]
            self.assertEqual(len(rows), item["rows"])
            self.assertEqual(len({r["group_id"] for r in rows}), item["groups"])
            self.assertTrue(all(r["partition"] == name for r in rows))
        for relative, sha in manifest["source_files"].items():
            self.assertEqual(digest((ROOT / relative).read_bytes()), sha)


if __name__ == "__main__":
    unittest.main()
