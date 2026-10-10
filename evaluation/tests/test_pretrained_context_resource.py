"""Behavioral checks for prospective family splits and complete disclosure labels."""
import copy
import json
from pathlib import Path
import unittest

from host_environment import configure_imports
configure_imports()
from privoke_eval import pretrained_context_resource as resource
from privoke_eval.synthetic_curriculum import canonical_json, opaque_key, sha256

ROOT = Path(__file__).resolve().parents[2]


class PretrainedResourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = json.loads((ROOT / "evaluation/datasets/contextual-head-study-20261010.json").read_text())
        cls.pools = resource.render(cls.source)

    def test_independent_family_inventory_and_qualification_denominators(self):
        inventory = resource.inventory(self.pools)
        self.assertEqual([inventory[s]["families"] for s in resource.SPLITS], [40, 10, 10])
        assessment = inventory["assessment"]
        self.assertEqual(assessment["rows"], 160)
        self.assertEqual(assessment["sensitivity"], {"S3": 56, "S0": 60, "S1": 20, "S2": 24})
        self.assertEqual(assessment["visibility"], {"P0": 20, "P1": 30, "P2": 20, "P3": 20, "P4": 30, "PU": 40})
        self.assertEqual(assessment["category_cardinality"], {"1": 56, "0": 80, "2": 24})

    def test_cue_crossover_preserves_actual_facts_and_complete_categories(self):
        for split, rows in self.pools.items():
            for start in range(0, len(rows), 16):
                family = rows[start:start + 16]
                self.assertTrue(all(r["classification"]["categories"] == [] for r in family[6:12] + family[14:]))
                for actual, fictional in zip(family[:6], family[6:12]):
                    self.assertEqual(actual["classification"]["visibility"], fictional["classification"]["visibility"])
                    self.assertIn(actual["text"].split(". ", 1)[1], fictional["text"])
                self.assertEqual(family[12]["classification"]["categories"], family[0]["classification"]["categories"])
                self.assertEqual(family[13]["classification"]["categories"], family[0]["classification"]["categories"])
                for slot in (*range(6, 12), 12, 13):
                    lo, hi = family[slot]["metadata"]["annotations"]["sensitivity"]["span"]
                    evidence = family[slot]["text"][lo:hi]
                    self.assertGreater(len(evidence), len(family[0]["text"].split(". ", 1)[1]))
                if family[0]["metadata"]["primary_category"] == "CHILD":
                    self.assertEqual(family[0]["classification"]["categories"], ["CHILD", "THIRD_PARTY"])
                for row in family:
                    for category in row["classification"]["categories"]:
                        evidence = row["metadata"]["annotations"]["categories"][category]
                        lo, hi = evidence["span"]
                        self.assertTrue(row["text"][lo:hi])

    def test_missing_category_evidence_and_cross_split_frames_rejected(self):
        source = copy.deepcopy(self.source)
        source["families"][36]["category_rationales"].pop("THIRD_PARTY")
        with self.assertRaises(ValueError):
            resource.render(source)

    def test_reviewed_full_categories_are_independent_of_sampling_stratum(self):
        names = {"sexual_intimaterelationship", "sexual_encounterhistory", "sexual_specificsexualrelationship"}
        for family in self.source["families"]:
            if family["family_id"] in names:
                self.assertEqual(family["categories"], ["SEXUAL", "THIRD_PARTY"])
                self.assertIn("THIRD_PARTY", family["category_rationales"])
        for invalid in (["HEALTH", "BOGUS"], ["HEALTH", "HEALTH"]):
            source = copy.deepcopy(self.source)
            source["families"][0]["categories"] = invalid
            with self.assertRaises(ValueError):
                resource.render(source)
        source = copy.deepcopy(self.source)
        source["frames"]["assessment"]["P0"] = source["frames"]["train"]["P0"]
        with self.assertRaises(ValueError):
            resource.render(source)

    def test_protected_opaque_domain_and_union_digest_fail_closed(self):
        row = self.pools["train"][0]
        sets = {"ids": [opaque_key("id", row["id"])], "groups": [], "texts": []}
        index = {"schema_version": 1, "all_exclusion_key_sets": sets,
                 "all_exclusion_key_sets_sha256": sha256(canonical_json(sets).encode())}
        with self.assertRaisesRegex(ValueError, "overlaps"):
            resource.check_exclusions(self.pools, index, [])
        index["all_exclusion_key_sets_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest"):
            resource.check_exclusions(self.pools, index, [])

    def test_prior_public_overlap_and_invalid_spans_rejected(self):
        sets = {"ids": [], "groups": [], "texts": []}
        index = {"schema_version": 1, "all_exclusion_key_sets": sets,
                 "all_exclusion_key_sets_sha256": sha256(canonical_json(sets).encode())}
        with self.assertRaises(ValueError):
            resource.check_exclusions(self.pools, index, [self.pools["assessment"][0]])
        pools = copy.deepcopy(self.pools)
        pools["train"][0]["metadata"]["annotations"]["sensitivity"]["span"] = [-1, 4]
        with self.assertRaises(ValueError):
            resource.validate_rows(pools)
