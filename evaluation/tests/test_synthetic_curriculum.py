"""Behavioral checks for synthetic fact preservation and permanent leakage barriers."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

from host_environment import configure_imports

configure_imports()
from privoke_eval.synthetic_curriculum import (
    LABEL_STATUS, MAX_CONTENT_TOKENS, TOKEN_PATTERN, build_curriculum, build_assessment,
    canonical_json, classification, opaque_key, prepare, reject_final_path,
    sha256, validate_pools, verify_exclusions,
)
from privoke_model.training_data import training_text_key

ROOT = Path(__file__).resolve().parents[2]
RESOURCE = ROOT / "evaluation/datasets/synthetic-teacher-templates.json"
REVISED = ROOT / "evaluation/datasets/synthetic-teacher-templates-v2.json"
ASSESSMENT = ROOT / "evaluation/datasets/contextual-assessment-20261009.json"
EMPTY_INDEX = {"schema_version": 1, "all_exclusion_key_sets": {"ids": [], "groups": [], "texts": []}}
EMPTY_INDEX["all_exclusion_key_sets_sha256"] = sha256(canonical_json(EMPTY_INDEX["all_exclusion_key_sets"]).encode())


class SyntheticCurriculumTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.resource = json.loads(RESOURCE.read_text(encoding="utf-8"))
        cls.pools = build_curriculum(cls.resource)

    def test_expected_pool_coverage_and_balanced_roles(self):
        self.assertEqual({name: len(rows) for name, rows in self.pools.items()},
                         {"train": 672, "heldout": 16, "replay": 64})
        categories = {name for row in self.pools["train"] for name in row["classification"]["categories"]}
        self.assertEqual(len(categories), 10)
        visibility = {row["classification"]["visibility"] for row in self.pools["train"]}
        self.assertTrue({"P0", "P2", "P3", "P4", "PU"} <= visibility)
        validate_pools(self.pools)

    def test_revised_equal_budget_preserves_guard_replay_and_has_authored_evolution(self):
        resource = json.loads(REVISED.read_text(encoding="utf-8"))
        revised = build_curriculum(resource)
        self.assertEqual({k: len(v) for k, v in revised.items()},
                         {k: len(v) for k, v in self.pools.items()})
        self.assertEqual(revised["heldout"], self.pools["heldout"])
        self.assertEqual(revised["replay"], self.pools["replay"])
        self.assertEqual(len({r["metadata"]["group_id"] for r in revised["train"]}), 28)
        for row in revised["train"]:
            self.assertEqual(row["metadata"]["generator"], "contextual_situations_v2")
            self.assertIn("contrast", json.loads(row["metadata"]["scenario_facts"]))
        del resource["families"][0]["evolved_clean"]
        with self.assertRaisesRegex(ValueError, "rendering"):
            build_curriculum(resource)

    def test_frozen_assessment_separate_from_both_curricula_and_covers_hard_positive_cues(self):
        resource = json.loads(ASSESSMENT.read_text(encoding="utf-8"))
        revised = build_curriculum(json.loads(REVISED.read_text(encoding="utf-8")))
        rows = build_assessment(resource, [self.pools, revised])
        self.assertEqual((len(rows), len({row["group_id"] for row in rows})), (64, 32))
        positives = [row for row in rows if row["required_sensitive"]]
        self.assertTrue(any(row["classification"]["visibility"] == "P0" for row in positives))
        for name in ("quoted_actual_fact_vs_fictional_quote", "hypothetical_frame_actual_fact_vs_invented_fact",
                     "mixed_discussion_actual_disclosure_vs_discussion"):
            self.assertTrue(any(row["metadata"]["contrast"] == name for row in positives))
        pools = copy.deepcopy(revised)
        pools["train"][0]["text"] = rows[0]["text"].upper()
        with self.assertRaisesRegex(ValueError, "overlaps"):
            build_assessment(resource, [pools])
        invalid = copy.deepcopy(resource)
        invalid["rows"][0]["required_sensitive"] = True
        with self.assertRaisesRegex(ValueError, "truth"):
            build_assessment(invalid)
        invalid = copy.deepcopy(resource)
        invalid["rows"][0]["text"] += " filler" * 100
        with self.assertRaisesRegex(ValueError, "capacity"):
            build_assessment(invalid)

    def test_assessment_is_frozen_outside_training_splits_and_protected_exclusions_apply(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            index = root / "exclusions.json"
            index.write_text(canonical_json(EMPTY_INDEX), encoding="utf-8")
            manifest = prepare(root / "package", REVISED, index, assessment_resource=ASSESSMENT)
            self.assertEqual(set(manifest["splits"]), {"train", "replay", "heldout"})
            self.assertEqual(manifest["assessment"]["count"], 64)
            self.assertEqual(sha256((root / "package/assessment.jsonl").read_bytes()), manifest["assessment"]["sha256"])
            blocked = copy.deepcopy(EMPTY_INDEX)
            first = json.loads(ASSESSMENT.read_text(encoding="utf-8"))["rows"][0]
            blocked["all_exclusion_key_sets"]["texts"] = [opaque_key("text_key", training_text_key(first["text"]))]
            blocked["all_exclusion_key_sets_sha256"] = sha256(canonical_json(blocked["all_exclusion_key_sets"]).encode())
            index.write_text(canonical_json(blocked), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "overlaps"):
                prepare(root / "blocked", REVISED, index, assessment_resource=ASSESSMENT)
            self.assertFalse((root / "blocked").exists())

    def test_seed_changes_order_never_family_membership(self):
        other = build_curriculum(self.resource, seed=71)
        for split in self.pools:
            self.assertEqual({r["id"] for r in self.pools[split]}, {r["id"] for r in other[split]})
            self.assertEqual({r["metadata"]["group_id"] for r in self.pools[split]},
                             {r["metadata"]["group_id"] for r in other[split]})
        self.assertNotEqual([r["id"] for r in self.pools["train"]], [r["id"] for r in other["train"]])

    def test_parent_targets_and_facts_survive_evolution(self):
        rows = {row["id"]: row for row in self.pools["train"]}
        for row in rows.values():
            parent = row["metadata"]["parent_id"]
            if parent:
                self.assertEqual(row["classification"], rows[parent]["classification"])
                self.assertEqual(row["metadata"]["scenario_facts"], rows[parent]["metadata"]["scenario_facts"])
                self.assertEqual(row["metadata"]["group_id"], rows[parent]["metadata"]["group_id"])
            self.assertEqual(row["metadata"]["label_status"], LABEL_STATUS)
            self.assertIn("unavailable", row["metadata"]["teacher_model"])

    def test_all_decisive_tokens_fit_smallest_runtime(self):
        for rows in self.pools.values():
            for row in rows:
                self.assertLessEqual(len(TOKEN_PATTERN.findall(training_text_key(row["text"]))), MAX_CONTENT_TOKENS)
                self.assertLessEqual(len(row["text"].split()), 45)

    def test_conflicting_normalized_duplicates_fail_closed(self):
        pools = copy.deepcopy(self.pools)
        pools["train"][0]["text"] = pools["heldout"][0]["text"].upper() + "  "
        pools["train"][0]["classification"] = classification("S3", "PU", ["HEALTH"])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            validate_pools(pools)

    def test_cross_split_family_rejected(self):
        pools = copy.deepcopy(self.pools)
        pools["heldout"][0]["metadata"]["group_id"] = pools["train"][0]["metadata"]["group_id"]
        with self.assertRaisesRegex(ValueError, "Family crosses"):
            validate_pools(pools)

    def test_opaque_protected_union_and_development_overlap_rejected(self):
        row = self.pools["train"][0]
        for field, kind, value in (("texts", "text_key", training_text_key(row["text"])),
                                   ("ids", "id", row["id"]),
                                   ("groups", "group", row["metadata"]["group_id"])):
            index = copy.deepcopy(EMPTY_INDEX)
            index["all_exclusion_key_sets"][field] = [opaque_key(kind, value)]
            index["all_exclusion_key_sets_sha256"] = sha256(canonical_json(index["all_exclusion_key_sets"]).encode())
            with self.assertRaisesRegex(ValueError, "overlaps"):
                verify_exclusions(self.pools, index)
        with self.assertRaisesRegex(ValueError, "overlaps"):
            verify_exclusions(self.pools, EMPTY_INDEX, [{"text": row["text"].upper()}])

    def test_modified_exclusion_union_rejected(self):
        index = copy.deepcopy(EMPTY_INDEX)
        index["all_exclusion_key_sets"]["texts"] = ["0" * 64]
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            verify_exclusions(self.pools, index)

    def test_invalid_labels_and_teacher_placeholders_rejected(self):
        with self.assertRaises(ValueError):
            classification("S9", "PU", [])
        with self.assertRaises(ValueError):
            classification("S0", "PRIVATE", [])
        with self.assertRaises(ValueError):
            classification("S3", "PU", ["HEALTH", "HEALTH"])
        resource = copy.deepcopy(self.resource)
        resource["families"][0]["teacher_private"] = "A patient has {other}."
        with self.assertRaisesRegex(ValueError, "slot"):
            build_curriculum(resource)

    def test_final_input_paths_rejected_before_reading(self):
        for path in ("not-present/final.jsonl", "not-present/locked-final/input.jsonl", "not-present/final/data"):
            with self.assertRaisesRegex(ValueError, "Final"):
                reject_final_path(Path(path))
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, "Final"):
                prepare(Path(folder) / "output", Path(folder) / "final.json", Path(folder) / "missing-index")

    def test_preparation_is_reproducible_and_immutable_with_pinned_development(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            index = root / "exclusion.json"
            index.write_text(canonical_json(EMPTY_INDEX), encoding="utf-8")
            development = root / "development.jsonl"
            development.write_text('{"text":"A unique development text outside all synthetic plans."}\n', encoding="utf-8")
            digest = sha256(development.read_bytes())
            first = prepare(root / "first", RESOURCE, index, development, digest)
            second = prepare(root / "second", RESOURCE, index, development, digest)
            self.assertEqual(first, second)
            for split in first["splits"].values():
                payload = (root / "first" / split["path"]).read_bytes()
                self.assertEqual(sha256(payload), split["sha256"])
                self.assertEqual(payload, (root / "second" / split["path"]).read_bytes())
            with self.assertRaisesRegex(ValueError, "fresh"):
                prepare(root / "first", RESOURCE, index)
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                prepare(root / "wrong", RESOURCE, index, development, "0" * 64)
            self.assertFalse((root / "wrong").exists())


if __name__ == "__main__":
    unittest.main()
