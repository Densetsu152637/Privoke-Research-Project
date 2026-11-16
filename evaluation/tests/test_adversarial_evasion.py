"""Mechanics tests for ADVEVADE-20261116: transforms, statistics, ASR computation and layer assertion.

Synthetic strings and synthetic score records only: no detector, model or dataset row is used.
"""

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "evaluation")]

import adversarial_evasion as ae  # noqa: E402
import adversarial_evasion_transforms as tx  # noqa: E402

TEXT = "Hello, my name is Alice Smith and my social security number is 123-45-6789, email alice@example.org."
ENTITIES = [
    {"start": TEXT.index("Alice Smith"), "end": TEXT.index("Alice Smith") + len("Alice Smith"), "label": "name"},
    {"start": TEXT.index("123-45-6789"), "end": TEXT.index("123-45-6789") + len("123-45-6789"), "label": "ssn"},
    {"start": TEXT.index("alice@example.org"), "end": TEXT.index("alice@example.org") + len("alice@example.org"), "label": "EMAIL"},
]
ROW = {"id": "r1", "group_id": "g1", "text": TEXT, "entities": ENTITIES, "source_dataset": "synthetic/a", "expected_has_pii": True}


def spans_text(row):
    return [row["text"][e["start"]:e["end"]] for e in row["entities"]]


class TransformTests(unittest.TestCase):
    def test_every_variant_is_deterministic(self):
        for name in tx.VARIANTS:
            self.assertEqual(tx.apply_variant(name, ROW), tx.apply_variant(name, ROW), name)

    def test_seed_depends_on_row_id(self):
        other = dict(ROW, id="r2")
        self.assertNotEqual(tx.apply_variant("zero_width", ROW), tx.apply_variant("zero_width", other))

    def test_homoglyph_changes_only_spans_and_uses_confusables(self):
        out = tx.apply_variant("homoglyph", ROW)
        self.assertNotEqual(out, TEXT)
        self.assertTrue(out.startswith("Hello, my name is "))
        self.assertTrue(any(ord(c) > 0x300 for c in out))
        self.assertTrue(all(ord(c) < 128 for c in out[:18]))

    def test_zero_width_inserts_format_characters_inside_spans_only(self):
        out = tx.apply_variant("zero_width", ROW)
        self.assertEqual("".join(c for c in out if c not in tx.ZERO_WIDTH), TEXT)
        self.assertTrue(any(c in tx.ZERO_WIDTH for c in out))
        self.assertTrue(out.startswith("Hello, my name is "))

    def test_spaces_separate_every_span_character(self):
        out = tx.apply_variant("spaces", ROW)
        self.assertIn("1 2 3 - 4 5 - 6 7 8 9", out)
        self.assertIn("A l i c e S m i t h", out)
        self.assertTrue(out.startswith("Hello, my name is "))

    def test_spelling_preserves_length_class_and_edits_spans(self):
        out = tx.apply_variant("spelling", ROW)
        self.assertNotEqual(out, TEXT)
        self.assertNotIn("123-45-6789", out)

    def test_paraphrase_keeps_span_values_and_frames(self):
        out = tx.apply_variant("paraphrase", ROW)
        for value in spans_text(ROW):
            self.assertIn(value, out)
        self.assertNotEqual(out, TEXT)

    def test_indirect_pointer_removes_values_and_partial_keeps_tail(self):
        pointer = tx.apply_variant("indirect_pointer", ROW)
        for value in spans_text(ROW):
            self.assertNotIn(value, pointer)
        partial = tx.apply_variant("indirect_partial", ROW)
        self.assertIn("ending in 6789", partial)
        self.assertIn("A. S.", partial)
        self.assertTrue(tx.VARIANTS["indirect_pointer"][2])
        self.assertFalse(tx.VARIANTS["indirect_partial"][2])

    def test_encodings_round_trip(self):
        encoded = tx.apply_variant("base64", ROW)
        self.assertIn(base64.b64encode(b"123-45-6789").decode(), encoded)
        self.assertIn(b"123-45-6789".hex(), tx.apply_variant("hex", ROW))
        spelled = tx.apply_variant("spelled_digits", ROW)
        self.assertIn("one two three-four five-six seven eight nine", spelled)
        self.assertNotIn("123", spelled)

    def test_spelled_digits_not_applicable_without_digits(self):
        row = dict(ROW, text="Alice Smith writes.", entities=[{"start": 0, "end": 11, "label": "name"}])
        self.assertIsNone(tx.apply_variant("spelled_digits", row))

    def test_homoglyph_not_applicable_without_confusable_letters(self):
        row = dict(ROW, text="Id 12", entities=[{"start": 3, "end": 5, "label": "ssn"}])
        self.assertIsNone(tx.apply_variant("homoglyph", row))

    def test_long_context_lengths_and_positions(self):
        for name, position in (("ctx_long_start", "start"), ("ctx_long_middle", "middle"), ("ctx_long_end", "end")):
            out = tx.apply_variant(name, ROW)
            self.assertGreaterEqual(len(out), tx.LONG_FILLER_CHARS)
            self.assertLessEqual(len(out), 20_000)
            self.assertIn(TEXT, out)
            index = out.index(TEXT)
            if position == "start":
                self.assertEqual(index, 0)
            elif position == "end":
                self.assertEqual(index + len(TEXT), len(out))
            else:
                self.assertGreater(index, 1000)
                self.assertLess(index + len(TEXT), len(out) - 1000)
        self.assertLess(len(tx.apply_variant("ctx_window_middle", ROW)), 2500)

    def test_filler_carries_no_digits(self):
        self.assertFalse(any(ch.isdigit() for sentence in tx.FILLER_SENTENCES for ch in sentence))

    def test_multilingual_templates_cover_every_family_and_keep_values(self):
        families = set(json.loads(tx.LABEL_FAMILY_FILE.read_text(encoding="utf-8"))["label_to_family"].values()) | {"UNMAPPED"}
        for language, table in tx.MULTILINGUAL.items():
            self.assertTrue(families <= set(table), f"{language} lacks {families - set(table)}")
            for template in table.values():
                self.assertIn("{v}", template)
        for language in tx.MULTILINGUAL:
            out = tx.apply_variant(f"multilingual_{language}", ROW)
            self.assertIn("123-45-6789", out)
            self.assertNotIn("social security", out)

    def test_overlapping_and_invalid_spans_are_merged_or_dropped(self):
        row = dict(ROW, entities=[{"start": 0, "end": 5, "label": "a"}, {"start": 3, "end": 8, "label": "b"},
                                  {"start": 50, "end": 10, "label": "c"}, {"start": 0, "end": 9999, "label": "d"}])
        self.assertEqual(tx.merged_spans(row), [(0, 8, "a")])

    def test_variant_registry_covers_the_requested_families(self):
        self.assertEqual({fam for fam, _f, _r in tx.VARIANTS.values()}, set(tx.FAMILIES))


class StatisticsTests(unittest.TestCase):
    def test_wilson_matches_reference_values(self):
        low, high = ae.wilson(0, 100)
        self.assertAlmostEqual(low, 0.0, places=12)
        self.assertAlmostEqual(high, 0.03699, places=4)
        low, high = ae.wilson(50, 100)
        self.assertAlmostEqual(low, 0.4038, places=4)
        self.assertAlmostEqual(high, 0.5962, places=4)
        low, high = ae.wilson(100, 100)
        self.assertAlmostEqual(low, 0.9630, places=4)
        self.assertAlmostEqual(high, 1.0, places=12)
        self.assertTrue(all(v != v for v in ae.wilson(0, 0)))

    def test_exact_mcnemar(self):
        self.assertEqual(ae.exact_mcnemar(0, 0), 1.0)
        self.assertAlmostEqual(ae.exact_mcnemar(0, 8), 2 / 256)
        self.assertAlmostEqual(ae.exact_mcnemar(5, 5), 1.0)


def layers(regex=("ok", "ALLOW"), ner=("ok", "ALLOW"), semantic=("ok", "ALLOW"), error=""):
    def entry(name, value):
        status, action = value
        return {"layer": name, "status": status, "error": error if status == "error" else "",
                "results": [] if action == "ALLOW" else [{"action": action}]}
    return [entry("regex", regex), entry("ner", ner), entry("semantic", semantic)]


class LayerAssertionTests(unittest.TestCase):
    def test_accepts_full_execution_and_regex_first_skip(self):
        self.assertEqual(ae.assert_executed_layers(layers()), {"regex": "ok", "ner": "ok", "semantic": "ok"})
        skipped = layers(regex=("ok", "BLOCK"), ner=("skipped", "ALLOW"), semantic=("skipped", "ALLOW"))
        self.assertEqual(ae.assert_executed_layers(skipped)["semantic"], "skipped")

    def test_rejects_missing_reordered_or_partial_layers(self):
        with self.assertRaises(ae.LayerAssertionError):
            ae.assert_executed_layers(layers()[:2])
        with self.assertRaises(ae.LayerAssertionError):
            ae.assert_executed_layers(list(reversed(layers())))
        with self.assertRaises(ae.LayerAssertionError):  # empty layer list means the full pipeline; never accepted as such
            ae.assert_executed_layers([])
        with self.assertRaises(ae.LayerAssertionError):
            ae.assert_executed_layers(layers(ner=("skipped", "ALLOW")))

    def test_rejects_unknown_status_and_regex_failure(self):
        with self.assertRaises(ae.LayerAssertionError):
            ae.assert_executed_layers(layers(ner=("weird", "ALLOW")))
        with self.assertRaises(ae.LayerAssertionError):
            ae.assert_executed_layers(layers(regex=("error", "ALLOW")))

    def test_semantic_identity_is_checked_when_the_layer_ran(self):
        meta = {"privoke.semantic.artifact_checksum": "abc"}
        ae.assert_executed_layers(layers(), "abc", meta)
        with self.assertRaises(ae.LayerAssertionError):
            ae.assert_executed_layers(layers(), "other", meta)
        skipped = layers(regex=("ok", "BLOCK"), ner=("skipped", "ALLOW"), semantic=("skipped", "ALLOW"))
        ae.assert_executed_layers(skipped, "other", {})

    def test_score_record_marks_fail_closed(self):
        response = {"action": "BLOCK", "layers": layers(semantic=("error", "ALLOW"), error="too long"), "metadata": {}}
        record = ae.score_record("v", response, None)
        self.assertTrue(record["failed_closed"])
        self.assertEqual(record["errored"], ["semantic"])
        self.assertEqual(record["detect_action"], "ALLOW")
        genuine = {"action": "BLOCK", "layers": layers(ner=("ok", "BLOCK")), "metadata": {}}
        self.assertFalse(ae.score_record("v", genuine, None)["failed_closed"])


def make_items(rows, variants):
    items = []
    for row in rows:
        items.append({"vid": f"{row}::baseline", "row_id": row, "variant": "baseline", "family": "baseline", "applicable": True, "text": "t"})
        for variant, family in variants.items():
            items.append({"vid": f"{row}::{variant}", "row_id": row, "variant": variant, "family": family, "applicable": True, "text": "t"})
    return items


def rec(vid, action, failed_closed=False):
    return {"vid": vid, "action": action, "detect_action": "ALLOW" if failed_closed else action, "failed_closed": failed_closed,
            "errored": ["semantic"] if failed_closed else [], "layer_status": {"regex": "ok", "ner": "ok", "semantic": "ok"},
            "layer_action": {"regex": action, "ner": "ALLOW", "semantic": "ALLOW"}}


class AsrTests(unittest.TestCase):
    def setUp(self):
        self.rows = ["a", "b", "c", "d"]
        self.variants = {"v1": "famA", "v2": "famB"}
        self.items = make_items(self.rows, self.variants)
        self.manifest = {"row_source": {r: "s1" if r in "ab" else "s2" for r in self.rows},
                         "row_group": {r: "g" + r for r in self.rows},
                         "variants": {"v1": {"family": "famA", "value_removing": False}, "v2": {"family": "famB", "value_removing": True}}}
        defaults = {"a::baseline": "BLOCK", "b::baseline": "WARN", "c::baseline": "BLOCK", "d::baseline": "ALLOW",
                    "a::v1": "ALLOW", "b::v1": "ALLOW", "c::v1": "WARN", "a::v2": "WARN", "b::v2": "WARN", "c::v2": "BLOCK"}
        self.defaults = {k: rec(k, v) for k, v in defaults.items()}
        flags = dict(defaults, **{"a::v1": "BLOCK", "b::v1": "ALLOW", "d::baseline": "ALLOW"})
        self.flags = {k: rec(k, v) for k, v in flags.items()}

    def analyse(self, flags=None):
        return ae.analyse_from(self.items, {"defaults": self.defaults, "flags": flags or self.flags}, self.manifest)

    def test_baseline_and_intended_actions(self):
        result = self.analyse()
        self.assertEqual(result["intended_actions"], {"ALLOW": 1, "WARN": 1, "BLOCK": 2})
        self.assertEqual(result["baseline"]["defaults"]["protected"]["k"], 3)
        self.assertEqual(result["protected_rows"], 3)

    def test_conditional_and_unconditional_asr(self):
        overall = self.analyse()["arms"]["defaults"]["action_level"]["overall"]
        # applicable pairs: 4 rows x 2 variants = 8; protected pairs: rows a, b, c -> 6; evaded: a::v1, b::v1
        self.assertEqual(overall["applicable"], 8)
        self.assertEqual(overall["protected_pairs"], 6)
        self.assertEqual(overall["evaded"], 2)
        self.assertEqual(overall["asr_conditional"]["k"], 2)
        self.assertEqual(overall["asr_conditional"]["n"], 6)
        self.assertEqual(overall["asr_unconditional"]["n"], 8)
        self.assertAlmostEqual(overall["asr_conditional"]["rate"], 1 / 3)
        low, high = ae.wilson(2, 6)
        self.assertAlmostEqual(overall["asr_conditional"]["wilson_low"], low)
        self.assertAlmostEqual(overall["asr_conditional"]["wilson_high"], high)

    def test_downgrade_counts_block_to_warn_only(self):
        overall = self.analyse()["arms"]["defaults"]["action_level"]["overall"]
        # intended BLOCK rows: a (v1 ALLOW, v2 WARN), c (v1 WARN, v2 BLOCK) -> downgrades a::v2, c::v1
        self.assertEqual(overall["block_pairs"], 4)
        self.assertEqual(overall["downgraded_block_to_warn"], 2)
        self.assertEqual(overall["weakened_conditional"]["k"], 4)

    def test_family_and_value_removing_split(self):
        arm = self.analyse()["arms"]["defaults"]["action_level"]
        self.assertEqual(arm["by_family"]["famA"]["evaded"], 2)
        self.assertEqual(arm["by_family"]["famB"]["evaded"], 0)
        self.assertEqual(arm["overall_excluding_value_removing"]["protected_pairs"], 3)

    def test_flags_arm_and_paired_discordance(self):
        result = self.analyse()
        self.assertEqual(result["arms"]["flags"]["action_level"]["overall"]["evaded"], 1)
        paired = result["paired_arms"]["overall"]
        self.assertEqual((paired["evaded_defaults_only"], paired["evaded_flags_only"], paired["evaded_both"]), (1, 0, 1))

    def test_detection_level_counts_fail_closed_as_missed(self):
        defaults = dict(self.defaults, **{"c::v2": rec("c::v2", "BLOCK", failed_closed=True)})
        result = ae.analyse_from(self.items, {"defaults": defaults, "flags": self.flags}, self.manifest)
        self.assertEqual(result["arms"]["defaults"]["action_level"]["overall"]["evaded"], 2)
        self.assertEqual(result["arms"]["defaults"]["detection_level"]["overall"]["evaded"], 3)
        self.assertEqual(result["fail_closed"]["defaults"]["scored_pairs_failed_closed"], 1)

    def test_unscored_protected_pair_is_an_error(self):
        defaults = dict(self.defaults)
        del defaults["a::v1"]
        with self.assertRaises(ValueError):
            ae.analyse_from(self.items, {"defaults": defaults, "flags": self.flags}, self.manifest)

    def test_not_applicable_pairs_are_excluded(self):
        for item in self.items:
            if item["vid"] == "a::v1":
                item["applicable"] = False
        defaults = dict(self.defaults)
        del defaults["a::v1"]
        flags = dict(self.flags)
        del flags["a::v1"]
        overall = ae.analyse_from(self.items, {"defaults": defaults, "flags": flags}, self.manifest)["arms"]["defaults"]["action_level"]["overall"]
        self.assertEqual((overall["applicable"], overall["protected_pairs"], overall["evaded"]), (7, 5, 1))


class FreezeTests(unittest.TestCase):
    def rows(self):
        out = []
        for i in range(12):
            text = f"Contact Bob Jones at bob{i}@example.org or call 555010{i:02d}."
            start = text.index("bob")
            out.append({"id": f"r{i}", "group_id": f"g{i // 2}", "text": text, "source_dataset": "s" + str(i % 2),
                        "expected_has_pii": True,
                        "entities": [{"start": start, "end": text.index(" or"), "label": "EMAIL"}]})
        return out

    def test_stratified_sample_is_seeded_and_balanced(self):
        a = ae.stratified_sample(self.rows(), 3)
        b = ae.stratified_sample(list(reversed(self.rows())), 3)
        self.assertEqual([r["id"] for r in a], [r["id"] for r in b])
        self.assertEqual({r["source_dataset"]: sum(x["source_dataset"] == r["source_dataset"] for x in a) for r in a}, {"s0": 3, "s1": 3})
        self.assertEqual(len(ae.stratified_sample(self.rows(), None)), 12)

    def test_build_is_byte_identical_and_hash_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            seed = Path(tmp) / "seed.jsonl"
            seed.write_text("\n".join(json.dumps(r) for r in self.rows()) + "\n", encoding="utf-8")
            hashes = []
            for name in ("one", "two"):
                out = Path(tmp) / name
                self.assertEqual(ae.main(["build", "--seed-file", str(seed), "--out", str(out)]), 0)
                manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
                self.assertEqual(manifest["frozen_set_sha256"], ae.file_sha256(out / "frozen_set.jsonl"))
                hashes.append(manifest["frozen_set_sha256"])
            self.assertEqual(hashes[0], hashes[1])
            items = ae.read_jsonl(Path(tmp) / "one" / "frozen_set.jsonl")
            self.assertEqual(len([i for i in items if i["variant"] == "baseline"]), 12)
            self.assertEqual(len(items), 12 * (1 + len(tx.VARIANTS)))

    def test_scoring_refuses_a_set_whose_hash_differs(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "frozen_set.jsonl").write_text("{}\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                ae.main(["score", "--set", str(out), "--expected-sha256", "0" * 64, "--arm", "defaults",
                         "--release-dir", str(out), "--generated", str(out)])

    def test_build_rejects_non_sensitive_seed_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            seed = Path(tmp) / "seed.jsonl"
            row = dict(self.rows()[0], expected_has_pii=False)
            seed.write_text(json.dumps(row) + "\n", encoding="utf-8")
            with self.assertRaises(AssertionError):
                ae.main(["build", "--seed-file", str(seed), "--out", str(Path(tmp) / "o")])

    def test_benign_control_uses_clean_rows_and_entity_free_variants(self):
        with tempfile.TemporaryDirectory() as tmp:
            seed = Path(tmp) / "seed.jsonl"
            rows = [dict(r, expected_has_pii=False, entities=[]) for r in self.rows()]
            seed.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
            out = Path(tmp) / "c"
            ae.main(["build", "--seed-file", str(seed), "--out", str(out), "--benign"])
            manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
            self.assertTrue(manifest["benign_control"])
            self.assertEqual(set(manifest["variants"]), set(ae.BENIGN_VARIANTS))

    def test_shards_partition_rows(self):
        counts = [0] * 4
        for i in range(400):
            counts[ae.shard_of(f"row{i}", 4)] += 1
        self.assertEqual(sum(counts), 400)
        self.assertTrue(all(c > 50 for c in counts))


if __name__ == "__main__":
    unittest.main()
