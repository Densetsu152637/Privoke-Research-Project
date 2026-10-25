"""Synthetic checks for the v3 driver extension and analysis (no model, spaCy or fresh data)."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import v3_analysis as va
import v3_scoring as v3
import w3_scoring as w3


def row(example_id, label, group, stratum, flag=False, action="ALLOW"):
    base = {"positive": flag, "action": action, "max_sensitivity": "S0", "categories": []}
    return {"example_id": example_id, "group_id": group, "expected_has_pii": label, "stratum": stratum,
            "regex": dict(base), "ner": dict(base), "union": dict(base)}


class DriverTests(unittest.TestCase):
    def test_registration_adds_f4_and_configs_without_touching_wave3_entries(self):
        before = {k: dict(v) for k, v in w3.CONFIGS.items() if k in ("O", "N")}
        saved_configs, saved_sets = dict(w3.CONFIGS), dict(w3.REGISTERED_SETS)

        def restore():  # the module tables are shared with the Wave 3 tests
            w3.CONFIGS.clear(); w3.CONFIGS.update(saved_configs)
            w3.REGISTERED_SETS.clear(); w3.REGISTERED_SETS.update(saved_sets)
        self.addCleanup(restore)
        v3.register()
        self.assertIn("f4", w3.REGISTERED_SETS)
        self.assertEqual(w3.REGISTERED_SETS["f4"][1], v3.F4_SHA256)
        for name in ("K", "K+all", "KA0"):
            self.assertIn(name, w3.CONFIGS)
        self.assertEqual({k: dict(w3.CONFIGS[k]) for k in ("O", "N")}, before)
        self.assertEqual(w3.CONFIGS["K"]["expect"], w3._N_EXPECT)  # K carries N's flag record
        self.assertEqual(w3.CONFIGS["KA0"]["tree"], "KA")
        self.assertEqual(set(w3.CONFIGS["K+all"]["env"]), {"PRIVOKE_STRIP_FORMAT_CHARS", "PRIVOKE_CANONICALISE_DIGITS",
                                                          "PRIVOKE_CANONICALISE_EMAIL_WORDS", "PRIVOKE_NER_CASELESS_GATE"})


class AnalysisTests(unittest.TestCase):
    def test_ni_verdict_three_outcomes(self):
        self.assertEqual(va.ni_verdict(-0.005, 0.01, -0.01), "pass")
        self.assertEqual(va.ni_verdict(-0.015, 0.002, -0.01), "inconclusive")
        self.assertEqual(va.ni_verdict(-0.03, -0.012, -0.01), "fail")
        self.assertEqual(va.ni_verdict(-0.03, -0.01, -0.01), "fail")  # upper limit at the margin is a failure
        self.assertEqual(va.ni_verdict(-0.01, 0.0, -0.01), "inconclusive")  # lower limit at the margin is not a pass

    def test_source_of(self):
        self.assertEqual(va.source_of("nvidia/Nemotron-PII"), "Nemotron-PII")
        self.assertEqual(va.source_of("piimb/privy"), "Privy")
        self.assertEqual(va.source_of("gretelai/gretel-pii-masking-en-v1"), "Gretel")
        self.assertEqual(va.source_of("ai4privacy/pii-masking-openpii-1m"), "ai4privacy")
        self.assertIsNone(va.source_of("other"))

    def test_standardised_delta_hand_computed(self):
        # four sources, 10 single-row clusters each; candidate gains `g` rows over the reference in every source
        ref, cand = [], []
        names = ["ai4privacy/x", "gretelai/x", "nvidia/Nemotron-PII", "piimb/privy"]
        for si, name in enumerate(names):
            for i in range(10):
                ref.append(row(f"{si}-{i}", True, f"{si}-{i}", name, flag=i < 5))
                cand.append(row(f"{si}-{i}", True, f"{si}-{i}", name, flag=i < 5 + si))  # gains 0, 1, 2, 3 rows
        res = va.standardised_delta(ref, cand, {"equal": va.W_EQUAL}, n_boot=500, seed=1)
        self.assertAlmostEqual(res["per_source_delta"]["Privy"], 0.3)
        self.assertAlmostEqual(res["weights"]["equal"]["estimate"], 0.25 * (0.0 + 0.1 + 0.2 + 0.3))
        lo, hi = res["weights"]["equal"]["lo"], res["weights"]["equal"]["hi"]
        self.assertLessEqual(lo, res["weights"]["equal"]["estimate"])
        self.assertGreaterEqual(hi, res["weights"]["equal"]["estimate"])

    def test_completeness_rejects_mismatched_ids_and_enforces_counts(self):
        a = [row("a", True, "g1", "s"), row("b", True, "g2", "s")]
        b = [row("a", True, "g1", "s"), row("c", True, "g2", "s")]
        per_cfg = {c: a for c in va.CONFIGS}
        va.completeness({"f4": per_cfg}, expect=False)
        per_cfg["K"] = b
        with self.assertRaises(ValueError):
            va.completeness({"f4": per_cfg}, expect=False)
        per_cfg["K"] = a
        sets = {s: per_cfg for s in ("f1", "f2", "f3", "f4")}
        with self.assertRaises(ValueError):
            va.completeness(sets, expect=True)  # 2 rows are not the registered counts

    def test_extra_pool_ids_excludes_existing_pool(self):
        key = {"key": {"o1": "f1", "o2": "f2", "o3": "f3"}}
        rows = [row("f1", None, "g", "s", flag=True), row("f2", None, "g", "s", flag=True), row("f3", None, "g", "s", flag=False)]
        for r in rows:
            r["union"]["positive"] = r["union"]["positive"]
        self.assertEqual(va.extra_pool_ids(rows, key, {"o1"}), ["o2"])
        with self.assertRaises(ValueError):
            va.extra_pool_ids(rows[:2], key, set())

    def test_promotion_rule(self):
        def H(h7, h8, g1, g2):
            return {"H7": {"verdict": h7}, "H8": {"verdict": h8}, "G1": {"verdict": g1}, "G2": {"verdict": g2}}
        self.assertIn("criterion 1 or 2", va.promotion(H("inconclusive", "pass", "pass", "pass"))["K"]["verdict"])
        self.assertIn("criterion 1 or 2", va.promotion(H("pass", "fail", "pass", "pass"))["K"]["verdict"])
        self.assertIn("guard", va.promotion(H("pass", "pass", "pass", "inconclusive"))["K"]["verdict"])
        v = va.promotion(H("pass", "pass", "pass", "pass"))["K"]["verdict"]
        self.assertIn("criterion 4", v)

    def test_layer_swap_hybrid_uses_regex_of_first_and_ner_of_second(self):
        r1 = row("a", True, "g", "s")
        r1["regex"]["positive"] = True
        r2 = row("a", True, "g", "s")
        r2["ner"]["positive"] = True
        r3 = row("b", True, "g", "s")
        r4 = row("b", True, "g", "s")
        r4["ner"]["positive"] = True
        out = va.hybrid([r1, r3, r3], [row("a", True, "g", "s"), r4, row("b", True, "g", "s")])
        self.assertTrue(out[0]["union"]["positive"])   # regex of the first list
        self.assertTrue(out[1]["union"]["positive"])   # NER of the second list
        self.assertFalse(out[2]["union"]["positive"])  # neither
        self.assertFalse(va.hybrid([r3], [dict(r3)])[0]["union"]["positive"])


if __name__ == "__main__":
    unittest.main()
