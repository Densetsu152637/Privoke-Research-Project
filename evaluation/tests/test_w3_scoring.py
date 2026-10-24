"""Synthetic checks for the Wave 3 driver and analysis (no model, spaCy or fresh data)."""
from pathlib import Path
import json
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import w3_analysis as wa
import w3_scoring as w3


def row(example_id, label, group, flags=(False, False), stratum=None):
    base = {"positive": False, "action": "ALLOW", "max_sensitivity": "S0", "categories": []}
    regex, ner = ({**base, "positive": f} for f in flags)
    union = {**base, "positive": flags[0] or flags[1]}
    return {"example_id": example_id, "group_id": group, "expected_has_pii": label, "stratum": stratum,
            "regex": regex, "ner": ner, "union": union}


class StatsTests(unittest.TestCase):
    def test_holm_is_monotone_and_capped(self):
        adj = wa.holm({"a": 0.01, "b": 0.04, "c": 0.03})
        self.assertAlmostEqual(adj["a"], 0.03)
        self.assertAlmostEqual(adj["c"], 0.06)
        self.assertAlmostEqual(adj["b"], 0.06)  # monotone: not below the previous adjusted value
        self.assertLessEqual(max(wa.holm({"x": 0.9, "y": 0.8}).values()), 1.0)

    def test_paired_wald_hand_computed(self):
        labels = [True] * 10
        base = [True] * 8 + [False] * 2
        cand = [True] * 7 + [False] * 3  # one loss, none gained -> delta -0.1 on 10 rows
        res = wa.paired_wald(labels, base, cand, [str(i) for i in range(10)], "pos")
        self.assertAlmostEqual(res["delta"], -0.1)
        # d = nine zeros and one -1: var = (0.1 - 0.01) * 10/9 = 0.1; se = sqrt(0.1/10) = 0.1
        self.assertAlmostEqual(res["se_row"], 0.1)
        self.assertAlmostEqual(res["lower_row_one_sided_975"], -0.1 - 1.959964 * 0.1)
        self.assertEqual(wa.paired_wald(labels, base, cand, ["g"] * 10, "neg")["delta"], None)

    def test_ni_directions(self):
        self.assertTrue(wa.ni_from_bootstrap({"estimate": 0.0, "lo": -0.005, "hi": 0.005})["passes"])
        self.assertFalse(wa.ni_from_bootstrap({"estimate": -0.01, "lo": -0.012, "hi": 0.0})["passes"])
        self.assertTrue(wa.ni_from_bootstrap({"estimate": 1.0, "lo": 0.0, "hi": 9.9}, 10.0, "upper")["passes"])
        self.assertFalse(wa.ni_from_bootstrap({"estimate": 5.0, "lo": 0.0, "hi": 10.1}, 10.0, "upper")["passes"])

    def test_pair_cell_identical_runs_have_zero_delta_and_pass_ni(self):
        rows = [row(f"r{i}", i % 2 == 0, f"g{i // 2}", (i % 4 == 0, False)) for i in range(40)]
        cell = wa.pair_cell(rows, rows, "union", "positive", 200, 1)
        self.assertEqual(cell["deltas"]["cand"]["recall"]["estimate"], 0.0)
        self.assertTrue(wa.ni_from_bootstrap(cell["deltas"]["cand"]["recall"])["passes"])
        self.assertEqual(cell["flips"]["fn_to_tp"] + cell["flips"]["tp_to_fn"], 0)

    def test_superiority_requires_ci_and_p(self):
        base = [row(f"n{i}", False, f"g{i}", (True, False)) for i in range(60)]
        cand = [row(f"n{i}", False, f"g{i}", (False, False)) for i in range(60)]
        cell = wa.pair_cell(base, cand, "regex", "positive", 400, 1)
        sup = wa.superiority(cell, "specificity", "mcnemar_negatives")
        self.assertTrue(sup["passes"])
        self.assertEqual(sup["flips"]["fp_to_tn"], 60)


class PerturbedTests(unittest.TestCase):
    def items(self, flags, transform="zero_width"):
        return [{"example_id": f"r{i}", "group_id": f"g{i}", "transform": transform, "regex": f, "ner": False, "union": f}
                for i, f in enumerate(flags)]

    def test_h5_cell_detects_improvement_and_rejects_mismatched_items(self):
        base = self.items([False] * 30)
        cand = self.items([True] * 30)
        cell = wa.h5_cell(base, cand, "union", 200, 1)
        self.assertEqual(cell["flips"]["fn_to_tp"], 30)
        self.assertGreater(cell["deltas"]["cand"]["recall"]["lo"], 0)
        with self.assertRaises(ValueError):
            wa.h5_cell(base, self.items([True] * 29), "union", 50, 1)

    def test_perturbed_analysis_holm_family(self):
        def make(flag_for):
            out = []
            for transform in wa.ALL_TRANSFORMS:
                for i in range(25):
                    out.append({"example_id": f"r{i}", "group_id": f"g{i}", "transform": transform, "regex": False,
                                "ner": False, "union": flag_for(transform)})
            return out
        base = make(lambda t: False)
        items = {"N": base}
        for cand in wa.R_CONFIGS:
            items[cand] = make(lambda t, c=cand: c == "N+strip" and t == "zero_width")
        res = wa.perturbed_analysis(items, 200, 1)
        self.assertTrue(res["hypotheses"]["H5a"]["passes"])
        self.assertFalse(res["hypotheses"]["H5b"]["passes"])
        self.assertTrue(all(0 <= h["p_holm"] <= 1 for h in res["hypotheses"].values()))


class DriverTests(unittest.TestCase):
    def test_frozen_configuration_table(self):
        self.assertEqual(set(w3.SCORED_CONFIGS), {c for c in w3.CONFIGS if c != "C0"})
        self.assertEqual(w3.SCORED_CONFIGS, wa.SCORED_CONFIGS)
        self.assertEqual(w3.CONFIGS["N+all"]["env"].keys(), {"PRIVOKE_STRIP_FORMAT_CHARS", "PRIVOKE_CANONICALISE_DIGITS",
                                                            "PRIVOKE_CANONICALISE_EMAIL_WORDS", "PRIVOKE_NER_CASELESS_GATE"})
        self.assertEqual(w3.H5_TRANSFORMS, wa.ALL_TRANSFORMS)
        self.assertEqual(w3.CONFIGS["N+trf"]["expect"]["ner_model"], "en_core_web_trf")

    def test_overrides_need_test_mode(self):
        with self.assertRaises(SystemExit):
            w3.resolve_set("f1", Path("."), False, {"f1": Path("x.jsonl")})

    def test_pool_builder_is_blinded_and_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            n = 1000
            ids = [f"f2-{i}" for i in range(n)]
            opaque = {f"a{i + 1:05d}": ids[i] for i in range(n)}
            audit_order = [f"a{i:05d}" for i in range(n, 0, -1)]
            (tmp / "packets").mkdir()
            for start in range(0, n, 100):
                w3.dump_jsonl(tmp / "packets" / f"packet-{start // 100 + 1:03d}.jsonl",
                              [{"item": f"a{i + 1:05d}", "text": f"text {i}"} for i in range(start, start + 100)])
            flagged_o = set(ids[:50])
            flagged_n = set(ids[40:70])
            rows = {"O": [row(i, None, i, (i in flagged_o, False)) for i in ids],
                    "N": [row(i, None, i, (i in flagged_n, False)) for i in ids]}
            manifest = w3.build_pool(rows, {"seed": 1, "key": opaque, "audit_order": audit_order}, tmp / "packets", tmp / "pool")
            self.assertEqual(manifest["flagged_union"], 70)
            self.assertEqual(manifest["audit_items"], 400)
            self.assertEqual(manifest["pool_size"], 470)
            membership = json.loads((tmp / "pool/coordinator/pool_membership.json").read_text())
            self.assertEqual(len(membership["audit"]), 400)
            # the audit items are the first 400 of the audit order that are not flagged
            flagged_items = set(membership["flagged_by"])
            expected = [a for a in audit_order if a not in flagged_items][:400]
            self.assertEqual(membership["audit"], expected)
            pooled = []
            for packet in sorted((tmp / "pool/packets").glob("pool-packet-*.jsonl")):
                for rec in w3.load_jsonl(packet):
                    self.assertEqual(set(rec), {"item", "text"})
                    pooled.append(rec["item"])
            self.assertEqual(pooled, sorted(pooled))
            self.assertEqual(len(pooled), 470)
            self.assertEqual(len(manifest["packets"]), 5)

    def test_equiv_detects_difference(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            a = [row("1", True, "g", (True, False)), row("2", False, "h")]
            b = [row("1", True, "g", (True, False)), row("2", False, "h", (True, False))]
            w3.dump_jsonl(tmp / "a" / "dev.rows.jsonl", a)
            w3.dump_jsonl(tmp / "b" / "dev.rows.jsonl", b)
            w3.dump_jsonl(tmp / "c" / "dev.rows.jsonl", a)
            out = tmp / "out.json"
            w3.command_equiv(type("A", (), {"a": tmp / "a", "b": tmp / "c", "sets": ["dev"], "out": out})())
            self.assertTrue(json.loads(out.read_text())["identical"])
            w3.command_equiv(type("A", (), {"a": tmp / "a", "b": tmp / "b", "sets": ["dev"], "out": out})())
            self.assertFalse(json.loads(out.read_text())["identical"])


if __name__ == "__main__":
    unittest.main()
