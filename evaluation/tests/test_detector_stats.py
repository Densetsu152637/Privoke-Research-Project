"""Hand-computed checks for the paired detector statistics (no model, spaCy or service)."""
from pathlib import Path
import sys
import unittest

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import detector_stats as ds


def record(example_id, label, group=None, **layers):
    base = {"positive": False, "action": "ALLOW", "max_sensitivity": "S0", "categories": []}
    out = {"example_id": example_id, "group_id": group, "expected_has_pii": label}
    for layer in ds.LAYERS:
        out[layer] = {**base, **layers.get(layer, {})}
    return out


class MetricTests(unittest.TestCase):
    def test_confusion_and_point_metrics(self):
        labels = [1, 1, 1, 1, 0, 0, 0, 0]
        preds = [1, 1, 0, 0, 1, 0, 0, 0]
        counts = ds.confusion(labels, preds)
        self.assertEqual(counts, {"tp": 2, "tn": 3, "fp": 1, "fn": 2})
        m = ds.point_metrics(counts)
        self.assertAlmostEqual(m["recall"], 0.5)
        self.assertAlmostEqual(m["specificity"], 0.75)
        self.assertAlmostEqual(m["precision"], 2 / 3)
        self.assertAlmostEqual(m["f2"], 10 / 19)  # 5*2 / (5*2 + 4*2 + 1)
        self.assertAlmostEqual(m["cost_2"], (2 * 2 + 1) / 8)
        self.assertAlmostEqual(m["cost_4"], (4 * 2 + 1) / 8)
        self.assertAlmostEqual(m["cost_9"], (9 * 2 + 1) / 8)

    def test_undefined_metrics_are_none(self):
        m = ds.point_metrics({"tp": 0, "tn": 4, "fp": 0, "fn": 0})
        self.assertIsNone(m["recall"])
        self.assertIsNone(m["precision"])
        self.assertIsNone(m["f2"])
        self.assertEqual(m["specificity"], 1.0)


class McNemarTests(unittest.TestCase):
    def test_exact_values(self):
        # b=0,c=5: P(X<=0)=1/32 -> p=2/32; mid-p = 2/32 - 1/32
        r = ds.mcnemar_exact(0, 5)
        self.assertAlmostEqual(r["p_two_sided"], 0.0625)
        self.assertAlmostEqual(r["p_mid"], 0.03125)
        # b=1,c=9: n=10, P(X<=1)=11/1024 -> p=22/1024
        self.assertAlmostEqual(ds.mcnemar_exact(1, 9)["p_two_sided"], 22 / 1024)
        self.assertAlmostEqual(ds.mcnemar_exact(9, 1)["p_two_sided"], 22 / 1024)
        # balanced and empty discordance give p=1
        self.assertEqual(ds.mcnemar_exact(3, 3)["p_two_sided"], 1.0)
        self.assertEqual(ds.mcnemar_exact(0, 0)["p_two_sided"], 1.0)
        # b=2,c=3: n=5, P(X<=2)=16/32 -> p=1.0
        self.assertEqual(ds.mcnemar_exact(2, 3)["p_two_sided"], 1.0)

    def test_flips_hand_case(self):
        labels = [1, 1, 1, 0, 0, 0]
        base = [0, 1, 1, 1, 0, 0]
        cand = [1, 1, 0, 0, 0, 1]
        f = ds.paired_flips(labels, base, cand)
        self.assertEqual((f["fn_to_tp"], f["tp_to_fn"], f["fp_to_tn"], f["tn_to_fp"]), (1, 1, 1, 1))
        self.assertEqual(f["pos_unchanged_correct"], 1)
        self.assertEqual(f["neg_unchanged_correct"], 1)
        self.assertEqual(f["mcnemar_positives"]["p_two_sided"], 1.0)
        # net gain of 3 on positives: only gains
        f2 = ds.paired_flips([1] * 5, [0] * 5, [1] * 5)
        self.assertEqual(f2["fn_to_tp"], 5)
        self.assertAlmostEqual(f2["mcnemar_positives"]["p_two_sided"], 0.0625)
        self.assertEqual(f2["mcnemar_negatives"]["n_discordant"], 0)

    def test_cluster_sign_test(self):
        labels = [1, 1, 1, 1, 0, 0]
        base = [0, 0, 0, 0, 0, 0]
        cand = [1, 1, 1, 1, 0, 1]
        groups = ["a", "a", "b", "b", "c", "c"]
        t = ds.cluster_sign_test(labels, base, cand, groups)
        # a: +2, b: +2, c: -1 (tn->fp)
        self.assertEqual((t["clusters_candidate_better"], t["clusters_baseline_better"]), (2, 1))
        self.assertEqual(t["p_two_sided"], 1.0)
        t = ds.cluster_sign_test(labels, base, cand, groups, on="positives")
        self.assertEqual((t["clusters_candidate_better"], t["clusters_baseline_better"]), (2, 0))
        self.assertAlmostEqual(t["p_two_sided"], 0.5)  # n=2: 2*P(X<=0)=2*1/4


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        rng = np.random.default_rng(7)
        self.n = 120
        self.labels = [bool(x) for x in rng.integers(0, 2, self.n)]
        self.groups = [f"g{i // 3}" for i in range(self.n)]
        self.a = [bool(l) if rng.random() < 0.7 else not l for l in self.labels]
        self.b = [bool(l) if rng.random() < 0.8 else not l for l in self.labels]

    def test_deterministic_given_seed(self):
        r1 = ds.paired_bootstrap(self.labels, self.groups, {"old": self.a, "new": self.b}, n_boot=300, seed=1)
        r2 = ds.paired_bootstrap(self.labels, self.groups, {"old": self.a, "new": self.b}, n_boot=300, seed=1)
        r3 = ds.paired_bootstrap(self.labels, self.groups, {"old": self.a, "new": self.b}, n_boot=300, seed=2)
        self.assertEqual(r1, r2)
        self.assertNotEqual(r1["metrics"]["old"]["recall"], r3["metrics"]["old"]["recall"])

    def test_matches_naive_cluster_resampling(self):
        n_boot, seed = 40, 3
        res = ds.paired_bootstrap(self.labels, self.groups, {"old": self.a}, n_boot=n_boot, seed=seed)
        cluster_of, k = ds._cluster_table(self.groups)
        rng = np.random.default_rng(seed)
        draws = rng.integers(0, k, size=(n_boot, k))
        y = np.array(self.labels)
        p = np.array(self.a)
        recalls = []
        for row in draws:
            idx = np.concatenate([np.where(cluster_of == c)[0] for c in row])
            tp = int((y[idx] & p[idx]).sum())
            fn = int((y[idx] & ~p[idx]).sum())
            recalls.append(tp / (tp + fn))
        lo, hi = np.quantile(recalls, [0.025, 0.975])
        self.assertAlmostEqual(res["metrics"]["old"]["recall"]["lo"], lo)
        self.assertAlmostEqual(res["metrics"]["old"]["recall"]["hi"], hi)

    def test_point_estimates_and_counts(self):
        r = ds.paired_bootstrap(self.labels, self.groups, {"old": self.a, "new": self.b}, n_boot=50, seed=1)
        self.assertEqual(r["counts"]["old"], ds.confusion(self.labels, self.a))
        self.assertEqual(r["n_clusters"], 40)
        self.assertAlmostEqual(r["deltas"]["new"]["recall"]["estimate"],
                               r["metrics"]["new"]["recall"]["estimate"] - r["metrics"]["old"]["recall"]["estimate"])

    def test_identical_decisions_have_zero_delta_interval(self):
        r = ds.paired_bootstrap(self.labels, self.groups, {"old": self.a, "new": list(self.a)}, n_boot=200, seed=1)
        for metric, d in r["deltas"]["new"].items():
            self.assertEqual((d["lo"], d["hi"], d["estimate"]), (0.0, 0.0, 0.0), metric)
            self.assertFalse(d["excludes_zero"])

    def test_single_cluster_collapses_to_point_estimate(self):
        r = ds.paired_bootstrap(self.labels, ["only"] * self.n, {"old": self.a}, n_boot=100, seed=1)
        m = r["metrics"]["old"]["recall"]
        self.assertEqual(m["lo"], m["hi"])
        self.assertAlmostEqual(m["lo"], m["estimate"])

    def test_clear_improvement_excludes_zero_and_undefined_counted(self):
        labels = [True] * 100 + [False] * 100
        groups = [f"r{i}" for i in range(200)]
        r = ds.paired_bootstrap(labels, groups, {"old": [False] * 200, "new": labels}, n_boot=200, seed=1)
        self.assertTrue(r["deltas"]["new"]["recall"]["excludes_zero"])
        self.assertGreater(r["deltas"]["new"]["recall"]["lo"], 0.9)
        # the all-negative baseline never predicts a positive: precision undefined in every replicate
        self.assertIsNone(r["metrics"]["old"]["precision"]["estimate"])
        self.assertEqual(r["metrics"]["old"]["precision"]["n_undefined"], 200)
        self.assertIsNone(r["metrics"]["old"]["precision"]["lo"])

    def test_cluster_resampling_is_wider_than_row_resampling_for_pure_clusters(self):
        labels = [bool((i // 10) % 2) for i in range(100)]  # ten label-pure clusters of ten rows
        pred = [True] * 100  # precision == share of positive rows in the resample
        rows = ds.paired_bootstrap(labels, [f"r{i}" for i in range(100)], {"x": pred}, n_boot=500, seed=1)
        clustered = ds.paired_bootstrap(labels, [f"c{i // 10}" for i in range(100)], {"x": pred}, n_boot=500, seed=1)
        width = lambda r: r["metrics"]["x"]["precision"]["hi"] - r["metrics"]["x"]["precision"]["lo"]
        self.assertGreater(width(clustered), 2 * width(rows))
        self.assertEqual(clustered["n_clusters"], 10)


class RecordHelperTests(unittest.TestCase):
    def test_rules_and_alignment(self):
        warn = record("a", True, "g", union={"positive": True, "action": "WARN"})
        block = record("b", True, "g", union={"positive": True, "action": "BLOCK"})
        allow = record("c", False, None, union={"positive": True, "action": "ALLOW"})  # S1 only
        self.assertEqual(ds.predictions([warn, block, allow], "union", "positive"), [True, True, True])
        self.assertEqual(ds.predictions([warn, block, allow], "union", "warn_or_block"), [True, True, False])
        self.assertEqual(ds.predictions([warn, block, allow], "union", "block"), [False, True, False])
        with self.assertRaises(ValueError):
            ds.row_prediction(warn, "semantic")
        self.assertEqual(ds.cluster_groups([warn, allow]), ["g", "row:c"])
        with self.assertRaises(ValueError):
            ds.align_rows([warn], [block])
        flipped = {**warn, "expected_has_pii": False}
        with self.assertRaises(ValueError):
            ds.align_rows([warn], [flipped])
        self.assertEqual(len(ds.align_rows([warn, block], [block, warn])), 2)

    def test_compare_runs_end_to_end(self):
        old = [record(f"p{i}", True, f"g{i // 2}") for i in range(6)] + \
              [record(f"n{i}", False, f"h{i}", union={"positive": True}) for i in range(4)]
        new = [record(f"p{i}", True, f"g{i // 2}", union={"positive": i < 4}) for i in range(6)] + \
              [record(f"n{i}", False, f"h{i}") for i in range(4)]
        res = ds.compare_runs(old, new, layer="union", rule="positive", n_boot=100, seed=1)
        self.assertEqual(res["counts"]["old"], {"tp": 0, "tn": 0, "fp": 4, "fn": 6})
        self.assertEqual(res["counts"]["new"], {"tp": 4, "tn": 4, "fp": 0, "fn": 2})
        self.assertEqual(res["flips"]["fn_to_tp"], 4)
        self.assertEqual(res["flips"]["fp_to_tn"], 4)
        self.assertEqual(res["n_clusters"], 7)
        sub = ds.compare_runs(old, new, layer="union", rule="positive", n_boot=10, seed=1,
                              subset=lambda r: r["expected_has_pii"], grouping="row")
        self.assertEqual(sub["n_rows"], 6)


if __name__ == "__main__":
    unittest.main()
