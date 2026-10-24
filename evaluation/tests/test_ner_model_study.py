"""Pure-logic tests for evaluation/ner_model_study.py (synthetic records, no models, no datasets)."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ner_model_study as study  # noqa: E402


def cell(tp, tn, fp, fn):
    return study.confusion([True] * (tp + fn) + [False] * (tn + fp),
                           [True] * tp + [False] * fn + [False] * tn + [True] * fp)


class LabelTests(unittest.TestCase):
    def test_labels_round_trip(self):
        for label in study.all_design_labels():
            self.assertEqual(study.config_label(study.parse_label(label)), label)

    def test_design_grid_covers_models_presets_thresholds_and_postfilter(self):
        labels = study.all_design_labels()
        self.assertEqual(len(labels), 6 + 2 * 5 * 2)
        self.assertIn(study.BASELINE, labels)


class SelectionTests(unittest.TestCase):
    def design(self, **cells):
        return {label: {"tune": c[0], "personalized": c[1]} for label, c in cells.items()}

    def test_highest_mean_balanced_accuracy_wins_and_spacy_is_ignored(self):
        design = {
            "sm-pf1": {"tune": cell(99, 99, 0, 0), "personalized": cell(99, 99, 0, 0)},
            "gliner-core-t0.3-pf1": {"tune": cell(6, 5, 5, 4), "personalized": cell(10, 10, 0, 0)},
            "gliner-core-t0.5-pf1": {"tune": cell(7, 8, 2, 3), "personalized": cell(10, 10, 0, 0)},
        }
        result = study.select_gliner(design)
        self.assertEqual(result["chosen"], "gliner-core-t0.5-pf1")
        self.assertEqual(result["post_review_labels"], ["gliner-core-t0.5-pf1", "gliner-core-t0.5-pf0"])
        self.assertEqual([r["label"] for r in result["ranking"]],
                         ["gliner-core-t0.5-pf1", "gliner-core-t0.3-pf1"])

    def test_ties_go_to_fewer_false_positives_then_label(self):
        design = {
            "gliner-pii-t0.3-pf1": {"tune": cell(5, 5, 5, 5), "personalized": cell(5, 5, 5, 5)},
            "gliner-core-t0.3-pf1": {"tune": cell(5, 5, 5, 5), "personalized": cell(5, 5, 5, 5)},
            "gliner-core-t0.4-pf1": {"tune": cell(5, 5, 5, 5), "personalized": cell(5, 5, 5, 5)},
        }
        self.assertEqual(study.select_gliner(design)["chosen"], "gliner-core-t0.3-pf1")

    def test_no_gliner_result_is_an_error(self):
        with self.assertRaises(ValueError):
            study.select_gliner({"sm-pf1": {"tune": cell(1, 1, 0, 0), "personalized": cell(1, 1, 0, 0)}})


class SplitTests(unittest.TestCase):
    def test_dev_half_matches_the_group_parity_definition(self):
        import hashlib
        for group in ("alpha", "beta", "gamma", "delta"):
            parity = int(hashlib.sha256(group.encode()).hexdigest(), 16) % 2
            self.assertEqual(study.dev_half(group), "check" if parity else "tune")

    def test_design_phase_cannot_load_post_review_splits(self):
        for split in study.POST_REVIEW_SPLITS:
            with self.assertRaises(SystemExit):
                study.load_split_rows(split, Path("."), "design")
        for split in study.DESIGN_SPLITS:
            with self.assertRaises(SystemExit):
                study.load_split_rows(split, Path("."), "post-review")


class CachingGlinerTests(unittest.TestCase):
    class Inner:
        def __init__(self):
            self.calls = []

        def predict_entities(self, text, labels, threshold=0.5, **kwargs):
            self.calls.append(threshold)
            return [{"text": "a", "start": 0, "end": 1, "label": "name", "score": 0.9},
                    {"text": "b", "start": 2, "end": 3, "label": "name", "score": 0.4}]

    def test_one_inner_call_serves_every_higher_threshold(self):
        inner = self.Inner()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cache.jsonl"
            cache = study.CachingGliner(inner, path)
            self.assertEqual(len(cache.predict_entities("t", ["name"], threshold=0.3)), 2)
            self.assertEqual(len(cache.predict_entities("t", ["name"], threshold=0.5)), 1)
            self.assertEqual(inner.calls, [study.GLINER_FLOOR])
            reloaded = study.CachingGliner(self.Inner(), path)
            self.assertEqual(len(reloaded.predict_entities("t", ["name"], threshold=0.7)), 1)
            self.assertEqual(reloaded.inner.calls, [])

    def test_label_set_is_part_of_the_key_and_floor_is_enforced(self):
        inner = self.Inner()
        cache = study.CachingGliner(inner, None)
        cache.predict_entities("t", ["name"], threshold=0.3)
        cache.predict_entities("t", ["name", "organization"], threshold=0.3)
        self.assertEqual(len(inner.calls), 2)
        with self.assertRaises(ValueError):
            cache.predict_entities("t", ["name"], threshold=0.2)


class ReportTests(unittest.TestCase):
    def test_render_report_and_collect_use_only_aggregates(self):
        import json
        union = {"positive": cell(3, 4, 1, 2), "block": cell(1, 5, 0, 4)}
        layer = {"positive": cell(1, 4, 1, 4), "block": cell(0, 5, 0, 5)}
        report = {"label": "sm-pf1", "config": {}, "tree_commit_sha": "x", "freeze_commit": None, "dataset_sha256": {},
                  "splits": {"tune": {"ner": layer, "union": union, "regex": layer, "mean_ms_per_prompt_indicative": 1.0}}}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "sm-pf1-design.json").write_text(json.dumps(report), encoding="utf-8")
            text = study.render_report(out, ("tune",))
            self.assertIn("| sm-pf1 | 1 | 1 |", text)
            self.assertIn("**tune**", text)
            self.assertEqual(study.render_report(out, ("check",)).count("| sm-pf1"), 0)

    def test_compact_comparison_keeps_decision_fields(self):
        metric = {"estimate": 0.1, "lo": 0.0, "hi": 0.2}
        cmp = {"deltas": {"new": {m: metric for m in ("recall", "specificity", "f2", "cost_4")}},
               "flips": {"fn_to_tp": 1, "tp_to_fn": 2, "fp_to_tn": 3, "tn_to_fp": 4,
                         "mcnemar_positives": {"p_two_sided": 0.5}, "mcnemar_negatives": {"p_two_sided": 0.25}},
               "cluster_sign_test": {"positives": {"p_two_sided": 1.0}, "negatives": {"p_two_sided": 0.75}},
               "counts": {}, "n_rows": 10, "n_clusters": 9}
        compact = study.compact_comparison(cmp)
        self.assertEqual(compact["flips"], {"fn_to_tp": 1, "tp_to_fn": 2, "fp_to_tn": 3, "tn_to_fp": 4})
        self.assertEqual(compact["mcnemar_negatives_p"], 0.25)
        self.assertEqual(compact["delta"]["recall"], metric)


class FreezeGuardTests(unittest.TestCase):
    def git(self, root, *args):
        subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)

    def test_freeze_file_must_be_committed_and_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.git(root, "init", "-q")
            self.git(root, "config", "user.email", "t@example.test")
            self.git(root, "config", "user.name", "t")
            freeze = root / "freeze.json"
            freeze.write_text("{}", encoding="utf-8")
            with self.assertRaises(SystemExit):
                study.require_committed(freeze, root)
            self.git(root, "add", "freeze.json")
            self.git(root, "commit", "-q", "-m", "freeze")
            self.assertEqual(len(study.require_committed(freeze, root)), 40)
            freeze.write_text('{"x": 1}', encoding="utf-8")
            with self.assertRaises(SystemExit):
                study.require_committed(freeze, root)


if __name__ == "__main__":
    unittest.main()
