"""Per-row record helpers of evaluate_installed_detectors.py, checked with stand-in results."""
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import evaluate_installed_detectors as ev


def hit(sens, *categories):
    sensitivity = SimpleNamespace(name=sens, value=int(sens[1:]))
    cats = [SimpleNamespace(name=c) for c in categories]
    return SimpleNamespace(classification=SimpleNamespace(sensitivity=lambda: sensitivity, categories=lambda: cats))


def strongest(results):
    top = max((int(r.classification.sensitivity().name[1:]) for r in results), default=0)
    return None, SimpleNamespace(name="BLOCK" if top >= 3 else "WARN" if top == 2 else "ALLOW")


class RowRecordTests(unittest.TestCase):
    def test_layer_row_reports_policy_action_sensitivity_and_categories(self):
        row = ev.layer_row([hit("S1", "IDENTITY"), hit("S3", "EMAIL", "IDENTITY")], strongest)
        self.assertEqual(row, {"positive": True, "max_sensitivity": "S3", "categories": ["EMAIL", "IDENTITY"],
                               "action": "BLOCK"})
        self.assertEqual(ev.layer_row([], strongest),
                         {"positive": False, "max_sensitivity": "S0", "categories": [], "action": "ALLOW"})
        # S1 with no category is allowed by the policy but is not S0, so it counts as positive
        self.assertEqual(ev.layer_row([hit("S1")], strongest)["action"], "ALLOW")
        self.assertTrue(ev.layer_row([hit("S1")], strongest)["positive"])

    def test_union_row_uses_runtime_action_and_merges_layers(self):
        regex = ev.layer_row([hit("S2", "PHONE")], strongest)
        ner = ev.layer_row([hit("S1", "PERSON")], strongest)
        union = ev.union_row(regex, ner, SimpleNamespace(action=SimpleNamespace(name="WARN")))
        self.assertEqual(union, {"positive": True, "max_sensitivity": "S2", "categories": ["PERSON", "PHONE"],
                                 "action": "WARN"})

    def test_final_identity_is_hashed_and_text_free(self):
        dev = ev.row_identity({"example_id": "x1", "group_id": "g"}, "dev")
        self.assertEqual(dev, ("x1", "g"))
        a = ev.row_identity({"example_id": "x1", "group_id": "g"}, "final")
        b = ev.row_identity({"example_id": "x1", "group_id": "g"}, "final")
        self.assertEqual(a, b)
        self.assertNotIn("x1", a[0])
        self.assertEqual(len(a[0]), 16)
        self.assertEqual(ev.row_identity({"id": "s1"}, "personalized"), ("s1", None))


if __name__ == "__main__":
    unittest.main()
