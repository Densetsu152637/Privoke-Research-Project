"""Tests that the ADVEVADE-20261116 record tables re-derive from stored aggregate counts (synthetic data only)."""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "evaluation")]

import adversarial_evasion as ae  # noqa: E402
import adversarial_evasion_report as rep  # noqa: E402
import adversarial_evasion_transforms as tx  # noqa: E402
from test_adversarial_evasion import make_items, rec  # noqa: E402


def synthetic_payload():
    variants = {"v1": "unicode", "v2": "indirect_reference"}
    rows = ["a", "b", "c", "d"]
    items = make_items(rows, variants)
    manifest = {"row_source": {r: "s1" for r in rows}, "row_group": {r: "g" + r for r in rows},
                "variants": {"v1": {"family": "unicode", "value_removing": False}, "v2": {"family": "indirect_reference", "value_removing": True}}}
    actions = {"a::baseline": "BLOCK", "b::baseline": "WARN", "c::baseline": "BLOCK", "d::baseline": "ALLOW",
               "a::v1": "ALLOW", "b::v1": "WARN", "c::v1": "WARN", "a::v2": "WARN", "b::v2": "ALLOW", "c::v2": "BLOCK"}
    defaults = {k: rec(k, v) for k, v in actions.items()}
    flags = {k: rec(k, v) for k, v in dict(actions, **{"a::v1": "BLOCK"}).items()}
    result = ae.analyse_from(items, {"defaults": defaults, "flags": flags}, manifest)
    control_items = [{"vid": f"x{i}::{v}", "row_id": f"x{i}", "variant": v, "family": v, "applicable": True, "text": "t"}
                     for i in range(4) for v in ("baseline", "paraphrase")]
    control_scores = {arm: {i["vid"]: rec(i["vid"], "WARN" if i["row_id"] == "x0" else "ALLOW") for i in control_items} for arm in ae.ARMS}
    return {"record": ae.RECORD_ID, "results": result, "control": {"results": ae.analyse_control(control_items, control_scores)}}


class ReportTests(unittest.TestCase):
    def test_stored_numbers_verify(self):
        self.assertEqual(rep.verify_numbers(synthetic_payload()), [])

    def test_tampered_count_is_detected(self):
        payload = synthetic_payload()
        payload["results"]["arms"]["defaults"]["action_level"]["overall"]["asr_conditional"]["k"] += 1
        self.assertTrue(rep.verify_numbers(payload))
        payload = synthetic_payload()
        payload["results"]["arms"]["flags"]["action_level"]["by_family"]["unicode"]["asr_conditional"]["wilson_high"] = 0.5
        self.assertTrue(rep.verify_numbers(payload))

    def test_render_is_deterministic_and_complete(self):
        payload = synthetic_payload()
        text = rep.render(payload)
        self.assertEqual(text, rep.render(copy.deepcopy(payload)))
        for family in ("unicode", "indirect_reference"):
            self.assertIn(f"| {family} |", text)
        self.assertIn("Specificity control", text)
        self.assertIn("Exact McNemar p", text)

    def test_check_round_trip_and_mismatch(self):
        payload = synthetic_payload()
        with tempfile.TemporaryDirectory() as tmp:
            j, m = Path(tmp) / "r.json", Path(tmp) / "r.md"
            j.write_text(json.dumps(payload), encoding="utf-8")
            m.write_text("intro\n" + rep.BEGIN + "\n" + rep.render(payload).rstrip("\n") + "\n" + rep.END + "\ntail\n", encoding="utf-8")
            self.assertEqual(rep.main(["check", "--json", str(j), "--md", str(m)]), 0)
            m.write_text(m.read_text(encoding="utf-8").replace("ALL variants", "All VARIANTS"), encoding="utf-8")
            self.assertEqual(rep.main(["check", "--json", str(j), "--md", str(m)]), 1)


if __name__ == "__main__":
    unittest.main()
