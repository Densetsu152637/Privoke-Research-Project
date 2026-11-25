"""Mechanics tests for the E2EEVADE harness (Stage 13b-1): synthetic rows, fake driver, no browser, no model.

Covers outcome classification, agreement with the Stage 3 ``summarise_pairs`` on the same pairs, the
value-removing split, refusal of an empty layer list, refusal of a host that is not a fixture, and
the stop on a layer mismatch. No prompt, dataset row or model output is used.
"""

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "evaluation")]

import adversarial_evasion as ae  # noqa: E402
import e2e_evasion as e2e  # noqa: E402
from cross_platform_probes import Capture  # noqa: E402

FULL = ("regex", "ner", "semantic")
BODY_PREFIX = '{"action":"next","messages":[{"content":{"content_type":"text","parts":['


def sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def body_for(text: str) -> bytes:
    return (BODY_PREFIX + json.dumps(text) + "]},\"role\":\"user\"}],\"model\":\"synthetic-model\"}").encode("utf-8")


def layers_payload(statuses=("ok", "ok", "ok"), actions=("ALLOW", "ALLOW", "ALLOW"), names=FULL):
    return [{"layer": n, "status": s, "error": "", "results": [{"action": a}]} for n, s, a in zip(names, statuses, actions)]


def tap_entry(text: str, action="ALLOW", requested=(2, 3, 4), layers=None, error=""):
    layers = layers_payload() if layers is None else layers
    return {"path": "/privoke.v1.PrivokeRuntimeService/AnalyzePrompt", "http_status": 200, "grpc_status": 0, "error": None,
            "request": {"request_id": "r", "layer_values": list(requested), "layers": [e2e.ENUM_LAYER[v] for v in requested],
                        "text_sha256": sha(text), "text_chars": len(text)},
            "response": {"request_id": "r", "action": action, "metadata": {}, "layers": layers, "error": error}}


def item(seed="s1", variant="baseline", text="synthetic prompt one", family=None, removing=False, applicable=True):
    return {"vid": f"{seed}::{variant}", "seed_id": seed, "variant": variant, "family": family or variant,
            "value_removing": removing, "applicable": applicable, "text": text}


class FakeTap:
    def __init__(self):
        self.entries = []

    def mark(self):
        return len(self.entries)

    def since(self, mark):
        return list(self.entries[mark:])


class FakeReceiver:
    def __init__(self):
        self.by_id = {}

    def captures_for(self, send_id):
        return self.by_id.get(send_id, [])


class FakeDriver:
    """Plays one installed extension: ``plan(text)`` says what each send does."""

    def __init__(self, tap, receiver, plan):
        self.tap, self.receiver, self.plan = tap, receiver, plan
        self.sends = 0

    def request(self, op, timeout=None, **fields):
        assert op == "send"
        self.sends += 1
        text, send_id = fields["prompt"], fields["sendId"]
        spec = self.plan(text)
        body = body_for(text)
        if spec.get("tap", True):
            self.tap.entries.append(tap_entry(text, spec.get("action", "ALLOW"), spec.get("requested", (2, 3, 4)),
                                              spec.get("layers")))
        if spec.get("deliver", True):
            self.receiver.by_id[send_id] = [Capture(send_id, "chatgpt.com", "POST", "/backend-api/conversation",
                                                    "application/json", body)]
        messages = [{"type": "ANALYZE_PROMPT", "text": text},
                    {"type": "ANALYZE_RESULT", "action": spec.get("action", "ALLOW"),
                     "noticeStatus": "RENDERED" if spec.get("warn") else None}]
        return {"outcome": {"messages": messages, "status": 200, "elapsedMs": 4.0},
                "url": spec.get("url", "https://chatgpt.com/backend-api/conversation?xp=" + send_id),
                "expectedBodySha256": hashlib.sha256(body).hexdigest()}


def make_world(plan):
    tap, receiver = FakeTap(), FakeReceiver()
    return FakeDriver(tap, receiver, plan), receiver, tap


def row_with(seed, variant, action, family=None, removing=False, failed_closed=False, error=None, applicable=True,
             detector=None, browser="chrome", attended=False):
    """A row whose observed end-to-end action is ``action`` (BLOCK, WARN, ALLOW) or None (not delivered)."""
    got = action in ("WARN", "ALLOW")
    row = {"seed_id": seed, "variant": variant, "family": family or variant, "value_removing": removing,
           "applicable": applicable, "browser": browser, "attended": attended, "receiver_got": got,
           "payload_intact": got, "warn_shown": action == "WARN", "decision": action, "layers_requested": list(FULL),
           "layers_executed": {n: "ok" for n in FULL}, "error": error, "failed_closed": failed_closed, "elapsed_ms": 10.0,
           "detector_level": None, "e2e_outcome": None, "scope_label": e2e.SCOPE_LABEL}
    if detector is not None:
        row["detector_level"] = {"action": detector, "failed_closed": False, "layers_executed": {n: "ok" for n in FULL}}
    return row


class LayerConfigurationTests(unittest.TestCase):
    def test_empty_layer_list_is_refused(self):
        for empty in ("", " , ", [], ()):
            with self.assertRaises(e2e.LayerConfigError):
                e2e.parse_layers(empty)
        with self.assertRaises(e2e.LayerConfigError):
            e2e.require_explicit_request_layers([])
        with self.assertRaises(e2e.LayerConfigError):
            e2e.assert_executed_layers(layers_payload(), ())

    def test_detector_arm_refuses_an_empty_or_partial_set_before_sending(self):
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            for bad in ((), "regex,ner"):
                with self.assertRaises(e2e.LayerConfigError):
                    e2e.score_detector_items([item()], lambda *a: calls.append(a), bad, Path(tmp) / "scores.jsonl")
        self.assertEqual(calls, [])

    def test_layer_names_and_order(self):
        self.assertEqual(e2e.parse_layers("semantic, regex"), ("regex", "semantic"))
        with self.assertRaises(e2e.LayerConfigError):
            e2e.parse_layers("regex,llm")
        with self.assertRaises(e2e.LayerConfigError):
            e2e.parse_layers("regex,regex")

    def test_executed_layers_agree_with_stage3_on_the_full_set(self):
        statuses = ("ok", "skipped", "error")
        for ner in statuses:
            for sem in statuses:
                for regex in statuses:
                    layers = layers_payload((regex, ner, sem))
                    try:
                        old = ae.assert_executed_layers(layers)
                    except ae.LayerAssertionError:
                        old = "refused"
                    try:
                        new = e2e.assert_executed_layers(layers, FULL)
                    except ae.LayerAssertionError:
                        new = "refused"
                    self.assertEqual(old, new, (regex, ner, sem))

    def test_wrong_layer_names_or_order_are_refused(self):
        for names in (("regex", "ner"), ("ner", "regex", "semantic"), ("regex", "ner", "semantic", "extra")):
            layers = [{"layer": n, "status": "ok", "error": "", "results": []} for n in names]
            with self.assertRaises(e2e.LayerMismatchError):
                e2e.assert_executed_layers(layers, FULL)

    def test_regex_first_skip_rule_applies_only_when_regex_was_requested(self):
        skipped = layers_payload(("ok", "skipped", "skipped"))
        self.assertEqual(e2e.assert_executed_layers(skipped, FULL)["semantic"], "skipped")
        no_regex = [{"layer": "ner", "status": "skipped", "error": "", "results": []},
                    {"layer": "semantic", "status": "ok", "error": "", "results": []}]
        with self.assertRaises(e2e.LayerMismatchError):
            e2e.assert_executed_layers(no_regex, ("ner", "semantic"))
        subset = [{"layer": "regex", "status": "ok", "error": "", "results": []},
                  {"layer": "semantic", "status": "skipped", "error": "", "results": []}]
        self.assertEqual(e2e.assert_executed_layers(subset, ("regex", "semantic"))["semantic"], "skipped")
        half = layers_payload(("ok", "skipped", "ok"))
        with self.assertRaises(e2e.LayerMismatchError):
            e2e.assert_executed_layers(half, FULL)

    def test_model_identity_is_checked_when_the_semantic_layer_ran(self):
        layers = layers_payload()
        e2e.assert_executed_layers(layers, FULL, "abc", {"privoke.semantic.artifact_checksum": "abc"})
        with self.assertRaises(e2e.LayerMismatchError):
            e2e.assert_executed_layers(layers, FULL, "abc", {"privoke.semantic.artifact_checksum": "other"})


class HostRefusalTests(unittest.TestCase):
    def test_only_fixture_hosts_are_accepted(self):
        self.assertEqual(e2e.require_fixture_host("https://chatgpt.com/backend-api/conversation"), "chatgpt.com")
        self.assertEqual(e2e.require_fixture_host("claude.ai:443"), "claude.ai")
        for bad in ("https://api.anthropic.com/v1/messages", "https://chatgpt.com.evil.test/", "example.org", "https:///x"):
            with self.assertRaises(e2e.HostRefusedError):
                e2e.require_fixture_host(bad)

    def test_a_send_to_a_non_fixture_host_is_refused_before_it_is_classified(self):
        driver, receiver, tap = make_world(lambda text: {"url": "https://api.example.org/v1/chat"})
        with self.assertRaises(e2e.HostRefusedError):
            e2e.send_item(driver, receiver, tap, item(), "chrome", False, FULL, "https://chatgpt.com/x", "s0")
        with self.assertRaises(e2e.HostRefusedError):
            e2e.send_item(driver, receiver, tap, item(), "chrome", False, FULL, "https://api.example.org/x", "s1")
        self.assertEqual(driver.sends, 1, "the second send must be refused before the driver is asked")

    def test_a_receiver_capture_from_a_foreign_host_is_refused(self):
        row_item = item()
        reply = {"outcome": {"messages": []}, "url": "https://chatgpt.com/x"}
        capture = Capture("s0", "evil.test", "POST", "/", "application/json", body_for(row_item["text"]))
        with self.assertRaises(e2e.HostRefusedError):
            e2e.build_row(row_item, "chrome", False, FULL, reply, [capture], [])


class RowConstructionTests(unittest.TestCase):
    def send(self, plan, text="synthetic prompt one"):
        driver, receiver, tap = make_world(plan)
        return e2e.send_item(driver, receiver, tap, item(text=text), "chrome", False, FULL, "https://chatgpt.com/x", "s0")

    def test_an_allowed_prompt_is_delivered_intact(self):
        row = self.send(lambda t: {})
        self.assertEqual((row["receiver_got"], row["payload_intact"], row["warn_shown"], row["decision"], row["error"]),
                         (True, True, False, "ALLOW", None))
        self.assertEqual(row["layers_requested"], list(FULL))
        self.assertEqual(row["layers_executed"], {n: "ok" for n in FULL})
        self.assertEqual(e2e.e2e_action(row), "ALLOW")
        self.assertEqual(set(e2e.EXPECTED_ROW_FIELDS) | set(e2e.EXTRA_ROW_FIELDS), set(row))

    def test_a_blocked_prompt_reaches_nothing(self):
        row = self.send(lambda t: {"action": "BLOCK", "deliver": False})
        self.assertEqual((row["receiver_got"], row["decision"], row["error"]), (False, "BLOCK", None))
        self.assertEqual(e2e.e2e_action(row), "BLOCK")

    def test_a_warned_prompt_needs_the_notice_before_it_counts_as_warn(self):
        shown = self.send(lambda t: {"action": "WARN", "warn": True})
        hidden = self.send(lambda t: {"action": "WARN", "warn": False})
        self.assertEqual(e2e.e2e_action(shown), "WARN")
        self.assertEqual(e2e.e2e_action(hidden), "ALLOW", "a WARN whose notice was never shown protects nobody")

    def test_an_altered_payload_is_not_intact(self):
        driver, receiver, tap = make_world(lambda t: {})
        row_item = item()
        reply = driver.request("send", prompt=row_item["text"], sendId="s0")
        altered = [Capture("s0", "chatgpt.com", "POST", "/", "application/json", body_for("changed text"))]
        row = e2e.build_row(row_item, "chrome", False, FULL, reply, altered, tap.entries)
        self.assertFalse(row["payload_intact"])
        self.assertIsNone(e2e.e2e_action(row))

    def test_a_missing_analysis_is_an_error_row_not_a_protection(self):
        row = self.send(lambda t: {"tap": False})
        self.assertIn("no_bridge_request", row["error"])
        self.assertIsNone(e2e.e2e_action(row))

    def test_the_bridge_and_page_decisions_must_agree(self):
        driver, receiver, tap = make_world(lambda t: {"action": "ALLOW"})
        reply = driver.request("send", prompt="synthetic prompt one", sendId="s0")
        tap.entries[-1]["response"]["action"] = "BLOCK"
        row = e2e.build_row(item(), "chrome", False, FULL, reply, receiver.captures_for("s0"), tap.entries)
        self.assertIn("page_bridge_decision_mismatch", row["error"])

    def test_fail_closed_is_recorded_from_the_executed_layers(self):
        layers = layers_payload(("ok", "ok", "error"), ("ALLOW", "ALLOW", "ALLOW"))
        row = self.send(lambda t: {"action": "BLOCK", "deliver": False, "layers": layers})
        self.assertTrue(row["failed_closed"])
        self.assertEqual(row["layers_executed"]["semantic"], "error")

    def test_stage3_score_record_agrees_on_failed_closed(self):
        for statuses, actions, action in ((("ok", "ok", "error"), ("ALLOW",) * 3, "BLOCK"),
                                          (("ok", "ok", "ok"), ("ALLOW",) * 3, "ALLOW"),
                                          (("ok", "error", "ok"), ("ALLOW", "ALLOW", "WARN"), "WARN")):
            response = {"action": action, "layers": layers_payload(statuses, actions), "metadata": {}}
            old = ae.score_record("v", response, None)
            new = e2e.response_summary(response)
            self.assertEqual((old["action"], old["failed_closed"], old["layer_status"], old["layer_action"]),
                             (new["action"], new["failed_closed"], new["layer_status"], new["layer_action"]))


class LayerMismatchStopsTheRunTests(unittest.TestCase):
    def test_a_request_without_the_semantic_layer_aborts(self):
        driver, receiver, tap = make_world(lambda t: {"requested": (2, 3)})
        with self.assertRaises(e2e.LayerMismatchError):
            e2e.send_item(driver, receiver, tap, item(), "chrome", False, FULL, "https://chatgpt.com/x", "s0")

    def test_an_empty_request_layer_list_aborts(self):
        driver, receiver, tap = make_world(lambda t: {"requested": ()})
        with self.assertRaises(e2e.LayerConfigError):
            e2e.send_item(driver, receiver, tap, item(), "chrome", False, FULL, "https://chatgpt.com/x", "s0")

    def test_a_response_that_executed_fewer_layers_aborts(self):
        layers = layers_payload(names=FULL)[:2]
        driver, receiver, tap = make_world(lambda t: {"layers": layers})
        with self.assertRaises(e2e.LayerMismatchError):
            e2e.send_item(driver, receiver, tap, item(), "chrome", False, FULL, "https://chatgpt.com/x", "s0")

    def test_run_items_stops_on_the_first_mismatch_and_keeps_earlier_rows(self):
        def plan(text):
            return {"requested": (2, 3)} if "drop" in text else {}
        driver, receiver, tap = make_world(plan)
        items = [item("a", "baseline", "keep one"), item("b", "baseline", "drop this one"), item("c", "baseline", "never sent")]
        with tempfile.TemporaryDirectory() as tmp:
            rows_path = Path(tmp) / "rows.jsonl"
            with self.assertRaises(e2e.RunAborted):
                e2e.run_items(driver, receiver, tap, items, "chrome", False, FULL, "https://chatgpt.com/x", rows_path)
            self.assertEqual([r["seed_id"] for r in e2e.read_jsonl(rows_path)], ["a"])
        self.assertEqual(driver.sends, 2)

    def test_run_items_resumes_and_skips_rows_already_written(self):
        driver, receiver, tap = make_world(lambda t: {})
        items = [item("a", "baseline", "one"), item("a", "v1", "two"), item("b", "baseline", "three", applicable=True),
                 item("b", "v2", "four", applicable=False)]
        with tempfile.TemporaryDirectory() as tmp:
            rows_path = Path(tmp) / "rows.jsonl"
            e2e.run_items(driver, receiver, tap, items[:2], "chrome", False, FULL, "https://chatgpt.com/x", rows_path)
            rows = e2e.run_items(driver, receiver, tap, items, "chrome", False, FULL, "https://chatgpt.com/x", rows_path)
            self.assertEqual([(r["seed_id"], r["variant"]) for r in rows], [("b", "baseline")])
            self.assertEqual(len(e2e.read_jsonl(rows_path)), 3)

    def test_too_many_consecutive_error_rows_abort(self):
        driver, receiver, tap = make_world(lambda t: {"tap": False})
        items = [item(f"s{i}", "baseline", f"prompt {i}") for i in range(5)]
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(e2e.RunAborted):
                e2e.run_items(driver, receiver, tap, items, "chrome", False, FULL, "https://chatgpt.com/x",
                              Path(tmp) / "rows.jsonl", max_consecutive_errors=3)
        self.assertEqual(driver.sends, 3)


class OutcomeClassificationTests(unittest.TestCase):
    def classify(self, baseline_action, variant_action, **kwargs):
        rows = [row_with("a", "baseline", baseline_action), row_with("a", "v1", variant_action, **kwargs)]
        return e2e.annotate_outcomes(rows)[1]["e2e_outcome"]

    def test_protected_pairs(self):
        self.assertEqual(self.classify("BLOCK", "BLOCK"), "protected")
        self.assertEqual(self.classify("WARN", "WARN"), "protected")
        self.assertEqual(self.classify("WARN", "BLOCK"), "protected")

    def test_evaded_and_downgraded(self):
        self.assertEqual(self.classify("BLOCK", "ALLOW"), "evaded")
        self.assertEqual(self.classify("WARN", "ALLOW"), "evaded")
        self.assertEqual(self.classify("BLOCK", "WARN"), "downgraded")

    def test_fail_closed_is_its_own_outcome_never_protected(self):
        self.assertEqual(self.classify("BLOCK", "BLOCK", failed_closed=True), "fail_closed")

    def test_unclassifiable_variant_rows_are_not_delivered_other(self):
        self.assertEqual(self.classify("BLOCK", None, error="no_bridge_request"), "not_delivered_other")
        self.assertEqual(self.classify("BLOCK", None), "not_delivered_other")

    def test_pairs_without_a_protected_baseline_get_no_outcome(self):
        self.assertIsNone(self.classify("ALLOW", "ALLOW"))
        self.assertIsNone(self.classify(None, "ALLOW"))
        rows = [row_with("a", "baseline", "BLOCK", failed_closed=True), row_with("a", "v1", "ALLOW")]
        self.assertIsNone(e2e.annotate_outcomes(rows)[1]["e2e_outcome"])

    def test_baseline_rows_and_inapplicable_rows_have_no_outcome(self):
        rows = [row_with("a", "baseline", "BLOCK"), row_with("a", "v1", "ALLOW", applicable=False)]
        self.assertEqual([r["e2e_outcome"] for r in e2e.annotate_outcomes(rows)], [None, None])

    def test_browsers_have_their_own_baselines(self):
        rows = [row_with("a", "baseline", "BLOCK", browser="chrome"), row_with("a", "baseline", "ALLOW", browser="edge"),
                row_with("a", "v1", "ALLOW", browser="chrome"), row_with("a", "v1", "ALLOW", browser="edge")]
        outcomes = [r["e2e_outcome"] for r in e2e.annotate_outcomes(rows)]
        self.assertEqual(outcomes, [None, None, "evaded", None])


def stage3_fixture():
    """Eight seeds, two variants (one value-removing), with chosen end-to-end and detector actions."""
    seeds = [f"s{i}" for i in range(8)]
    e2e_base = dict(zip(seeds, ["BLOCK", "BLOCK", "WARN", "WARN", "BLOCK", "ALLOW", "WARN", "BLOCK"]))
    det_base = dict(zip(seeds, ["BLOCK", "WARN", "WARN", "BLOCK", "BLOCK", "WARN", "ALLOW", "BLOCK"]))
    e2e_v1 = dict(zip(seeds, ["ALLOW", "BLOCK", "ALLOW", "WARN", "WARN", "ALLOW", "WARN", "BLOCK"]))
    det_v1 = dict(zip(seeds, ["BLOCK", "ALLOW", "ALLOW", "WARN", "ALLOW", "WARN", "ALLOW", "BLOCK"]))
    e2e_v2 = dict(zip(seeds, ["ALLOW", "ALLOW", "WARN", "ALLOW", "BLOCK", "ALLOW", "ALLOW", "WARN"]))
    det_v2 = dict(zip(seeds, ["ALLOW", "BLOCK", "ALLOW", "ALLOW", "BLOCK", "ALLOW", "ALLOW", "ALLOW"]))
    rows = []
    for s in seeds:
        for variant, family, removing, e2e_map, det_map in (
                ("baseline", "baseline", False, e2e_base, det_base), ("v1", "unicode", False, e2e_v1, det_v1),
                ("v2", "indirect_reference", True, e2e_v2, det_v2)):
            rows.append(row_with(s, variant, e2e_map[s], family, removing, detector=det_map[s]))
    return rows, (e2e_base, e2e_v1, e2e_v2), (det_base, det_v1, det_v2)


class ScoringAgreesWithStage3Tests(unittest.TestCase):
    def stage3(self, base, v1, v2, groups):
        items = [{"vid": f"{s}::{v}", "row_id": s, "variant": v, "family": f, "applicable": True}
                 for s in base for v, f in (("v1", "unicode"), ("v2", "indirect_reference"))]
        scores = {f"{s}::{n}": {"action": m[s], "failed_closed": False} for n, m in (("baseline", base), ("v1", v1), ("v2", v2))
                  for s in base}
        return items, base, scores

    def test_each_arm_matches_summarise_pairs_on_the_pairs_both_arms_scored(self):
        rows, e2e_maps, det_maps = stage3_fixture()
        result = e2e.score_group(rows)
        usable = [s for s in e2e_maps[0]]
        for arm, maps in (("end_to_end", e2e_maps), ("detector_level", det_maps)):
            items, intended, scores = self.stage3(*maps, groups=None)
            pairs = ae.evaluate_arm(items, intended, scores)
            expected = ae.summarise_pairs(pairs)
            actual = result["arms"][arm]["action_level"]["overall"]
            for key in ("applicable", "protected_pairs", "evaded", "block_pairs", "downgraded_block_to_warn", "failed_closed_after"):
                self.assertEqual(actual[key], expected[key], (arm, key))
            self.assertEqual(actual["asr_conditional"], e2e._clean(expected["asr_conditional"]))
            self.assertEqual(actual["asr_unconditional"], e2e._clean(expected["asr_unconditional"]))
            by_variant = {v: ae.summarise_pairs(g) for v, g in ae.group_pairs(pairs, "variant").items()}
            for name, summary in by_variant.items():
                self.assertEqual(result["arms"][arm]["action_level"]["by_variant"][name]["evaded"], summary["evaded"])
        self.assertEqual(result["pairs_scored_in_both"], len(usable) * 2)

    def test_value_removing_families_are_split_and_never_hidden(self):
        rows, e2e_maps, _ = stage3_fixture()
        result = e2e.score_group(rows)
        level = result["arms"]["end_to_end"]["action_level"]
        overall, kept = level["overall"], level["overall_excluding_value_removing"]
        self.assertGreater(overall["applicable"], kept["applicable"])
        self.assertEqual(kept["applicable"], 8)
        self.assertEqual(set(level["by_family"]), {"unicode", "indirect_reference"})
        self.assertEqual(level["by_family"]["indirect_reference"]["applicable"], 8)
        self.assertNotEqual(overall["asr_conditional"], kept["asr_conditional"])
        items, intended, scores = self.stage3(*e2e_maps, groups=None)
        expected_keep = ae.summarise_pairs([p for p in ae.evaluate_arm(items, intended, scores) if p["variant"] == "v1"])
        self.assertEqual(kept["evaded"], expected_keep["evaded"])

    def test_each_arm_keeps_its_own_denominator_and_the_paired_set_is_the_intersection(self):
        rows, e2e_maps, det_maps = stage3_fixture()
        result = e2e.score_group(rows)
        e2e_protected = sum(1 for a in e2e_maps[0].values() if a != "ALLOW")
        det_protected = sum(1 for a in det_maps[0].values() if a != "ALLOW")
        self.assertEqual(result["arms"]["end_to_end"]["protected_baselines"], e2e_protected)
        self.assertEqual(result["arms"]["detector_level"]["protected_baselines"], det_protected)
        both = [s for s in e2e_maps[0] if e2e_maps[0][s] != "ALLOW" and det_maps[0][s] != "ALLOW"]
        paired = result["paired_conditional"]["all_families"]
        self.assertEqual(paired["protected_in_both"], len(both) * 2)
        self.assertEqual(paired["evaded_e2e_only"] + paired["evaded_detector_only"] + paired["evaded_both"]
                         + paired["evaded_neither"], len(both) * 2)
        self.assertEqual(paired["exact_mcnemar_p"], ae.exact_mcnemar(paired["evaded_e2e_only"], paired["evaded_detector_only"]))

    def test_excluded_pairs_are_listed_with_reasons(self):
        rows, _, _ = stage3_fixture()
        for row in rows:
            if row["seed_id"] == "s0" and row["variant"] == "v1":
                row["error"] = "no_bridge_request"
            if row["seed_id"] == "s1" and row["variant"] == "baseline":
                row["detector_level"] = None
            if row["seed_id"] == "s2" and row["variant"] == "baseline":
                row["failed_closed"] = True
        result = e2e.score_group(rows)
        reasons = {(e["seed_id"], e["variant"]): e["reasons"] for e in result["excluded_pairs"]}
        self.assertEqual(reasons[("s0", "v1")], ["variant_not_scored_e2e"])
        self.assertEqual(reasons[("s1", "v1")], ["baseline_not_scored_detector"])
        self.assertEqual(reasons[("s2", "v2")], ["baseline_failed_closed_e2e"])
        self.assertEqual(result["pairs_excluded"], len(result["excluded_pairs"]))
        self.assertEqual(result["pairs_scored_in_both"] + result["pairs_excluded"], result["applicable_pairs_sent"])

    def test_results_contain_ids_and_counts_only(self):
        rows, _, _ = stage3_fixture()
        encoded = json.dumps(e2e.score_group(rows))
        self.assertNotIn("NaN", encoded)
        for forbidden in ('"text"', '"prompt"', '"body"', '"notes"'):
            self.assertNotIn(forbidden, encoded)


class SamplingAndPlanningTests(unittest.TestCase):
    SOURCES = {f"a{i}": "src_a" for i in range(60)} | {f"b{i}": "src_b" for i in range(30)} | {f"c{i}": "src_c" for i in range(10)}

    def test_the_sample_is_stratified_seeded_and_stable(self):
        first = e2e.stratified_seed_sample(self.SOURCES, 20)
        self.assertEqual(first, e2e.stratified_seed_sample(self.SOURCES, 20))
        self.assertEqual(len(first), 20)
        counts = {s: sum(1 for r in first if self.SOURCES[r] == s) for s in ("src_a", "src_b", "src_c")}
        self.assertEqual(counts, {"src_a": 12, "src_b": 6, "src_c": 2})
        self.assertNotEqual(first, e2e.stratified_seed_sample(self.SOURCES, 20, seed=1))
        self.assertEqual(len(e2e.stratified_seed_sample(self.SOURCES, 500)), 100)

    def test_excluded_ids_never_enter_the_sample(self):
        banned = {f"a{i}" for i in range(0, 60, 2)}
        sample = e2e.stratified_seed_sample(self.SOURCES, 40, exclude=banned)
        self.assertFalse(banned & set(sample))
        self.assertEqual(len(sample), 40)

    def test_seed_count_follows_the_pilot_with_a_floor(self):
        plan = e2e.plan_seed_count(seconds_per_send=2.0, sends_per_seed=21.0, hours=8.0, floor=200)
        self.assertEqual(plan["budget_seeds"], 685)
        self.assertEqual(plan["n_seed"], 685)
        self.assertFalse(plan["floor_binding"])
        slow = e2e.plan_seed_count(seconds_per_send=10.0, sends_per_seed=21.0, hours=8.0, floor=200)
        self.assertEqual((slow["budget_seeds"], slow["n_seed"], slow["floor_binding"], slow["exceeds_budget"]), (137, 200, True, True))
        capped = e2e.plan_seed_count(2.0, 21.0, available=300)
        self.assertEqual(capped["n_seed"], 300)

    def test_the_pilot_takes_the_first_twenty_sendable_items(self):
        items = [item("a", "baseline")] + [item("a", f"v{i}", applicable=bool(i % 5)) for i in range(40)]
        chosen = e2e.pilot_items(items)
        self.assertEqual(len(chosen), 20)
        self.assertTrue(all(i["applicable"] for i in chosen))
        self.assertEqual(chosen[0]["variant"], "baseline")


class BuildRunSetTests(unittest.TestCase):
    """A tiny frozen set and F4 source stand in for the real ones; the module hashes are patched."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.rows = []
        for i in range(6):
            text = f"My name is Alice Smith{i} and my id is 123-45-678{i}."
            ent = [{"start": text.index("Alice"), "end": text.index("Alice") + len(f"Alice Smith{i}"), "label": "name"},
                   {"start": text.index("123"), "end": len(text) - 1, "label": "ssn"}]
            self.rows.append({"id": f"r{i}", "group_id": f"g{i // 2}", "text": text, "entities": ent,
                              "source_dataset": "src_a" if i < 4 else "src_b", "expected_has_pii": True})
        self.frozen = self.tmp / "frozen"
        self.frozen.mkdir()
        items = ae.build_items(self.rows)
        payload = "\n".join(ae.canonical_line(i) for i in items) + "\n"
        (self.frozen / "frozen_set.jsonl").write_text(payload, encoding="utf-8", newline="\n")
        self.f4 = self.tmp / "f4.jsonl"
        self.f4.write_text("\n".join(ae.canonical_line(r) for r in self.rows) + "\n", encoding="utf-8", newline="\n")
        self.manifest = {
            "record": e2e.STAGE3_RECORD, "generator_revision": e2e.STAGE3_GENERATOR_REVISION,
            "frozen_set_sha256": ae.file_sha256(self.frozen / "frozen_set.jsonl"),
            "seed_file": str(self.f4), "seed_file_sha256": ae.file_sha256(self.f4),
            "transform_module_sha256": e2e.STAGE3_TRANSFORMS_SHA256,
            "row_source": {r["id"]: r["source_dataset"] for r in self.rows}, "row_group": {r["id"]: r["group_id"] for r in self.rows},
            "variants": {n: {"family": f, "value_removing": rem} for n, (f, _fn, rem) in e2e.stage3.VARIANTS.items()}}
        (self.frozen / "manifest.json").write_text(json.dumps(self.manifest), encoding="utf-8")
        self.root = self.tmp / "local"
        patches = [mock.patch.object(e2e, "FROZEN_SET_SHA256", self.manifest["frozen_set_sha256"]),
                   mock.patch.object(e2e, "F4_SOURCE_SHA256", self.manifest["seed_file_sha256"]),
                   mock.patch.dict(os.environ, {"S13_LOCAL_INPUTS_ROOT": str(self.root)})]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.out = self.root / "s13b" / "run"

    def test_the_run_set_reuses_stage3_text_and_adds_the_new_variants(self):
        plan = e2e.build_run_set(self.frozen, self.out, 4)
        items = e2e.read_jsonl(self.out / "run_set.jsonl")
        self.assertEqual(plan["n_seed"], 4)
        self.assertEqual(len(items), 4 * (1 + len(e2e.ALL_VARIANTS)))
        frozen = {i["vid"]: i for i in e2e.read_jsonl(self.frozen / "frozen_set.jsonl")}
        for it in items:
            if it["variant"] in e2e.STAGE3_VARIANTS + (e2e.BASELINE,):
                self.assertEqual(it["text"], frozen[it["vid"]]["text"])
                self.assertEqual(it["applicable"], frozen[it["vid"]]["applicable"])
        new = [i for i in items if i["variant"] in e2e.E2E_VARIANTS]
        self.assertTrue(new and any(i["applicable"] for i in new))
        for it in new:
            if it["applicable"]:
                self.assertNotEqual(it["text"], next(b for b in items if b["seed_id"] == it["seed_id"] and b["variant"] == "baseline")["text"])
        self.assertEqual(items[0]["variant"], "baseline")
        self.assertEqual(plan["run_set_sha256"], ae.file_sha256(self.out / "run_set.jsonl"))

    def test_the_plan_holds_ids_and_counts_but_no_prompt_text(self):
        e2e.build_run_set(self.frozen, self.out, 4)
        plan_text = (self.out / "run_plan.json").read_text(encoding="utf-8")
        for row in self.rows:
            self.assertNotIn(row["text"], plan_text)
            self.assertNotIn("Alice", plan_text)
        plan = json.loads(plan_text)
        self.assertEqual(plan["frozen_set_sha256"], e2e.FROZEN_SET_SHA256)
        self.assertEqual(plan["sample_seed"], e2e.SAMPLE_SEED)
        self.assertEqual(sorted(plan["seed_ids"]), sorted(plan["seed_group"]))

    def test_a_changed_frozen_set_is_refused_before_anything_is_read(self):
        (self.frozen / "frozen_set.jsonl").write_text("{}\n", encoding="utf-8")
        with mock.patch.object(e2e.ae, "canonical_line", side_effect=AssertionError("must not read")):
            with self.assertRaises(e2e.HarnessError):
                e2e.build_run_set(self.frozen, self.out, 4)

    def test_a_manifest_linking_a_different_source_is_refused(self):
        bad = dict(self.manifest, seed_file_sha256="0" * 64)
        (self.frozen / "manifest.json").write_text(json.dumps(bad), encoding="utf-8")
        with self.assertRaises(e2e.HarnessError):
            e2e.build_run_set(self.frozen, self.out, 4)

    def test_a_changed_source_file_is_refused(self):
        self.f4.write_text(self.f4.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        with self.assertRaises(e2e.HarnessError):
            e2e.build_run_set(self.frozen, self.out, 4)

    def test_excluded_seeds_are_not_sampled_and_the_exclusion_is_recorded(self):
        plan = e2e.build_run_set(self.frozen, self.out, 4, exclude_ids={"r0", "r1"})
        self.assertFalse({"r0", "r1"} & set(plan["seed_ids"]))
        self.assertEqual(plan["excluded_ids"], 2)

    def test_prompt_bearing_output_is_refused_outside_the_ignored_directory(self):
        for bad in (self.tmp / "elsewhere", self.root / "s13a", Path("relative/dir")):
            with self.assertRaises(e2e.HarnessError):
                e2e.build_run_set(self.frozen, bad, 4)
        self.assertTrue(e2e.ensure_out_dir(self.root / "s13b" / "pilot").is_dir())

    def test_a_different_run_set_is_never_overwritten(self):
        e2e.build_run_set(self.frozen, self.out, 4)
        with self.assertRaises(e2e.HarnessError):
            e2e.build_run_set(self.frozen, self.out, 3)

    def test_a_variant_subset_is_honoured(self):
        e2e.build_run_set(self.frozen, self.out, 4, variants=("homoglyph", "fragmented_identifier"))
        names = {i["variant"] for i in e2e.read_jsonl(self.out / "run_set.jsonl")}
        self.assertEqual(names, {"baseline", "homoglyph", "fragmented_identifier"})
        with self.assertRaises(e2e.HarnessError):
            e2e.build_run_set(self.frozen, self.out, 4, variants=("nonsense",))


class DetectorArmTests(unittest.TestCase):
    def test_detector_scores_assert_the_layers_and_resume(self):
        calls = []

        def analyse(text, request_id):
            calls.append(request_id)
            return {"action": "BLOCK", "layers": layers_payload(("ok", "skipped", "skipped"), ("BLOCK", "ALLOW", "ALLOW")),
                    "metadata": {}}
        items = [item("a", "baseline", "one"), item("a", "v1", "two"), item("a", "v2", "three", applicable=False)]
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "scores.jsonl"
            self.assertEqual(e2e.score_detector_items(items, analyse, FULL, out), 2)
            self.assertEqual(e2e.score_detector_items(items, analyse, FULL, out), 0)
            records = e2e.read_jsonl(out)
        self.assertEqual([r["vid"] for r in records], ["a::baseline", "a::v1"])
        self.assertEqual(records[0]["scope_label"], e2e.DETECTOR_SCOPE_LABEL)
        self.assertEqual(len(calls), 2)

    def test_a_detector_response_with_the_wrong_layers_aborts(self):
        def analyse(text, request_id):
            return {"action": "ALLOW", "layers": layers_payload(names=FULL)[:2], "metadata": {}}
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(e2e.LayerMismatchError):
                e2e.score_detector_items([item()], analyse, FULL, Path(tmp) / "scores.jsonl")


class HostLockTests(unittest.TestCase):
    def test_the_lock_is_exclusive_and_released(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "s13-host.lock"
            first = e2e.HostLock("13b-2", path).acquire()
            self.assertEqual(json.loads(path.read_text())["stage"], "13b-2")
            self.assertEqual(json.loads(path.read_text())["pid"], os.getpid())
            with self.assertRaises(e2e.HostLockHeld):
                e2e.HostLock("13e", path).acquire()
            first.release()
            self.assertFalse(path.exists())
            with e2e.HostLock("13e", path):
                self.assertTrue(path.exists())
            self.assertFalse(path.exists())


class WireAndTapTests(unittest.TestCase):
    @staticmethod
    def varint(value):
        out = bytearray()
        while True:
            byte = value & 0x7F
            value >>= 7
            out.append(byte | (0x80 if value else 0))
            if not value:
                return bytes(out)

    def field(self, number, payload: bytes):
        return self.varint(number << 3 | 2) + self.varint(len(payload)) + payload

    def encode_request(self, text, layers, request_id="req-1", packed=True):
        data = self.field(1, text.encode()) + self.field(5, request_id.encode())
        if packed:
            data += self.field(7, b"".join(self.varint(v) for v in layers))
        else:
            data += b"".join(self.varint(7 << 3) + self.varint(v) for v in layers)
        return data

    def encode_response(self, action, layers, request_id="req-1", error=""):
        data = self.field(1, request_id.encode()) + self.field(2, action.encode())
        data += self.field(8, self.field(1, b"privoke.semantic.artifact_checksum") + self.field(2, b"abc"))
        for name, status, result_action in layers:
            body = self.varint(1 << 3) + self.varint(e2e.LAYER_ENUM[name]) + self.field(2, status.encode())
            body += self.field(3, self.field(2, result_action.encode()))
            data += self.field(10, body)
        if error:
            data += self.field(12, error.encode())
        return data

    @staticmethod
    def frame(payload, flag=0):
        return bytes([flag]) + len(payload).to_bytes(4, "big") + payload

    def test_request_and_response_decode_without_generated_stubs(self):
        for packed in (True, False):
            request = e2e.decode_analyze_request(self.encode_request("héllo", [2, 3, 4], packed=packed))
            self.assertEqual((request["text"], request["layer_values"], request["request_id"]), ("héllo", [2, 3, 4], "req-1"))
        response = e2e.decode_analyze_response(self.encode_response(
            "WARN", [("regex", "ok", "ALLOW"), ("ner", "ok", "WARN"), ("semantic", "error", "ALLOW")], error="boom"))
        self.assertEqual(response["action"], "WARN")
        self.assertEqual([(l["layer"], l["status"], l["results"][0]["action"]) for l in response["layers"]],
                         [("regex", "ok", "ALLOW"), ("ner", "ok", "WARN"), ("semantic", "error", "ALLOW")])
        self.assertEqual(response["metadata"], {"privoke.semantic.artifact_checksum": "abc"})
        self.assertEqual(response["error"], "boom")
        summary = e2e.response_summary(response)
        self.assertEqual((summary["detect_action"], summary["failed_closed"]), ("WARN", False))

    def test_truncated_messages_are_rejected(self):
        with self.assertRaises(e2e.WireError):
            e2e.parse_message(self.field(1, b"abcdef")[:-2])
        with self.assertRaises(e2e.WireError):
            list(e2e.iter_grpc_web_frames(b"\x00\x00\x00\x00\x09ab"))

    def test_the_tap_forwards_to_the_real_bridge_and_logs_hash_only_entries(self):
        spec = importlib.util.spec_from_file_location("e2e_test_bridge", ROOT / "extension/runtime-supervisor/src/grpc_web_bridge.py")
        try:
            bridge_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(bridge_module)
        except ImportError:
            self.skipTest("grpc is not installed in this interpreter")
        seen = []

        def invoker(path, payload, target, timeout):
            seen.append((path, payload))
            return self.encode_response("BLOCK", [("regex", "ok", "BLOCK"), ("ner", "skipped", "ALLOW"), ("semantic", "skipped", "ALLOW")])
        bridge = bridge_module.GrpcWebBridge(host="127.0.0.1", port=0, rpc_invoker=invoker)
        bridge.start()
        self.addCleanup(bridge.stop)
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "tap.jsonl"
            tap = e2e.BridgeTap(bridge.port, listen_port=0, log_path=log)
            tap.start()
            self.addCleanup(tap.stop)
            request = self.frame(self.encode_request("secret looking synthetic text", [2, 3, 4]))
            import http.client
            headers = {"Origin": "chrome-extension://abcdefghijklmnop", "Content-Type": "application/grpc-web+proto"}
            mark = tap.mark()
            connection = http.client.HTTPConnection("127.0.0.1", tap.port, timeout=10)
            connection.request("OPTIONS", "/privoke.v1.PrivokeRuntimeService/AnalyzePrompt", headers=headers)
            options = connection.getresponse()
            options.read()
            self.assertEqual(options.status, 204)
            self.assertEqual(options.getheader("Access-Control-Allow-Origin"), headers["Origin"])
            connection = http.client.HTTPConnection("127.0.0.1", tap.port, timeout=10)
            connection.request("POST", "/privoke.v1.PrivokeRuntimeService/AnalyzePrompt", body=request, headers=headers)
            reply = connection.getresponse()
            data = reply.read()
            self.assertEqual(reply.status, 200)
            self.assertEqual(reply.getheader("Access-Control-Allow-Origin"), headers["Origin"])
            self.assertEqual(e2e.grpc_status_of(data), 0)
            health = http.client.HTTPConnection("127.0.0.1", tap.port, timeout=10)
            health.request("POST", "/privoke.v1.PrivokeRuntimeControlService/ModelStreamingHealth",
                           body=self.frame(b""), headers=headers)
            health.getresponse().read()
            entries = tap.since(mark)
            logged = log.read_text(encoding="utf-8")
        self.assertEqual(len(entries), 1, "only AnalyzePrompt calls are logged")
        entry = entries[0]
        self.assertEqual(entry["request"]["layers"], ["regex", "ner", "semantic"])
        self.assertEqual(entry["request"]["text_sha256"], sha("secret looking synthetic text"))
        self.assertEqual(entry["response"]["action"], "BLOCK")
        self.assertEqual([l["status"] for l in entry["response"]["layers"]], ["ok", "skipped", "skipped"])
        self.assertNotIn("secret looking", logged)
        self.assertEqual(len(seen), 2)
        self.assertEqual(e2e.decode_analyze_request(seen[0][1])["text"], "secret looking synthetic text")


class DriverContractTests(unittest.TestCase):
    def test_the_driver_loads_and_answers_unknown_operations(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is not installed")
        process = subprocess.Popen([node, str(e2e.E2E_DRIVER)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, encoding="utf8", cwd=str(ROOT / "extension"))
        timer = threading.Timer(30, process.kill)
        timer.start()
        try:
            process.stdin.write(json.dumps({"id": 1, "op": "bogus"}) + "\n")
            process.stdin.write(json.dumps({"id": 2, "op": "foreign"}) + "\n")
            process.stdin.write(json.dumps({"id": 3, "op": "close"}) + "\n")
            process.stdin.flush()
            replies = [json.loads(process.stdout.readline()) for _ in range(3)]
        finally:
            timer.cancel()
            process.kill()
            process.wait(timeout=10)
            for pipe in (process.stdin, process.stdout, process.stderr):
                pipe.close()
        self.assertIn("unknown op", replies[0]["error"])
        self.assertIn("error", replies[1], "foreign before launch has no session")
        self.assertEqual(replies[2], {"id": 3, "ok": True})


if __name__ == "__main__":
    unittest.main()
