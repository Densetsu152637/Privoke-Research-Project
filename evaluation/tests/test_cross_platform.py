"""Mechanics tests for XPLAT-20261117: probe catalogue, scoring, summary and receiver.

No browser, runtime or provider is used. Outcomes are synthetic page results.
"""

import json
import shutil
import ssl
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from urllib.parse import unquote_plus

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "evaluation")]

import cross_platform_probes as cp  # noqa: E402
import cross_platform_receiver as receiver  # noqa: E402


def bodies():
    return cp.dump_bodies()


def outcome_for(probe: cp.ProbeDef, action: str, **overrides):
    messages = [
        {"type": "ANALYZE_PROMPT", "text": probe.prompt, "targetApp": probe.target_app, "requestId": "r"},
        {"type": "ANALYZE_RESULT", "action": action, "requestId": "r", "noticeStatus": "RENDERED"},
    ]
    if probe.transport == "fetch":
        outcome = {"transport": "fetch", "messages": messages}
        if action == "BLOCK":
            outcome.update(errorName="TypeError", errorMessage="Prompt blocked by PriVoke.")
        else:
            outcome.update(status=200)
    else:
        outcome = {"transport": "xhr", "messages": messages}
        if action == "BLOCK":
            outcome.update(status=0, readyState=4, events=["error", "loadend"])
        else:
            outcome.update(status=200, readyState=4, events=["load", "loadend"])
    outcome.update(overrides)
    return outcome


def capture_for(probe: cp.ProbeDef, body: bytes | None = None) -> cp.Capture:
    from urllib.parse import urlsplit
    parts = urlsplit(probe.request_url())
    path = parts.path + ("?" + parts.query if parts.query else "")
    return cp.Capture(probe=probe.id, host=probe.host, method="POST", path=path,
                      content_type=probe.content_type,
                      body=probe.body.encode("utf8") if body is None else body)


class CatalogueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bodies = bodies()
        cls.catalogue = cp.build_catalogue(cls.bodies)

    def test_catalogue_counts_derive_from_the_fixture(self):
        shapes = cp.load_shapes()
        expected = len(shapes["shapes"]) * len(cp.TRANSPORTS) * len(cp.CASES) + len(shapes["negativeControls"])
        self.assertEqual(len(self.catalogue), expected)
        self.assertEqual(len({p.id for p in self.catalogue}), len(self.catalogue))
        categories = {p.category for p in self.catalogue}
        self.assertEqual(categories, {cp.CATEGORY_DECISION, cp.CATEGORY_PROVIDER_SHAPE, cp.CATEGORY_NEGATIVE})

    def test_every_supported_host_has_a_shape_and_bodies_carry_only_the_frozen_prompt(self):
        hosts = {p.host for p in self.catalogue if p.category != cp.CATEGORY_NEGATIVE}
        self.assertEqual(hosts, {"chatgpt.com", "chat.openai.com", "claude.ai", "gemini.google.com",
                                 "copilot.microsoft.com", "api.openai.com"})
        for probe in self.catalogue:
            self.assertIn(probe.host, cp.FIXTURE_HOSTS)
            if probe.expects_analysis:
                self.assertIn(probe.prompt, unquote_plus(probe.body))

    def test_failure_probes_cover_the_four_fault_groups(self):
        groups = cp.build_failure_probes(self.bodies)
        self.assertEqual(set(groups), {"unavailable", "recovered", "suspended", "resumed"})
        ids = [p.id for group in groups.values() for p in group]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(p.category == cp.CATEGORY_FAILURE for group in groups.values() for p in group))


class ScoringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalogue = {p.id: p for p in cp.build_catalogue(bodies())}

    def test_allow_and_warn_pass_only_with_one_unchanged_forward(self):
        for action in ("ALLOW", "WARN"):
            for transport in cp.TRANSPORTS:
                probe = self.catalogue[f"claude-completion.{transport}.{action.lower()}"]
                good = cp.score_probe(probe, outcome_for(probe, action), [capture_for(probe)])
                self.assertTrue(good["passed"], good["failed_checks"])
                self.assertFalse(cp.score_probe(probe, outcome_for(probe, action), [])["passed"])
                altered = cp.score_probe(probe, outcome_for(probe, action),
                                         [capture_for(probe, probe.body.encode() + b" ")])
                self.assertIn("forwarded_body_unchanged", altered["failed_checks"])
                twice = cp.score_probe(probe, outcome_for(probe, action),
                                       [capture_for(probe), capture_for(probe)])
                self.assertIn("receiver_count", twice["failed_checks"])

    def test_block_requires_zero_sends_and_a_terminal_failure(self):
        for transport in cp.TRANSPORTS:
            probe = self.catalogue[f"copilot-chat-message.{transport}.block"]
            self.assertTrue(cp.score_probe(probe, outcome_for(probe, "BLOCK"), [])["passed"])
            leaked = cp.score_probe(probe, outcome_for(probe, "BLOCK"), [capture_for(probe)])
            self.assertIn("receiver_count", leaked["failed_checks"])
        fetch_probe = self.catalogue["copilot-chat-message.fetch.block"]
        resolved = cp.score_probe(fetch_probe, outcome_for(fetch_probe, "ALLOW"), [])
        self.assertFalse(resolved["passed"])
        xhr_probe = self.catalogue["copilot-chat-message.xhr.block"]
        no_events = outcome_for(xhr_probe, "BLOCK", events=["error"])
        self.assertIn("xhr_blocked_terminal", cp.score_probe(xhr_probe, no_events, [])["failed_checks"])

    def test_wrong_action_or_prompt_or_target_fails(self):
        probe = self.catalogue["gemini-stream-generate.fetch.allow"]
        wrong_action = cp.score_probe(probe, outcome_for(probe, "WARN"), [capture_for(probe)])
        self.assertIn("action_observed", wrong_action["failed_checks"])
        outcome = outcome_for(probe, "ALLOW")
        outcome["messages"][0]["text"] = "something else"
        self.assertIn("analysed_prompt_exact", cp.score_probe(probe, outcome, [capture_for(probe)])["failed_checks"])
        outcome = outcome_for(probe, "ALLOW")
        outcome["messages"][0]["targetApp"] = "chatgpt"
        self.assertIn("target_app", cp.score_probe(probe, outcome, [capture_for(probe)])["failed_checks"])

    def test_negative_controls_require_no_analysis(self):
        probe = self.catalogue["unsupported-host.fetch"]
        clean = {"transport": "fetch", "status": 200, "messages": []}
        self.assertTrue(cp.score_probe(probe, clean, [capture_for(probe)])["passed"])
        analysed = dict(clean, messages=[{"type": "ANALYZE_PROMPT", "text": "x"}])
        self.assertIn("no_analysis", cp.score_probe(probe, analysed, [capture_for(probe)])["failed_checks"])

    def test_harness_errors_never_pass(self):
        probe = self.catalogue["claude-completion.fetch.allow"]
        self.assertFalse(cp.score_probe(probe, {"harnessError": "boom"}, [])["passed"])

    def test_failure_probes_fail_open_once_and_abort_sends_nothing(self):
        groups = cp.build_failure_probes(bodies())
        open_probe = groups["unavailable"][0]
        warn = [{"type": "ANALYZE_PROMPT", "text": open_probe.prompt, "targetApp": "chatgpt"},
                {"type": "ANALYZE_RESULT", "action": "WARN", "noticeStatus": "RENDERED"}]
        good = cp.score_probe(open_probe, {"status": 200, "messages": warn}, [capture_for(open_probe)])
        self.assertTrue(good["passed"], good["failed_checks"])
        blocked = cp.score_probe(open_probe, {"errorName": "TypeError", "errorMessage": "Prompt blocked by PriVoke.",
                                              "messages": warn}, [])
        self.assertFalse(blocked["passed"])
        abort_probe = groups["suspended"][0]
        aborted = cp.score_probe(abort_probe, {"errorName": "AbortError", "messages": warn[:1]}, [])
        self.assertTrue(aborted["passed"], aborted["failed_checks"])
        sent = cp.score_probe(abort_probe, {"errorName": "AbortError", "messages": warn[:1]}, [capture_for(abort_probe)])
        self.assertFalse(sent["passed"])

    def test_summary_is_a_function_of_the_records(self):
        records = [
            {"passed": True, "category": "decision", "expected_action": "ALLOW", "receiver_count": 1},
            {"passed": True, "category": "decision", "expected_action": "BLOCK", "receiver_count": 0},
            {"passed": False, "category": "decision", "expected_action": "WARN", "receiver_count": 1},
            {"passed": True, "category": "failure-handling", "expected_action": "WARN", "receiver_count": 1},
        ]
        summary = cp.summarise(records)
        self.assertEqual((summary["total"], summary["passed"], summary["failed"]), (4, 3, 1))
        self.assertEqual(summary["allow_forwarded_unchanged"], 1)
        self.assertEqual(summary["block_zero_send"], 1)
        self.assertEqual(summary["warn_forwarded_unchanged"], 0)
        self.assertEqual(summary["by_category"]["decision"], {"total": 3, "passed": 2})

    def test_probe_id_attribution(self):
        self.assertEqual(cp.probe_id_from_path("/a/b?bl=x&xp=my.probe"), "my.probe")
        self.assertIsNone(cp.probe_id_from_path("/a/b"))


@unittest.skipUnless(shutil.which("openssl"), "openssl is required to mint the synthetic certificate")
class ReceiverTests(unittest.TestCase):
    def test_receiver_records_exact_bytes_and_serves_pages(self):
        with tempfile.TemporaryDirectory() as directory:
            cert, key, spki = receiver.generate_certificate(Path(directory))
            self.assertRegex(spki, r"^[A-Za-z0-9+/]{43}=$")
            server = receiver.Receiver(cert, key, port=0)
            port = server.server.server_address[1]
            server.start()
            try:
                context = ssl.create_default_context(cafile=str(cert))
                context.check_hostname = False
                payload = b'{"x": "\xc3\xa9"}'
                request = urllib.request.Request(f"https://127.0.0.1:{port}/p?xp=probe-1", data=payload,
                                                 headers={"Content-Type": "application/json", "Host": "chatgpt.com"})
                with urllib.request.urlopen(request, context=context, timeout=10) as response:
                    self.assertEqual(json.loads(response.read()), {"ok": True})
                page = urllib.request.Request(f"https://127.0.0.1:{port}/", headers={"Host": "chatgpt.com"})
                with urllib.request.urlopen(page, context=context, timeout=10) as response:
                    self.assertIn(b"synthetic", response.read())
            finally:
                server.stop()
            captures = server.captures_for("probe-1")
            self.assertEqual(len(captures), 1)
            self.assertEqual(captures[0].body, payload)
            self.assertEqual(captures[0].sha256, cp.sha256_hex(payload))
            self.assertEqual(server.unattributed(), [])
            self.assertEqual(server.foreign_hosts, [])


RECORD = ROOT / "paper" / "research" / "cross-platform-20261117.json"


@unittest.skipUnless(RECORD.is_file(), "the retained result record is not present")
class RecordTests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads(RECORD.read_text(encoding="utf8"))

    def test_stored_summaries_rederive_from_the_probe_records(self):
        for browser in self.record["browsers"]:
            if browser["status"] != "run":
                self.assertNotIn("probes", browser)
                continue
            self.assertEqual(browser["summary"], cp.summarise(browser["probes"]))
            self.assertEqual(browser["summary"]["total"], len(browser["probes"]))
            for probe in browser["probes"]:
                self.assertEqual(probe["passed"], all(probe["checks"].values()), probe["id"])

    def test_record_declares_live_validation_blocked_and_no_outside_traffic(self):
        self.assertTrue(any("Live-provider" in item for item in self.record["blocked"]))
        self.assertEqual(self.record["receiver"]["foreign_host_requests"], [])
        self.assertEqual(self.record["runtime"]["outbound_non_loopback_connections"], [])
        self.assertEqual(self.record["native_launcher_events"], [])
        for browser in self.record["browsers"]:
            if browser["status"] == "run":
                self.assertEqual(browser["unattributed_receiver_posts"], 0)

    def test_edge_copilot_gap_is_recorded_as_bypass_not_hidden(self):
        edge = next(b for b in self.record["browsers"] if b["key"] == "edge")
        failed = sorted(p["id"] for p in edge["probes"] if not p["passed"])
        self.assertEqual(len(failed), 12)
        self.assertTrue(all(name.startswith("copilot-") for name in failed))



class CoverageTests(unittest.TestCase):
    def test_provider_hosts_exclude_the_negative_control_host(self):
        self.assertNotIn("example.com", cp.PROVIDER_HOSTS)
        self.assertIn("copilot.microsoft.com", cp.PROVIDER_HOSTS)

    def test_coverage_status_distinguishes_surfaced_and_silent_gaps(self):
        self.assertEqual(cp.coverage_status(True, ""), "covered")
        # EDGE-COPILOT-1: Edge refuses the scripts but the extension badges the tab.
        self.assertEqual(cp.coverage_status(False, "!"), "gap_surfaced")
        self.assertEqual(cp.coverage_status(False, ""), "silent_gap")
        self.assertEqual(cp.coverage_status(False, {"harnessError": "n/a"}), "gap_badge_not_measured")


if __name__ == "__main__":
    unittest.main()
