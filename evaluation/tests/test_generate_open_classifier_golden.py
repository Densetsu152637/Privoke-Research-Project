"""Mechanics of the external-classifier golden generator (RUST-S16), with no network and no API key."""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "evaluation"))
golden = importlib.import_module("generate_open_classifier_golden")

FIXTURE = REPO / "rust" / "crates" / "privoke-semantic" / "tests" / "fixtures" / "open_classifier_golden.json"


def sdk_available() -> bool:
    return all(importlib.util.find_spec(name) is not None for name in ("openai", "httpx"))


class CommittedFixtureTest(unittest.TestCase):
    """The committed fixture, read as data (no SDK needed)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_body_hashes_match_the_recorded_bodies(self) -> None:
        for case in self.document["requests"]:
            request = case["request"]
            if request["body"] is None:
                continue
            body = request["body"].encode("utf-8")
            self.assertEqual(hashlib.sha256(body).hexdigest(), request["body_sha256"], case["id"])
            self.assertEqual(len(body), request["body_len"], case["id"])

    def test_no_credential_is_recorded(self) -> None:
        text = FIXTURE.read_text(encoding="utf-8")
        self.assertNotIn("AWS_SECRET", text)
        self.assertNotIn("sk-", text)
        for case in self.document["requests"]:
            self.assertEqual(case["request"]["headers"]["authorization"], "Bearer <redacted>")
        prompts = {case["prompt"] for case in self.document["requests"]}
        self.assertNotIn("secret-key", prompts)

    def test_every_remaining_corpus_prompt_is_covered(self) -> None:
        wanted = {prompt["id"] for prompt in golden.load_prompts()}
        got = {case["prompt"] for case in self.document["requests"] if case["config"] == "default"}
        self.assertEqual(wanted, got)

    def test_response_cases_cover_ok_and_error_outcomes(self) -> None:
        outcomes = {case["python"]["status"] for case in self.document["responses"]}
        self.assertEqual(outcomes, {"ok", "error"})
        self.assertGreaterEqual(len(self.document["responses"]), 80)


@unittest.skipUnless(sdk_available(), "openai and httpx are not installed in this interpreter")
class RegenerationTest(unittest.TestCase):
    def test_regeneration_reproduces_the_committed_request_bodies(self) -> None:
        document = golden.build()
        committed = json.loads(FIXTURE.read_text(encoding="utf-8"))
        if document["openai"] != committed["openai"]:
            self.skipTest(f"SDK {document['openai']} differs from the recorded {committed['openai']}")
        self.assertEqual(
            [case["request"]["body_sha256"] for case in document["requests"]],
            [case["request"]["body_sha256"] for case in committed["requests"]],
        )
        self.assertEqual(document["responses"], committed["responses"])


if __name__ == "__main__":
    unittest.main()
