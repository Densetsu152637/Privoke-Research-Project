"""Probe catalogue and pure scoring for the cross-platform study (XPLAT-20261117).

The catalogue mirrors the probe categories of the Linux installed-browser
evidence (ALLOW unchanged send, BLOCK zero-send, WARN forwarding, failure
handling) for the Windows host. Everything here is pure so that it can be
unit-tested without a browser; the orchestrator is ``cross_platform_study.py``.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

REPO_ROOT = Path(__file__).resolve().parents[1]
SHAPES_JSON = REPO_ROOT / "extension" / "test" / "fixtures" / "provider-shapes.json"
SHAPES_MODULE = REPO_ROOT / "extension" / "test" / "fixtures" / "provider-shapes.mjs"

# Frozen synthetic prompts shared with the Linux installed-browser probes.
CASES: dict[str, dict[str, Any]] = {
    "ALLOW": {"prompt": "Please explain the steps in this process.", "forwarded": True},
    "WARN": {"prompt": "My profile handle is @privoke_fixture.", "forwarded": True},
    "BLOCK": {"prompt": "Contact alex@example.com about the draft.", "forwarded": False},
}
TRANSPORTS = ("fetch", "xhr")
BASE_SHAPE = "chatgpt-conversation"

CATEGORY_DECISION = "decision"
CATEGORY_PROVIDER_SHAPE = "provider-shape"
CATEGORY_NEGATIVE = "negative-control"
CATEGORY_FAILURE = "failure-handling"

FIXTURE_HOSTS = (
    "chatgpt.com", "chat.openai.com", "claude.ai", "gemini.google.com",
    "copilot.microsoft.com", "api.openai.com", "example.com",
)


@dataclass
class ProbeDef:
    id: str
    category: str
    transport: str
    shape_id: str
    url: str
    page_url: str
    prompt: str
    body: str
    content_type: str
    expected_action: str | None  # ALLOW/WARN/BLOCK from the real detector, None when no analysis
    expected_forwarded: bool
    expects_analysis: bool = True
    target_app: str | None = None
    fault: str | None = None  # None | "unavailable" | "suspended"
    abort_after_ms: int | None = None
    expect_failure_warn: bool = False
    expect_abort: bool = False
    timeout_ms: int = 120_000
    notes: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""

    def request_url(self) -> str:
        sep = "&" if urlsplit(self.url).query else "?"
        return f"{self.url}{sep}xp={self.id}"

    def to_spec(self) -> dict[str, Any]:
        spec: dict[str, Any] = {
            "transport": self.transport,
            "url": self.request_url(),
            "headers": {"content-type": self.content_type},
            "body": self.body,
        }
        if self.abort_after_ms is not None:
            spec["abortAfterMs"] = self.abort_after_ms
        return spec


def load_shapes() -> dict[str, Any]:
    return json.loads(SHAPES_JSON.read_text(encoding="utf8"))


def dump_bodies(node: str = "node") -> dict[str, dict[str, dict[str, str]]]:
    """Ask the shared JS builder for every shape x prompt body (single source)."""
    prompts = {name: case["prompt"] for name, case in CASES.items()}
    result = subprocess.run(
        [node, str(SHAPES_MODULE), "--dump", json.dumps(prompts)],
        check=True, capture_output=True, text=True, cwd=str(REPO_ROOT / "extension"),
    )
    return json.loads(result.stdout)


def page_url_for(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.hostname}/"


def _decision_probe(shape: dict[str, Any], bodies: dict, transport: str, action: str,
                    category: str) -> ProbeDef:
    built = bodies["shapes"][shape["id"]][action]
    return ProbeDef(
        id=f"{shape['id']}.{transport}.{action.lower()}",
        category=category, transport=transport, shape_id=shape["id"], url=shape["url"],
        page_url=page_url_for(shape["url"]), prompt=CASES[action]["prompt"],
        body=built["text"], content_type=built["contentType"],
        expected_action=action, expected_forwarded=CASES[action]["forwarded"],
        target_app=shape["targetApp"],
    )


def build_catalogue(bodies: dict) -> list[ProbeDef]:
    """Non-fault probes: decision (base shape) and provider-shape probes plus negatives."""
    shapes = load_shapes()
    probes: list[ProbeDef] = []
    for shape in shapes["shapes"]:
        category = CATEGORY_DECISION if shape["id"] == BASE_SHAPE else CATEGORY_PROVIDER_SHAPE
        for transport in TRANSPORTS:
            for action in CASES:
                probes.append(_decision_probe(shape, bodies, transport, action, category))
    for control in shapes["negativeControls"]:
        built = bodies["negativeControls"][control["id"]]
        probes.append(ProbeDef(
            id=f"{control['id']}.fetch", category=CATEGORY_NEGATIVE, transport="fetch",
            shape_id=control["id"], url=control["url"], page_url=page_url_for("https://chatgpt.com/"),
            prompt=CASES["BLOCK"]["prompt"], body=built["text"], content_type=built["contentType"],
            expected_action=None, expected_forwarded=True, expects_analysis=False,
        ))
    return probes


def build_failure_probes(bodies: dict) -> dict[str, list[ProbeDef]]:
    """Failure-handling probes grouped by the runtime fault they need."""
    shapes = {shape["id"]: shape for shape in load_shapes()["shapes"]}
    base = shapes[BASE_SHAPE]

    def make(name: str, transport: str, action: str, **kwargs: Any) -> ProbeDef:
        probe = _decision_probe(base, bodies, transport, action, CATEGORY_FAILURE)
        probe.id = f"failure.{name}"
        for key, value in kwargs.items():
            setattr(probe, key, value)
        return probe

    unavailable = [
        make("unavailable.fetch.block-prompt", "fetch", "BLOCK", fault="unavailable",
             expected_action="WARN", expected_forwarded=True, expect_failure_warn=True,
             notes="runtime unreachable: a BLOCK-worthy prompt fails open with a warning"),
        make("unavailable.xhr.block-prompt", "xhr", "BLOCK", fault="unavailable",
             expected_action="WARN", expected_forwarded=True, expect_failure_warn=True),
    ]
    recovery = [
        make("recovered.fetch.block", "fetch", "BLOCK"),
        make("recovered.xhr.allow", "xhr", "ALLOW"),
    ]
    suspended = [
        make("suspended.fetch.abort", "fetch", "BLOCK", fault="suspended", abort_after_ms=1500,
             expected_action=None, expected_forwarded=False, expect_abort=True,
             notes="caller cancellation while the runtime is hung: no send, AbortError"),
        make("suspended.xhr.abort", "xhr", "BLOCK", fault="suspended", abort_after_ms=1500,
             expected_action=None, expected_forwarded=False, expect_abort=True),
        make("suspended.fetch.timeout", "fetch", "BLOCK", fault="suspended",
             expected_action="WARN", expected_forwarded=True, expect_failure_warn=True,
             timeout_ms=90_000, notes="runtime hung past the analysis deadline: fail open once"),
        make("suspended.xhr.timeout", "xhr", "BLOCK", fault="suspended",
             expected_action="WARN", expected_forwarded=True, expect_failure_warn=True,
             timeout_ms=90_000),
    ]
    recovery_after_suspend = [
        make("resumed.fetch.block", "fetch", "BLOCK"),
        make("resumed.xhr.allow", "xhr", "ALLOW"),
    ]
    return {
        "unavailable": unavailable,
        "recovered": recovery,
        "suspended": suspended,
        "resumed": recovery_after_suspend,
    }


# --- scoring ---------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Capture:
    probe: str | None
    host: str
    method: str
    path: str
    content_type: str | None
    body: bytes

    @property
    def sha256(self) -> str:
        return sha256_hex(self.body)


def probe_id_from_path(path: str) -> str | None:
    values = parse_qs(urlsplit(path).query).get("xp")
    return values[0] if values else None


def _messages(outcome: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    return [m for m in outcome.get("messages", []) if m.get("type") == kind]


def score_probe(probe: ProbeDef, outcome: dict[str, Any], captures: list[Capture]) -> dict[str, Any]:
    """Return a verdict record; ``passed`` is true only when every check holds."""
    checks: dict[str, bool] = {}
    reasons: list[str] = []
    if "harnessError" in outcome or outcome.get("error"):
        return {"id": probe.id, "passed": False, "checks": {"harness": False},
                "reasons": [f"harness error: {outcome.get('harnessError') or outcome.get('error')}"],
                "receiver_count": len(captures)}

    results = _messages(outcome, "ANALYZE_RESULT")
    prompts = _messages(outcome, "ANALYZE_PROMPT")
    action = results[-1]["action"] if results else None

    if probe.expects_analysis:
        checks["one_analysis_request"] = len(prompts) == 1
        if prompts:
            checks["analysed_prompt_exact"] = prompts[0].get("text") == probe.prompt
            if probe.target_app:
                checks["target_app"] = prompts[0].get("targetApp") == probe.target_app
        if not probe.expect_abort:
            checks["action_observed"] = action == probe.expected_action
        if probe.expect_failure_warn:
            checks["failure_notice_rendered"] = bool(results) and results[-1].get("noticeStatus") == "RENDERED"
    else:
        checks["no_analysis"] = not prompts and not results

    checks["receiver_count"] = len(captures) == int(probe.expected_forwarded)
    if probe.expected_forwarded and captures:
        capture = captures[0]
        expected_path = urlsplit(probe.request_url())
        checks["forwarded_method_post"] = capture.method == "POST"
        checks["forwarded_path"] = capture.path == expected_path.path + ("?" + expected_path.query if expected_path.query else "")
        checks["forwarded_host"] = capture.host.split(":")[0] == probe.host
        checks["forwarded_body_unchanged"] = capture.body == probe.body.encode("utf8")
        checks["forwarded_body_sha256"] = capture.sha256 == sha256_hex(probe.body.encode("utf8"))

    if probe.transport == "fetch":
        if probe.expect_abort:
            checks["fetch_abort_error"] = outcome.get("errorName") == "AbortError"
        elif probe.expected_forwarded:
            checks["fetch_resolved_200"] = outcome.get("status") == 200 and not outcome.get("errorName")
        else:
            checks["fetch_rejected_typeerror"] = (outcome.get("errorName") == "TypeError"
                                                  and "blocked" in str(outcome.get("errorMessage", "")).lower())
    else:
        events = outcome.get("events", [])
        if probe.expect_abort:
            checks["xhr_abort_events"] = "abort" in events and "loadend" in events
        elif probe.expected_forwarded:
            checks["xhr_resolved_200"] = outcome.get("status") == 200 and "load" in events
        else:
            checks["xhr_blocked_terminal"] = (outcome.get("status") == 0 and outcome.get("readyState") == 4
                                              and "error" in events and "loadend" in events)

    for name, ok in checks.items():
        if not ok:
            reasons.append(name)
    return {
        "id": probe.id, "category": probe.category, "transport": probe.transport,
        "shape": probe.shape_id, "host": probe.host, "expected_action": probe.expected_action,
        "observed_action": action, "expected_forwarded": probe.expected_forwarded,
        "receiver_count": len(captures), "passed": all(checks.values()), "checks": checks,
        "failed_checks": reasons, "elapsed_ms": outcome.get("elapsedMs"),
        "page_error": outcome.get("errorName"),
    }


def summarise(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts derived only from the per-probe records."""
    by_category: dict[str, dict[str, int]] = {}
    for record in records:
        bucket = by_category.setdefault(record.get("category", "unknown"), {"total": 0, "passed": 0})
        bucket["total"] += 1
        bucket["passed"] += int(bool(record["passed"]))
    return {
        "total": len(records),
        "passed": sum(1 for r in records if r["passed"]),
        "failed": sum(1 for r in records if not r["passed"]),
        "allow_forwarded_unchanged": sum(1 for r in records if r.get("expected_action") == "ALLOW"
                                         and r["passed"] and r["receiver_count"] == 1),
        "warn_forwarded_unchanged": sum(1 for r in records if r.get("expected_action") == "WARN"
                                        and r.get("category") != CATEGORY_FAILURE
                                        and r["passed"] and r["receiver_count"] == 1),
        "block_zero_send": sum(1 for r in records if r.get("expected_action") == "BLOCK"
                               and r["passed"] and r["receiver_count"] == 0),
        "by_category": by_category,
    }
