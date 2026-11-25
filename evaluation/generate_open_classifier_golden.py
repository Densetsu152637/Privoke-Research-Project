"""Golden requests and parsed responses of the external classifier for the Rust client (RUST-S16, stage 16).

``extension/client-runtime/src/LLM/open_classifier.py`` is run unmodified against an in-process ``httpx.MockTransport``
(no network, no API key: the key is the literal ``PLACEHOLDER``). For each stage 0 worker-frame prompt the exact HTTP
request the OpenAI SDK builds is recorded (method, URL, headers and the body bytes), and for a set of recorded
responses the outcome of ``OpenClassifier.classify`` (the parsed results or the raised error text).

Host run, read-only on the environment::

    python evaluation/generate_open_classifier_golden.py \
        --out rust/crates/privoke-semantic/tests/fixtures/open_classifier_golden.json

The Python environment needs ``openai`` and ``httpx`` (recorded in the output). ``evaluation/.venv-v1-v3-pipeline`` lists
``openai`` but cannot import it (``httpx`` is missing), so the host interpreter with ``openai`` 3.3.1 is the reference.
The ``secret-key`` prompt of the corpus is left out (it holds a credential-shaped example string); the ``overlong``
prompt is recorded by hash only. The ``authorization`` header value is never recorded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
CLIENT = REPO / "extension" / "client-runtime"
PROMPTS = REPO / "tests" / "conformance" / "worker-frames" / "prompts.json"
SKIPPED_PROMPTS = {"secret-key"}
HASH_ONLY_PROMPTS = {"overlong"}
PLACEHOLDER_KEY = "PLACEHOLDER"
# SDK telemetry that depends on the host, never reproduced by the Rust client.
HOST_HEADERS = ("user-agent", "x-stainless-")
ENV_NAMES = (
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "OPENAI_API_BASE",
    "OPENAI_MODEL",
    "OPENAI_TIMEOUT_SECONDS",
    "OPENAI_TEMPERATURE",
    "OPENAI_MAX_TOKENS",
)


def bootstrap():
    """Import the client with only the pieces the classifier needs (no dotenv, no gRPC stack)."""
    for path in (CLIENT, REPO / "shared" / "python"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    if "privoke_service.stack_connection" not in sys.modules:
        package = types.ModuleType("privoke_service")
        package.__path__ = []
        stack = types.ModuleType("privoke_service.stack_connection")
        stack.load_runtime_environment = lambda root: None
        package.stack_connection = stack
        sys.modules["privoke_service"] = package
        sys.modules["privoke_service.stack_connection"] = stack
    # `src/LLM/__init__.py` imports the gRPC model streamer; bind the two packages without running their initialisers.
    for name, path in (("src", CLIENT / "src"), ("src.LLM", CLIENT / "src" / "LLM")):
        if name not in sys.modules:
            package = types.ModuleType(name)
            package.__path__ = [str(path)]
            sys.modules[name] = package
    from src.LLM import open_classifier

    return open_classifier


def load_prompts() -> list[dict]:
    prompts = json.loads(PROMPTS.read_text(encoding="utf-8"))["prompts"]
    return [prompt for prompt in prompts if prompt["id"] not in SKIPPED_PROMPTS]


class Recorder:
    """An ``httpx`` transport that records the request and replays one canned response."""

    def __init__(self, status: int = 200, body: bytes | str = b'{"choices": []}') -> None:
        import httpx

        self.httpx = httpx
        self.status = status
        self.body = body.encode("utf-8") if isinstance(body, str) else body
        self.requests: list = []

    def handler(self, request):
        self.requests.append(request)
        return self.httpx.Response(
            self.status, content=self.body, headers={"content-type": "application/json"}
        )


def make_classifier(module, recorder: Recorder, base_url: str | None, **options):
    """``OpenClassifier`` with its SDK client rebuilt on the mock transport (same options, no retries)."""
    from openai import OpenAI

    classifier = module.OpenClassifier(base_url=base_url, **options)
    client_options = {
        "api_key": PLACEHOLDER_KEY,
        "timeout": classifier.client.timeout,
        "http_client": recorder.httpx.Client(transport=recorder.httpx.MockTransport(recorder.handler)),
        "max_retries": 0,
    }
    if base_url:
        client_options["base_url"] = base_url
    classifier.client = OpenAI(**client_options)
    return classifier


def request_record(request) -> dict:
    headers = {}
    for name, value in request.headers.items():
        lowered = name.lower()
        if lowered == "authorization":
            scheme = value.split(" ", 1)[0]
            headers[lowered] = f"{scheme} <redacted>"
        elif any(lowered.startswith(prefix) for prefix in HOST_HEADERS):
            continue
        else:
            headers[lowered] = value
    body = request.content
    return {
        "method": request.method,
        "url": str(request.url),
        "headers": dict(sorted(headers.items())),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_len": len(body),
        "body": body.decode("utf-8"),
    }


def capture_request(module, text: str, base_url: str | None, **options) -> dict:
    recorder = Recorder()
    classifier = make_classifier(module, recorder, base_url, **options)
    try:
        classifier.classify(text)
    except RuntimeError:
        pass
    if len(recorder.requests) != 1:
        raise RuntimeError(f"expected exactly one request, saw {len(recorder.requests)}")
    return request_record(recorder.requests[0])


def request_cases(module) -> list[dict]:
    os.environ["OPENAI_API_KEY"] = PLACEHOLDER_KEY
    cases = []
    prompts = load_prompts()
    for prompt in prompts:
        record = capture_request(module, prompt["text"], None)
        if prompt["id"] in HASH_ONLY_PROMPTS:
            record["body"] = None
        cases.append({"id": f"default/{prompt['id']}", "prompt": prompt["id"], "config": "default", "request": record})
    probe = next(prompt for prompt in prompts if prompt["id"] == "email")
    configs = {
        "explicit": (
            "http://localhost:9/v1",
            {"model": "test-model", "temperature": 1.0, "max_tokens": 64},
        ),
        "slash_base": ("http://localhost:9/v1/", {"model": "test-model", "temperature": 0.0, "max_tokens": 1}),
        "two_point_zero": ("https://example.test/api", {"model": "m", "temperature": 2.0, "max_tokens": 4096}),
        "fractional": (None, {"model": "gpt-4.1", "temperature": 0.1, "max_tokens": 777}),
    }
    for name, (base_url, options) in configs.items():
        record = capture_request(module, probe["text"], base_url, **options)
        cases.append(
            {
                "id": f"{name}/email",
                "prompt": "email",
                "config": name,
                "base_url": base_url,
                "options": options,
                "request": record,
            }
        )
    return cases


def chat(content, **extra) -> str:
    message = {"role": "assistant", "content": content}
    message.update(extra)
    return json.dumps(
        {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
        }
    )


def finding(**overrides) -> dict:
    item = {
        "sensitivity": "S2",
        "visibility": "PU",
        "categories": ["HEALTH"],
        "section_of_text": "diabetes",
        "reasoning": "A health condition is disclosed.",
        "confidence": 0.9,
        "metadata": {},
    }
    item.update(overrides)
    return item


def without(key: str) -> dict:
    return {name: value for name, value in finding().items() if name != key}


def results(*items) -> str:
    return chat(json.dumps({"results": list(items)}))


MINIMAL = (
    '{"sensitivity": "S2", "visibility": "PU", "categories": [], "section_of_text": "x", "reasoning": "r"%s}'
)


def response_cases() -> list[dict]:
    """Recorded responses: (id, text classified, http status, raw HTTP body)."""
    text = "I was diagnosed with type 2 diabetes last March."
    start = text.index("diabetes")
    zoe = "Zoë lives in Zürich \U0001f600 and takes metformin."
    emoji = zoe.index(chr(0x1F600))
    utf16 = zoe.index("metformin") + 1
    all_categories = [
        "HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL",
        "SEXUAL", "CHILD", "LOCATION", "IDENTITY", "THIRD_PARTY",
    ]
    cases = [
        ("results_one", text, 200, results(finding())),
        ("results_empty_envelope", text, 200, chat('{"results": []}')),
        ("results_empty_envelope_spaced", text, 200, chat('  {"results" : [ ]}\n')),
        (
            "results_two_findings",
            text,
            200,
            results(
                finding(),
                finding(
                    sensitivity="S3", visibility="P4", categories=["HEALTH", "IDENTITY", "THIRD_PARTY"],
                    section_of_text="type 2", confidence=1, reasoning="r",
                ),
            ),
        ),
        ("classification_results_key", text, 200, chat(json.dumps({"classification_results": [finding()]}))),
        ("bare_object", text, 200, chat(json.dumps(finding()))),
        ("bare_list", text, 200, chat(json.dumps([finding()]))),
        ("bare_empty_list", text, 200, chat("[]")),
        ("results_not_list", text, 200, chat('{"results": "none"}')),
        ("results_null", text, 200, chat('{"results": null}')),
        ("results_empty_with_extra_key", text, 200, chat('{"results": [], "note": "x"}')),
        ("empty_object", text, 200, chat("{}")),
        ("json_string", text, 200, chat('"hello"')),
        ("json_number", text, 200, chat("3")),
        ("json_null", text, 200, chat("null")),
        ("s0_complete", text, 200, results(finding(sensitivity="S0", categories=[], confidence=0.0))),
        ("confidence_missing", text, 200, results(without("confidence"))),
        ("confidence_null", text, 200, results(finding(confidence=None))),
        ("confidence_integer_one", text, 200, results(finding(confidence=1))),
        ("confidence_integer_zero", text, 200, results(finding(confidence=0))),
        ("confidence_over_one", text, 200, results(finding(confidence=1.5))),
        ("confidence_negative", text, 200, results(finding(confidence=-0.1))),
        ("confidence_string", text, 200, results(finding(confidence="0.9"))),
        ("confidence_bool", text, 200, results(finding(confidence=True))),
        ("confidence_nan_token", text, 200, chat('{"results": [' + MINIMAL % ', "confidence": NaN' + "]}")),
        (
            "nan_in_metadata",
            text,
            200,
            chat('{"results": [' + MINIMAL % ', "metadata": {"a": NaN, "b": -Infinity}' + "]}"),
        ),
        ("bare_nan", text, 200, chat("NaN")),
        (
            "confidence_precise",
            text,
            200,
            chat('{"results": [' + MINIMAL % ', "confidence": 0.12345678901234568' + "]}"),
        ),
        ("unknown_sensitivity", text, 200, results(finding(sensitivity="S9"))),
        ("lowercase_sensitivity", text, 200, results(finding(sensitivity="s2"))),
        ("unknown_visibility", text, 200, results(finding(visibility="P9"))),
        ("sensitivity_missing", text, 200, results(without("sensitivity"))),
        ("visibility_missing", text, 200, results(without("visibility"))),
        ("unknown_category", text, 200, results(finding(categories=["HEALTH", "WEATHER"]))),
        ("categories_missing", text, 200, results(without("categories"))),
        ("categories_string", text, 200, results(finding(categories="HEALTH"))),
        ("categories_non_string_item", text, 200, results(finding(categories=[1]))),
        ("all_categories", text, 200, results(finding(categories=all_categories))),
        ("duplicate_categories", text, 200, results(finding(categories=["HEALTH", "HEALTH"]))),
        ("section_missing", text, 200, results(without("section_of_text"))),
        ("section_only_text_key", text, 200, results({**without("section_of_text"), "text": "diabetes"})),
        ("reasoning_missing", text, 200, results(without("reasoning"))),
        ("reasoning_number", text, 200, results(finding(reasoning=3))),
        ("metadata_missing", text, 200, results(without("metadata"))),
        ("metadata_list", text, 200, results(finding(metadata=[]))),
        (
            "metadata_reserved_keys",
            text,
            200,
            results(finding(metadata={"source": "x", "signal": 1, "signals": [], "keep": {"a": 1}})),
        ),
        ("span_valid", text, 200, results(finding(span=[start, start + 8]))),
        ("span_mismatch", text, 200, results(finding(span=[0, 8]))),
        ("span_reversed", text, 200, results(finding(span=[start + 8, start]))),
        ("span_empty_range", text, 200, results(finding(span=[3, 3]))),
        ("span_past_end", text, 200, results(finding(span=[start, 500]))),
        ("span_negative", text, 200, results(finding(span=[-1, 8]))),
        ("span_float", text, 200, results(finding(span=[float(start), float(start + 8)]))),
        ("span_bool", text, 200, chat('{"results": [' + MINIMAL % ', "span": [false, true]' + "]}")),
        ("span_wrong_length", text, 200, results(finding(span=[start]))),
        ("span_null", text, 200, results(finding(span=None))),
        ("span_not_list", text, 200, results(finding(span=f"{start}-{start + 8}"))),
        ("span_in_code_points", zoe, 200, results(finding(section_of_text="\U0001f600", span=[emoji, emoji + 1]))),
        ("span_in_code_points_word", zoe, 200, results(finding(section_of_text="metformin", span=[utf16 - 1, utf16 + 8]))),
        ("span_utf16_offsets_rejected", zoe, 200, results(finding(section_of_text="metformin", span=[utf16, utf16 + 9]))),
        ("item_not_object", text, 200, results(finding(), 3)),
        ("item_null", text, 200, results(None)),
        (
            "extra_fields_ignored",
            text,
            200,
            results(finding(extra="x", action="BLOCK", classification={"sensitivity": "S0"})),
        ),
        (
            "content_unicode_escapes",
            zoe,
            200,
            chat(
                '{"results": [{"sensitivity": "S1", "visibility": "P0", "categories": ["LOCATION"], '
                '"section_of_text": "Z\\u00fcrich", "reasoning": "caf\\u00e9 \\ud83d\\ude00", "confidence": 0.5}]}'
            ),
        ),
        (
            "duplicate_keys_last_wins",
            text,
            200,
            chat(
                '{"results": [{"sensitivity": "S1", "sensitivity": "S3", "visibility": "PU", "categories": [], '
                '"section_of_text": "x", "reasoning": "r"}]}'
            ),
        ),
        ("content_with_markdown_fence", text, 200, chat('```json\n{"results": []}\n```')),
        ("content_invalid_json", text, 200, chat("not json")),
        ("content_truncated_json", text, 200, chat('{"results": [{"sensitivity": "S2"')),
        ("content_empty_string", text, 200, chat("")),
        ("content_whitespace", text, 200, chat("  \n\t ")),
        ("content_null", text, 200, chat(None)),
        ("content_null_with_refusal", text, 200, chat(None, refusal="I cannot help with that.")),
        ("content_list", text, 200, chat([{"type": "text", "text": "{}"}])),
        ("content_number", text, 200, chat(5)),
        ("no_choices", text, 200, json.dumps({"id": "x", "choices": []})),
        (
            "choices_second_ignored",
            text,
            200,
            json.dumps(
                {
                    "id": "x",
                    "choices": [
                        {"index": 0, "message": {"role": "assistant", "content": '{"results": []}'}, "finish_reason": "stop"},
                        {"index": 1, "message": {"role": "assistant", "content": "not json"}, "finish_reason": "stop"},
                    ],
                }
            ),
        ),
        (
            "http_401",
            text,
            401,
            json.dumps({"error": {"message": "Incorrect credentials", "type": "invalid_request_error"}}),
        ),
        ("http_429", text, 429, json.dumps({"error": {"message": "Rate limit reached", "type": "rate_limit_error"}})),
        ("http_500", text, 500, json.dumps({"error": {"message": "server error"}})),
        ("http_500_html", text, 500, "<html>bad gateway</html>"),
        ("http_200_html", text, 200, "<html>not the api</html>"),
        ("http_200_empty", text, 200, ""),
        ("http_200_empty_object", text, 200, "{}"),
    ]
    return [{"id": id_, "text": txt, "status": status, "http_body": body} for id_, txt, status, body in cases]


def json_safe(value):
    """Non-finite floats become the strings the Rust parser substitutes for the NaN and Infinity tokens."""
    if isinstance(value, float) and value != value:
        return "NaN"
    if isinstance(value, float) and value in (float("inf"), float("-inf")):
        return "Infinity" if value > 0 else "-Infinity"
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    return value


def result_record(result) -> dict:
    return {
        "packed": result.classification.pack(),
        "section_of_text": result.section_of_text,
        "reasoning": result.reasoning,
        "span": None if result.span is None else list(result.span),
        "confidence": result.confidence,
        "metadata": json_safe(result.metadata),
    }


def run_response(module, case: dict) -> dict:
    os.environ["OPENAI_API_KEY"] = PLACEHOLDER_KEY
    recorder = Recorder(case["status"], case["http_body"])
    classifier = make_classifier(module, recorder, "http://localhost:9/v1")
    try:
        classified = classifier.classify(case["text"])
    except Exception as exc:  # noqa: BLE001 - the whole outcome is the recorded datum
        return {"status": "error", "type": type(exc).__name__, "message": str(exc)}
    return {"status": "ok", "results": [result_record(result) for result in classified]}


def environment_cases(module) -> list[dict]:
    """Outcomes of the constructor under a chosen environment (resolution order, defaults, errors)."""
    scenarios = {
        "defaults": {"OPENAI_API_KEY": PLACEHOLDER_KEY},
        "all_set": {
            "OPENAI_API_KEY": PLACEHOLDER_KEY,
            "OPENAI_BASE_URL": "http://localhost:9/v1",
            "OPENAI_MODEL": "env-model",
            "OPENAI_TIMEOUT_SECONDS": "12.5",
            "OPENAI_TEMPERATURE": "0.75",
            "OPENAI_MAX_TOKENS": "99",
        },
        "api_base_fallback": {"OPENAI_API_KEY": PLACEHOLDER_KEY, "OPENAI_API_BASE": "http://localhost:8/v1"},
        "base_url_wins": {
            "OPENAI_API_KEY": PLACEHOLDER_KEY,
            "OPENAI_BASE_URL": "http://localhost:9/v1",
            "OPENAI_API_BASE": "http://localhost:8/v1",
        },
        "empty_base_url_falls_through": {
            "OPENAI_API_KEY": PLACEHOLDER_KEY,
            "OPENAI_BASE_URL": "",
            "OPENAI_API_BASE": "http://localhost:8/v1",
        },
        "empty_model_default": {"OPENAI_API_KEY": PLACEHOLDER_KEY, "OPENAI_MODEL": ""},
        "no_key": {},
        "empty_key": {"OPENAI_API_KEY": ""},
        "zero_timeout": {"OPENAI_API_KEY": PLACEHOLDER_KEY, "OPENAI_TIMEOUT_SECONDS": "0"},
        "negative_timeout": {"OPENAI_API_KEY": PLACEHOLDER_KEY, "OPENAI_TIMEOUT_SECONDS": "-1"},
        "bad_timeout": {"OPENAI_API_KEY": PLACEHOLDER_KEY, "OPENAI_TIMEOUT_SECONDS": "soon"},
        "bad_temperature": {"OPENAI_API_KEY": PLACEHOLDER_KEY, "OPENAI_TEMPERATURE": "warm"},
        "zero_max_tokens": {"OPENAI_API_KEY": PLACEHOLDER_KEY, "OPENAI_MAX_TOKENS": "0"},
        "bad_max_tokens": {"OPENAI_API_KEY": PLACEHOLDER_KEY, "OPENAI_MAX_TOKENS": "1.5"},
        "padded_numbers": {
            "OPENAI_API_KEY": PLACEHOLDER_KEY,
            "OPENAI_TEMPERATURE": " 0.5 ",
            "OPENAI_MAX_TOKENS": " 8 ",
            "OPENAI_TIMEOUT_SECONDS": " 3 ",
        },
    }
    cases = []
    for name, values in scenarios.items():
        for key in ENV_NAMES:
            os.environ.pop(key, None)
        os.environ.update(values)
        try:
            classifier = module.OpenClassifier()
        except Exception as exc:  # noqa: BLE001
            outcome = {"status": "error", "type": type(exc).__name__, "message": str(exc)}
        else:
            outcome = {
                "status": "ok",
                "model": classifier.model,
                "temperature": classifier.temperature,
                "max_tokens": classifier.max_tokens,
                "base_url": str(classifier.client.base_url),
                "timeout": classifier.client.timeout,
            }
        cases.append({"id": name, "environment": values, "outcome": outcome})
    return cases


def build() -> dict:
    module = bootstrap()
    import httpx
    import openai

    saved = {name: os.environ.pop(name, None) for name in ENV_NAMES}
    try:
        document = {
            "note": (
                "Generated by evaluation/generate_open_classifier_golden.py from the unmodified Python client against "
                "an in-process mock transport. The API key is the literal PLACEHOLDER and is never recorded; "
                "host-dependent SDK headers (user-agent, x-stainless-*) are omitted."
            ),
            "openai": openai.__version__,
            "httpx": httpx.__version__,
            "python": sys.version.split()[0],
            "requests": request_cases(module),
            "responses": [],
            "environments": environment_cases(module),
        }
        for case in response_cases():
            document["responses"].append({**case, "python": run_response(module, case)})
    finally:
        for key in ENV_NAMES:
            os.environ.pop(key, None)
        for name, value in saved.items():
            if value is not None:
                os.environ[name] = value
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    document = build()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(document, indent=1, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(f"wrote {args.out}: {len(document['requests'])} requests, {len(document['responses'])} responses")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
