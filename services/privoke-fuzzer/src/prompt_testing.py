from __future__ import annotations

import argparse
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List
from urllib import error, request

DEFAULT_DUMP_DIR = "/workspace/dumps/privoke-fuzzer"
DEFAULT_RUNTIME_URL = "http://client-runtime:8765"
DEFAULT_SOURCE = "privoke-fuzzer-test"
DEFAULT_PROMPT = (
    "Summarize whether this text contains private information: "
    "my email is alex@example.com and my card is 4111 1111 1111 1111."
)
LAYER_CHOICES = (
    "runtime",
    "pipeline",
    "regex",
    "ner",
    "semantic",
    "semantic-streamed",
    "semantic-local",
    "semantic-openai",
)


def add_test_prompt_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--layer",
        action="append",
        choices=LAYER_CHOICES,
        help=(
            "Detection layer to exercise. Repeat to run multiple layers. "
            "Defaults to runtime."
        ),
    )
    parser.add_argument(
        "--runtime-url",
        default=os.getenv("PRIVOKE_RUNTIME_URL", DEFAULT_RUNTIME_URL),
        help="Base client-runtime URL or full /analyze URL for runtime-layer tests.",
    )
    parser.add_argument(
        "--endpoint",
        default="/analyze",
        help="Prompt analysis path when --runtime-url is a base URL.",
    )
    parser.add_argument(
        "-p",
        "--prompt",
        action="append",
        help="Prompt text to test. May be supplied multiple times.",
    )
    parser.add_argument(
        "--prompt-file",
        help=(
            "Path to a JSON, JSONL, or text file. JSON entries may be strings "
            "or objects with text/prompt fields."
        ),
    )
    parser.add_argument(
        "--generated-count",
        type=int,
        default=0,
        help="Generate this many prompts from the fuzzer prompt dataset.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=int(os.getenv("FUZZ_SEED", "1337")),
        help="Seed used when --generated-count is set.",
    )
    parser.add_argument(
        "--dataset-path",
        default=os.getenv("FUZZ_PROMPT_DATASET_PATH"),
        help="Optional JSON/JSONL prompt seed dataset for generated prompts.",
    )
    parser.add_argument(
        "--semantic-backend",
        choices=("streamed", "local", "openai"),
        default=os.getenv("PRIVOKE_TEST_SEMANTIC_BACKEND", "streamed"),
        help="Backend used by --layer semantic.",
    )
    parser.add_argument("--llm-base-url", help="Base URL for local/OpenAI-like tests.")
    parser.add_argument("--llm-model", help="Model id for semantic layer tests.")
    parser.add_argument("--llm-api-key", help="API key for local/OpenAI-like tests.")
    parser.add_argument(
        "--model-streaming-target",
        default=os.getenv("MODEL_STREAMING_TARGET"),
        help="gRPC target for streamed semantic layer tests.",
    )
    parser.add_argument(
        "--dump-dir",
        default=os.getenv("PRIVOKE_FUZZER_DUMP_DIR", DEFAULT_DUMP_DIR),
        help="Directory where a JSON result file will be written.",
    )
    parser.add_argument(
        "--source",
        default=DEFAULT_SOURCE,
        help="source value included in runtime prompt inspection requests.",
    )
    parser.add_argument("--target-app", help="Optional target_app value.")
    parser.add_argument("--visibility-hint", help="Optional visibility hint, e.g. P3.")
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=120.0,
        help="HTTP/model timeout for prompt tests.",
    )


def run_prompt_tests(args: argparse.Namespace) -> None:
    if args.timeout_seconds <= 0:
        raise SystemExit("--timeout-seconds must be greater than zero.")
    if args.generated_count < 0:
        raise SystemExit("--generated-count must be zero or greater.")

    layers = _normalise_layers(args.layer, args.semantic_backend)
    prompt_requests = _build_prompt_requests(args)
    run_id = _run_id()
    started_at = datetime.now(timezone.utc).isoformat()

    results = []
    for index, prompt_request in enumerate(prompt_requests, start=1):
        runtime_request = _runtime_request(prompt_request, args, run_id, index)
        prompt_result = {
            "index": index,
            "request": runtime_request,
            "expected_classification": prompt_request.get("expected_classification"),
            "layers": {},
        }
        for layer in layers:
            prompt_result["layers"][layer] = _run_layer(
                layer,
                prompt_request,
                args,
                runtime_request,
            )
        results.append(prompt_result)

    payload = {
        "run_id": run_id,
        "created_at": started_at,
        "layers": layers,
        "runtime_url": _analyze_url(args.runtime_url, args.endpoint),
        "results": results,
    }
    output_path = _write_dump(Path(args.dump_dir), run_id, payload)

    summary = _summary(results, output_path)
    print(json.dumps(summary, indent=2, sort_keys=True))


def _normalise_layers(
    raw_layers: List[str] | None,
    semantic_backend: str,
) -> List[str]:
    layers = raw_layers or ["runtime"]
    normalised = []
    for layer in layers:
        resolved = (
            f"semantic-{semantic_backend}"
            if layer == "semantic"
            else layer
        )
        if resolved not in normalised:
            normalised.append(resolved)
    return normalised


def _build_prompt_requests(args: argparse.Namespace) -> List[Dict[str, Any]]:
    prompt_requests = []

    for prompt in args.prompt or []:
        prompt_requests.append({"text": prompt})

    if args.prompt_file:
        prompt_requests.extend(_load_prompt_file(Path(args.prompt_file)))

    if args.generated_count:
        prompt_requests.extend(
            _generated_prompt_requests(
                args.generated_count,
                args.seed,
                args.dataset_path,
            )
        )

    if not prompt_requests:
        prompt_requests.append({"text": DEFAULT_PROMPT})

    return prompt_requests


def _generated_prompt_requests(
    count: int,
    seed: int,
    dataset_path: str | None,
) -> List[Dict[str, Any]]:
    from prompt_generation import generate_training_prompts

    generated = generate_training_prompts(
        count=count,
        seed=seed,
        dataset_path=dataset_path,
    )
    return [
        {
            "text": example.text,
            "expected_classification": example.expected_classification.to_dict(),
            "metadata": dict(example.metadata),
        }
        for example in generated
    ]


def _load_prompt_file(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise SystemExit(f"Prompt file does not exist: {path}")

    if path.suffix.lower() == ".jsonl":
        return [
            _prompt_request_from_value(json.loads(line))
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    if path.suffix.lower() == ".json":
        parsed = json.loads(path.read_text(encoding="utf-8"))
        return [_prompt_request_from_value(item) for item in _json_prompt_items(parsed)]

    return [
        {"text": line.strip()}
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _json_prompt_items(parsed: Any) -> Iterable[Any]:
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        for key in ("prompts", "samples", "data", "requests"):
            value = parsed.get(key)
            if isinstance(value, list):
                return value
        return [parsed]
    raise SystemExit("JSON prompt file must contain an object or list.")


def _prompt_request_from_value(value: Any) -> Dict[str, Any]:
    if isinstance(value, str):
        return {"text": value}
    if not isinstance(value, dict):
        raise SystemExit("Prompt entries must be strings or JSON objects.")

    prompt_text = value.get("text", value.get("prompt"))
    if not isinstance(prompt_text, str) or not prompt_text.strip():
        raise SystemExit("Prompt objects must include a non-empty text or prompt field.")

    payload = dict(value)
    payload["text"] = prompt_text.strip()
    payload.pop("prompt", None)
    return payload


def _run_layer(
    layer: str,
    prompt_request: Dict[str, Any],
    args: argparse.Namespace,
    runtime_request: Dict[str, Any],
) -> Dict[str, Any]:
    try:
        if layer == "runtime":
            return _run_runtime_layer(runtime_request, args)
        if layer == "pipeline":
            return _run_pipeline_layer(prompt_request)
        if layer == "regex":
            return _run_regex_layer(prompt_request["text"])
        if layer == "ner":
            return _run_ner_layer(prompt_request["text"])
        if layer == "semantic-streamed":
            return _run_semantic_streamed_layer(prompt_request["text"], args)
        if layer == "semantic-local":
            return _run_semantic_local_layer(prompt_request["text"], args)
        if layer == "semantic-openai":
            return _run_semantic_openai_layer(prompt_request["text"], args)
    except Exception as exc:
        return {
            "status": "error",
            "error": str(exc),
        }

    return {
        "status": "error",
        "error": f"Unsupported layer: {layer}",
    }


def _run_runtime_layer(
    runtime_request: Dict[str, Any],
    args: argparse.Namespace,
) -> Dict[str, Any]:
    return _post_prompt(
        _analyze_url(args.runtime_url, args.endpoint),
        runtime_request,
        args.timeout_seconds,
    )


def _run_pipeline_layer(prompt_request: Dict[str, Any]) -> Dict[str, Any]:
    from privoke_client_runtime.hosting.analyzer import analyse_prompt_request
    from privoke_client_runtime.hosting.serialization import parse_prompt_request

    request_payload = {"text": prompt_request["text"]}
    for key in ("source", "target_app", "visibility_hint", "request_id", "metadata"):
        if key in prompt_request:
            request_payload[key] = prompt_request[key]

    return {
        "status": "ok",
        "response": analyse_prompt_request(parse_prompt_request(request_payload)),
    }


def _run_regex_layer(text: str) -> Dict[str, Any]:
    from privoke_client_runtime.detection import normalize_text
    from privoke_client_runtime.regex.rule_detector import RuleDetector

    results = RuleDetector().analyze(normalize_text(text))
    return _direct_results_response(results)


def _run_ner_layer(text: str) -> Dict[str, Any]:
    from privoke_client_runtime.NER import EntityNERDetector
    from privoke_client_runtime.detection import normalize_text

    results = EntityNERDetector().extract_entities(normalize_text(text))
    return _direct_results_response(results)


def _run_semantic_streamed_layer(
    text: str,
    args: argparse.Namespace,
) -> Dict[str, Any]:
    from privoke_client_runtime.LLM.privoke_classifier import PriVokeClassifier

    model_id = args.llm_model or os.getenv("MODEL_ID")
    classifier = PriVokeClassifier(
        target=args.model_streaming_target,
        model_id=model_id,
        timeout_seconds=args.timeout_seconds,
    )
    return _direct_results_response(classifier.classify(text))


def _run_semantic_local_layer(
    text: str,
    args: argparse.Namespace,
) -> Dict[str, Any]:
    from privoke_client_runtime.LLM.local_classifier import LocalClassifier

    classifier = LocalClassifier(
        base_url=args.llm_base_url,
        model=args.llm_model,
        api_key=args.llm_api_key,
        timeout_seconds=args.timeout_seconds,
    )
    return _direct_results_response(classifier.classify(text))


def _run_semantic_openai_layer(
    text: str,
    args: argparse.Namespace,
) -> Dict[str, Any]:
    from privoke_client_runtime.LLM.open_classifier import OpenClassifier

    classifier = OpenClassifier(
        base_url=args.llm_base_url,
        model=args.llm_model,
        api_key=args.llm_api_key,
        timeout_seconds=args.timeout_seconds,
    )
    return _direct_results_response(classifier.classify(text))


def _direct_results_response(results) -> Dict[str, Any]:
    return {
        "status": "ok",
        "result_count": len(results),
        "results": [result.to_dict() for result in results],
    }


def _runtime_request(
    prompt_request: Dict[str, Any],
    args: argparse.Namespace,
    run_id: str | None,
    index: int | None,
) -> Dict[str, Any]:
    metadata = prompt_request.get("metadata")
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, dict):
        raise SystemExit("Prompt request metadata must be a JSON object.")

    payload = {
        "text": prompt_request["text"],
        "source": prompt_request.get("source", args.source),
        "metadata": dict(metadata),
    }
    if run_id is not None:
        payload["metadata"].update(
            {
                "test_run_id": run_id,
                "test_index": index,
            }
        )
    for key in ("target_app", "visibility_hint", "request_id"):
        value = prompt_request.get(key, getattr(args, key, None))
        if value is not None:
            payload[key] = value
    return payload


def _analyze_url(runtime_url: str, endpoint: str) -> str:
    base = runtime_url.rstrip("/")
    if base.endswith("/analyze") or base.endswith("/v1/analyze"):
        return base

    path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
    return f"{base}{path}"


def _post_prompt(
    url: str,
    payload: Dict[str, Any],
    timeout_seconds: float,
) -> Dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request_obj = request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with request.urlopen(request_obj, timeout=timeout_seconds) as response:
            response_body = response.read().decode("utf-8")
            return {
                "status": "ok",
                "http_status": response.status,
                "response": json.loads(response_body),
            }
    except error.HTTPError as exc:
        response_body = exc.read().decode("utf-8", errors="replace")
        return {
            "status": "error",
            "http_status": exc.code,
            "error": _parse_error_body(response_body),
        }
    except error.URLError as exc:
        return {
            "status": "error",
            "http_status": None,
            "error": str(exc.reason),
        }


def _parse_error_body(body: str) -> Any:
    try:
        return json.loads(body)
    except ValueError:
        return body


def _write_dump(dump_dir: Path, run_id: str, payload: Dict[str, Any]) -> Path:
    dump_dir.mkdir(parents=True, exist_ok=True)
    output_path = dump_dir / f"{run_id}.json"
    output_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return output_path


def _summary(results: List[Dict[str, Any]], output_path: Path) -> Dict[str, Any]:
    failed = 0
    layer_counts: Dict[str, Dict[str, int]] = {}
    for result in results:
        for layer, layer_result in result["layers"].items():
            status = layer_result.get("status", "error")
            if status != "ok":
                failed += 1
            layer_counts.setdefault(layer, {"ok": 0, "error": 0})
            layer_counts[layer]["ok" if status == "ok" else "error"] += 1

    return {
        "output_path": str(output_path),
        "prompt_count": len(results),
        "layer_counts": layer_counts,
        "failed_layer_runs": failed,
    }


def _run_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"fuzzer-test-prompts-{timestamp}-{uuid.uuid4().hex[:8]}"
