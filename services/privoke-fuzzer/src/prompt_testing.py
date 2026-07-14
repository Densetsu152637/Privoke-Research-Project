from __future__ import annotations

import argparse
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

DEFAULT_DUMP_DIR = "/workspace/dumps/privoke-fuzzer"
DEFAULT_SOURCE = "privoke-fuzzer-test"
DEFAULT_PROMPT = (
    "Summarize whether this text contains private information: "
    "my email is alex@example.com and my card is 4111 1111 1111 1111."
)
LAYER_CHOICES = (
    "runtime",
    "regex",
    "ner",
    "semantic",
)


def add_test_prompt_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--runtime-target",
        default=os.getenv("PRIVOKE_RUNTIME_TARGET", "privoke-runtime:50054"),
        help="gRPC target for the locally running PriVoke runtime.",
    )
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
    regex_order = parser.add_mutually_exclusive_group()
    regex_order.add_argument(
        "--regex-first",
        action="store_const",
        const=True,
        dest="regex_first",
        help="Ask the runtime to complete regex detection before other layers.",
    )
    regex_order.add_argument(
        "--regex-parallel",
        action="store_const",
        const=False,
        dest="regex_first",
        help="Ask the runtime to schedule regex with the other requested layers.",
    )
    parser.set_defaults(regex_first=None)
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
        help="Model timeout for semantic prompt tests.",
    )


def run_prompt_tests(args: argparse.Namespace) -> None:
    if args.timeout_seconds <= 0:
        raise SystemExit("--timeout-seconds must be greater than zero.")
    if args.generated_count < 0:
        raise SystemExit("--generated-count must be zero or greater.")

    layers = _normalise_layers(args.layer)
    prompt_requests = _build_prompt_requests(args)
    run_id = _run_id()
    started_at = datetime.now(timezone.utc).isoformat()

    results = []
    for index, prompt_request in enumerate(prompt_requests, start=1):
        runtime_request = _runtime_request(prompt_request, args, run_id, index)
        prompt_result = {
            "index": index,
            "prompt": prompt_request["text"],
            "request": runtime_request,
            "expected_classification": prompt_request.get("expected_classification"),
            "layers": {},
        }
        prompt_result["layers"] = _run_layers(layers, args, runtime_request)
        results.append(prompt_result)

    report = {
        "run_id": run_id,
        "created_at": started_at,
        "layers": layers,
        "runtime_mode": "grpc",
        "runtime_target": args.runtime_target,
        "results": results,
    }
    output_path = _output_path(Path(args.dump_dir), run_id)
    report["summary"] = _summary(results, output_path)
    _write_dump(output_path, report)

    print(json.dumps(report, indent=2, sort_keys=True))
    if report["summary"]["failed_layer_runs"]:
        raise SystemExit(1)


def _normalise_layers(
    raw_layers: List[str] | None,
) -> List[str]:
    layers = raw_layers or ["runtime"]
    normalised = []
    for layer in layers:
        if layer not in normalised:
            normalised.append(layer)
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


def _run_layers(
    layers: List[str],
    args: argparse.Namespace,
    runtime_request: Dict[str, Any],
) -> Dict[str, Dict[str, Any]]:
    from runtime_client import PrivokeRuntimeClient

    try:
        response = PrivokeRuntimeClient(
            args.runtime_target,
            timeout_seconds=args.timeout_seconds,
        ).analyze(
            runtime_request,
            layers=layers,
            regex_first=args.regex_first,
        )
    except Exception as exc:
        return {
            layer: {"status": "error", "error": str(exc)}
            for layer in layers
        }

    if layers == ["runtime"] or "runtime" in layers:
        status = "error" if response.get("error") else "ok"
        return {"runtime": {
            "status": status,
            "error": response.get("error"),
            "action": response.get("action"),
            "classification": response.get("classification"),
            "response": response,
        }}

    executions = {item["layer"]: item for item in response.get("layers", [])}
    layer_results = {}
    for layer in layers:
        execution = executions.get(layer) or {
            "status": "error",
            "error": f"Runtime did not return an execution result for {layer}.",
            "results": [],
        }
        results = execution.get("results", [])
        layer_results[layer] = {
            "status": execution.get("status", "error"),
            "error": execution.get("error"),
            "result_count": len(results),
            "classifications": [_classification_view(item) for item in results],
            "results": results,
        }
    return layer_results


def _classification_view(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "action": result.get("action"),
        "classification": result.get("classification"),
        "section_of_text": result.get("section_of_text"),
        "span": result.get("span"),
        "confidence": result.get("confidence"),
        "reasoning": result.get("reasoning"),
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


def _output_path(dump_dir: Path, run_id: str) -> Path:
    dump_dir.mkdir(parents=True, exist_ok=True)
    return dump_dir / f"{run_id}.json"


def _write_dump(output_path: Path, payload: Dict[str, Any]) -> None:
    output_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )


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
