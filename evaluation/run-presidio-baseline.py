"""Run upstream Presidio independently of PriVoke's detector implementation.

Execute in the runtime image with evaluation mounted. Aggregate these raw
predictions using the evaluator's metrics; no runtime API or custom rules are used.
"""
import argparse
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import time

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("Refusing to overwrite a baseline run.")
    content = args.dataset_file.read_bytes()
    examples = [json.loads(line) for line in content.decode().splitlines() if line.strip()]
    configuration = {"nlp_engine_name": "spacy", "models": [
        {"lang_code": "en", "model_name": "en_core_web_sm"}]}
    engine = NlpEngineProvider(nlp_configuration=configuration).create_engine()
    analyzer = AnalyzerEngine(nlp_engine=engine, supported_languages=["en"])
    predictions = []
    for example in examples:
        start = time.perf_counter()
        try:
            results = analyzer.analyze(text=example["text"], language="en", score_threshold=0.5)
            record = {"status": "ok", "detected_sensitive": bool(results),
                      "entities": sorted({result.entity_type for result in results}),
                      "elapsed_ms": (time.perf_counter() - start) * 1000}
        except Exception as exc:
            record = {"status": "error", "error": str(exc)}
        predictions.append({"example_id": example["id"],
                            "group_id": example.get("group_id", example["id"]),
                            "expected_has_pii": example["expected_has_pii"], **record})
    report = {"baseline": "presidio-small-english", "dataset_sha256": hashlib.sha256(content).hexdigest(),
              "configuration": configuration, "threshold": 0.5,
              "supported_entities": sorted(analyzer.get_supported_entities(language="en")),
              "versions": {name: version(name) for name in ("presidio-analyzer", "spacy", "en-core-web-sm")},
              "predictions": predictions}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    errors = sum(record["status"] == "error" for record in predictions)
    print(json.dumps({"output": str(args.output), "count": len(predictions), "errors": errors}))
    return bool(errors)

if __name__ == "__main__":
    raise SystemExit(main())
