"""Compare revised rule predictions on development data against archived layers."""
import hashlib
import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "evaluation/results"
PROGRAM = """
import json,sys
from src.regex.rule_detector import RuleDetector
from src.detection.preprocessing import normalize_text
detector=RuleDetector()
rows=[]
for example in json.load(sys.stdin):
    hits=detector.analyze(normalize_text(example['text']))
    positive=any(hit.classification.sensitivity().name!='S0' or hit.classification.categories() for hit in hits)
    rows.append({'example_id':example['id'],'group_id':example['group_id'],
                 'expected_has_pii':example['expected_has_pii'], 'detected_sensitive':bool(positive),
                 'status':'ok','rules':[hit.metadata.get('rule_name') for hit in hits]})
print(json.dumps(rows))
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=RESULTS / "context-rules-development.json")
    args = parser.parse_args()
    output = args.output
    if output.exists():
        raise SystemExit("Refusing to overwrite a diagnostic run.")
    content = (RESULTS / "locked-public/development.jsonl").read_bytes()
    examples = [json.loads(line) for line in content.decode().splitlines() if line.strip()]
    command = ["docker", "compose", "-f", "docker-compose.yml", "-f", "evaluation/compose.tests.yml",
               "run", "--rm", "--no-deps", "-T", "--entrypoint", "python", "client-runtime", "-c", PROGRAM]
    result = subprocess.run(command, input=json.dumps(examples), capture_output=True,
                            text=True, cwd=ROOT)
    if result.returncode:
        raise SystemExit(result.stderr)
    predictions = json.loads(result.stdout)
    base = RESULTS / "original_public_development_frozen"
    layers = {}
    for layer in ("regex", "ner", "semantic"):
        reference = json.loads(next(base.glob(f"local-jsonl_{layer}_*_results.json")).read_text(encoding="utf-8"))
        layers[layer] = {row["example_id"]: row["detected_sensitive"]
                         for row in reference["metadata"]["predictions"]}
    reports = {}
    for layer in ("regex", "regex-ner", "pipeline"):
        rows = [{**row, "detected_sensitive": bool(row["detected_sensitive"] or
                (layer != "regex" and layers["ner"][row["example_id"]]) or
                (layer == "pipeline" and layers["semantic"][row["example_id"]]))}
                for row in predictions]
        tp = sum(row["expected_has_pii"] and row["detected_sensitive"] for row in rows)
        tn = sum(not row["expected_has_pii"] and not row["detected_sensitive"] for row in rows)
        positive = sum(row["expected_has_pii"] for row in rows)
        negative = len(rows) - positive
        reports[layer] = {"metadata": {"predictions": rows}, "metrics": {
            "true_positives": tp, "true_negatives": tn, "false_positives": negative - tn,
            "false_negatives": positive - tp, "recall": tp / positive, "specificity": tn / negative}}
    source_hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                     for path in [ROOT / "extension/client-runtime/src/regex/rules_financial.py",
                                  ROOT / "extension/client-runtime/src/regex/rules_location.py"]}
    output.write_text(json.dumps({"scope": "Development-only rule diagnosis; reused original NER/semantic predictions",
                                  "dataset_sha256": hashlib.sha256(content).hexdigest(),
                                  "source_sha256": source_hashes, "layers": reports}, indent=2), encoding="utf-8")
    print(json.dumps({layer: report["metrics"] for layer, report in reports.items()}))


if __name__ == "__main__":
    main()
