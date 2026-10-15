"""Inspect original-model development margins without touching the final partition."""
import json
import hashlib
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "evaluation/results"

PROGRAM = """
import json,sys
from src.model import TinyTransformerModel
from src.detection.preprocessing import normalize_text
payload=json.load(sys.stdin)
model=TinyTransformerModel.from_artifact(payload['artifact'])
rows=[]
for example in payload['examples']:
    prediction=model.predict(normalize_text(example['text']))
    rows.append({'example_id':example['id'], 'expected_has_pii':example['expected_has_pii'],
                 'detected_sensitive':prediction.sensitivity!='S0' or bool(prediction.categories),
                 'sensitivity_probabilities':prediction.sensitivity_probabilities,
                 'category_probabilities':prediction.category_probabilities})
print(json.dumps({'config':payload['artifact']['config'], 'predictions':rows}))
"""


def main():
    output = RESULTS / "original-semantic-development-normalized-margins.json"
    if output.exists():
        raise SystemExit("Refusing to overwrite diagnostics.")
    artifact = json.loads((RESULTS / "original-v0.3.0-model.json").read_text(encoding="utf-8"))
    examples = [json.loads(line) for line in (RESULTS / "locked-public/development.jsonl")
                .read_text(encoding="utf-8").splitlines() if line.strip()]
    command = ["docker", "compose", "-f", "docker-compose.yml", "-f", "evaluation/compose.tests.yml",
               "exec", "-T", "client-runtime", "python", "-c", PROGRAM]
    result = subprocess.run(command, input=json.dumps({"artifact": artifact, "examples": examples}),
                            capture_output=True, text=True, cwd=ROOT)
    if result.returncode:
        raise SystemExit(result.stderr)
    report = json.loads(result.stdout)
    report["model_file_sha256"] = hashlib.sha256(
        (RESULTS / "original-v0.3.0-model.json").read_bytes()).hexdigest()
    report["dataset_sha256"] = hashlib.sha256(
        (RESULTS / "locked-public/development.jsonl").read_bytes()).hexdigest()
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    predictions = report["predictions"]
    reference = json.loads(next((RESULTS / "original_public_development_frozen")
                               .glob("local-jsonl_semantic_*_results.json")).read_text(encoding="utf-8"))
    reference_by_id = {row["example_id"]: row for row in reference["metadata"]["predictions"]}
    if len(reference_by_id) != len(predictions) or any(
            row["detected_sensitive"] != reference_by_id[row["example_id"]]["detected_sensitive"]
            for row in predictions):
        raise SystemExit("Offline diagnostics differ from archived live semantic classifications.")
    if report["config"]["sensitivity_labels"][0] != "S0":
        raise SystemExit("Calibration grid requires S0 as the first sensitivity label.")
    other = json.loads(next((RESULTS / "original_public_development_frozen")
                           .glob("local-jsonl_regex-ner_*_results.json")).read_text(encoding="utf-8"))
    other_by_id = {row["example_id"]: row["detected_sensitive"]
                   for row in other["metadata"]["predictions"]}
    clean = sum(not row["expected_has_pii"] for row in predictions)
    sensitive = len(predictions) - clean
    table = []
    for threshold in (0, .25, .5, .6, .7, .8, .85, .9, .95, .99, 1):
        detected = [(row, other_by_id[row["example_id"]] or
                     1 - row["sensitivity_probabilities"][0] >= threshold)
                    for row in predictions]
        tp = sum(row["expected_has_pii"] and positive for row, positive in detected)
        tn = sum(not row["expected_has_pii"] and not positive for row, positive in detected)
        table.append({"threshold": threshold, "recall": tp / sensitive,
                      "specificity": tn / clean, "tp": tp, "tn": tn})
    (RESULTS / "original-semantic-development-normalized-calibration-grid.json").write_text(
        json.dumps({"scope": "Exploratory development-only gate; not deployed or final-tested",
                    "category": "sensitivity probability mass above S0 with fixed regex/NER union",
                    "grid": table}, indent=2), encoding="utf-8")
    print(json.dumps(table))


if __name__ == "__main__":
    main()
