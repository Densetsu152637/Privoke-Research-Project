"""Measure whether case folding removes useful named-entity cues on development data."""
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "evaluation/results"
PROGRAM = """
import json,sys
from src.NER import EntityNERDetector
from src.detection.preprocessing import normalize_text
detector=EntityNERDetector()
rows=[]
for example in json.load(sys.stdin):
    row={'example_id':example['id'],'group_id':example['group_id'],
         'expected_has_pii':example['expected_has_pii']}
    for key,text in [('original_case',example['text']),('canonical_lower',normalize_text(example['text']))]:
        hits=detector.extract_entities(text)
        row[key]=any(hit.classification.sensitivity().name!='S0' or hit.classification.categories() for hit in hits)
    rows.append(row)
print(json.dumps(rows))
"""


def main():
    output = RESULTS / "ner-casing-development.json"
    if output.exists():
        raise SystemExit("Refusing to overwrite a diagnostic run.")
    examples = [json.loads(line) for line in (RESULTS / "locked-public/development.jsonl")
                .read_text(encoding="utf-8").splitlines() if line.strip()]
    command = ["docker", "compose", "-f", "docker-compose.yml", "-f", "evaluation/compose.tests.yml",
               "run", "--rm", "--no-deps", "-T", "--entrypoint", "python", "client-runtime", "-c", PROGRAM]
    result = subprocess.run(command, input=json.dumps(examples), capture_output=True, text=True, cwd=ROOT)
    if result.returncode:
        raise SystemExit(result.stderr)
    rows = json.loads(result.stdout)
    reference = json.loads(next((RESULTS / "original_public_development_frozen")
                               .glob("local-jsonl_ner_*_results.json")).read_text(encoding="utf-8"))
    by_id = {row["example_id"]: row for row in reference["metadata"]["predictions"]}
    assert len(rows) == len(by_id)
    assert all(bool(row["canonical_lower"]) == by_id[row["example_id"]]["detected_sensitive"] for row in rows)
    counts = {}
    for key in ("original_case", "canonical_lower"):
        tp = sum(row["expected_has_pii"] and row[key] for row in rows)
        tn = sum(not row["expected_has_pii"] and not row[key] for row in rows)
        counts[key] = {"tp": tp, "tn": tn, "fp": 238 - tn, "fn": 264 - tp,
                       "recall": tp / 264, "specificity": tn / 238}
    output.write_text(json.dumps({"scope": "Exploratory development-only raw-case versus canonical-lower NER",
                                  "predictions": rows, "counts": counts}, indent=2), encoding="utf-8")
    print(json.dumps(counts))


if __name__ == "__main__":
    main()
