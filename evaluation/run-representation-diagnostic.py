"""Orchestrate offline pooled-feature export and the frozen-probe fit."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "evaluation/results"
OUT = RESULTS / "frozen-representation-study"
COMPOSE = ["docker", "compose", "-f", "docker-compose.yml", "-f", "evaluation/compose.tests.yml",
           "-f", "evaluation/compose.public-negatives.yml"]
EXPORT_PROGRAM = r'''
import json,sys
from src.model import TinyTransformerModel
from src.detection.preprocessing import normalize_text
payload=json.load(sys.stdin)
model=TinyTransformerModel.from_artifact(payload['artifact'])
result={}
for name,rows in payload['partitions'].items():
    features=[]
    for start in range(0,len(rows),32):
        batch=rows[start:start+32]
        predictions=model.predict_many([normalize_text(row['text']) for row in batch])
        for row,pred in zip(batch,predictions):
            features.append({'id':row['id'],'group_id':row['group_id'],
                'expected_has_pii':row['expected_has_pii'],'pooled':list(pred.pooled),
                'original_binary':pred.sensitivity!='S0' or bool(pred.categories)})
    result[name]=features
print(json.dumps({'config':payload['artifact']['config'],'partitions':result}))
'''


def call(arguments, *, input=None):
    return subprocess.run(COMPOSE + arguments, cwd=ROOT, input=input, text=True,
                          capture_output=True, check=True).stdout


def reference_file(directory, layer):
    files = list(directory.glob(f"local-jsonl_{layer}_*_results.json"))
    if len(files) != 1:
        raise ValueError(f"Expected one archived {layer} report in {directory}.")
    return files[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=OUT)
    args = parser.parse_args()
    if args.output != OUT:
        raise SystemExit("This protocol writes only to evaluation/results/frozen-representation-study.")
    if not OUT.exists():
        call(["run", "--rm", "--no-deps", "-T", "evaluation-tests", "python", "prepare-representation-study.py"])
    if (OUT / "features.json").exists() or (OUT / "fit-report.json").exists():
        raise SystemExit("Refusing to overwrite existing feature or fit evidence.")
    manifest = json.loads((OUT / "manifest.json").read_text(encoding="utf-8"))
    partitions = {}
    for name in ("train", "validation", "development"):
        path = OUT / f"{name}.jsonl"
        if hashlib.sha256(path.read_bytes()).hexdigest() != manifest["partition_sha256"][name]:
            raise ValueError(f"{name} partition hash mismatch.")
        partitions[name] = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    artifact_path = RESULTS / "original-v0.3.0-model.json"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    response = call(["exec", "-T", "client-runtime", "python", "-c", EXPORT_PROGRAM],
                    input=json.dumps({"artifact": artifact, "partitions": partitions}))
    exported = json.loads(response)
    if set(exported["partitions"]) != set(partitions):
        raise ValueError("Runtime export did not return every partition.")
    original_report = reference_file(RESULTS / "original_public_development_frozen", "semantic")
    rule_union = RESULTS / "context-rules-v2-development.json"
    rule_report = json.loads(rule_union.read_text(encoding="utf-8"))
    for source_name, digest in rule_report.get("source_sha256", {}).items():
        normalized = source_name.replace("\\", "/")
        source_path = (ROOT / normalized).resolve()
        if ROOT.resolve() not in source_path.parents or hashlib.sha256(source_path.read_bytes()).hexdigest() != digest:
            raise ValueError("Revised rule source hash mismatch.")
    payload = {"partitions": {name: {"rows": rows, "features": exported["partitions"][name]}
                              for name, rows in partitions.items()},
               "partition_paths": {name: f"/workspace/evaluation/results/frozen-representation-study/{name}.jsonl"
                                   for name in partitions},
               "partition_sha256": manifest["partition_sha256"],
               "original_semantic_reference": "/workspace/evaluation/results/original_public_development_frozen/" + original_report.name,
               "locked_development": "/workspace/evaluation/results/locked-public/development.jsonl",
               "rule_union": "/workspace/evaluation/results/context-rules-v2-development.json",
               "rule_source_sha256": {name.replace("\\", "/"): digest
                                       for name, digest in rule_report["source_sha256"].items()},
               "artifact_sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
               "dataset_manifest_sha256": hashlib.sha256((OUT / "manifest.json").read_bytes()).hexdigest(),
               "runtime_config": exported["config"]}
    # Preserve the prepared normalized-text keys, but discard raw prompts from feature evidence.
    for part in payload["partitions"].values():
        for row in part["rows"]:
            del row["text"]
    (OUT / "features.json").write_text(json.dumps(payload), encoding="utf-8")
    call(["run", "--rm", "--no-deps", "-T", "evaluation-tests", "python", "fit-representation-probe.py",
          "--input", "results/frozen-representation-study/features.json",
          "--output", "results/frozen-representation-study/fit-report.json"])
    print(json.dumps({"output": OUT.as_posix(), "artifact_sha256": payload["artifact_sha256"],
                      "features_sha256": hashlib.sha256((OUT / "features.json").read_bytes()).hexdigest()}))


if __name__ == "__main__":
    main()
