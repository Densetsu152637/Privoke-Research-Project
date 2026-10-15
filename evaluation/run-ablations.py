"""Invoke matched evaluator runs; keep detection and fuzzer implementation separate."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
from host_environment import configure_imports

configure_imports()

from privoke_model.artifact import float32
from privoke_model.fingerprint import parameter_fingerprint


def verify_semantic_identity(report, artifact):
    """Reject mislabeled streamed-model results even when version strings match."""
    expected = {"model_id": artifact["model_id"], "model_version": artifact["version"],
                "artifact_checksum": artifact["checksum"],
                "parameter_fingerprint": parameter_fingerprint(
                    {name: tuple(float32(value) for value in tensor["values"])
                     for name, tensor in artifact["parameters"].items()},
                    {name: tensor["shape"] for name, tensor in artifact["parameters"].items()})}
    for row in report["metadata"]["predictions"]:
        for execution in row.get("layers", []):
            if execution["layer"] != "DETECTION_LAYER_SEMANTIC" or execution["status"] != "ok":
                continue
            for result in execution["results"]:
                metadata = result.get("metadata", {})
                if any(metadata.get(key) != value for key, value in expected.items()):
                    raise ValueError("Returned semantic model ID, version, checksum or fingerprint differs from the artifact.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset-file", type=Path, required=True)
    parser.add_argument("--run-name", required=True)
    parser.add_argument("--layers", nargs="+", default=["regex", "ner", "semantic", "regex-ner", "pipeline"])
    parser.add_argument("--model-artifact", type=Path, required=True)
    parser.add_argument("--bootstrap-iterations", type=int, default=2000)
    args = parser.parse_args()
    if args.bootstrap_iterations < 0:
        parser.error("Bootstrap iterations must be non-negative.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", args.run_name):
        parser.error("Use a run identifier of 1-64 letters, digits, dots, underscores or hyphens, starting with a letter or digit.")
    root = Path(__file__).resolve().parent
    output = root / "results" / args.run_name
    if output.exists():
        raise SystemExit("Refusing to overwrite a matched run directory.")
    output.mkdir(parents=True)
    artifact_bytes = args.model_artifact.read_bytes()
    artifact = json.loads(artifact_bytes)
    manifest = {"dataset_sha256": hashlib.sha256(args.dataset_file.read_bytes()).hexdigest(),
                "model_id": artifact["model_id"],
                "model_file_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
                "model_version": artifact["version"], "artifact_checksum": artifact["checksum"],
                "layers": args.layers, "bootstrap_iterations": args.bootstrap_iterations, "completed": []}
    manifest_path = output / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    for layer in args.layers:
        command = [sys.executable, str(root / "evaluate.py"), "--dataset", "local-jsonl",
                   "--dataset-file", str(args.dataset_file), "--samples", "all", "--seed", "3102026",
                   "--layer", layer, "--backend", "streamed", "--run-name", args.run_name,
                   "--output-dir", str(output), "--bootstrap-iterations", str(args.bootstrap_iterations), "--quiet"]
        with (output / (layer + ".log")).open("w", encoding="utf-8") as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                    env={**os.environ, "MODEL_ID": artifact["model_id"]})
        if result.returncode:
            raise SystemExit(f"{layer} failed; retain its log and do not treat this batch as complete.")
        reports = list(output.glob(f"local-jsonl_{layer}_*_results.json"))
        if len(reports) != 1:
            raise SystemExit(f"Expected one {layer} report; found {len(reports)}")
        report = json.loads(reports[0].read_text())
        if report["errors"]:
            raise SystemExit(f"{layer} returned runtime errors")
        verify_semantic_identity(report, artifact)
        observed = {result["metadata"]["model_version"]
                    for record in report["metadata"]["predictions"]
                    for execution in record.get("layers", [])
                    for result in execution.get("results", [])
                    if "model_version" in result.get("metadata", {})}
        if observed and observed != {artifact["version"]}:
            raise SystemExit(f"Model changed during {layer}: {observed}")
        checksums = {result["metadata"]["artifact_checksum"]
                     for record in report["metadata"]["predictions"]
                     for execution in record.get("layers", [])
                     for result in execution.get("results", [])
                     if "artifact_checksum" in result.get("metadata", {})}
        if checksums and checksums != {artifact["checksum"]}:
            raise SystemExit(f"Artifact changed during {layer}: {checksums}")
        manifest["completed"].append({"layer": layer, "report": reports[0].name,
                                      "report_sha256": hashlib.sha256(reports[0].read_bytes()).hexdigest(),
                                      "observed_model_versions": sorted(observed),
                                      "observed_artifact_checksums": sorted(checksums)})
        manifest_path.write_text(json.dumps(manifest, indent=2))
        print(json.dumps({"layer": layer, "recall": report["metrics"]["recall"],
                          "specificity": report["metrics"]["specificity"]}), flush=True)

if __name__ == "__main__":
    main()
