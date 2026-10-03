"""Score a frozen sparse presence artifact through the typed runtime RPC."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import statistics
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import traceback
import uuid

import grpc

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared/python"))
from privoke_model.artifact import load_artifact  # noqa: E402
from privoke_model.fingerprint import parameter_fingerprint  # noqa: E402
from privoke_model.presence import PRESENCE_ARCHITECTURE, SparsePresenceModel  # noqa: E402
from privoke_eval.presence_rpc import response_record, validate_response  # noqa: E402
from privoke_eval.presence_training import binary_metrics, metrics_by_family, source_family  # noqa: E402

LOCKED_DEV_SHA256 = "65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095"
LOCKED_DEV_ROWS = 502
GENERATED = Path("/workspace/extension/client-runtime/generated")
if GENERATED.is_dir():
    sys.path.insert(0, str(GENERATED))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def write_exclusive(path: Path, value) -> str:
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return hashlib.sha256(raw).hexdigest()


def replace_json(path: Path, value) -> None:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(raw, encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def load_stubs():
    from privoke.v1 import runtime_pb2, runtime_pb2_grpc
    return runtime_pb2, runtime_pb2_grpc


def expected_identity(artifact: dict) -> dict:
    params = {name: tensor["values"] for name, tensor in artifact["parameters"].items()}
    shapes = {name: tensor["shape"] for name, tensor in artifact["parameters"].items()}
    return {"model_id": artifact["model_id"], "model_version": artifact["version"],
            "artifact_checksum": artifact["checksum"],
            "parameter_fingerprint": parameter_fingerprint(params, shapes),
            "threshold": artifact["config"]["threshold"]}


def score_one(stub, pb, row: dict, model_id: str, identity: dict,
              local_model: SparsePresenceModel, request_id: str) -> dict:
    local_probability = local_model.predict_probability(row["text"])
    response = stub.DetectAnnotationPresence(
        pb.DetectAnnotationPresenceRequest(request_id=request_id, text=row["text"], model_id=model_id),
        timeout=120)
    raw = response_record(response)
    checked = validate_response(raw, request_id=request_id, expected_identity=identity,
                                present_enum=pb.ANNOTATION_PRESENCE_PRESENT,
                                absent_enum=pb.ANNOTATION_PRESENCE_ABSENT,
                                expected_probability=local_probability)
    return {"id": row["id"], "group_id": row["group_id"],
            "source_family": source_family(row["group_id"]),
            "expected_has_pii": row["expected_has_pii"],
            "probability": checked["probability"], "local_probability": local_probability,
            "threshold": checked["threshold"],
            "predicted_present": checked["predicted_label"] == pb.ANNOTATION_PRESENCE_PRESENT,
            "elapsed_ms": checked["elapsed_ms"], "request_id": request_id,
            **checked["identity"]}


def run(artifact_path: Path, selection_path: Path, dataset_path: Path,
        output: Path, target: str, source_revision: str, protocol_sha256: str) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    run_record = {"status": "running", "started_at_utc": datetime.now(timezone.utc).isoformat(),
                  "source_revision": source_revision, "protocol_sha256": protocol_sha256,
                  "artifact_file": artifact_path.as_posix(),
                  "artifact_sha256": sha256_file(artifact_path), "dataset_sha256": sha256_file(dataset_path),
                  "target": target, "script_sha256": sha256_file(Path(__file__)),
                  "rows": 0, "errors": []}
    manifest_path = output / "run-manifest.json"
    write_exclusive(manifest_path, run_record)
    try:
        selection = json.loads(selection_path.read_text(encoding="utf-8"))
        if selection.get("status") != "selected":
            raise ValueError("Presence profile lacks a frozen successful selection.")
        if sha256_file(artifact_path) != selection.get("selected_artifact_sha256"):
            raise ValueError("Artifact file bytes differ from frozen selection hash.")
        artifact = load_artifact(artifact_path)
        if artifact["architecture"] != PRESENCE_ARCHITECTURE:
            raise ValueError("Supplied artifact is not the sparse presence architecture.")
        if artifact["checksum"] != selection["artifact_identity"]["artifact_checksum"]:
            raise ValueError("Artifact checksum differs from frozen profile selection.")
        if artifact["model_id"] != selection["artifact_identity"]["model_id"]:
            raise ValueError("Artifact model ID differs from frozen profile selection.")
        metadata = artifact["metadata"]
        if (metadata.get("source_revision") != source_revision
                or metadata.get("protocol_sha256") != protocol_sha256
                or selection.get("source_revision") != source_revision
                or selection.get("protocol_sha256") != protocol_sha256):
            raise ValueError("Source/protocol identity differs from the frozen profile fit.")
        if metadata.get("release_version") != artifact["version"]:
            raise ValueError("Artifact version differs from its release metadata.")
        if metadata.get("profile") != selection.get("profile") or metadata.get("task") != "annotation_presence":
            raise ValueError("Artifact profile/task differs from frozen selection.")
        if metadata.get("normalization") != "training_text_key_v1" or not metadata.get("arithmetic"):
            raise ValueError("Artifact normalization/arithmetic identity is incomplete.")
        input_hashes = selection.get("input_hashes", {})
        if (metadata.get("prepared_manifest_sha256") != input_hashes.get("manifest_sha256")
                or metadata.get("train_sha256") != input_hashes.get("partition_sha256", {}).get("train")
                or metadata.get("validation_sha256") != input_hashes.get("partition_sha256", {}).get("validation")
                or metadata.get("locked_development_sha256") != input_hashes.get("locked_sha256", {}).get("development")):
            raise ValueError("Artifact input digests differ from the frozen selection.")
        identity = expected_identity(artifact)
        if identity != selection["artifact_identity"]:
            raise ValueError("Artifact serialized identity differs from the selection record.")
        if (sha256_file(dataset_path) != LOCKED_DEV_SHA256
                or sha256_file(dataset_path) != input_hashes.get("locked_sha256", {}).get("development")):
            raise ValueError("Scoring input does not match the locked development digest.")
        rows = read_jsonl(dataset_path)
        if len(rows) != LOCKED_DEV_ROWS:
            raise ValueError("Scoring input does not contain exactly 502 development rows.")
        ids = [row.get("id") for row in rows]
        if any(not isinstance(value, str) or not value for value in ids) or len(set(ids)) != len(ids):
            raise ValueError("Development IDs are invalid or duplicated.")
        if any(type(row.get("expected_has_pii")) is not bool or not isinstance(row.get("group_id"), str)
               or not isinstance(row.get("text"), str) for row in rows):
            raise ValueError("Development row is missing a strict label, group or text.")
        local_model = SparsePresenceModel.from_artifact(artifact)
        pb, grpc_pb = load_stubs()
        request_prefix = f"presence-score-{uuid.uuid4().hex}"
        report_rows, predictions, labels, durations = [], [], [], []
        with grpc.insecure_channel(target) as channel:
            stub = grpc_pb.PrivokeRuntimeServiceStub(channel)
            for index, row in enumerate(rows):
                request_id = f"{request_prefix}-{index:04d}"
                try:
                    record = score_one(stub, pb, row, artifact["model_id"], identity,
                                       local_model, request_id)
                    report_rows.append(record)
                    predictions.append(record["predicted_present"])
                    labels.append(row["expected_has_pii"])
                    durations.append(record["elapsed_ms"])
                except Exception as exc:
                    run_record["errors"].append({"row_id": row["id"], "request_id": request_id,
                                                  "type": type(exc).__name__, "error": str(exc)})
                    report_rows.append({"id": row["id"], "group_id": row["group_id"],
                                        "expected_has_pii": row["expected_has_pii"],
                                        "request_id": request_id, "error": str(exc)})
        if run_record["errors"]:
            metrics = None
            family_metrics = None
        else:
            probabilities = [row["probability"] for row in report_rows]
            metrics = binary_metrics(labels, probabilities, artifact["config"]["threshold"])
            # Ensure typed RPC output labels are the same binary predictions as shared arithmetic.
            if predictions != [p >= artifact["config"]["threshold"] for p in probabilities]:
                raise ValueError("Returned RPC labels are inconsistent with the frozen threshold.")
            family_metrics = metrics_by_family(rows, probabilities, artifact["config"]["threshold"])
        run_record.update({"status": "complete" if not run_record["errors"] else "failed",
            "stage": "scored" if not run_record["errors"] else "rpc_scoring",
            "rows": len(rows), "successful_rows": len(report_rows) - len(run_record["errors"]),
            "metrics": metrics, "source_family_metrics": family_metrics,
            "elapsed_ms": {"median": statistics.median(durations) if durations else None,
                            "p95": sorted(durations)[min(len(durations)-1, math.ceil(.95*len(durations))-1)] if durations else None},
            "returned_identity": identity,
            "report_sha256": None, "finished_at_utc": datetime.now(timezone.utc).isoformat()})
        write_exclusive(output / "predictions.json", {"rows": report_rows})
        run_record["report_sha256"] = write_exclusive(output / "report.json", run_record)
        (output / "run-manifest.json").write_text(
            json.dumps(run_record, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n",
            encoding="utf-8", newline="\n")
        return run_record
    except Exception as exc:
        failure = {"status": "failed", "type": type(exc).__name__, "error": str(exc),
                   "traceback": traceback.format_exc(), "source_revision": source_revision}
        write_exclusive(output / "failure.json", failure)
        run_record.update({"status": "failed", "stage": "pre_or_during_scoring",
                           "failure": failure, "finished_at_utc": datetime.now(timezone.utc).isoformat()})
        replace_json(manifest_path, run_record)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--dataset-file", type=Path, required=True,
                        help="Locked development JSONL only; never pass final.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", default=os.getenv("PRIVOKE_RUNTIME_TARGET", "client-runtime:50054"))
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--protocol-sha256", required=True)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40,64}", args.source_revision):
        parser.error("--source-revision must be a full lowercase Git object ID.")
    if not re.fullmatch(r"[0-9a-f]{64}", args.protocol_sha256):
        parser.error("--protocol-sha256 must be a lowercase SHA-256 digest.")
    output = args.output.resolve()
    results = (ROOT / "evaluation/results").resolve()
    if results not in output.parents:
        parser.error("--output must be a fresh child under evaluation/results.")
    if "final" in args.dataset_file.name.lower():
        parser.error("Final partition cannot be scored.")
    result = run(args.artifact, args.selection, args.dataset_file, output, args.target,
                 args.source_revision, args.protocol_sha256)
    print(json.dumps({"status": result["status"], "rows": result["rows"],
                      "errors": len(result["errors"]), "output": output.as_posix()}, sort_keys=True))
    return 0 if result["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
