"""Measure one immutable-base or receipt-bound presence update candidate."""
from __future__ import annotations

import argparse
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import statistics
import sys
import traceback
import uuid
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared/python"))
from privoke_model.artifact import load_artifact  # noqa: E402
from privoke_model.presence import PRESENCE_ARCHITECTURE, SparsePresenceModel  # noqa: E402
from privoke_eval.presence_evidence import (  # noqa: E402
    load_frozen_fit, sha256_file, validate_base_and_candidate,
    validate_retention_selection,
)
from privoke_eval.presence_training import binary_metrics, metrics_by_family, source_family  # noqa: E402

_SCORER_SPEC = importlib.util.spec_from_file_location(
    "evaluate_presence_rpc", ROOT / "evaluation/evaluate-presence.py")
if _SCORER_SPEC is None or _SCORER_SPEC.loader is None:
    raise RuntimeError("Could not load the strict typed presence RPC scorer.")
_SCORER = importlib.util.module_from_spec(_SCORER_SPEC)
_SCORER_SPEC.loader.exec_module(_SCORER)

PARTITIONS = {"validation": (968, "partition"), "development": (502, "development")}
LOCKED_DEV_SHA256 = "65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095"


def read_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def write_exclusive(path: Path, value) -> str:
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    import hashlib
    return hashlib.sha256(raw).hexdigest()


def validate_rows(path: Path, partition: str, fit_record: dict) -> list[dict]:
    if "final" in path.name.lower():
        raise ValueError("Final partition cannot be scored.")
    digest = sha256_file(path)
    selection = fit_record["selection"]
    input_hashes = selection.get("input_hashes", {})
    if partition == "validation":
        expected_digest = input_hashes.get("partition_sha256", {}).get("validation")
    else:
        expected_digest = input_hashes.get("locked_sha256", {}).get("development")
        if digest != LOCKED_DEV_SHA256:
            raise ValueError("Development input differs from the locked development file.")
    if not expected_digest or digest != expected_digest:
        raise ValueError(f"{partition} input digest differs from the fit-pinned partition.")
    rows = read_jsonl(path)
    expected_count = PARTITIONS[partition][0]
    if len(rows) != expected_count:
        raise ValueError(f"{partition} input must contain exactly {expected_count} rows.")
    ids = [row.get("id") for row in rows]
    if any(not isinstance(value, str) or not value for value in ids) or len(set(ids)) != len(ids):
        raise ValueError(f"{partition} IDs are invalid or duplicated.")
    for row in rows:
        if (type(row.get("expected_has_pii")) is not bool or not isinstance(row.get("group_id"), str)
                or not row["group_id"] or not isinstance(row.get("text"), str)):
            raise ValueError(f"{partition} row has malformed truth, group, or text.")
    return rows


def run(base_path: Path, candidate_path: Path, selection_path: Path, fit_manifest_path: Path,
        dataset_path: Path, partition: str, output: Path, target: str,
        source_revision: str, fit_source_revision: str, protocol_sha256: str,
        update_evidence_path: Path | None, retention_selection_path: Path | None) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    manifest_path = output / "run-manifest.json"
    run_record = {"status": "running", "stage": "input_validation",
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_revision": source_revision, "fit_source_revision": fit_source_revision,
        "protocol_sha256": protocol_sha256, "fit_manifest": fit_manifest_path.as_posix(),
        "fit_manifest_sha256": sha256_file(fit_manifest_path), "selection": selection_path.as_posix(),
        "base_artifact": base_path.as_posix(), "base_artifact_sha256": sha256_file(base_path),
        "candidate_artifact": candidate_path.as_posix(), "candidate_artifact_sha256": sha256_file(candidate_path),
        "dataset_file": dataset_path.as_posix(), "dataset_sha256": sha256_file(dataset_path),
        "partition": partition, "target": target, "script_sha256": sha256_file(Path(__file__)),
        "errors": [], "rows": 0}
    write_exclusive(manifest_path, run_record)
    try:
        if partition not in PARTITIONS:
            raise ValueError("Partition must be validation or development.")
        fit_record = load_frozen_fit(selection_path, fit_manifest_path,
                                     fit_source_revision=fit_source_revision,
                                     protocol_sha256=protocol_sha256)
        if base_path.resolve() != fit_record["artifact_path"]:
            raise ValueError("Base artifact path is not the exact frozen fitted profile artifact.")
        base, candidate = load_artifact(base_path), load_artifact(candidate_path)
        evidence = (json.loads(update_evidence_path.read_text(encoding="utf-8"))
                    if update_evidence_path else None)
        candidate_record = validate_base_and_candidate(
            base, candidate, fit_record=fit_record, candidate_path=candidate_path, evidence=evidence)
        run_record["candidate"] = candidate_record
        if partition == "development":
            if retention_selection_path is None:
                raise ValueError("Development scoring requires a persisted validation retention selection.")
            retention = json.loads(retention_selection_path.read_text(encoding="utf-8"))
            validate_retention_selection(retention, candidate, candidate_path, fit_record,
                                         source_revision, protocol_sha256)
            run_record["retention_selection"] = retention_selection_path.as_posix()
            run_record["retention_selection_sha256"] = sha256_file(retention_selection_path)
        elif retention_selection_path is not None:
            raise ValueError("Retention selection is only accepted for fixed development scoring.")
        rows = validate_rows(dataset_path, partition, fit_record)
        local_model = SparsePresenceModel.from_artifact(candidate)
        import grpc
        pb, grpc_pb = _SCORER.load_stubs()
        prefix = f"presence-{partition}-{uuid.uuid4().hex}"
        row_records, durations, errors = [], [], []
        with grpc.insecure_channel(target) as channel:
            stub = grpc_pb.PrivokeRuntimeServiceStub(channel)
            for index, row in enumerate(rows):
                request_id = f"{prefix}-{index:04d}"
                try:
                    record = _SCORER.score_one(stub, pb, row, candidate["model_id"],
                        candidate_record["candidate_identity"], local_model, request_id)
                    row_records.append(record)
                    durations.append(record["elapsed_ms"])
                except Exception as exc:
                    error = {"row_id": row["id"], "request_id": request_id,
                             "type": type(exc).__name__, "error": str(exc)}
                    errors.append(error)
                    row_records.append({"id": row["id"], "group_id": row["group_id"],
                        "expected_has_pii": row["expected_has_pii"], "request_id": request_id,
                        "error": str(exc)})
        if errors:
            metrics = family_metrics = None
        else:
            probabilities = [record["probability"] for record in row_records]
            labels = [row["expected_has_pii"] for row in rows]
            metrics = binary_metrics(labels, probabilities, candidate["config"]["threshold"])
            family_metrics = metrics_by_family(rows, probabilities, candidate["config"]["threshold"])
        run_record.update({"status": "complete" if not errors else "failed",
            "stage": "scored" if not errors else "rpc_scoring", "rows": len(rows),
            "successful_rows": len(rows) - len(errors), "errors": errors,
            "metrics": metrics, "source_family_metrics": family_metrics,
            "elapsed_ms": {"median": statistics.median(durations) if durations else None,
                "p95": sorted(durations)[min(len(durations)-1, math.ceil(.95*len(durations))-1)] if durations else None},
            "returned_identity": candidate_record["candidate_identity"],
            "finished_at_utc": datetime.now(timezone.utc).isoformat()})
        write_exclusive(output / "predictions.json", {"rows": row_records})
        run_record["report_sha256"] = write_exclusive(output / "report.json", run_record)
        manifest_path.write_text(json.dumps(run_record, ensure_ascii=False, sort_keys=True,
                                            indent=2, allow_nan=False) + "\n",
                                 encoding="utf-8", newline="\n")
        return run_record
    except Exception as exc:
        failure = {"status": "failed", "stage": run_record.get("stage"),
                   "type": type(exc).__name__, "error": str(exc),
                   "traceback": traceback.format_exc(), "source_revision": source_revision,
                   "fit_source_revision": fit_source_revision}
        write_exclusive(output / "failure.json", failure)
        run_record.update({"status": "failed", "failure": failure,
                           "finished_at_utc": datetime.now(timezone.utc).isoformat()})
        manifest_path.write_text(json.dumps(run_record, ensure_ascii=False, sort_keys=True,
                                            indent=2, allow_nan=False) + "\n",
                                 encoding="utf-8", newline="\n")
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-artifact", type=Path, required=True)
    parser.add_argument("--candidate-artifact", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--fit-manifest", type=Path, required=True)
    parser.add_argument("--dataset-file", type=Path, required=True)
    parser.add_argument("--partition", choices=tuple(PARTITIONS), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", default=os.getenv("PRIVOKE_RUNTIME_TARGET", "client-runtime:50054"))
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--fit-source-revision")
    parser.add_argument("--protocol-sha256", required=True)
    parser.add_argument("--update-evidence", type=Path)
    parser.add_argument("--retention-selection", type=Path)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40,64}", args.source_revision):
        parser.error("--source-revision must be a full lowercase Git object ID.")
    fit_source_revision = args.fit_source_revision or args.source_revision
    if not re.fullmatch(r"[0-9a-f]{40,64}", fit_source_revision):
        parser.error("--fit-source-revision must be a full lowercase Git object ID.")
    if not re.fullmatch(r"[0-9a-f]{64}", args.protocol_sha256):
        parser.error("--protocol-sha256 must be a lowercase SHA-256 digest.")
    output = args.output.resolve()
    if (ROOT / "evaluation/results").resolve() not in output.parents:
        parser.error("--output must be a fresh child under evaluation/results.")
    result = run(args.base_artifact, args.candidate_artifact, args.selection, args.fit_manifest,
                 args.dataset_file, args.partition, output, args.target, args.source_revision,
                 fit_source_revision, args.protocol_sha256, args.update_evidence,
                 args.retention_selection)
    print(json.dumps({"status": result["status"], "partition": args.partition,
                      "rows": result["rows"], "errors": len(result["errors"]),
                      "output": output.as_posix()}, sort_keys=True))
    return 0 if result["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
