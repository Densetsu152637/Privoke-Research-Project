"""Strict provenance and immutable-base checks for presence study scoring."""
from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Mapping

from privoke_model.artifact import load_artifact
from privoke_model.fingerprint import parameter_fingerprint
from privoke_model.presence import PRESENCE_ARCHITECTURE, SparsePresenceModel

PROFILES = ("efficient", "balanced", "quality")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact_identity(artifact: Mapping) -> dict:
    model = SparsePresenceModel.from_artifact(artifact)
    return {"model_id": artifact["model_id"], "model_version": artifact["version"],
            "artifact_checksum": artifact["checksum"],
            "parameter_fingerprint": parameter_fingerprint(model.parameters, model.shapes),
            "threshold": artifact["config"]["threshold"]}


def _resolve_inside(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError("Fit manifest contains an invalid artifact locator.")
    candidate = (root / relative).resolve()
    if root.resolve() not in candidate.parents:
        raise ValueError("Fit artifact locator escapes its result directory.")
    return candidate


def load_frozen_fit(selection_path: Path, fit_manifest_path: Path, *,
                    fit_source_revision: str, protocol_sha256: str) -> dict:
    """Verify the completed all-profile fit and return its pinned selection/artifact."""
    fit_manifest_path = fit_manifest_path.resolve()
    selection_path = selection_path.resolve()
    fit_root = fit_manifest_path.parent
    manifest_bytes = fit_manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    if (manifest.get("status") != "complete"
            or manifest.get("selections_frozen_before_development_scoring") is not True
            or manifest.get("errors") not in (None, [])):
        raise ValueError("Fit manifest is incomplete or did not freeze selections before development.")
    if manifest.get("source_revision") != fit_source_revision or manifest.get("protocol_sha256") != protocol_sha256:
        raise ValueError("Fit source/protocol identity differs from the requested study binding.")
    profiles = manifest.get("profiles")
    if not isinstance(profiles, dict) or set(profiles) != set(PROFILES):
        raise ValueError("Fit manifest must contain exactly the three predefined profiles.")
    verified = {}
    for profile in PROFILES:
        entry = profiles[profile]
        if not isinstance(entry, dict) or entry.get("status") != "selected":
            raise ValueError(f"Fit profile {profile} did not complete a successful selection.")
        on_disk_selection = _resolve_inside(fit_root, f"profiles/{profile}/selection.json")
        selection = json.loads(on_disk_selection.read_text(encoding="utf-8"))
        if selection != entry:
            raise ValueError(f"Profile {profile} selection differs from the run manifest.")
        artifact_path = _resolve_inside(fit_root, selection.get("selected_artifact_file"))
        artifact_sha = sha256_file(artifact_path)
        if artifact_sha != selection.get("selected_artifact_sha256"):
            raise ValueError(f"Profile {profile} selected artifact file digest mismatch.")
        artifact = load_artifact(artifact_path)
        identity = artifact_identity(artifact)
        if identity != selection.get("artifact_identity"):
            raise ValueError(f"Profile {profile} artifact identity differs from its frozen selection.")
        metadata = artifact.get("metadata", {})
        hashes = selection.get("input_hashes", {})
        if (artifact.get("architecture") != PRESENCE_ARCHITECTURE
                or artifact.get("model_id") != f"privoke-presence-{profile}"
                or artifact.get("config", {}).get("profile") != profile
                or metadata.get("profile") != profile
                or metadata.get("task") != "annotation_presence"
                or metadata.get("release_version") != artifact.get("version")
                or metadata.get("source_revision") != fit_source_revision
                or metadata.get("protocol_sha256") != protocol_sha256
                or selection.get("source_revision") != fit_source_revision
                or selection.get("protocol_sha256") != protocol_sha256
                or metadata.get("prepared_manifest_sha256") != hashes.get("manifest_sha256")
                or metadata.get("train_sha256") != hashes.get("partition_sha256", {}).get("train")
                or metadata.get("validation_sha256") != hashes.get("partition_sha256", {}).get("validation")
                or metadata.get("locked_development_sha256") != hashes.get("locked_sha256", {}).get("development")):
            raise ValueError(f"Profile {profile} artifact provenance differs from the frozen fit inputs.")
        verified[profile] = {"selection": selection, "artifact": artifact,
                             "artifact_path": artifact_path, "artifact_sha256": artifact_sha}
    requested = json.loads(selection_path.read_text(encoding="utf-8"))
    profile = requested.get("profile")
    if profile not in PROFILES or selection_path != _resolve_inside(fit_root, f"profiles/{profile}/selection.json"):
        raise ValueError("Requested selection is not one of the exact frozen profile selection files.")
    if profile not in verified or requested != verified[profile]["selection"]:
        raise ValueError("Requested selection is not the manifest-bound frozen selection.")
    return {"manifest": manifest, "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "fit_root": fit_root, "profiles": verified, "selection": requested,
            "profile": profile, **verified[profile]}


def validate_base_and_candidate(base: Mapping, candidate: Mapping, *,
                                fit_record: Mapping, candidate_path: Path,
                                evidence: Mapping | None) -> dict:
    """Require frozen release tensors/config and verify an accepted update receipt."""
    selection = fit_record["selection"]
    if sha256_file(fit_record["artifact_path"]) != selection["selected_artifact_sha256"]:
        raise ValueError("Frozen base artifact changed after fit verification.")
    base_identity = artifact_identity(base)
    if (base_identity != selection.get("artifact_identity")
            or sha256_file(fit_record["artifact_path"]) != selection["selected_artifact_sha256"]
            or base != fit_record["artifact"]):
        raise ValueError("Base artifact is not the exact frozen profile release.")
    if candidate.get("architecture") != PRESENCE_ARCHITECTURE or candidate.get("model_id") != base.get("model_id"):
        raise ValueError("Candidate architecture/model ID differs from the fitted base.")
    changed = candidate != base
    if candidate.get("config") != base.get("config"):
        raise ValueError("Candidate changed the frozen config, vocabulary, IDF settings or threshold.")
    if set(candidate.get("parameters", {})) != set(base.get("parameters", {})):
        raise ValueError("Candidate tensor manifest differs from fitted base.")
    trainable_changes = 0
    for name, base_tensor in base["parameters"].items():
        candidate_tensor = candidate["parameters"][name]
        if candidate_tensor.get("shape") != base_tensor.get("shape") or candidate_tensor.get("trainable") != base_tensor.get("trainable"):
            raise ValueError(f"Candidate tensor {name} changed shape/trainable metadata.")
        if name.startswith("features.") and candidate_tensor["values"] != base_tensor["values"]:
            raise ValueError("Candidate changed frozen vocabulary IDF parameters.")
        if name.startswith("head.presence.") and candidate_tensor["values"] != base_tensor["values"]:
            trainable_changes += 1
    if changed:
        if trainable_changes == 0 or candidate.get("version") != base["version"] + "+train.1":
            raise ValueError("Updated candidate must contain changed head weights at exactly +train.1.")
        base_meta, updated_meta = base.get("metadata", {}), candidate.get("metadata", {})
        for key, value in base_meta.items():
            if key not in ("training_revision", "last_update_source") and updated_meta.get(key) != value:
                raise ValueError(f"Candidate changed immutable provenance metadata {key}.")
        if (updated_meta.get("release_version") != base_meta.get("release_version")
                or updated_meta.get("training_revision") != "1"):
            raise ValueError("Candidate release/update revision metadata is inconsistent.")
        if evidence is None:
            raise ValueError("A changed candidate requires the durable update evidence wrapper.")
        _validate_update_evidence(evidence, base, candidate, candidate_path)
    elif evidence is not None:
        _validate_update_evidence(evidence, base, candidate, candidate_path)
    return {"changed": changed, "base_identity": base_identity,
            "candidate_identity": artifact_identity(candidate),
            "candidate_sha256": sha256_file(candidate_path),
            "fit_source_revision": selection["source_revision"],
            "fit_manifest_sha256": fit_record["manifest_sha256"]}


def _validate_update_evidence(evidence: Mapping, base: Mapping, candidate: Mapping, candidate_path: Path) -> None:
    if not isinstance(evidence, Mapping):
        raise ValueError("Update evidence must be a JSON object.")
    base_identity, candidate_identity = artifact_identity(base), artifact_identity(candidate)
    if (evidence.get("candidate_artifact_sha256") != sha256_file(candidate_path)
            or evidence.get("candidate_artifact_checksum") != candidate["checksum"]):
        raise ValueError("Update evidence does not bind the exact candidate artifact bytes/checksum.")
    request_fp = evidence.get("request_fingerprint")
    if not isinstance(request_fp, str) or not HEX64.fullmatch(request_fp):
        raise ValueError("Update evidence lacks a valid request fingerprint.")
    request = evidence.get("request")
    response = evidence.get("response")
    receipt = evidence.get("receipt")
    if not all(isinstance(value, Mapping) for value in (request, response, receipt)):
        raise ValueError("Update evidence must contain request, response and durable receipt objects.")
    metadata = response.get("metadata")
    if not isinstance(metadata, Mapping):
        raise ValueError("Update response lacks typed metadata.")
    expected_fields = {"model_id": base["model_id"], "base_version": base["version"],
                       "applied_version": candidate["version"]}
    if request.get("model_id") != base["model_id"]:
        raise ValueError("Update request model identity differs from the fitted base.")
    if response.get("accepted") is not True or response.get("model_id") != base["model_id"]:
        raise ValueError("Update response was not accepted for the expected model.")
    if any(response.get(key) != value for key, value in expected_fields.items()):
        raise ValueError("Update response base/applied model versions differ from artifacts.")
    if metadata.get("task") != "annotation_presence" or metadata.get("candidate_parameter_fingerprint") != candidate_identity["parameter_fingerprint"]:
        raise ValueError("Update response metadata task or candidate fingerprint mismatch.")
    if metadata.get("base_parameter_fingerprint") != base_identity["parameter_fingerprint"]:
        raise ValueError("Update response metadata base fingerprint mismatch.")
    if receipt.get("found") is not True or receipt.get("accepted") is not True:
        raise ValueError("Durable update receipt is missing or rejected.")
    if any(receipt.get(key) != value for key, value in expected_fields.items()):
        raise ValueError("Durable receipt model identity/version fields mismatch.")
    if receipt.get("request_fingerprint") != request_fp:
        raise ValueError("Durable receipt request fingerprint mismatch.")
    if not isinstance(request.get("request_id"), str) or not request["request_id"]:
        raise ValueError("Update evidence request ID is missing.")
    if not isinstance(request.get("source_id"), str) or not request["source_id"]:
        raise ValueError("Update evidence source ID is missing.")
    if type(request.get("prompt_count")) is not int or request["prompt_count"] != 256:
        raise ValueError("Update evidence prompt count must match the fixed 256-example protocol.")
    if type(request.get("seed")) is not int or request["seed"] not in (42, 43, 44):
        raise ValueError("Update evidence seed is outside the fixed independent cycle set.")
    if type(response.get("prompts_generated")) is not int or response["prompts_generated"] != request["prompt_count"]:
        raise ValueError("Update response generated prompt count differs from request.")


def validate_retention_selection(record: Mapping, candidate: Mapping, candidate_path: Path,
                                 fit_record: Mapping, source_revision: str,
                                 protocol_sha256: str) -> None:
    """Require the persisted pre-development retention decision to bind the candidate."""
    identity = artifact_identity(candidate)
    base_metrics = record.get("base_validation_metrics")
    _validate_validation_metrics(base_metrics)
    attempts = record.get("attempts")
    if (not isinstance(attempts, list) or len(attempts) != 3
            or {item.get("seed") for item in attempts if isinstance(item, Mapping)} != {42, 43, 44}
            or any(not isinstance(item, Mapping) or item.get("status") not in
                   ("accepted", "rejected", "failed", "accepted_unscored") for item in attempts)):
        raise ValueError("Retention selection must retain terminal records for all three fixed seeds.")
    by_seed = {item["seed"]: item for item in attempts}
    eligible = []
    for seed, attempt in by_seed.items():
        accepted_status = attempt["status"] in ("accepted", "accepted_unscored")
        if type(attempt.get("accepted")) is not bool or attempt["accepted"] != accepted_status:
            raise ValueError("Retention attempt accepted flag disagrees with its terminal status.")
        if attempt["status"] == "accepted":
            _validate_validation_metrics(attempt.get("validation_metrics"))
            for key in ("artifact_sha256", "validation_report_sha256"):
                if not isinstance(attempt.get(key), str) or not HEX64.fullmatch(attempt[key]):
                    raise ValueError(f"Scored accepted attempt lacks a valid {key}.")
            if (not isinstance(attempt.get("artifact_checksum"), str)
                    or not HEX64.fullmatch(attempt["artifact_checksum"])
                    or not isinstance(attempt.get("parameter_fingerprint"), str)
                    or not HEX64.fullmatch(attempt["parameter_fingerprint"])):
                raise ValueError("Scored accepted attempt lacks an artifact checksum/fingerprint.")
            metrics = attempt["validation_metrics"]
            if metrics["recall"] >= 0.90 and metrics["specificity"] > base_metrics["specificity"]:
                eligible.append(attempt)
        elif attempt["status"] == "accepted_unscored" and "validation_metrics" in attempt:
            raise ValueError("An accepted-but-unscored attempt cannot carry validation metrics.")
    if (record.get("status") != "selected"
            or record.get("profile") != fit_record["profile"]
            or record.get("source_revision") != source_revision
            or record.get("fit_source_revision") != fit_record["selection"]["source_revision"]
            or record.get("protocol_sha256") != protocol_sha256
            or record.get("fit_manifest_sha256") != fit_record["manifest_sha256"]
            or record.get("chosen_candidate_artifact_sha256") != sha256_file(candidate_path)
            or record.get("chosen_artifact_checksum") != candidate["checksum"]
            or record.get("chosen_parameter_fingerprint") != identity["parameter_fingerprint"]
            or record.get("base_artifact_sha256") != fit_record["selection"]["selected_artifact_sha256"]
            or not isinstance(record.get("validation_metrics"), Mapping)):
        raise ValueError("Retention selection does not bind this exact candidate/source/protocol.")
    chosen_seed = record.get("chosen_seed")
    if chosen_seed is not None and (type(chosen_seed) is not int or chosen_seed not in (42, 43, 44)):
        raise ValueError("Retention selection seed is outside the fixed independent cycle set.")
    if candidate["version"] == fit_record["artifact"]["version"] and chosen_seed is not None:
        raise ValueError("Fitted base retention must have a null chosen seed.")
    if candidate["version"] != fit_record["artifact"]["version"] and chosen_seed is None:
        raise ValueError("Updated-candidate retention must identify the selected independent seed.")
    if chosen_seed is not None:
        selected_attempt = by_seed[chosen_seed]
        if selected_attempt["status"] != "accepted":
            raise ValueError("Only an accepted and validation-scored cycle may be retained.")
    hashes = fit_record["selection"].get("input_hashes", {})
    validation_sha = hashes.get("partition_sha256", {}).get("validation")
    if record.get("validation_dataset_sha256") != validation_sha:
        raise ValueError("Retention decision is not bound to the fit-pinned validation rows.")
    for key in ("base_validation_report_sha256", "chosen_validation_report_sha256"):
        if not isinstance(record.get(key), str) or not HEX64.fullmatch(record[key]):
            raise ValueError(f"Retention decision lacks a valid {key}.")
    base_metrics = record.get("base_validation_metrics")
    chosen_metrics = record.get("validation_metrics")
    _validate_validation_metrics(base_metrics)
    _validate_validation_metrics(chosen_metrics)
    fit_candidates = fit_record["selection"].get("candidates", [])
    selected_fit_candidate = next((item for item in fit_candidates
                                   if item.get("C") == fit_record["selection"].get("selected_C")
                                   and item.get("converged") is True), None)
    fit_base_metrics = selected_fit_candidate.get("validation_metrics") if selected_fit_candidate else None
    if not isinstance(fit_base_metrics, Mapping) or any(
            base_metrics.get(key) != fit_base_metrics.get(key)
            for key in ("tp", "tn", "fp", "fn", "positive_examples", "absent_examples", "recall", "specificity")):
        raise ValueError("Recorded RPC baseline does not match the selected fitted validation candidate.")
    if base_metrics["recall"] < 0.90:
        raise ValueError("Fitted-base validation recall is below the prospective floor.")
    if chosen_seed is None:
        if record.get("restoration_verified") is not True:
            raise ValueError("Retaining the base requires a verified restoration record.")
        if chosen_metrics != base_metrics:
            raise ValueError("Base fallback validation metrics differ from its measured baseline.")
    elif (chosen_metrics["recall"] < 0.90
          or chosen_metrics["specificity"] <= base_metrics["specificity"]):
        raise ValueError("Retained update fails the fixed validation recall/specificity criteria.")
    if eligible:
        ranked = max(eligible, key=lambda item: (item["validation_metrics"]["specificity"],
                                                 item["validation_metrics"]["recall"], -item["seed"]))
        if chosen_seed != ranked["seed"]:
            raise ValueError("Retention choice does not replay the fixed validation specificity/recall/seed ranking.")
        if (record["chosen_candidate_artifact_sha256"] != ranked["artifact_sha256"]
                or record["chosen_artifact_checksum"] != ranked["artifact_checksum"]
                or record["chosen_parameter_fingerprint"] != ranked["parameter_fingerprint"]
                or record["chosen_validation_report_sha256"] != ranked["validation_report_sha256"]
                or chosen_metrics != ranked["validation_metrics"]):
            raise ValueError("Retention decision fields differ from the ranked eligible attempt.")
    elif chosen_seed is not None:
        raise ValueError("Retention selected an update although no attempt passed validation gates.")
    elif record.get("chosen_validation_report_sha256") != record.get("base_validation_report_sha256"):
        raise ValueError("Base fallback must select its measured base validation report.")


def _validate_validation_metrics(metrics: Mapping) -> None:
    if not isinstance(metrics, Mapping):
        raise ValueError("Validation metrics must be a mapping.")
    count_keys = ("tp", "tn", "fp", "fn", "positive_examples", "absent_examples")
    if any(type(metrics.get(key)) is not int or metrics[key] < 0 for key in count_keys):
        raise ValueError("Validation metrics lack strict nonnegative raw confusion counts.")
    if (metrics["tp"] + metrics["fn"] != 475
            or metrics["tn"] + metrics["fp"] != 493
            or metrics["positive_examples"] != 475
            or metrics["absent_examples"] != 493):
        raise ValueError("Validation confusion counts do not cover 475 positives and 493 absent rows.")
    expected_recall = metrics["tp"] / 475
    expected_specificity = metrics["tn"] / 493
    recall, specificity = metrics.get("recall"), metrics.get("specificity")
    if (isinstance(recall, bool) or not isinstance(recall, (int, float))
            or not math.isfinite(recall) or not math.isclose(recall, expected_recall, rel_tol=0.0, abs_tol=1e-12)
            or isinstance(specificity, bool) or not isinstance(specificity, (int, float))
            or not math.isfinite(specificity) or not math.isclose(specificity, expected_specificity, rel_tol=0.0, abs_tol=1e-12)):
        raise ValueError("Validation recall/specificity do not recompute from raw confusion counts.")
