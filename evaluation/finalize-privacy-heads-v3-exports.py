"""Versioned post-fit export repair: preserve PH3 training and frozen sources.

The original exporter compared Classification instances by object identity.
This separate finalizer checks native values and exact finite logits, binds its
own reviewed source/test proof, and preserves existing selected asset bytes.
"""
from __future__ import annotations

import argparse
import math
from pathlib import Path
import sys

import torch

from privoke_eval import privacy_heads_v3 as core

CORRECTION_ID = "PH3-EXPORT-VALUE-PARITY-R1"
TEST_PATH = "evaluation/tests/test_privacy_heads_v3_export_finalize.py"


def prediction_values(predictions, texts):
    from src.classification import ClassificationResult
    core.require(len(predictions) == len(texts), "Native prediction row count differs")
    rows = []
    for text, (value, confidence) in zip(texts, predictions):
        core.require(math.isfinite(confidence) and 0 <= confidence <= 1,
                     "Native confidence is not finite and bounded")
        rows.append({"packed": value.pack(), "named": value.to_dict(), "confidence": confidence,
                     "action": ClassificationResult(value, text, "export parity",
                                                    confidence=confidence).action().name})
    return rows


def assert_values_and_logits(before, after, before_logits, after_logits, row_count):
    """Compare values, including policy action, rather than Classification identity."""
    core.require(row_count > 0 and len(before) == len(after) == row_count,
                 "Serialized parity row count differs")
    core.require(set(before_logits) == set(after_logits) == set(core.LABELS),
                 "Serialized parity task set differs")
    errors = {}
    for task, labels in core.LABELS.items():
        left, right = before_logits[task], after_logits[task]
        core.require(left.shape == right.shape == (row_count, len(labels)),
                     "Serialized logit shape differs")
        core.require(bool(torch.isfinite(left).all()) and bool(torch.isfinite(right).all()),
                     "Serialized logits are nonfinite")
        core.require(torch.equal(left, right), "Serialized native logits differ: " + task)
        errors[task] = float((left - right).abs().max())
    core.require(before == after, "Serialized packed/named/confidence/action values differ")
    return {"rows": row_count, "packed_named_confidence_action_exact": True,
            "finite_logits_exact": True, "max_abs_logit_errors": errors}


def native_parity(model, reloaded, rows):
    texts = [row["text"] for row in rows]
    before = prediction_values(model.predictions(texts), texts)
    after = prediction_values(reloaded.predictions(texts), texts)
    with torch.no_grad():
        before_logits, after_logits = model(texts), reloaded(texts)
    result = assert_values_and_logits(before, after, before_logits, after_logits, len(rows))
    result["row_ids"] = [row["id"] for row in rows]
    return result


def correction_record(results, test_proof):
    """Write a reviewable commitment before any export index can be published."""
    results = Path(results)
    protocol, binding, _, _ = core.validate_protocol(results)
    test_proof = Path(test_proof).resolve()
    proof = core.read(test_proof)
    source_sha = core.file_hash(__file__)
    test_sha = core.file_hash(Path(binding["repository"]) / TEST_PATH)
    core.require(proof.get("status") == "passed" and proof.get("exit") == 0
                 and proof.get("finalizer_sha256") == source_sha
                 and proof.get("test_source_sha256") == test_sha,
                 "Corrective source/test proof missing or changed")
    failures = sorted((results / "failures").glob("export-*.json"))
    core.require(len(failures) == 3, "Exactly three preserved original export failures required")
    fits, partials = {}, {}
    for tier in core.TIERS:
        summary_path = results / "fits" / tier / "complete.json"
        summary = core.read(summary_path)
        core.require(summary["epoch"] >= core.POLICY["min_epochs"], "Incomplete fit")
        fits[tier] = {"summary_sha256": core.file_hash(summary_path), "checkpoint": summary["checkpoint"],
                      "terminal_epoch": summary["epoch"], "selected_epoch": summary["best_epoch"]}
        directory = Path(binding["models"]) / "exports" / tier / "selected"
        partials[tier] = {name: core.file_hash(directory / name) for name in
                         ("model.safetensors", "manifest.json", "evidence.json", "config.json", "vocab.txt")}
    record = {"schema": 1, "correction_id": CORRECTION_ID, "study_id": core.STUDY_ID,
              "protocol_sha256": core.file_hash(results / "protocol.json"),
              "original_source_closure": protocol["source_closure"],
              "original_exporter_sha256": protocol["source_files"]["evaluation/privoke_eval/privacy_heads_v3.py"],
              "finalizer_sha256": source_sha, "test_source_sha256": test_sha,
              "test_proof": str(test_proof), "test_proof_sha256": core.file_hash(test_proof),
              "failures": {p.relative_to(results).as_posix(): core.file_hash(p) for p in failures},
              "fits": fits, "partial_selected_assets": partials,
              "change": "Object-identity comparison replaced only by exact native value and finite-logit comparison",
              "unchanged": "Training, checkpoints, selection, artifact/evidence schema, native inference and frozen sources",
              "fresh_eval_access": False, "refitting": False, "promotion": False}
    path = results / "corrections" / "export-value-parity-r1.json"
    core.retain(path, record)
    return record


def require_correction_acceptance(results):
    results = Path(results)
    path = results / "corrections" / "export-value-parity-r1.json"
    record = core.read(path)
    acceptance_path = results / "export-correction-acceptance.json"
    acceptance = core.read(acceptance_path)
    core.require(acceptance.get("status") == "accepted"
                 and acceptance.get("correction_record_sha256") == core.file_hash(path)
                 and acceptance.get("finalizer_sha256") == core.file_hash(__file__)
                 and acceptance.get("protocol_sha256") == core.file_hash(results / "protocol.json"),
                 "Root export correction acceptance missing or drifted")
    core.require(record["finalizer_sha256"] == core.file_hash(__file__)
                 and record["test_proof_sha256"] == core.file_hash(record["test_proof"]),
                 "Corrective source/test proof drift")
    binding = core.read(results / "bindings.json")
    core.require(record["test_source_sha256"] == core.file_hash(Path(binding["repository"]) / TEST_PATH),
                 "Corrective regression test source drift")
    return record, core.file_hash(acceptance_path)


def finalize_tier(results, tier):
    results = Path(results)
    protocol, binding, _, validation = core.validate_protocol(results)
    correction, acceptance_sha = require_correction_acceptance(results)
    models = Path(binding["models"])
    summary_path = results / "fits" / tier / "complete.json"
    summary = core.read(summary_path)
    core.require(core.file_hash(summary_path) == correction["fits"][tier]["summary_sha256"],
                 "Fit changed since corrective review")
    checkpoints = models / "cells" / tier / "checkpoints"
    state = core.restore_checkpoint(checkpoints, summary["identity"])
    core.require(core.read(checkpoints / "latest.json")["sha256"] == summary["checkpoint"],
                 "Terminal checkpoint changed")
    original, model = core.load_initial(binding["repository"], tier, models / "initials" / tier)
    outputs, proofs = {}, {}
    from src.v3.model import PretrainedV3
    for kind, key, epoch in (("selected", "best_heads", state["best_epoch"]),
                             ("terminal", "heads", state["epoch"])):
        model.heads.load_state_dict(state[key], strict=True)
        directory = models / "exports" / tier / kind
        directory.mkdir(parents=True, exist_ok=True)
        candidate_path = directory / "model.safetensors"
        if kind == "selected":
            for name, sha in correction["partial_selected_assets"][tier].items():
                core.require(core.file_hash(directory / name) == sha, "Partial selected bytes changed")
            # Reuse the actual existing blob, then prove its complete tensors and values.
            payload = candidate_path.read_bytes()
            inventory = core.tensor_inventory(model.state_dict())
        else:
            temporary = directory / "corrective-export.tmp"
            try:
                inventory = model.export(temporary)
                payload = temporary.read_bytes()
            finally:
                temporary.unlink(missing_ok=True)
        frozen = core.frozen_proof(original["tensors"], inventory)
        core.require(frozen["changed_tensors"], "Export has no learned heads")
        # These fields deliberately match the immutable original exporter exactly.
        evidence = {"schema": 1, "study_id": core.STUDY_ID, "scope": "heads", "layers": [4],
                    "tier": tier, "base": core.INITIAL_PINS[tier][0],
                    "protocol_sha256": core.file_hash(results / "protocol.json"),
                    "dataset_manifest_sha256": protocol["dataset_manifest_sha256"],
                    "source_closure": protocol["source_closure"], "policy": core.POLICY,
                    "fit_summary_sha256": core.file_hash(summary_path), "checkpoint": summary["checkpoint"],
                    "epoch": epoch, "kind": kind, "candidate_blob": core.digest(payload), "frozen": frozen,
                    "selection": "validation_only_no_fresh_eval_access",
                    "publication": "research_only_no_legacy_guard_or_promotion"}
        evidence_bytes = core.canonical(evidence)
        manifest = dict(original, parent=core.INITIAL_PINS[tier][0], original=core.INITIAL_PINS[tier][0],
                        scope="heads", blob=core.digest(payload), tensors=inventory,
                        evidence=core.digest(evidence_bytes))
        core.retain(candidate_path, payload)
        core.retain(directory / "evidence.json", evidence_bytes)
        core.retain(directory / "manifest.json", manifest)
        for filename in ("config.json", "vocab.txt"):
            core.retain(directory / filename, (models / "initials" / tier / filename).read_bytes())
        reloaded = PretrainedV3.load(manifest, candidate_path, directory / "config.json",
                                    directory / "vocab.txt", device="cpu")
        actual_inventory = core.tensor_inventory(reloaded.state_dict())
        core.require(actual_inventory == inventory, "Serialized complete tensor inventory differs")
        actual_frozen = core.frozen_proof(original["tensors"], actual_inventory)
        core.require(actual_frozen == frozen, "Serialized frozen encoder proof differs")
        core.require(all(torch.equal(reloaded.heads[name].detach(), value) for name, value in state[key].items()),
                     "Serialized heads differ from chosen checkpoint")
        proofs[kind] = {"parity": native_parity(model, reloaded, validation[:8]),
                        "frozen": actual_frozen, "checkpoint_heads_exact": True, "epoch": epoch}
        outputs[kind] = {"directory": str(directory), "manifest_sha256": core.file_hash(directory / "manifest.json"),
                         "blob": manifest["blob"], "evidence": manifest["evidence"], "epoch": epoch}
    core.validate_protocol(results)
    require_correction_acceptance(results)
    proof = {"schema": 1, "correction_id": CORRECTION_ID, "tier": tier,
             "correction_record_sha256": core.file_hash(results / "corrections/export-value-parity-r1.json"),
             "acceptance_sha256": acceptance_sha, "proofs": proofs,
             "expected_export_index_sha256": core.digest(core.canonical(outputs)),
             "selected_partial_bytes_preserved": True, "fresh_eval_access": False, "refitting": False}
    # Corrective acceptance and parity evidence exist before index publication.
    core.retain(results / "corrections/exports" / (tier + ".json"), proof)
    core.retain(results / "exports" / (tier + ".json"), outputs)
    return outputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("record", "finalize"))
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--test-proof", type=Path)
    parser.add_argument("--tier", choices=core.TIERS)
    args = parser.parse_args()
    binding = core.read(args.results / "bindings.json")
    core.configure_repository(binding["repository"])
    if args.action == "record":
        if args.test_proof is None:
            parser.error("--test-proof is required")
        result = correction_record(args.results, args.test_proof)
    else:
        if args.tier is None:
            parser.error("--tier is required")
        result = finalize_tier(args.results, args.tier)
    print(core.canonical(result).decode(), end="")


if __name__ == "__main__":
    main()
