"""Regenerate aggregate publication from accepted hash-bound inputs, without RPCs.

Usage: python reproduce.py RAW_RESULTS BUILD_EVIDENCE OUTPUT_DIRECTORY
The explicit schemas reject new fields and invalid numeric leaves. Example IDs,
candidate identities and local paths have designated omissions, not a blacklist.
"""
from pathlib import Path
import hashlib
import json
import math
import sys


SOURCE = "f2df530353a66de657a9a1adb8699021b072e418"
EXPECTED = {
    "protocol.json": "39cbf3f7d88ed3b0260f97b41ebe3c41bd8b0e09376bf3e1488dba600da0aef3",
    "summary.json": "66c419b4e3f755242ee7ac42dde5df84d40e5f5ce5ab1f255a1b0d2510716fc8",
    "audit.json": "10c58eef05a5f9d90cd3a6419e6f080aa151f2e219bdaf3508a8a801ae00476f",
}
BUILD_EXPECTED = {
    "full-handoff-receipt.json": "0f1140be4ecc5475f9eefeaf8630d4ed1be2f318f706aea25414a0ec74bfb35c",
    "full-resource-inventory.json": "93435ce4bc87c30497c902caf9fc64e12d5eb72993d431cc1d6f0f7c2445e8cf",
    "process-cessation-receipt.json": "70d34cfa1bcb66e4e74c15c09379d6f3591904860fcec12bab4afc14eca303d8",
}
PROFILES = ("efficient", "balanced", "quality")
CELL_IDS = tuple(f"{p}-{arm}" for p in PROFILES for arm in ("control", "revised-42", "revised-43", "revised-44"))
OMIT = object()
NUMBER = object()
CONTEXT = "sensitivity_accuracy visibility_accuracy category_exact_accuracy joint_accuracy action_accuracy under_restriction_rate over_restriction_rate".split()
DEVELOPMENT = "true_positives true_negatives false_positives false_negatives recall specificity precision f1 accuracy balanced_accuracy runtime_errors evaluated_samples loaded_samples coverage".split()
DEVELOPMENT_CHANGES = "recall specificity precision f1 accuracy balanced_accuracy".split()
DISCLOSURE = "joint_accuracy sensitivity_accuracy visibility_accuracy category_exact_accuracy action_accuracy".split()
PREDICATES = ("training_exact_above_minimum", "heldout_exact_no_decline", "heldout_recall_no_decline", "heldout_specificity_no_decline", "no_safety_regression")
GATE_METRICS = "candidate_heldout_clean_specificity candidate_heldout_exact_match_rate candidate_heldout_safety_regression_rate candidate_heldout_sensitive_recall exact_match_rate heldout_clean_examples heldout_clean_specificity heldout_exact_match_rate heldout_sensitive_examples heldout_sensitive_recall".split()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def project(value, schema, location="root"):
    """Apply an exact field allowlist; only designated private fields disappear."""
    if schema is OMIT:
        return OMIT
    if schema is NUMBER:
        if type(value) not in (int, float) or not math.isfinite(value):
            raise ValueError(f"Expected finite number at {location}")
        return value
    if schema is bool or schema is str:
        if type(value) is not schema:
            raise ValueError(f"Unexpected type at {location}")
        return value
    if callable(schema):
        return schema(value)
    if isinstance(schema, dict):
        if not isinstance(value, dict) or value.keys() != schema.keys():
            raise ValueError(f"Unrecognized or missing fields at {location}")
        return {k: project(value[k], spec, f"{location}.{k}") for k, spec in schema.items() if spec is not OMIT}
    if isinstance(schema, list):
        if not isinstance(value, list):
            raise ValueError(f"Expected list at {location}")
        return [project(item, schema[0], f"{location}[]") for item in value]
    if type(value) is not type(schema) or value != schema:
        raise ValueError(f"Unexpected constant at {location}")
    return value


def numbers(keys):
    return dict.fromkeys(keys, NUMBER)


def choice(values):
    def validate(value):
        if not isinstance(value, str) or value not in values:
            raise ValueError("Unknown public identifier or predicate")
        return value
    return validate


def hashes(value):
    if not isinstance(value, dict):
        raise ValueError("Expected hash inventory")
    for key, digest in value.items():
        if not isinstance(key, str) or key.startswith(("/", "\\")) or ":" in key or ".." in key.split("/"):
            raise ValueError("Only repository-relative hash inventory keys are public")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("Invalid SHA256 inventory")
    return dict(value)


HARM = {**numbers(("new_under_restrictions", "new_over_restrictions", "newly_incorrect_actions")), "passed": bool}
CONTEXT_METRICS = numbers(["rows", "groups", *CONTEXT])
DEV_METRICS = {**numbers(DEVELOPMENT), "paper_result_valid": bool}
CHANGES = {"changed_rows": NUMBER, "changed_ids": OMIT}
CELL = {"id": choice(CELL_IDS), "kind": "live", "profile": choice(PROFILES),
        "curriculum": choice(("current", "revised")), "policy": choice(("deterministic_v1", "seeded_family_v1")),
        "sampler_seed": NUMBER, "replay_weight": NUMBER, "project": OMIT, "shared_control": bool}
DECISION = {"decision_checkpoint": NUMBER, "descriptive_checkpoints": [NUMBER],
            **dict.fromkeys(("per_seed", "profile", "qualification", "interpretation"), str)}


def paired(contextual):
    keys = CONTEXT if contextual else DEVELOPMENT_CHANGES
    interval = {"estimate": NUMBER, "interval_95": [NUMBER]}
    if not contextual:
        interval["defined_replicates"] = NUMBER
    bootstrap = {"method": str, **numbers(("iterations", "seed", "rows", "groups")),
                 "changes": dict.fromkeys(keys, interval)}
    if not contextual:
        bootstrap.update(valid=bool, improved=NUMBER, deteriorated=NUMBER)
    arm = {"before": CONTEXT_METRICS if contextual else DEV_METRICS,
           "after": CONTEXT_METRICS if contextual else DEV_METRICS, "paired": bootstrap}
    if contextual:
        arm["casewise_action_harms"] = HARM
    return {"semantic": arm}


def checkpoint(final=False):
    endpoint = {"metrics": CONTEXT_METRICS, "prediction_changes": CHANGES, "casewise_harms": HARM}
    result = {"subgroups": dict.fromkeys(("controls", "disclosures", "hard_positives"), CONTEXT_METRICS),
              **numbers(("attempts", "accepted_updates", "rejected_attempts")),
              "development": {"metrics": DEV_METRICS, "prediction_changes": CHANGES},
              "contextual": endpoint, "fixtures": endpoint}
    if final:
        result.update(paired_development=paired(False), paired_contextual=paired(True))
    return result


def gate_counts(value):
    if not isinstance(value, dict) or not set(value) <= {"accepted", "rejected", *PREDICATES}:
        raise ValueError("Unknown gate predicate count")
    return project(value, numbers(value))


GATE = {"counts": gate_counts,
        "attempts": [{**numbers(("cycle",)), "published": bool, "gate_passed": bool,
                      "metrics": numbers(GATE_METRICS), "failed_predicates": [choice(PREDICATES)],
                      "base_version": OMIT, "base_parameter_fingerprint": OMIT, "candidate_parameter_fingerprint": OMIT}],
        "candidate_evidence_limit": str}
CELL_RESULT = {"cell": CELL, **numbers(("attempts", "accepted_updates", "rejected_attempts", "final_24_attempts_accepted")),
               "publication": numbers(("durable_publications", "durable_receipts", "replayed_acknowledgments_reconciled_from_durable_metadata")),
               "exposure": numbers(("reservations", "presentations", "unique_rows", "unique_families", "maximum_row_exposures")),
               "gate_diagnostics": GATE, "checkpoints": {str(c): checkpoint(c == 168) for c in (0, 24, 72, 168)},
               **dict.fromkeys(("qualified", "tradeoff_only", "no_specificity_or_context_joint_gain", "continuing_rejections_final24"), bool)}
EFFECT_NUMBERS = numbers(("revised_final_minus_shared_control_final", "revised_change_from_baseline", "shared_control_change_from_baseline", "difference_in_changes"))
EFFECT = {"shared_control_id": choice(CELL_IDS), "baseline_predictions_and_identities_identical": bool,
          "difference_in_changes_equivalent_to_final_contrast": bool, "interpretation": str,
          "development": dict.fromkeys(("recall", "specificity"), EFFECT_NUMBERS),
          "contextual": dict.fromkeys(CONTEXT, EFFECT_NUMBERS), "disclosures": dict.fromkeys(DISCLOSURE, EFFECT_NUMBERS),
          "fixture_harms_vs_shared_control": HARM,
          "exact_prediction_changes_vs_shared_control": dict.fromkeys(("development", "contextual", "fixtures"), CHANGES),
          "paired_development_vs_shared_control": paired(False), "paired_contextual_vs_shared_control": paired(True)}


def summary_projection(summary):
    profiles = {}
    for profile in PROFILES:
        revised = [f"{profile}-revised-{seed}" for seed in (42, 43, 44)]
        # Failure labels are enumerated from the frozen decision implementation.
        failures = [f"{name}_{ref}" for ref in ("baseline", "control") for name in (
            "context_joint_not_strictly_better", "annotation_recall_declined", "fixture_harm",
            *(f"disclosure_{metric}_declined" for metric in DISCLOSURE))]
        profiles[profile] = {"shared_control": f"{profile}-control",
            "revised_seed_decisions": dict.fromkeys(revised, {"promising": bool, "failed_criteria": [choice(failures)]}),
            "promising_seeds": NUMBER, "any_seed_fixture_harm_veto": bool, "promising_package": bool,
            "decision": choice(("promising", "seed-sensitive/tradeoff-or-plateau")), "seed_spread_interpretation": str,
            "revised_final_effects_vs_shared_control": dict.fromkeys(revised, EFFECT)}
    return project(summary, {"schema_version": "accelerated-semantic-v1", "evaluation_layers": [choice(("semantic",))],
        "cells": [CELL_RESULT], "profiles": profiles, "attempts": NUMBER, "allocated_presentations": NUMBER,
        "source_revision": SOURCE, "protocol_sha256": EXPECTED["protocol.json"], "decision_rules": DECISION})


def protocol_projection(protocol):
    inputs = {name: {"manifest": OMIT, "manifest_sha256": str, "files": hashes} for name in ("current", "revised")}
    inputs.update({name: {"path": OMIT, "sha256": str} for name in ("dataset", "fixture", "exclusion_index")})
    serving = ("privoke-fuzzer", "param-update-service", "client-runtime", "model-streaming-service", "telemetry-service")
    schema = {"schema_version": "accelerated-semantic-v1", "evaluation_layers": [choice(("semantic",))],
        "research_id": "AS-20261010", "original_user_message_at": None, "user_objective": str,
        "study_id": "privoke-accelerated-20261010", "created_at": str, "source_revision": SOURCE,
        "source_files": hashes, "images": dict.fromkeys(serving, str), "image_source_attestation": OMIT,
        "inputs": inputs, "cells": [CELL], "live": {**numbers(("attempts", "prompt_count", "new_rows", "replay_rows", "heldout_rows", "trainer_seed", "learning_rate", "gradient_clamp", "replay_weight", "replay_fraction", "transforms")), "checkpoints": [NUMBER], "mining": bool},
        "decision": DECISION, "analysis": {**numbers(("bootstrap_iterations", "bootstrap_seed")), "seed_spread": str, "intervals": str},
        "limitations": [str]}
    result = project(protocol, schema)
    result["execution_protocol_sha256"] = EXPECTED["protocol.json"]
    result["image_source_attestation"] = {service: hashes({path.removeprefix("/workspace/"): digest for path, digest in files.items()})
                                          for service, files in protocol["image_source_attestation"].items()}
    if set(result["image_source_attestation"]) != {"privoke-fuzzer", "param-update-service", "client-runtime"}:
        raise ValueError("Unknown source-overlay service")
    return result


def read_bound(root, expected):
    data = {}
    for name, digest in expected.items():
        if sha(root / name) != digest:
            raise ValueError(f"Accepted input hash differs: {name}")
        data[name] = json.loads((root / name).read_text(encoding="utf-8-sig"),
                                parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))
    return data


def encoded(value):
    return (json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def publish(source, build, destination):
    source, build, destination = map(Path, (source, build, destination))
    if destination.resolve() in (source.resolve(), build.resolve()) or any(root.resolve() in destination.resolve().parents for root in (source, build)):
        raise ValueError("Publication destination must be separate from accepted raw evidence")
    raw, receipts = read_bound(source, EXPECTED), read_bound(build, BUILD_EXPECTED)
    summary, protocol, audit = raw["summary.json"], raw["protocol.json"], raw["audit.json"]
    if not audit["passed"] or audit["summary_sha256"] != EXPECTED["summary.json"] or audit["protocol_sha256"] != EXPECTED["protocol.json"]:
        raise ValueError("Raw audit does not bind the accepted summary and protocol")
    if [c["cell"]["id"] for c in summary["cells"]] != list(CELL_IDS) or set(audit["archives"]) != set(CELL_IDS):
        raise ValueError("Expected twelve unique cells and archives")
    if (summary["attempts"], summary["allocated_presentations"], sum(c["accepted_updates"] for c in summary["cells"]), sum(c["rejected_attempts"] for c in summary["cells"])) != (2016, 64512, 1270, 746):
        raise ValueError("Accepted study totals differ")
    inventory, cessation, handoff = (receipts[name] for name in ("full-resource-inventory.json", "process-cessation-receipt.json", "full-handoff-receipt.json"))
    outputs = {"summary.json": summary_projection(summary), "protocol.json": protocol_projection(protocol),
        "audit.json": project(audit, {"passed": bool, "protocol_sha256": str, "summary_sha256": str, "archives": dict.fromkeys(CELL_IDS, str), "checks": [str]}),
        "provenance.json": {"execution_source_revision": SOURCE, "raw_input_sha256": EXPECTED,
            "accepted_handoff_sha256": BUILD_EXPECTED, "counts": {k: handoff[k] for k in ("attempts", "accepted", "rejected", "gate_diagnostics", "presentations", "checkpoint_observations", "qualified_cells")},
            "all_archives_and_static_inputs_reverified": handoff["all_archives_reverified"] and handoff["freeze_and_static_inputs_reverified"],
            "process_cessation": {k: cessation[k] for k in ("execution_exit", "audit_exit", "passed")},
            "resource_status_at_handoff": {"stopped_containers": len(inventory["containers"]), "retained_volumes": len(inventory["volumes"]), "empty_networks": len(inventory["networks"]), "retained_task_images": len(inventory["images"]), "checks": inventory["checks"], "cleanup_status": "retained pending separate cleanup acceptance"},
            "runtime_scope": handoff["runtime_scope"], "cell_runtime_seconds": {r["id"]: r["cell_start_to_archive_seconds"] for r in handoff["cells"]},
            "projection": "Explicit field allowlists preserve numeric metrics, counts, predicates, decisions, controlled contrasts and intervals without rounding. Omit changed_ids everywhere, per-attempt base_version and parameter fingerprints, project storage names and local input paths. Image source names are repository-relative. The raw audit binds the raw summary; the publication manifest separately binds public bytes.",
            "candidate_evidence_limit": summary["cells"][0]["gate_diagnostics"]["candidate_evidence_limit"]}}
    blobs = {name: encoded(value) for name, value in outputs.items()}
    # The audited receipt is already aggregate-only; preserve its original bytes.
    blobs["audit.json"] = (source / "audit.json").read_bytes()
    manifest = {"reproduction_script_sha256": sha(Path(__file__)),
        "published_sha256": {name: hashlib.sha256(blob).hexdigest() for name, blob in sorted(blobs.items())},
        "raw_to_published": {name: {"raw_sha256": EXPECTED[name], "published_sha256": hashlib.sha256(blobs[name]).hexdigest(), "identical_bytes": (source / name).read_bytes() == blobs[name]} for name in EXPECTED},
        "projection": outputs["provenance.json"]["projection"]}
    blobs["publication-hashes.json"] = encoded(manifest)
    destination.mkdir(parents=True, exist_ok=True)
    for name, blob in blobs.items():
        (destination / name).write_bytes(blob)
    # Fail if any accepted input changed while projection was being generated.
    read_bound(source, EXPECTED)
    read_bound(build, BUILD_EXPECTED)
    return manifest


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    print(json.dumps(publish(*sys.argv[1:]), indent=2))
