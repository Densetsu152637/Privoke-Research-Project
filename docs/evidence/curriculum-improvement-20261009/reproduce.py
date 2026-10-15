"""Publish selected safe aggregates from the accepted local study; no RPCs/fitting.

Usage: python reproduce.py PATH_TO_V2_RESULTS OUTPUT_DIRECTORY
Only the listed, hash-bound JSON inputs are read. Raw prompts, predictions,
weights, environment values and database contents are never published.
"""
from pathlib import Path
import hashlib
import json
import sys


EXPECTED = {
    "protocol.json": "f631c6078c439f9f7ff616e29f9c3d09ad36e22f079d2cdeed16a7fb459fc602",
    "semantic-imports.json": "8d43fd5d0fda1a6e73b7796cfc0b2585c09ef2d8080c5973b0e23a70f06c5bfa",
    "summary.json": "b191e660f3e792a53047282c352e57089ff1f1bf05698a1c3c0d40b0c72867c2",
    "audit.json": "e7b54de530239e39d0b7974c9ccd675152ca76bc2e13af507c16f3564ad43bd4",
    "post-observation-contextual-subgroups.json": "944b71e7d5df0e21ddaf8fb76843d6f9c533440ff8e0a0edc9c7ffe086cf63a8",
    "rejection-breakdown.json": "964652044466bfa1b45662327906fb9d5f8d91b58d3206f1cacc97a1de92fde2",
    "final-resource-inventory.json": "239ebf8f30b7eecedba0ce851d2bab98761aac2e245b83d1d47be8cf8ddbabfc",
    "final-handoff.json": "cae6957bc737defc03e3118457a8f9fb3612d43d767e0795f0246c422122e980",
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def select(value, keys):
    return {key: value[key] for key in keys}


def validate_safe(value):
    forbidden = {"text", "prompt", "prompts", "predictions", "row_ids", "raw",
                 "parameters", "gradients", "environment", "secret", "api_key"}
    if isinstance(value, dict):
        assert not forbidden.intersection(value), forbidden.intersection(value)
        for item in value.values():
            validate_safe(item)
    elif isinstance(value, list):
        for item in value:
            validate_safe(item)


def publish(source, destination):
    data = {}
    for name, expected in EXPECTED.items():
        assert sha(source / name) == expected, name
        data[name] = json.loads((source / name).read_text(encoding="utf-8"))
    protocol, summary = data["protocol.json"], data["summary.json"]
    audit, handoff = data["audit.json"], data["final-handoff.json"]
    inventory = data["final-resource-inventory.json"]
    assert audit["passed"] and audit["summary_sha256"] == EXPECTED["summary.json"]
    assert len(summary["cells"]) == 63 and len(summary["groups"]) == 21
    assert len(summary["contrasts"]) == 24
    assert sum(c["eligible"] for c in summary["cells"]) == 0
    assert summary["live_attempts"] == 900 and summary["accepted_updates"] == 615
    assert summary["offline_steps"] == 360
    assert sum(c["rejected_attempts"] or 0 for c in summary["cells"]) == 285
    outputs = {
        "summary.json": select(summary, ("schema_version", "evaluation_layers", "protocol_sha256",
            "source_revision", "imported_semantic_cells", "prospective_semantic_cells", "status",
            "live_cells", "offline_cells", "live_attempts", "accepted_updates", "offline_steps",
            "cells", "groups", "contrasts", "limitations", "inference")),
        "audit.json": audit,
        "contextual-subgroups.json": select(data["post-observation-contextual-subgroups.json"],
            ("analysis", "created_at", "source_revision", "protocol_sha256", "summary_sha256",
             "method", "cells", "paired_comparisons", "profile_mode_statistics")),
        "rejection-breakdown.json": data["rejection-breakdown.json"],
    }
    amendment = select(protocol["amendment"], ("user_instruction", "original_user_message_at",
        "original_user_message_time_status", "recorded_at", "cessation_verified_at",
        "eligibility_changed_after_observation", "imported_cells", "prospective_cells", "reason"))
    inputs = {key: {k: v for k, v in value.items() if k not in {"path", "manifest"}}
              for key, value in protocol["inputs"].items()}
    outputs["protocol.json"] = {
        **select(protocol, ("schema_version", "evaluation_layers", "study_id", "created_at",
            "source_revision", "source_files", "images", "cells", "live", "offline", "analysis", "limitations")),
        "original_protocol_sha256": protocol["imports"]["protocol_sha256"],
        "original_source_revision": protocol["imports"]["source_revision"],
        "execution_protocol_sha256": EXPECTED["protocol.json"],
        "import_manifest_sha256": EXPECTED["semantic-imports.json"],
        "amendment": amendment, "inputs": inputs,
        "note": "Safe selected protocol fields; execution protocol bytes remain immutable in ignored raw evidence.",
    }
    outputs["provenance.json"] = {
        "execution_source_revision": protocol["source_revision"],
        "publication_revision": "Later documentation-only revision; does not replace execution commitments.",
        "local_input_sha256": EXPECTED,
        "publication_projection": "All cell/group/contrast metrics, counts, intervals and qualification values are unchanged. Summary omits duplicated amendment provenance; protocol separates import/source attestation into provenance and omits local input paths; subgroup omits local endpoint path/hash inventory. Raw audit summary_sha256 binds the original local summary, not the published projection. Publication hashes below bind the actual selected files.",
        "original_import_archives": {key: value["archive_sha256"]
                                     for key, value in protocol["imports"]["cells"].items()},
        "training_equivalence": protocol["amendment"]["training_equivalence"],
        "image_source_attestation": protocol["image_source_attestation"],
        "counts": handoff["counts"],
        "terminal_processes": handoff["terminal_processes"],
        "live_acceptance_by_profile": handoff["live_acceptance_by_profile"],
        "resource_status_at_handoff": handoff["resources"],
        "resource_volume_reconciliation": select(inventory["volume_reconciliation"],
            ("verified_at", "superseded_inventory_sha256", "defect", "method",
             "expected_unique_volumes", "inspected_unique_volumes", "prior_network_retirement_volume_proof")),
        "recovery_artifact_sha256": {name: value for name, value in handoff["artifact_sha256"].items()
                                    if "network" in name or "timing" in name or "superseded" in name},
        "limitations": handoff["limitations"],
        "privacy": "Selected aggregates, source paths, model/cell identities and hashes only; no raw prompts, predictions, PII, weights, secrets or environment values.",
    }
    destination.mkdir(parents=True, exist_ok=True)
    for name, value in outputs.items():
        validate_safe(value)
        (destination / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    raw_names = {"summary.json": "summary.json", "protocol.json": "protocol.json",
                 "audit.json": "audit.json", "contextual-subgroups.json": "post-observation-contextual-subgroups.json",
                 "rejection-breakdown.json": "rejection-breakdown.json"}
    manifest = {
        "reproduction_script_sha256": sha(Path(__file__)),
        "published_sha256": {name: sha(destination / name) for name in sorted(outputs)},
        "raw_to_published": {name: {"raw_name": raw_name, "raw_sha256": EXPECTED[raw_name],
                                     "published_sha256": sha(destination / name),
                                     "identical_bytes": EXPECTED[raw_name] == sha(destination / name)}
                             for name, raw_name in raw_names.items()},
        "projection": outputs["provenance.json"]["publication_projection"],
    }
    (destination / "publication-hashes.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    print(json.dumps(publish(Path(sys.argv[1]), Path(sys.argv[2])), indent=2))
