"""Read-only admission of the interrupted v1 study's isolated semantic views."""
from pathlib import Path

from privoke_eval import continual_fuzzer_study as continual

V1_PROTOCOL_SHA = "0892e64651a59d279aafa8975cca90cc337e769509853bd84cd5c0d1e83ad713"
V1_SOURCE = "4b71dc504d71d71f7159279911f9cd839ab72e7d"
USER_INSTRUCTION = "when running the pipelines for testing the LLM layer, ensure you are running them only with the LLM layer (and in the future as well)"
IMPORT_IDS = {f"efficient-{arm}-{seed}" for arm in "abcde" for seed in (42, 43, 44)}


def semantic_view(layers, *, imported=False):
    """Select before computing metrics; imports retain unrelated historical bytes."""
    if "semantic" not in layers or (not imported and set(layers) != {"semantic"}):
        raise ValueError("Semantic-only endpoint required; unexpected or missing layer.")
    report = layers["semantic"]
    if not report.get("predictions"):
        raise ValueError("Empty semantic endpoint.")
    for row in report["predictions"]:
        if row.get("status") != "ok":
            raise ValueError("Unsuccessful semantic observation cannot be imported or scored.")
        continual.require_semantic_execution(row.get("raw", {}))
    return {"semantic": report}


def archive_commitment(directory, expected):
    archive = directory / "archive.json"
    if continual.sha(archive) != expected:
        raise ValueError("Imported archive commitment changed.")
    inventory = continual.read_json(archive)
    for name, value in inventory.items():
        path = (directory / name).resolve()
        path.relative_to(directory.resolve())
        if continual.sha(path) != value:
            raise ValueError("Imported archive file changed.")


def build_import_manifest(output):
    output = continual.permitted_path(output)
    protocol_path = output / "protocol.json"
    protocol = continual.read_json(protocol_path)
    state = continual.read_json(output / "supervisor.json")
    if (continual.sha(protocol_path) != V1_PROTOCOL_SHA or state["protocol_sha256"] != V1_PROTOCOL_SHA
            or protocol["source_revision"] != V1_SOURCE or set(state["cells"]) != IMPORT_IDS):
        raise ValueError("Only the reviewed 15 completed v1 efficient cells may be imported.")
    pause_path = output / "semantic-only-pause-checkpoint.json"
    pause = continual.read_json(pause_path)
    if (pause.get("status") != "deliberately_stopped_for_semantic_only_amendment"
            or pause.get("complete_cells") != 15 or pause.get("pending") is not None):
        raise ValueError("Unresolved v1 stop checkpoint.")
    cells = {}
    for cell in protocol["cells"]:
        key = cell["id"]
        if key not in IMPORT_IDS:
            continue
        saved = state["cells"][key]
        if saved["status"] != "complete":
            raise ValueError("Incomplete v1 cell.")
        directory = output / "cells" / key
        archive_commitment(directory, saved["archive_sha256"])
        observations = 0
        for cycle in (0, 20):
            endpoints = [continual.read_json(directory / "controller/privoke-efficient" / f"checkpoint-{cycle:03d}.json")]
            endpoints += [continual.read_json(directory / f"{name}-{cycle:03d}.json")["layers"] for name in ("context", "fixture")]
            for endpoint in endpoints:
                observations += len(semantic_view(endpoint, imported=True)["semantic"]["predictions"])
        if observations != 1228:
            raise ValueError("Imported semantic endpoint budget differs.")
        cells[key] = {"cell": cell, "state": saved, "directory": str(directory),
                      "archive_sha256": saved["archive_sha256"], "semantic_observations": observations}
    return {"schema_version": 1, "protocol_path": str(protocol_path), "protocol_sha256": V1_PROTOCOL_SHA,
            "source_revision": V1_SOURCE, "pause_path": str(pause_path), "pause_sha256": continual.sha(pause_path),
            "user_instruction": USER_INSTRUCTION, "cessation_verified_at": pause["verified_at"],
            "cells": cells, "semantic_observations": sum(c["semantic_observations"] for c in cells.values())}


def verify_import_manifest(manifest):
    fresh = build_import_manifest(Path(manifest["protocol_path"]).parent)
    if fresh != manifest:
        raise ValueError("Frozen semantic import manifest changed.")
    return continual.read_json(manifest["protocol_path"])
