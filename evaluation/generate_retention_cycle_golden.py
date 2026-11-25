"""Local golden generator for complete ORIGINAL retention cycles of the Rust fuzzer (`rust/services/fuzzer`, stage 21, RUST-S21G item 5).

Historical (stage V3-R8b): the Rust consumer of this golden, `rust/services/fuzzer`, was deleted when V1 training was retired,
so the output path below no longer exists in the tree. The generator is kept as the record of how the stage 21 golden was made.

A retention cycle needs the real approved TRAIN bank, the ORIGINAL teacher artifact, the references and the manifest of a profile,
and the retained cycles of the sensitive retention pilots (`sensitive-retention-pilot03` gate, `sensitive-retention-pilot04` gate and
hinge) hold real runtime responses that are bound to those releases. The oracle is the maintained Python fuzzer, run in process as
`generate_full_adam_cycle_golden.py` does, with the sidecars of the pilot's own compose file and the response of each retained cycle
replayed for the request the oracle builds over the committed benign fixtures.

The golden holds the retained release (the bank holds prompt text), so it is written under `rust/services/fuzzer/tests/local/`, which
Git ignores, and is never committed. The Rust replay is the env-gated `tests/retention_cycles.rs`.

The release records the teacher path as given, and `training_evidence_sha256` hashes it, so both runs read the sidecars by bare file
names from the working directory (`bank.json`, `references.json`, `manifest.json`, `teacher.json`): the path string is the same on
the Windows oracle and in the Linux replay.

Usage (host Python, for example `evaluation/.venv-v1-v3-pipeline`):
  python evaluation/generate_retention_cycle_golden.py --results <main checkout>/evaluation/results --generated <dir>
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import generate_coverage_cycle_golden as coverage  # noqa: E402
import generate_full_adam_cycle_golden as fa  # noqa: E402

base = fa.base
STUDY = fa.STUDY
OUTPUT = base.ROOT / "rust/services/fuzzer/tests/local/retention_cycles_golden.json"
SIDECARS = (("bank", "bank.json", "FUZZ_RETENTION_BANK_PATH"), ("references", "references.json", "FUZZ_RETENTION_REFERENCE_PATH"),
            ("manifest", "manifest.json", "FUZZ_RETENTION_MANIFEST_PATH"), ("teacher", "teacher.json", "FUZZ_RETENTION_TEACHER_PATH"))
TARGETS = {"bank": "/retention/bank.json", "references": "/retention/references.json", "manifest": "/retention/manifest.json",
           "teacher": "/retention/teacher.json"}
# (pilot directory, cell). Every retained cycle of the cell is replayed.
CELLS = (("sensitive-retention-pilot03", "quality-gate"), ("sensitive-retention-pilot04", "quality-hinge"),
         ("sensitive-retention-pilot04", "efficient-hinge"), ("sensitive-retention-pilot04", "balanced-gate"))


def cell_sidecars(study: Path, pilot: str, cell: str, results: Path) -> dict:
    """The four sidecar files of the cell's fuzzer service, from the pilot's own compose file (relative to `results`)."""
    compose = json.loads((study / pilot / "compose.pilot.json").read_text(encoding="utf-8"))
    volumes = compose["services"][f"{cell}-fuzzer"]["volumes"]
    found = {}
    for name, target in TARGETS.items():
        source = next(volume["source"] for volume in volumes if volume["target"] == target)
        found[name] = Path(source).resolve().relative_to(results.resolve()).as_posix()
    return found


def cell_records(study: Path, pilot: str, cell: str) -> list:
    records = []
    for path in sorted((study / pilot / "execution" / "cells" / cell / "fuzzer" / "training-cycles").glob("*/*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        if (record["training_stage"] == "full_encoder" and record["metadata"].get("contextual_sampling_strategy") == coverage.BENIGN
                and record["metadata"].get("contextual_training_optimizer", "").startswith("full_projected_adam64_original_train_")):
            records.append(record)
    return sorted(records, key=lambda record: record["request_id"])


def golden(results: Path, generated: Path) -> dict:
    base.bootstrap(generated)
    from privoke.v1 import parameters_pb2, runtime_pb2  # noqa: PLC0415
    from privoke_model import sensitive_retention as retention  # noqa: PLC0415
    from privoke_model.full_adam import CONFIG, canonical  # noqa: PLC0415
    from prompt_generation import benign_coverage as benign  # noqa: PLC0415
    from prompt_generation.taxonomy_coverage import load_dataset as load_taxonomy_dataset  # noqa: PLC0415

    study = results / STUDY
    dataset = load_taxonomy_dataset(str(base.TAXONOMY_DATASET))
    release = benign.load_release(str(coverage.PATHS["FUZZ_BENIGN_POOL_PATH"]), str(coverage.PATHS["FUZZ_BENIGN_MANIFEST_PATH"]),
                                  str(coverage.PATHS["FUZZ_BENIGN_EXCLUSION_PROOF_PATH"]), dataset)
    benign_pins = {"taxonomy_dataset_sha256": dataset.sha256, benign.POOL_KEY: release.pool.sha256,
                   benign.MANIFEST_KEY: release.sha256, benign.PROOF_KEY: release.proof_sha256}
    sequences = []
    for pilot, cell in CELLS:
        records = cell_records(study, pilot, cell)
        if not records:
            continue
        sidecars = cell_sidecars(study, pilot, cell, results)
        first = records[0]
        policy = first["metadata"]["contextual_training_optimizer"]
        pin = first["metadata"][retention.MANIFEST_KEY]
        retention_policy = {
            "expected_contextual_training_objective": retention.OBJECTIVES[policy],
            "expected_contextual_training_optimizer": policy,
            "expected_contextual_candidate_eligibility": retention.ELIGIBILITY,
            "expected_full_projected_adam_config_v1": canonical(CONFIG),
            "expected_contextual_training_scope": "full_encoder",
            "expected_original_train_retention_manifest_sha256": pin}
        cycles = []
        for record in records:
            seed = int(record["request_id"].split("-")[-2])
            request = parameters_pb2.FuzzerTrainingRequest(
                request_id=record["request_id"], source_id=record.get("original_source_id", record["source_id"]),
                model_id=record["model_id"], prompt_count=32, seed=seed,
                metadata={"initiator": "param-update-service", "require_full_capability": "true", "expected_base_version": record["base_version"],
                          "contextual_sampling_strategy": coverage.BENIGN, **benign_pins, **retention_policy})
            raw = base64.b64decode(record["execution_evidence"]["response_protobuf_base64"])
            cycles.append((request, "full_encoder", raw, base.ack_bytes_for(parameters_pb2, record)))
        with tempfile.TemporaryDirectory() as scratch:
            for name, bare, _ in SIDECARS:
                shutil.copyfile(results / sidecars[name], Path(scratch) / bare)
            env = {"MODEL_ID": first["model_id"], **fa.full_adam_env(), "FUZZ_RETENTION_MANIFEST_SHA256": pin,
                   **{variable: bare for _, bare, variable in SIDECARS},
                   **{name: str(path) for name, path in coverage.PATHS.items() if name != "FUZZ_REHEARSAL_MANIFEST_PATH"}}
            cwd = Path.cwd()
            os.chdir(scratch)
            try:
                sequence = fa.run_sequence(f"retention-{pilot[-7:]}-{cell}", env, cycles, generated)
            finally:
                os.chdir(cwd)
        for name in ("FUZZ_BENIGN_POOL_PATH", "FUZZ_BENIGN_MANIFEST_PATH", "FUZZ_BENIGN_EXCLUSION_PROOF_PATH"):
            sequence["env"].pop(name, None)
        sequence["paths"] = {name: coverage.relative(path) for name, path in coverage.PATHS.items() if name != "FUZZ_REHEARSAL_MANIFEST_PATH"}
        sequence["sidecars"] = sidecars
        sequence["recorded"] = {"study": STUDY, "pilot": pilot, "cell": cell, "request_ids": [record["request_id"] for record in records],
                                "recorded_runtime_request_matches": [
                                    base.b64(base64.b64decode(record["execution_evidence"]["request_protobuf_base64"])) == result["runtime_request"]
                                    for record, result in zip(records, sequence["cycles"])]}
        sequences.append(sequence)
    if not sequences:
        raise SystemExit(f"{study} holds no retained ORIGINAL retention cycles")
    return {"schema": 1, "oracle": "services/privoke-fuzzer/src/fuzzer_service.py", "python": sys.version.split()[0],
            "normalisation": "timestamp file names become ordinals; the dump directory becomes <DUMP>; sidecars are read by bare file name",
            "sequences": sequences}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results", type=Path, required=True, help="evaluation/results of a checkout holding the retained iterative study")
    parser.add_argument("--generated", type=Path, required=True, help="directory with the generated protobuf clients (privoke/v1)")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    document = golden(args.results, args.generated)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"output": str(args.output), "sequences": [
        {"label": sequence["label"], "outcomes": [cycle["outcome"].get("abort", ["ok"])[:2] for cycle in sequence["cycles"]],
         "files": len(sequence["files"]), "recorded_request_matches": sequence["recorded"]["recorded_runtime_request_matches"]}
        for sequence in document["sequences"]]}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
