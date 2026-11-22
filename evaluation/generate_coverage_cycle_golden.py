"""Golden generator for the Rust fuzzer's rehearsal and benign coverage cycles (`rust/services/fuzzer`, stage 21, RUST-S21G item 5).

The oracle is the maintained Python fuzzer, `services/privoke-fuzzer/src/fuzzer_service.py`, run in process on the host exactly as
`generate_full_adam_cycle_golden.py` does (it reuses that module's channel, normalisation and sequence runner): the client runtime is
replaced by the response bytes of a retained FULL projected Adam cycle of the iterative fuzzer study and the parameter-update service
by a fake. The samplers run over committed fixtures, so no study data is read beyond the two retained runtime responses:

* the taxonomy dataset `rust/crates/privoke-curriculum/tests/fixtures/bc01/taxonomy-coverage-v1.json`,
* the rehearsal manifest `rust/services/fuzzer/tests/fixtures/rehearsal-manifest.json`, which this script prepares from that dataset
  with `anchor_rehearsal.prepare_manifest` (ids, commitments and counts only), and
* the benign pool, manifest and exclusion proof of the same `bc01` fixture directory.

Both strategies expand to 64 TRAIN rows and 16 guard rows, as the taxonomy cycle of the recorded response does, so the recorded response is
replayed for the request the oracle builds. A complete ORIGINAL retention cycle needs the real bank, references and teacher bytes and is
covered by the gated test of the Rust crate; here its refusals before the release is read are replayed.

The golden keeps repo-relative fixture paths in `paths` (the oracle ran on absolute ones, which are not recorded).

Usage (host Python, for example `evaluation/.venv-v1-v3-pipeline`):
  python evaluation/generate_coverage_cycle_golden.py --results <main checkout>/evaluation/results --generated <dir>
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import generate_full_adam_cycle_golden as fa  # noqa: E402

base = fa.base
ROOT = base.ROOT
OUTPUT = ROOT / "rust/services/fuzzer/tests/fixtures/coverage_cycles_golden.json"
REHEARSAL_MANIFEST = ROOT / "rust/services/fuzzer/tests/fixtures/rehearsal-manifest.json"
BC01 = ROOT / "rust/crates/privoke-curriculum/tests/fixtures/bc01"
PATHS = {
    "FUZZ_REHEARSAL_MANIFEST_PATH": REHEARSAL_MANIFEST,
    "FUZZ_BENIGN_POOL_PATH": BC01 / "pool-authored.json",
    "FUZZ_BENIGN_MANIFEST_PATH": BC01 / "benign-manifest.json",
    "FUZZ_BENIGN_EXCLUSION_PROOF_PATH": BC01 / "exclusion-proof.json",
}
REHEARSAL = "taxonomy_anchor_rehearsal_v1"
BENIGN = "taxonomy_benign_coverage_v1"


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def golden(results: Path, generated: Path) -> dict:
    base.bootstrap(generated)
    from privoke.v1 import parameters_pb2, runtime_pb2  # noqa: PLC0415
    from privoke_model.full_adam import CONFIG, canonical  # noqa: PLC0415
    from prompt_generation import anchor_rehearsal as rehearsal  # noqa: PLC0415
    from prompt_generation import benign_coverage as benign  # noqa: PLC0415
    from prompt_generation.taxonomy_coverage import load_dataset as load_taxonomy_dataset  # noqa: PLC0415

    dataset = load_taxonomy_dataset(str(base.TAXONOMY_DATASET))
    prepared = rehearsal.prepare_manifest(dataset)
    REHEARSAL_MANIFEST.write_bytes(prepared)
    manifest = rehearsal.load_manifest(str(REHEARSAL_MANIFEST), dataset)
    release = benign.load_release(str(PATHS["FUZZ_BENIGN_POOL_PATH"]), str(PATHS["FUZZ_BENIGN_MANIFEST_PATH"]),
                                  str(PATHS["FUZZ_BENIGN_EXCLUSION_PROOF_PATH"]), dataset)
    passed, rejected = fa.full_records(results)

    def response_bytes(record, request_id, mutate=None):
        raw = base64.b64decode(record["execution_evidence"]["response_protobuf_base64"])
        response = runtime_pb2.ComputeSemanticGradientsResponse.FromString(raw)
        response.request_id = request_id
        if mutate:
            mutate(response)
        return response.SerializeToString(deterministic=True)

    rehearsal_pins = {"taxonomy_dataset_sha256": dataset.sha256, rehearsal.BANK_KEY: manifest.bank_sha256,
                      rehearsal.MANIFEST_KEY: manifest.sha256}
    benign_pins = {"taxonomy_dataset_sha256": dataset.sha256, benign.POOL_KEY: release.pool.sha256,
                   benign.MANIFEST_KEY: release.sha256, benign.PROOF_KEY: release.proof_sha256}

    def build(record, request_id, strategy, pins, policy=True, **extra):
        metadata = {"initiator": "param-update-service", "require_full_capability": "true",
                    "expected_base_version": record["base_version"], **pins}
        if strategy is not None:
            metadata["contextual_sampling_strategy"] = strategy
        if policy:
            metadata.update(fa.policy_metadata(canonical, CONFIG))
        metadata.update(extra)
        return parameters_pb2.FuzzerTrainingRequest(
            request_id=request_id, source_id=record.get("original_source_id", record["source_id"]),
            model_id=record["model_id"], prompt_count=32, seed=42, metadata=metadata)

    def cycle(record, request_id, strategy, pins, scope="full_encoder", mutate=None, policy=True, answer=None, **extra):
        request = build(record, request_id, strategy, pins, policy=policy, **extra)
        return (request, scope, response_bytes(answer or record, request_id, mutate), base.ack_bytes_for(parameters_pb2, answer or record))

    def bad_objective(response):
        response.metadata["executed_contextual_training_objective"] = "legacy_sum_category"

    def bad_summary(response):
        response.metadata["full_projected_adam_summary_v1"] = "{}"

    retention = {
        "expected_contextual_training_objective": fa.RETENTION_GATE_OBJECTIVE,
        "expected_contextual_training_optimizer": fa.RETENTION_GATE_POLICY,
        "expected_contextual_candidate_eligibility": fa.RETENTION_ELIGIBILITY,
        "expected_original_train_retention_manifest_sha256": "0" * 64}
    wrong_bank = {**rehearsal_pins, rehearsal.BANK_KEY: "0" * 64}
    wrong_pool = {**benign_pins, benign.POOL_KEY: "0" * 64}
    first_benign = cycle(passed, "coverage-benign", BENIGN, benign_pins)
    cycles = [
        cycle(passed, "coverage-rehearsal", REHEARSAL, rehearsal_pins),
        first_benign,
        cycle(rejected, "coverage-rehearsal-refused", REHEARSAL, rehearsal_pins),
        cycle(rejected, "coverage-benign-refused", BENIGN, benign_pins),
        # The benign request again: the durable reservation allows it, the physical attempt reservation refuses a second call.
        first_benign,
        cycle(passed, "coverage-rehearsal-weak-policy", REHEARSAL, rehearsal_pins, policy=False),
        cycle(passed, "coverage-benign-weak-policy", BENIGN, benign_pins, policy=False),
        cycle(passed, "coverage-rehearsal-heads", REHEARSAL, rehearsal_pins, scope="heads", policy=False),
        cycle(passed, "coverage-rehearsal-wrong-bank", REHEARSAL, wrong_bank),
        cycle(passed, "coverage-benign-wrong-pool", BENIGN, wrong_pool),
        cycle(passed, "coverage-rehearsal-no-dataset-pin", REHEARSAL, {k: v for k, v in rehearsal_pins.items() if k != "taxonomy_dataset_sha256"}),
        cycle(passed, "coverage-benign-bad-objective", BENIGN, benign_pins, mutate=bad_objective),
        cycle(passed, "coverage-rehearsal-bad-summary", REHEARSAL, rehearsal_pins, mutate=bad_summary),
        # ORIGINAL retention needs the benign composition and, past the benign admission, the four configured sidecars.
        cycle(passed, "coverage-retention-benign-no-sidecars", BENIGN, benign_pins, **retention),
        cycle(passed, "coverage-retention-rehearsal", REHEARSAL, rehearsal_pins, **retention),
        cycle(passed, "coverage-retention-no-strategy", None, {}, **retention),
        # Pins of a strategy that was not requested.
        cycle(passed, "coverage-orphan-benign-pins", None, benign_pins),
        cycle(passed, "coverage-orphan-rehearsal-pins", None, rehearsal_pins),
        cycle(passed, "coverage-benign-diagnostics", BENIGN, benign_pins, study_gate_diagnostics="v1"),
    ]
    env = {"MODEL_ID": passed["model_id"], **fa.full_adam_env(), **{name: str(path) for name, path in PATHS.items()}}
    configured = fa.run_sequence("coverage-configured", env, cycles, generated)
    bare_env = {"MODEL_ID": passed["model_id"], **fa.full_adam_env()}
    bare_cycles = [
        cycle(passed, "coverage-rehearsal-no-path", REHEARSAL, rehearsal_pins),
        cycle(passed, "coverage-benign-no-paths", BENIGN, benign_pins),
    ]
    bare = fa.run_sequence("coverage-unconfigured", bare_env, bare_cycles, generated)
    for sequence, used in ((configured, PATHS), (bare, {})):
        for name in PATHS:
            sequence["env"].pop(name, None)
        sequence["paths"] = {name: relative(path) for name, path in used.items()}
        sequence["recorded"] = {
            "study": fa.STUDY, "passed_request_id": passed["request_id"], "rejected_request_id": rejected["request_id"],
            "note": "runtime responses of retained FULL Adam cycles replayed for the requests the oracle builds over the committed fixtures"}
    return {"schema": 1, "oracle": "services/privoke-fuzzer/src/fuzzer_service.py", "python": sys.version.split()[0],
            "normalisation": "timestamp file names become ordinals; the dump directory becomes <DUMP>",
            "rehearsal_manifest_sha256": manifest.sha256, "benign_manifest_sha256": release.sha256,
            "sequences": [configured, bare]}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results", type=Path, required=True, help="evaluation/results of a checkout holding the retained iterative study")
    parser.add_argument("--generated", type=Path, required=True, help="directory with the generated protobuf clients (privoke/v1)")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    document = golden(args.results, args.generated)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    summary = [[cycle["outcome"].get("abort", ["ok"])[:2] for cycle in sequence["cycles"]] for sequence in document["sequences"]]
    print(json.dumps({"output": str(args.output), "outcomes": summary,
                      "files": [len(sequence["files"]) for sequence in document["sequences"]]}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
