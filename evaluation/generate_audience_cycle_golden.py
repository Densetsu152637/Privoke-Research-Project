"""Golden generator for the Rust fuzzer's audience coverage cycles (`rust/services/fuzzer`, stage 21, RUST-S21H item 2).

Historical (stage V3-R8b): the Rust consumer of this golden, `rust/services/fuzzer`, was deleted when V1 training was retired,
so the output path below no longer exists in the tree. The generator is kept as the record of how the stage 21 golden was made.

The oracle is the maintained Python fuzzer (`fuzzer_service.py` with `prompt_generation/audience_coverage.py`), run in process as
`generate_full_adam_cycle_golden.py` does. The audience sampler is the default strategy when no dataset is configured; the pinned
AU3 release (`services/privoke-fuzzer/data/audience-v3-manifest-v1.json` and its catalogs) is committed, so nothing here needs study
data except the runtime response bytes of a retained heads cycle, replayed for the request the oracle builds (the response is
validated against its own configuration and counts, not against the prompts).

Python binds the sha256 of its own sampler sources (`implementation_closure`) into the request fingerprint, the audit and the
retained evidence. A Windows checkout may hold CRLF files; the oracle hashes with line endings normalised to LF, which is what the
Linux checkout of CI holds, so the golden is the golden of a Linux run.

Usage (host Python): python evaluation/generate_audience_cycle_golden.py --results <main checkout>/evaluation/results --generated <dir>
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import generate_full_adam_cycle_golden as fa  # noqa: E402

base = fa.base
OUTPUT = base.ROOT / "rust/services/fuzzer/tests/fixtures/audience_cycles_golden.json"
STRATEGY = "audience_coverage_v1"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--generated", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    base.bootstrap(args.generated)
    from privoke.v1 import parameters_pb2, runtime_pb2  # noqa: PLC0415
    from prompt_generation import audience_coverage as audience  # noqa: PLC0415

    original = audience.implementation_closure

    def linux_closure():
        """The closure over the same files with LF endings (the Linux checkout of CI)."""
        crlf = bytes([13, 10])
        files = {name: hashlib.sha256((base.ROOT / name).read_bytes().replace(crlf, bytes([10]))).hexdigest()
                 for name in sorted(original()["files"])}
        return {"sha256": audience.digest(audience.canonical(files)), "files": files}

    audience.implementation_closure = linux_closure
    records = list(base.recorded_records(args.results, base.STUDY_V2))
    passed = next(r for r in records if r["training_stage"] == "heads" and r["gate_passed"] and r.get("ack"))
    rejected = next(r for r in records if r["training_stage"] == "heads" and not r["gate_passed"])

    def make(record, request_id, prompt_count=32, scope_metadata=None):
        request = base.build_request(parameters_pb2, {**record, "request_id": request_id}, 42)
        request.prompt_count = prompt_count
        request.metadata.update(scope_metadata or {})
        response = runtime_pb2.ComputeSemanticGradientsResponse.FromString(
            base64.b64decode(record["execution_evidence"]["response_protobuf_base64"]))
        response.request_id = request_id
        return (request, "heads", response.SerializeToString(deterministic=True), base.ack_bytes_for(parameters_pb2, record))

    first = make(passed, "audience-1")
    from privoke_model.full_adam import CONFIG, canonical  # noqa: PLC0415
    policy = fa.policy_metadata(canonical, CONFIG)
    cycles = [first, make(rejected, "audience-2"), first, make(passed, "audience-3", prompt_count=64),
              make(passed, "audience-4", prompt_count=16), make(passed, "audience-5", scope_metadata=policy),
              make(passed, "audience-6", scope_metadata={"contextual_sampling_strategy": STRATEGY})]
    # The release is the fixture copy that holds exactly the bytes the bundled manifest pins (its catalogs are pinned as CRLF).
    fixture = "rust/crates/privoke-curriculum/tests/fixtures/au3/audience-v3-manifest-v1.json"
    env = {"MODEL_ID": passed["model_id"], "FUZZ_PROMPT_DATASET_PATH": None, "FUZZ_CONTEXTUAL_SAMPLING_STRATEGY": STRATEGY,
           "FUZZ_AUDIENCE_MANIFEST_PATH": str(base.ROOT / fixture), "FUZZ_AUDIENCE_MANIFEST_SHA256": audience.BUNDLED_MANIFEST_SHA256
           if hasattr(audience, "BUNDLED_MANIFEST_SHA256") else "7f17f43473deb4235ed189508008576abd19cf5eba0e9912d4c4ba4c58d7c010"}
    sequence = fa.run_sequence("audience-coverage", env, cycles, args.generated)
    sequence["env"].pop("FUZZ_AUDIENCE_MANIFEST_PATH")
    sequence["env"]["FUZZ_PROMPT_DATASET_PATH"] = ""  # unset for the oracle; empty is unset for Rust
    sequence["paths"] = {"FUZZ_AUDIENCE_MANIFEST_PATH": fixture}
    sequence["recorded"] = {"cell": base.STUDY_V2, "passed_request_id": passed["request_id"], "rejected_request_id": rejected["request_id"]}
    document = {"schema": 1, "oracle": "services/privoke-fuzzer/src/fuzzer_service.py", "python": sys.version.split()[0],
                "normalisation": "timestamp file names become ordinals; the dump directory becomes <DUMP>; sources hashed with LF endings",
                "sequences": [sequence]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"output": str(args.output), "outcomes": [c["outcome"].get("abort", ["ok"])[:2] for c in sequence["cycles"]],
                      "files": len(sequence["files"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
