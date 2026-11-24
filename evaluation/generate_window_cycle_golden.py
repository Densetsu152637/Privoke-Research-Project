"""Local golden generator for the Rust fuzzer's frozen-window cycle (`rust/services/fuzzer`, stage 21, RUST-S21H item 1).

Historical (stage V3-R8b): the Rust consumer of this golden, `rust/services/fuzzer`, was deleted when V1 training was retired,
so the output path below no longer exists in the tree. The generator is kept as the record of how the stage 21 golden was made.

The oracle is the maintained Python fuzzer, `services/privoke-fuzzer/src/fuzzer_service.py` with `training/window_cycle.py` and
`training/window_evidence.py`, run in process as `generate_full_adam_cycle_golden.py` does: the client runtime is replaced by the
response bytes of a real retained window cycle and the parameter-update service by a fake. The retained cycles are the three
host fits of the task-query window study (`task_query_window_20261012`, cells `v1-window-42` (no update), `-43` (selected and
published) and `-44` (no update)); each runs over its own frozen window, component release, taxonomy dataset and benign
snapshot, all read from the local checkout. The window cycle sends its physical request over `grpc.insecure_channel`, so that
call is replaced by the same scripted channel.

A window holds prompt text, so the golden is written under `rust/services/fuzzer/tests/local/`, which Git ignores, and is never
committed. The Rust replay is the env-gated `tests/window_cycles.rs`. The sidecars are copied to a scratch directory under bare
file names and the oracle runs there, as `generate_retention_cycle_golden.py` does (the retained inputs record the teacher
path as given).

`PRIVOKE_FUZZER_DUMP_DIR` evidence names the attempt files by absolute path and keeps the sha256 of the retained window inputs,
written by Python in text mode (CRLF on a Windows host): the golden keeps the oracle's raw path and hash per cycle for the
`training_evidence_sha256` binding, and the dump keeps the LF hash that Rust writes.

Usage (host Python, for example `evaluation/.venv-v1-v3-pipeline`, with `PRIVOKE_GENERATED` naming the generated protobuf clients):
  python evaluation/generate_window_cycle_golden.py --root <main checkout> --generated <dir>
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import generate_full_adam_cycle_golden as fa  # noqa: E402

base = fa.base
OUTPUT = base.ROOT / "rust/services/fuzzer/tests/local/window_cycles_golden.json"
REFUSALS = base.ROOT / "rust/services/fuzzer/tests/fixtures/window_refusals_golden.json"
STUDY = "evaluation/results/task_query_window_20261012/host-v2/cells"
RELEASES = "models/experiments/task_query_window_20261012/releases/host-v2/v1"
ITERATIVE = "evaluation/results/iterative_fuzzer_20261011"
SEEDS = (42, 43, 44)
SIDECARS = {
    "window": ("window.json", "FUZZ_WINDOW_PATH"),
    "bank": ("bank.json", "FUZZ_COMPONENT_BANK_PATH"),
    "references": ("references.json", "FUZZ_COMPONENT_REFERENCE_PATH"),
    "manifest": ("manifest.json", "FUZZ_COMPONENT_MANIFEST_PATH"),
    "teacher": ("teacher.json", "FUZZ_COMPONENT_TEACHER_PATH"),
    "taxonomy": ("taxonomy.json", "FUZZ_PROMPT_DATASET_PATH"),
    "benign_pool": ("benign_pool.json", "FUZZ_BENIGN_POOL_PATH"),
    "benign_manifest": ("benign_manifest.json", "FUZZ_BENIGN_MANIFEST_PATH"),
    "benign_proof": ("benign_proof.json", "FUZZ_BENIGN_EXCLUSION_PROOF_PATH"),
}


def sidecar_sources(seed: int) -> dict:
    release = f"{RELEASES}/{seed}"
    return {
        "window": f"{release}/window.json", "bank": f"{release}/bank.json", "references": f"{release}/references-v2.json",
        "manifest": f"{release}/component-manifest-v2.json", "teacher": f"{release}/original.json",
        "taxonomy": f"{ITERATIVE}/taxonomy-coverage/release/taxonomy-coverage-v1.json",
        "benign_pool": f"{ITERATIVE}/train-benign-coverage/pool-authored.json",
        "benign_manifest": f"{ITERATIVE}/train-benign-coverage/r1/benign-manifest.json",
        "benign_proof": f"{ITERATIVE}/train-benign-coverage/r1/exclusion-proof.json",
    }


def cell_record(root: Path, seed: int) -> tuple:
    cell = root / STUDY / f"v1-window-{seed}"
    compose = json.loads((cell / "compose.json").read_text(encoding="utf-8"))
    environment = compose["services"][f"v1-window-{seed}-fuzzer"]["environment"]
    records = sorted((cell / "fuzzer" / "training-cycles").glob("*/*.json"))
    if len(records) != 1:
        raise SystemExit(f"{cell} holds {len(records)} retained window cycles; expected one")
    return json.loads(records[0].read_text(encoding="utf-8")), environment


def raw_response(record) -> bytes:
    return base64.b64decode(record["execution_evidence"]["response_protobuf_base64"])


def patch_insecure_channel():
    """The window cycle calls the runtime over `grpc.insecure_channel`: answer it with the scripted channel of the sequence."""
    import grpc  # noqa: PLC0415

    class Context:
        def __init__(self, channel):
            self.channel = channel

        def __enter__(self):
            return self.channel

        def __exit__(self, *exc):
            return False

    original = grpc.insecure_channel

    def scripted(target, *args, **kwargs):
        import fuzzer_service  # noqa: PLC0415

        return Context(fuzzer_service.service_channel(target))

    grpc.insecure_channel = scripted
    return lambda: setattr(grpc, "insecure_channel", original)


def fix_window_input_hashes(files: dict) -> dict:
    """Python wrote the retained window inputs in text mode, so on Windows the sha256 it recorded is of the CRLF bytes."""
    pattern = re.compile(r'("window_inputs": \{"path": "<DUMP>/([^"]+)", "sha256": ")([0-9a-f]{64})(")')

    def replace(match):
        text = files[match.group(2)]
        return match.group(1) + hashlib.sha256(text.encode("utf-8")).hexdigest() + match.group(4)

    return {key: pattern.sub(replace, text) for key, text in files.items()}


def sequence_for(root: Path, seed: int, generated: Path) -> dict:
    base.bootstrap(generated)
    from privoke.v1 import parameters_pb2, runtime_pb2  # noqa: PLC0415
    from privoke_model import window_training as window  # noqa: PLC0415

    record, environment = cell_record(root, seed)
    sources = sidecar_sources(seed)
    window_pin = environment["FUZZ_WINDOW_MANIFEST_SHA256"]
    component_pin = environment["FUZZ_COMPONENT_MANIFEST_SHA256"]
    metadata = {
        "initiator": "privoke-fuzzer-cli", "contextual_sampling_strategy": window.SAMPLER,
        "expected_contextual_training_optimizer": window.POLICY, "expected_contextual_training_objective": window.OBJECTIVE,
        "expected_contextual_candidate_eligibility": window.ELIGIBILITY, "expected_contextual_training_scope": "full_encoder",
        "expected_" + window.CONFIG_KEY: window.canonical(window.CONFIG), "expected_" + window.WINDOW_KEY: window_pin,
        "expected_" + window.REFERENCE_KEY: component_pin}

    def build(request_id, *, seed_value=seed, prompt_count=256, drop=(), **extra):
        meta = {key: value for key, value in {**metadata, **extra}.items() if key not in drop}
        return parameters_pb2.FuzzerTrainingRequest(
            request_id=request_id, source_id=record["original_source_id"], model_id=record["model_id"],
            prompt_count=prompt_count, seed=seed_value, metadata=meta)

    def response_for(request_id, mutate=None):
        response = runtime_pb2.ComputeSemanticGradientsResponse.FromString(raw_response(record))
        response.request_id = request_id
        if mutate:
            mutate(response)
        return response.SerializeToString(deterministic=True)

    ack = base.ack_bytes_for(parameters_pb2, record)
    primary = build(record["request_id"])
    cycles = [(primary, "full_encoder", response_for(record["request_id"]), ack)]
    if not record["gate_passed"]:
        # The known no-update receipt answers the same request without another fit.
        cycles.append((primary, "full_encoder", response_for(record["request_id"]), ack))
        corrupt_id = f"window-bad-optimizer-{seed}"

        def corrupt(response):
            response.metadata["executed_contextual_training_optimizer"] = "full_projected_adam64_v1"

        cycles += [
            (build(corrupt_id), "full_encoder", response_for(corrupt_id, corrupt), ack),
            (build(f"window-seed-{seed}", seed_value=seed + 1), "full_encoder", response_for(f"window-seed-{seed}"), ack),
            (build(f"window-heads-{seed}"), "heads", response_for(f"window-heads-{seed}"), ack),
            (build(f"window-count-{seed}", prompt_count=255), "full_encoder", response_for(f"window-count-{seed}"), ack),
            (build(f"window-orphan-{seed}", drop=("expected_contextual_training_optimizer",)), "full_encoder",
             response_for(f"window-orphan-{seed}"), ack),
        ]
    env = {"MODEL_ID": record["model_id"], **fa.full_adam_env(), "FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE": "1",
           "FUZZ_MIN_EXACT_MATCH_RATE": "0.0", "FUZZ_MAX_PROMPT_COUNT": "256", "FUZZ_HELDOUT_PROMPT_COUNT": "16",
           "FUZZ_TIMEOUT_SECONDS": environment["FUZZ_TIMEOUT_SECONDS"], "FUZZ_WINDOW_MANIFEST_SHA256": window_pin,
           "FUZZ_COMPONENT_MANIFEST_SHA256": component_pin,
           "FUZZ_COMPONENT_TEACHER_SHA256": environment["FUZZ_COMPONENT_TEACHER_SHA256"],
           **{variable: bare for bare, variable in SIDECARS.values()}}
    restore = patch_insecure_channel()
    cwd = Path.cwd()
    with tempfile.TemporaryDirectory() as scratch:
        for name, (bare, _) in SIDECARS.items():
            shutil.copyfile(root / sources[name], Path(scratch) / bare)
        os.chdir(scratch)
        try:
            sequence = fa.run_sequence(f"window-{seed}", env, cycles, generated)
        finally:
            os.chdir(cwd)
            restore()
    sequence["files"] = fix_window_input_hashes(sequence["files"])
    sequence["sidecars"] = {name: sources[name] for name in SIDECARS}
    sequence["recorded"] = {
        "study": "task_query_window_20261012", "cell": f"v1-window-{seed}", "request_id": record["request_id"],
        "gate_passed": record["gate_passed"],
        "recorded_runtime_request_matches": base.b64(base64.b64decode(record["execution_evidence"]["request_protobuf_base64"]))
        == sequence["cycles"][0]["runtime_request"]}
    return sequence


def refusals(generated: Path) -> dict:
    """The refusals that need no window, no component release and no study data (nothing here holds prompt text): the admission of a
    window request and the checks before any source is read. Committed, so that CI replays them against the Python oracle."""
    base.bootstrap(generated)
    from privoke.v1 import parameters_pb2, runtime_pb2  # noqa: PLC0415
    from privoke_model import window_training as window  # noqa: PLC0415

    pins = ("a" * 64, "b" * 64)
    metadata = {
        "initiator": "privoke-fuzzer-cli", "contextual_sampling_strategy": window.SAMPLER,
        "expected_contextual_training_optimizer": window.POLICY, "expected_contextual_training_objective": window.OBJECTIVE,
        "expected_contextual_candidate_eligibility": window.ELIGIBILITY, "expected_contextual_training_scope": "full_encoder",
        "expected_" + window.CONFIG_KEY: window.canonical(window.CONFIG), "expected_" + window.WINDOW_KEY: pins[0],
        "expected_" + window.REFERENCE_KEY: pins[1]}

    def build(request_id, *, prompt_count=256, drop=(), **extra):
        meta = {key: value for key, value in {**metadata, **extra}.items() if key not in drop}
        return parameters_pb2.FuzzerTrainingRequest(request_id=request_id, source_id="window-refusals", model_id="privoke-balanced",
                                                    prompt_count=prompt_count, seed=42, metadata=meta)

    empty = runtime_pb2.ComputeSemanticGradientsResponse().SerializeToString(deterministic=True)
    ack = parameters_pb2.ParameterUpdateAck().SerializeToString(deterministic=True)
    requests = [
        (build("refuse-heads"), "heads"),
        (build("refuse-count", prompt_count=255), "full_encoder"),
        (build("refuse-orphan", drop=("expected_contextual_training_optimizer",)), "full_encoder"),
        (build("refuse-backtracking", expected_contextual_training_backtracking_policy="full_train_backtracking_v1"), "full_encoder"),
        (build("refuse-diagnostics", expected_contextual_training_diagnostics_policy="train_before_candidate_v1"), "full_encoder"),
        (build("refuse-config", **{"expected_" + window.CONFIG_KEY: "{}"}), "full_encoder"),
        (build("refuse-pin", **{"expected_" + window.WINDOW_KEY: "short"}), "full_encoder"),
        (build("refuse-no-window"), "full_encoder"),
    ]
    env = {"MODEL_ID": "privoke-balanced", **fa.full_adam_env()}
    sequence = fa.run_sequence("window-refusals", env, [(request, scope, empty, ack) for request, scope in requests], generated)
    return {"schema": 1, "refusals_only": True, "oracle": "services/privoke-fuzzer/src/fuzzer_service.py", "python": sys.version.split()[0],
            "normalisation": "none: every request is refused before a reservation, a source or a runtime call", "sequences": [sequence]}


def golden(root: Path, generated: Path, seeds) -> dict:
    return {"schema": 1, "oracle": "services/privoke-fuzzer/src/fuzzer_service.py", "python": sys.version.split()[0],
            "normalisation": "timestamp file names become ordinals; the dump directory becomes <DUMP>; sidecars are read by bare file name; "
                             "the retained window input hash is the LF hash",
            "sequences": [sequence_for(root, seed, generated) for seed in seeds]}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, required=True, help="the main checkout (holds evaluation/results and models/experiments)")
    parser.add_argument("--generated", type=Path, required=True, help="directory with the generated protobuf clients (privoke/v1)")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--seed", type=int, action="append", choices=SEEDS, help="a cell to replay (default: all three)")
    parser.add_argument("--refusals", action="store_true", help="write the committed refusals golden instead (needs no study data)")
    args = parser.parse_args(argv)
    if args.refusals:
        document = refusals(args.generated)
        output = REFUSALS if args.output == OUTPUT else args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        print(json.dumps({"output": str(output), "outcomes": [cycle["outcome"].get("abort", ["ok"]) for cycle in document["sequences"][0]["cycles"]]}))
        return 0
    document = golden(args.root, args.generated, args.seed or SEEDS)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"output": str(args.output), "sequences": [
        {"label": sequence["label"], "outcomes": [cycle["outcome"].get("abort", ["ok"])[:2] for cycle in sequence["cycles"]],
         "files": len(sequence["files"]), "recorded": sequence["recorded"]} for sequence in document["sequences"]]}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
