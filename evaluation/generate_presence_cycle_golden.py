"""Golden generator for the Rust fuzzer's presence training cycle (`rust/services/fuzzer`, stage 21, RUST-S21H item 3).

The oracle is the maintained Python fuzzer (`FuzzerTrainingService.RunPresenceTrainingCycle` with `training/presence.py`,
`runtime_client.compute_presence_gradients` and `validate_presence_training_update`), run in process as
`generate_full_adam_cycle_golden.py` does. The presence dataset is the committed synthetic fixture of the curriculum crate, so
everything here is committed; no study data is needed. The runtime is replaced by a scripted `ComputePresenceGradientsResponse` built
from the request the oracle sends (a synthetic but contract-valid answer: three actual executions, a presence head gradient and the
binary metrics), because no retained presence fuzzer cycle exists; the runtime side of the presence route is the stage 19 and 17
port and is replayed against its own golden.

Cycles: an accepted cycle and its repeat (there is no reservation, so the repeat trains again), a candidate that is worse on the
held-out strata (refused by the presence guard and retained as evidence), a runtime response with a missing execution (refused by the
response admission, retained as a rejected attempt), and the request-validation refusals.

Usage (host Python): python evaluation/generate_presence_cycle_golden.py --generated <dir>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import generate_full_adam_cycle_golden as fa  # noqa: E402

base = fa.base
OUTPUT = base.ROOT / "rust/services/fuzzer/tests/fixtures/presence_cycles_golden.json"
DATASET = "rust/crates/privoke-curriculum/tests/fixtures/presence-synthetic.jsonl"
MODEL = "privoke-presence-balanced"
PRESENT = 2


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--generated", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    base.bootstrap(args.generated)
    from privoke.v1 import parameters_pb2, runtime_pb2  # noqa: PLC0415

    def answer(*, worse=False, drop_execution=False):
        def build(request):
            count, held = len(request.examples), len(request.heldout_examples)
            present = sum(1 for row in request.heldout_examples if row.target == PRESENT)
            absent = held - present
            candidate_present = present - 1 if worse and present > 1 else present
            correct = count // 2 + 1
            metrics = {
                "examples": float(count), "heldout_examples": float(held), "heldout_present_examples": float(present),
                "heldout_absent_examples": float(absent), "candidate_heldout_examples": float(held),
                "candidate_heldout_present_examples": float(present), "candidate_heldout_absent_examples": float(absent),
                "average_loss": 0.25, "exact_match_rate": correct / count,
                "heldout_exact_match_rate": 1.0, "heldout_present_recall": 1.0, "heldout_absent_specificity": 1.0,
                "candidate_heldout_exact_match_rate": (candidate_present + absent) / held,
                "candidate_heldout_present_recall": candidate_present / present, "candidate_heldout_absent_specificity": 1.0}
            executions = [runtime_pb2.SemanticTrainingExecution(phase=phase, layer=runtime_pb2.DETECTION_LAYER_SEMANTIC, status="ok",
                                                                examples=size)
                          for phase, size in (("training", count), ("base_heldout", held), ("candidate_heldout", held))]
            if drop_execution:
                executions.pop()
            response = runtime_pb2.ComputePresenceGradientsResponse(
                request_id=request.request_id, model_id=request.model_id, base_version="v0.1.0",
                gradients=[runtime_pb2.RuntimeParameterDelta(name="head.presence.weight", values=[0.001, -0.002, 0.0, 0.004], shape=[4])],
                metrics=metrics, metadata={"base_parameter_fingerprint": "ab" * 32, "updated_parameter_fingerprint": "cd" * 32},
                executions=executions)
            return response.SerializeToString(deterministic=True)
        return build

    ack = parameters_pb2.ParameterUpdateAck(accepted=True, model_id=MODEL, applied_version="v0.1.1",
                                            message="Parameter update applied.").SerializeToString(deterministic=True)

    def request(request_id, prompt_count=8, model_id=MODEL):
        return parameters_pb2.FuzzerTrainingRequest(request_id=request_id, source_id="presence-golden", model_id=model_id,
                                                    prompt_count=prompt_count, seed=42)

    first = (request("presence-1"), "presence", answer(), ack)
    cycles = [first, (request("presence-2"), "presence", answer(worse=True), ack), first,
              (request("presence-3"), "presence", answer(drop_execution=True), ack),
              (request("presence-4", model_id="other"), "presence", answer(), ack),
              (request("presence-5", prompt_count=1), "presence", answer(), ack)]
    sequence = fa.run_sequence("presence-cycle", {"MODEL_ID": "privoke-baseline", "FUZZ_PRESENCE_DATASET_PATH": str(base.ROOT / DATASET)},
                               cycles, args.generated)
    sequence["env"].pop("FUZZ_PRESENCE_DATASET_PATH", None)
    sequence["paths"] = {"FUZZ_PRESENCE_DATASET_PATH": DATASET}
    document = {"schema": 1, "oracle": "services/privoke-fuzzer/src/fuzzer_service.py", "python": sys.version.split()[0],
                "normalisation": "timestamp file names become ordinals; the dump directory becomes <DUMP>", "sequences": [sequence]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"output": str(args.output), "outcomes": [c["outcome"].get("abort", ["ok"])[:2] for c in sequence["cycles"]],
                      "files": len(sequence["files"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
