"""Golden generator for the Rust fuzzer's TRAIN diagnostics and FULL backtracking cycles (`rust/services/fuzzer`, stage 21, RUST-S21G item 3).

Historical (stage V3-R8b): the Rust consumer of this golden, `rust/services/fuzzer`, was deleted when V1 training was retired,
so the output path below no longer exists in the tree. The generator is kept as the record of how the stage 21 golden was made.

The oracle is the maintained Python fuzzer, `services/privoke-fuzzer/src/fuzzer_service.py`, run in process on the host exactly as
`generate_full_adam_cycle_golden.py` does (it reuses that module's channel, normalisation and sequence runner): the client runtime is
replaced by scripted responses and the parameter-update service by a fake.

No study has retained a physical backtracking or TRAIN diagnostics response (the retained iterative cycles are FULL projected Adam), so
the responses are built here from the real response of a retained FULL Adam cycle: its model configuration, its tensors and its
identities are kept, the Adam evidence is removed and the TRAIN diagnostics record, the backtracking trace and its trials are written
for the request the oracle built (counts and losses are derived from it), the way the Python unit tests build them. A response is a
function of the oracle's request, recorded as the bytes the oracle was answered with; the Rust replay answers the same bytes. The
samplers run over the committed taxonomy fixture, so no study data is committed.

Covered: a selected backtracking step (one fit, one improving trial) with the compact publication, the known one-fit rejection (five
trials, no improvement), a TRAIN diagnostics only cycle, and the refusals: a malformed rejection, a trial rate that is not the scaled
request rate, diagnostics that differ from the trial losses, a policy or counts mismatch, a heads scope header and a duplicate field.

Usage (host Python, for example `evaluation/.venv-v1-v3-pipeline`):
  python evaluation/generate_backtracking_cycle_golden.py --results <main checkout>/evaluation/results --generated <dir>
"""
from __future__ import annotations

import argparse
import base64
import json
import math
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import generate_full_adam_cycle_golden as fa  # noqa: E402

base = fa.base
OUTPUT = base.ROOT / "rust/services/fuzzer/tests/fixtures/backtracking_cycles_golden.json"
PREPARATION = "a" * 64
POLICY = "full_train_backtracking_v1"
DIAGNOSTICS = "train_before_candidate_v1"
CLASS_BALANCED = "class_balanced_contextual_v1"


def golden(results: Path, generated: Path) -> dict:
    base.bootstrap(generated)
    from privoke.v1 import parameters_pb2, runtime_pb2  # noqa: PLC0415
    from privoke_contracts.classification import Classification  # noqa: PLC0415
    from privoke_model import contextual_training as ct  # noqa: PLC0415
    from privoke_model.fingerprint import parameter_fingerprint  # noqa: PLC0415

    passed, _ = fa.full_records(results)
    raw_passed = base64.b64decode(passed["execution_evidence"]["response_protobuf_base64"])
    ack = base.ack_bytes_for(parameters_pb2, passed)
    compact = lambda value: json.dumps(value, separators=(",", ":"))  # noqa: E731

    def morph(request, *, kind, objective=fa.OBJECTIVE, mutate=None):
        """The retained FULL Adam response as a `kind` ("selected", "rejected" or "diagnostics") response to `request`."""
        response = runtime_pb2.ComputeSemanticGradientsResponse.FromString(raw_passed)
        response.request_id = request.request_id
        meta = response.metadata
        for key in list(meta):
            if key.startswith(("full_projected_adam", "full_adam_")) or key in (
                    "contextual_training_optimizer", "contextual_candidate_eligibility", "executed_contextual_training_optimizer"):
                del meta[key]
        meta[ct.EXECUTED_OBJECTIVE_KEY] = objective
        meta[ct.DIAGNOSTICS_POLICY_KEY] = DIAGNOSTICS
        shapes = {p.name: tuple(p.shape) for p in response.gradients}
        delta = {p.name: tuple(p.values) for p in response.gradients}
        rows = len(request.examples)
        sensitive = sum(Classification(item.target.packed).is_sensitive() for item in request.examples)
        schema, columns = ct.training_loss_contract(objective)
        base_fp, updated_fp = meta["base_parameter_fingerprint"], meta["updated_parameter_fingerprint"]
        coordinates = sum(math.prod(shape) for shape in shapes.values())
        head = [.5, .25, .125, .0625][: len(columns) - 1]
        base_losses = [*head, math.fsum(head)]
        better = [*head[:-1], head[-1] / 2]
        better_losses = [*better, math.fsum(better)]
        rate = request.learning_rate
        if kind in ("selected", "rejected"):
            meta[ct.BACKTRACKING_KEY] = POLICY
            meta[ct.BACKTRACKING_PREPARATION_KEY] = PREPARATION
            meta["learning_rate"] = str(rate)
            header = {"schema": schema, "policy": POLICY, "objective": objective, "base": [base_fp, base_losses],
                      "raw": ["d" * 64, meta["trained_parameter_inventory_fingerprint"], coordinates, 1., 1.],
                      "selected": None if kind == "rejected" else 0, "gradient_fits": 1}
            if schema == 2:
                header["loss_columns"] = list(columns)
            rejected = kind == "rejected"
            scales = ct.BACKTRACKING_SCALES if rejected else ct.BACKTRACKING_SCALES[:1]
            losses = base_losses if rejected else better_losses
            trials = [[rate * scale, losses, 0, .0001, .0001, parameter_fingerprint(delta, shapes), updated_fp, "ok", rows, True, rows]
                      for scale in scales]
            meta[ct.BACKTRACKING_TRACE_KEY] = compact(header)
            meta[ct.BACKTRACKING_TRIALS_KEY] = compact(trials)
            response.metrics.update(gradient_fits=1, backtracking_trials=len(trials), backtracking_semantic_examples=rows * len(trials),
                                    backtracking_forward_attempts=len(trials), backtracking_attempted_semantic_examples=rows * len(trials))
            if rejected:
                response.error = ct.BACKTRACKING_REJECTION
                del response.gradients[:]
                del response.executions[1:]
                del meta["updated_parameter_fingerprint"]
                for key in list(response.metrics):
                    if key.startswith(("heldout_", "candidate_heldout_")):
                        del response.metrics[key]
            else:
                meta["effective_learning_rate"] = str(trials[0][0])
        if kind != "rejected":
            record = {"schema": schema, "objective": objective, "fingerprints": [base_fp, updated_fp],
                      "phases": [["base_training", "semantic", "ok", rows], ["candidate_training", "semantic", "ok", rows]],
                      "counts": [rows, rows - sensitive, sensitive], "loss_columns": list(columns),
                      "loss": [base_losses, better_losses], "accuracy_columns": list(ct.DIAGNOSTIC_ACCURACY_COLUMNS),
                      "accuracy": [[.5] * 6, [1.] * 6], "update_columns": list(ct.DIAGNOSTIC_UPDATE_COLUMNS),
                      "update": [coordinates, 0, .0001, .0001]}
            meta[ct.DIAGNOSTICS_KEY] = compact(record)
        if mutate:
            mutate(response, request)
        return response.SerializeToString(deterministic=True)

    def policy(objective=fa.OBJECTIVE, backtracking=True):
        metadata = {"expected_contextual_training_objective": objective,
                    "expected_contextual_training_diagnostics_policy": DIAGNOSTICS}
        if backtracking:
            metadata["expected_contextual_training_backtracking_policy"] = POLICY
            metadata["expected_contextual_training_backtracking_preparation_sha256"] = PREPARATION
        return metadata

    def cycle(request_id, kind, scope="full_encoder", expectations=None, objective=fa.OBJECTIVE, mutate=None, strategy=base.TAXONOMY, **extra):
        metadata = {"initiator": "param-update-service", "require_full_capability": "true", "expected_base_version": passed["base_version"],
                    **(policy() if expectations is None else expectations), **extra}
        if strategy is not None:
            metadata["contextual_sampling_strategy"] = strategy
        request = parameters_pb2.FuzzerTrainingRequest(
            request_id=request_id, source_id=passed.get("original_source_id", passed["source_id"]), model_id=passed["model_id"],
            prompt_count=32, seed=42, metadata=metadata)
        return (request, scope, lambda asked, kind=kind, objective=objective, mutate=mutate: morph(asked, kind=kind, objective=objective, mutate=mutate), ack)

    def corrupt_trial(index, position, value):
        def mutate(response, _request):
            rows = json.loads(response.metadata[ct.BACKTRACKING_TRIALS_KEY])
            rows[index][position] = value
            response.metadata[ct.BACKTRACKING_TRIALS_KEY] = compact(rows)
        return mutate

    def set_metadata(key, value):
        def mutate(response, _request):
            response.metadata[key] = value
        return mutate

    def delete_metadata(key):
        def mutate(response, _request):
            del response.metadata[key]
        return mutate

    def extra_guard(response, _request):
        response.executions.add(phase="base_heldout", layer=4, status="ok", examples=1)

    def wrong_counts(response, _request):
        record = json.loads(response.metadata[ct.DIAGNOSTICS_KEY])
        record["counts"] = [record["counts"][0], record["counts"][2], record["counts"][1]]
        response.metadata[ct.DIAGNOSTICS_KEY] = compact(record)

    def duplicate_field(response, _request):
        text = response.metadata[ct.DIAGNOSTICS_KEY]
        response.metadata[ct.DIAGNOSTICS_KEY] = text[:-1] + ',"schema":2}'

    def loss_mismatch(response, _request):
        record = json.loads(response.metadata[ct.DIAGNOSTICS_KEY])
        record["loss"][1][0] = record["loss"][1][0] + .01
        record["loss"][1][-1] = math.fsum(record["loss"][1][:-1])
        response.metadata[ct.DIAGNOSTICS_KEY] = compact(record)

    diagnostics_only = policy(backtracking=False)
    class_balanced_only = policy(CLASS_BALANCED, backtracking=False)
    cycles = [
        cycle("bt-selected", "selected"),
        cycle("bt-rejected", "rejected"),
        cycle("bt-diagnostics-only", "diagnostics", expectations=diagnostics_only),
        cycle("bt-diagnostics-class-balanced", "diagnostics", expectations=class_balanced_only, objective=CLASS_BALANCED),
        cycle("bt-heads-scope", "selected", scope="heads"),
        cycle("bt-malformed-rejection-guard", "rejected", mutate=extra_guard),
        cycle("bt-malformed-rejection-rate", "rejected", mutate=corrupt_trial(1, 0, .5)),
        cycle("bt-selected-rate", "selected", mutate=corrupt_trial(0, 0, .5)),
        cycle("bt-selected-policy", "selected", mutate=set_metadata(ct.BACKTRACKING_KEY, "unknown")),
        cycle("bt-selected-preparation", "selected", mutate=set_metadata(ct.BACKTRACKING_PREPARATION_KEY, "b" * 64)),
        cycle("bt-selected-effective-rate", "selected", mutate=set_metadata("effective_learning_rate", "0.5")),
        cycle("bt-selected-loss-mismatch", "selected", mutate=loss_mismatch),
        cycle("bt-selected-no-trace", "selected", mutate=delete_metadata(ct.BACKTRACKING_TRACE_KEY)),
        cycle("bt-diagnostics-counts", "diagnostics", expectations=diagnostics_only, mutate=wrong_counts),
        cycle("bt-diagnostics-duplicate-field", "diagnostics", expectations=diagnostics_only, mutate=duplicate_field),
        cycle("bt-diagnostics-policy", "diagnostics", expectations=diagnostics_only, mutate=delete_metadata(ct.DIAGNOSTICS_POLICY_KEY)),
        cycle("bt-diagnostics-missing", "diagnostics", expectations=diagnostics_only, mutate=delete_metadata(ct.DIAGNOSTICS_KEY)),
        # Backtracking needs diagnostics, an objective and a preparation pin.
        cycle("bt-no-preparation-pin", "selected", expectations={
            "expected_contextual_training_objective": fa.OBJECTIVE, "expected_contextual_training_diagnostics_policy": DIAGNOSTICS,
            "expected_contextual_training_backtracking_policy": POLICY}),
    ]
    env = {"MODEL_ID": passed["model_id"], **fa.full_adam_env()}
    sequence = fa.run_sequence("backtracking-diagnostics", env, cycles, generated)
    sequence["recorded"] = {
        "study": fa.STUDY, "passed_request_id": passed["request_id"],
        "note": "the model configuration, tensors and identities of a retained FULL Adam response; the diagnostics and backtracking "
                "evidence is written for the request the oracle built"}
    return {"schema": 1, "oracle": "services/privoke-fuzzer/src/fuzzer_service.py", "python": sys.version.split()[0],
            "normalisation": "timestamp file names become ordinals; the dump directory becomes <DUMP>", "sequences": [sequence]}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results", type=Path, required=True, help="evaluation/results of a checkout holding the retained iterative study")
    parser.add_argument("--generated", type=Path, required=True, help="directory with the generated protobuf clients (privoke/v1)")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    document = golden(args.results, args.generated)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    sequence = document["sequences"][0]
    print(json.dumps({"output": str(args.output), "outcomes": [cycle["outcome"].get("abort", ["ok"])[:2] for cycle in sequence["cycles"]],
                      "files": len(sequence["files"])}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
