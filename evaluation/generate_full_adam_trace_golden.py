"""Golden generator for the fuzzer's FULL Adam trace admission (`rust/services/fuzzer/src/full_adam.rs`, RUST-S21E).

Historical (stage V3-R8b): the Rust consumer of this golden, `rust/services/fuzzer`, was deleted when V1 training was retired,
so the output path below no longer exists in the tree. The generator is kept as the record of how the stage 21 golden was made.

The oracle is `privoke_model.full_adam.validate_trace`. One real FULL Adam fit is the base: a retained iterative-fuzzer cycle whose
runtime response carries the 64-step recurrence (the trace is prompt-free: fingerprints, losses and counts only). The golden keeps
the metadata fields the validator reads, plus mutations of them (tampered identities, recurrence breaks, accounting breaks,
non-canonical JSON, a HEAD update), each answered by the Python oracle.

Usage (host Python, for example `evaluation/.venv-v1-v3-pipeline`):
  python evaluation/generate_full_adam_trace_golden.py --results <main checkout>/evaluation/results --generated <dir>
where `--generated` holds `privoke/v1` (for example `<main checkout>/extension/client-runtime/generated`).
"""
from __future__ import annotations

import argparse
import base64
import glob
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "rust/services/fuzzer/tests/fixtures/full_adam_trace_golden.json"
CELL = "iterative_fuzzer_20261011/block08/terminal-archive/balanced/fuzzer/training-cycles"
KEYS = ("contextual_training_optimizer", "full_projected_adam_config_v1", "executed_contextual_training_optimizer",
        "contextual_candidate_eligibility", "full_projected_adam_trace_v1", "full_projected_adam_summary_v1", "base_parameter_fingerprint")


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def base_case(results: Path, generated: Path) -> dict:
    sys.path[:0] = [str(generated), str(ROOT / "shared" / "python")]
    from privoke.v1 import runtime_pb2  # noqa: PLC0415
    from privoke_model.fingerprint import parameter_fingerprint  # noqa: PLC0415

    for path in sorted(glob.glob(str(results / CELL / "*" / "*.json"))):
        record = json.loads(Path(path).read_text(encoding="utf-8"))
        metadata = record["metadata"]
        if metadata.get("training_scope") != "full_encoder" or "full_projected_adam_trace_v1" not in metadata:
            continue
        evidence = record["execution_evidence"]
        request = runtime_pb2.ComputeSemanticGradientsRequest.FromString(base64.b64decode(evidence["request_protobuf_base64"]))
        response = runtime_pb2.ComputeSemanticGradientsResponse.FromString(base64.b64decode(evidence["response_protobuf_base64"]))
        delta = parameter_fingerprint({p.name: tuple(p.values) for p in response.gradients}, {p.name: tuple(p.shape) for p in response.gradients})
        return {"metadata": {key: metadata[key] for key in KEYS}, "examples": len(request.examples),
                "candidate": metadata["updated_parameter_fingerprint"], "delta": delta}
    raise SystemExit("no retained FULL Adam cycle found under " + CELL)


def resum(metadata: dict, trace: dict) -> dict:
    """The metadata of a mutated trace with its summary recomputed, so that only the mutation under test is wrong."""
    raw = canonical(trace)
    summary = json.loads(metadata["full_projected_adam_summary_v1"])
    summary.update(trace_sha256=hashlib.sha256(raw.encode()).hexdigest(), counts=trace["counts"], base=trace["base"], final=trace["final"],
                   delta=trace["delta"])
    return {"full_projected_adam_trace_v1": raw, "full_projected_adam_summary_v1": canonical(summary)}


def build(results: Path, generated: Path) -> dict:
    sys.path[:0] = [str(generated), str(ROOT / "shared" / "python")]
    from privoke_model.full_adam import validate_trace  # noqa: PLC0415

    base = base_case(results, generated)
    metadata = base["metadata"]
    trace = json.loads(metadata["full_projected_adam_trace_v1"])

    def mutated(function):
        copy = json.loads(json.dumps(trace))
        function(copy)
        return resum(metadata, copy)

    def step(index, **changes):
        def apply(copy):
            copy["steps"][index].update(changes)
        return apply

    def counts(**changes):
        def apply(copy):
            copy["counts"].update(changes)
        return apply

    head = {key: value for key, value in metadata.items() if "trace" not in key and "summary" not in key and "eligibility" not in key}
    head["executed_contextual_training_optimizer"] = "dormant_head_v1"
    specs = [
        ("valid FULL fit", {}, {}),
        ("HEAD update without evidence", {"scope": "heads", "replace": head}, {}),
        ("HEAD update with a trace", {"scope": "heads"}, {}),
        ("wrong candidate fingerprint", {"candidate": "0" * 64}, {}),
        ("wrong delta fingerprint", {"delta": "1" * 64}, {}),
        ("wrong example count", {"examples": base["examples"] - 1}, {}),
        ("missing policy", {}, {"contextual_training_optimizer": None}),
        ("wrong config", {}, {"full_projected_adam_config_v1": "{}"}),
        ("missing eligibility", {}, {"contextual_candidate_eligibility": None}),
        ("not executed", {}, {"executed_contextual_training_optimizer": "dormant_head_v1"}),
        ("missing trace", {}, {"full_projected_adam_trace_v1": None}),
        ("missing summary", {}, {"full_projected_adam_summary_v1": None}),
        ("non-canonical trace", {}, {"full_projected_adam_trace_v1": metadata["full_projected_adam_trace_v1"].replace(":", ": ", 1)}),
        ("another base", {}, {"base_parameter_fingerprint": "2" * 64}),
        ("stale summary", {}, {"full_projected_adam_trace_v1": canonical({**trace, "steps": [dict(trace["steps"][0], loss=9.0)] + trace["steps"][1:]})}),
        ("a step that does not chain", {}, mutated(step(3, before="3" * 64))),
        ("a negative loss", {}, mutated(step(5, loss=-1.0))),
        ("a negative clip count", {}, mutated(step(7, clipped=-1))),
        ("a malformed hash", {}, mutated(step(9, gradient="XYZ"))),
        ("an extra step field", {}, mutated(step(11, extra=1))),
        ("another final state", {}, mutated(lambda copy: copy["steps"][-1].update(after="4" * 64))),
        ("fewer steps", {}, mutated(lambda copy: copy.update(steps=copy["steps"][:63]))),
        ("wrong direction count", {}, mutated(counts(directions_completed=63))),
        ("wrong microbatch accounting", {}, mutated(counts(microbatch_backward_completed=1))),
        ("wrong state count", {}, mutated(counts(train_parameter_states=64))),
        ("an unknown trace field", {}, mutated(lambda copy: copy.update(extra=1))),
    ]
    cases = []
    for label, options, edits in specs:
        case_metadata = dict(options.get("replace", metadata))
        for key, value in edits.items():
            if value is None:
                case_metadata.pop(key, None)
            else:
                case_metadata[key] = value
        record = {"label": label, "scope": options.get("scope", "full_encoder"), "examples": options.get("examples", base["examples"]),
                  "candidate": options.get("candidate", base["candidate"]), "delta": options.get("delta", base["delta"]), "metadata": case_metadata}
        try:
            result = validate_trace(case_metadata, scope=record["scope"], examples=record["examples"], candidate_fingerprint=record["candidate"],
                                    delta_fingerprint=record["delta"])
            record["result"] = "none" if result is None else "trace"
        except (ValueError, TypeError, KeyError) as exc:
            record["error"] = str(exc)
        cases.append(record)
    return {"schema": 1, "oracle": "privoke_model.full_adam.validate_trace", "python": sys.version.split()[0], "cases": cases}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--generated", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    document = build(args.results, args.generated)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"cases": len(document["cases"]), "valid": sum("result" in case for case in document["cases"]),
                      "errors": sum("error" in case for case in document["cases"]), "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
