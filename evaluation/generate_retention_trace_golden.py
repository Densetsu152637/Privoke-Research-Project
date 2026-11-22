"""Golden generator for the fuzzer's ORIGINAL retention evidence (`rust/services/fuzzer/src/retention.rs`, RUST-S21F item 2).

The oracles are `privoke_model.sensitive_retention.validate_trace` and `execution_phases` and
`training.sensitive_retention_evidence.validate_source_bindings`. The bases are two retained ORIGINAL retention cycles of the iterative
fuzzer study (a gate-only and a hinge policy of the efficient profile): the runtime's raw trace (ids, packed classifications,
confidences, margins and the 64-step recurrences, no prompt text), the bounded summary and the fingerprints the validators bind.
Each case is the base metadata with a few keys replaced (a mutated trace is re-summarised, so that only the mutation under test
is wrong) and the Python oracle's verdict or error message. The source-binding cases carry the eligible references of the
retained release (ids, gold, ORIGINAL packed value, confidence, margin: no text) as the Rust `Release` holds them.

Usage (host Python, for example `evaluation/.venv-v1-v3-pipeline`):
  python evaluation/generate_retention_trace_golden.py --results <main checkout>/evaluation/results --generated <dir> --models <main checkout>/models
"""
from __future__ import annotations

import argparse
import base64
import copy
import glob
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "rust/services/fuzzer/tests/fixtures/retention_trace_golden.json"
STUDY = "iterative_fuzzer_20261011/sensitive-retention-pilot04/execution/cells"
CELLS = ("efficient-gate", "efficient-hinge")
TRACE, SUMMARY, MANIFEST, OPTIMIZER = ("original_train_retention_trace_v1", "original_train_retention_summary_v1",
                                       "original_train_retention_manifest_sha256", "contextual_training_optimizer")
DROP = {"model_config", "trained_parameter_names", "full_adam_numpy_work_v1", "model_cache_key"}


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def bootstrap(generated: Path) -> None:
    for path in (ROOT / "shared" / "python", ROOT / "services" / "privoke-fuzzer" / "src", generated):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))


def base_record(results: Path, models: Path, cell: str) -> dict:
    from privoke.v1 import runtime_pb2  # noqa: PLC0415
    from privoke_model.fingerprint import parameter_fingerprint  # noqa: PLC0415
    from privoke_model import sensitive_retention as contract  # noqa: PLC0415

    cycles = sorted(glob.glob(str(results / STUDY / cell / "fuzzer" / "training-cycles" / "*" / "*.json")))
    record = json.loads(Path(cycles[0]).read_text(encoding="utf-8"))
    metadata = record["metadata"]
    evidence = record["execution_evidence"]
    request = runtime_pb2.ComputeSemanticGradientsRequest.FromString(base64.b64decode(evidence["request_protobuf_base64"]))
    response = runtime_pb2.ComputeSemanticGradientsResponse.FromString(base64.b64decode(evidence["response_protobuf_base64"]))
    delta = parameter_fingerprint({p.name: tuple(p.values) for p in response.gradients}, {p.name: tuple(p.shape) for p in response.gradients})
    sidecar = json.loads(Path(results / STUDY / cell / "fuzzer" / "original-train-retention" / metadata[MANIFEST] / "release.json").read_text(encoding="utf-8"))
    profile = json.loads(base64.b64decode(sidecar["manifest"]))["teacher"]["profile"]
    release = contract.RetentionRelease(*(base64.b64decode(sidecar[k]) for k in ("bank", "references", "manifest")),
                                        str(models / f"privoke-{profile}.json"))
    contract.validate_release(release, model_id=record["model_id"], expected_sha256=metadata[MANIFEST])
    references = [{"id": source["id"], "gold": source["packed_classification"], "original": reference["packed"],
                   "confidence": reference["confidence"], "margin": reference["margin"]} for source, reference in release.eligible]
    return {"name": cell, "metadata": {k: v for k, v in metadata.items() if k not in DROP}, "examples": len(request.examples),
            "candidate": metadata["updated_parameter_fingerprint"], "delta": delta, "model_id": record["model_id"],
            "release_sha256": release.sha256, "references": references, "_release": release}


def resummed(metadata: dict, trace: dict) -> dict:
    """The metadata of a mutated trace with its bounded summary recomputed."""
    raw = canonical(trace)
    adam = trace["adam"]
    safety = trace["safety"]
    summary = {"schema": 1, "policy": trace["policy"], "manifest_sha256": metadata[MANIFEST], "trace_sha256": hashlib.sha256(raw.encode()).hexdigest(),
               "base": adam["base"], "final": adam["final"], "delta": adam["delta"], "eligible": len(safety),
               "violations": sum(bool(row["violation"]) for row in safety), "auxiliary": trace["auxiliary"]["counts"]}
    return {TRACE: raw, SUMMARY: canonical(summary)}


def build(results: Path, generated: Path, models: Path) -> dict:
    bootstrap(generated)
    from privoke_model import sensitive_retention as contract  # noqa: PLC0415
    from training import sensitive_retention_evidence as evidence  # noqa: PLC0415

    bases = [base_record(results, models, cell) for cell in CELLS]
    cases = []

    def run(label, index, kind, edits=None, **options):
        base = bases[index]
        metadata = dict(base["metadata"])
        for key, value in (edits or {}).items():
            if value is None:
                metadata.pop(key, None)
            else:
                metadata[key] = value
        case = {"label": label, "base": index, "kind": kind, "set": {k: v for k, v in (edits or {}).items() if v is not None},
                "unset": sorted(k for k, v in (edits or {}).items() if v is None)}
        scope = options.get("scope", "full_encoder")
        candidate = options.get("candidate", base["candidate"])
        delta = options.get("delta", base["delta"])
        case.update(scope=scope, candidate=candidate, delta=delta, examples=options.get("examples", base["examples"]))
        try:
            if kind == "trace":
                result = contract.validate_trace(metadata, scope=scope, examples=case["examples"], candidate_fingerprint=candidate, delta_fingerprint=delta)
                case["result"] = "trace" if result is not None else "none"
            elif kind == "phases":
                case["result"] = [[name, count] for name, count in contract.execution_phases(metadata)]
            else:
                evidence.validate_source_bindings(metadata, base["_release"])
                case["result"] = "ok"
        except (ValueError, TypeError, KeyError) as exc:
            case["error"] = str(exc)
        cases.append(case)

    def mutated(index, function):
        trace = json.loads(bases[index]["metadata"][TRACE])
        function(trace)
        return resummed(bases[index]["metadata"], trace)

    def row(side, position, **changes):
        def apply(trace):
            trace[side][position].update(changes)
        return apply

    for index, base in enumerate(bases):
        name = base["name"]
        run(f"{name}: valid trace", index, "trace")
        run(f"{name}: phases", index, "phases")
        run(f"{name}: source bindings", index, "bindings")
        run(f"{name}: HEAD scope", index, "trace", scope="heads")
        run(f"{name}: wrong candidate", index, "trace", candidate="0" * 64)
        run(f"{name}: wrong delta", index, "trace", delta="1" * 64)
        run(f"{name}: missing trace", index, "trace", {TRACE: None})
        run(f"{name}: non-canonical trace", index, "trace", {TRACE: base["metadata"][TRACE].replace(":", ": ", 1)})
        run(f"{name}: another manifest pin", index, "trace", {MANIFEST: "2" * 64})
        run(f"{name}: not executed", index, "trace", {"executed_contextual_training_optimizer": "dormant_head_v1"})
        run(f"{name}: stale summary", index, "trace", {SUMMARY: base["metadata"][SUMMARY].replace("eligible", "eligibles")})
        run(f"{name}: violation flag flipped", index, "trace", mutated(index, lambda t: t["safety"][0].update(violation=not t["safety"][0]["violation"])))
        run(f"{name}: hinge differs", index, "trace", mutated(index, row("safety", 1, hinge=9.5)))
        run(f"{name}: extra row field", index, "trace", mutated(index, row("safety", 2, extra=1)))
        run(f"{name}: confidence not rounded", index, "trace", mutated(index, row("base_safety", 0, original_confidence=0.12345)))
        run(f"{name}: action out of range", index, "trace", mutated(index, row("safety", 3, candidate_action=3)))
        run(f"{name}: membership reordered", index, "trace", mutated(index, lambda t: t.update(base_safety=list(reversed(t["base_safety"])))))
        run(f"{name}: too few rows", index, "trace", mutated(index, lambda t: t.update(safety=t["safety"][:10], base_safety=t["base_safety"][:10])))
        run(f"{name}: unknown trace field", index, "trace", mutated(index, lambda t: t.update(extra=1)))
        run(f"{name}: auxiliary schema", index, "trace", mutated(index, lambda t: t["auxiliary"].update(extra=1)))
        run(f"{name}: wrong auxiliary counts", index, "trace", mutated(index, lambda t: t["auxiliary"]["counts"].update(directions_completed=1) if t["auxiliary"]["counts"] else t["auxiliary"].update(counts={"x": 1})))
        run(f"{name}: fewer auxiliary steps", index, "trace", mutated(index, lambda t: t["auxiliary"].update(steps=t["auxiliary"]["steps"][:-1] if t["auxiliary"]["steps"] else [{}])))
        run(f"{name}: wrong adam final", index, "trace", mutated(index, lambda t: t["adam"].update(final="3" * 64)))
        run(f"{name}: summary eligible out of range", index, "phases", {SUMMARY: canonical({**json.loads(base["metadata"][SUMMARY]), "eligible": 19})})
        run(f"{name}: summary missing", index, "phases", {SUMMARY: None})
        run(f"{name}: bindings another manifest", index, "bindings", {MANIFEST: "4" * 64})
        run(f"{name}: bindings id differs", index, "bindings", {TRACE: canonical({**json.loads(base["metadata"][TRACE]), "safety": [dict(r, id="x") if i == 0 else r for i, r in enumerate(json.loads(base["metadata"][TRACE])["safety"])]})})
        run(f"{name}: bindings gold differs", index, "bindings", {TRACE: canonical({**json.loads(base["metadata"][TRACE]), "base_safety": [dict(r, gold=r["gold"] ^ 1) if i == 4 else r for i, r in enumerate(json.loads(base["metadata"][TRACE])["base_safety"])]})})
        run(f"{name}: bindings margin differs", index, "bindings", {TRACE: canonical({**json.loads(base["metadata"][TRACE]), "safety": [dict(r, original_margin=r["original_margin"] + 1) if i == 5 else r for i, r in enumerate(json.loads(base["metadata"][TRACE])["safety"])]})})
        run(f"{name}: bindings short membership", index, "bindings", {TRACE: canonical({**json.loads(base["metadata"][TRACE]), "safety": json.loads(base["metadata"][TRACE])["safety"][:-1]})})
    for base in bases:
        base.pop("_release")
    return {"schema": 1, "oracle": "privoke_model.sensitive_retention + training.sensitive_retention_evidence", "python": sys.version.split()[0],
            "bases": bases, "cases": cases}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--generated", type=Path, required=True)
    parser.add_argument("--models", type=Path, required=True, help="directory with the ORIGINAL teacher artifacts (privoke-<profile>.json)")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    document = build(args.results, args.generated, args.models)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"cases": len(document["cases"]), "valid": sum("error" not in c for c in document["cases"]),
                      "errors": sum("error" in c for c in document["cases"]), "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
