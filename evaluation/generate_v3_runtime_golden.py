"""Golden generator for the Rust V3 runtime service (`rust/services/v3-runtime`, stage 22 of the server rewrite).

The oracle is the maintained Python `services/pretrained-v3/src/runtime_server.py`, run in process on the host with its real
`RuntimeServer.AnalyzePrompt` and `RuntimeServer.FitCandidate`. Its one network dependency, the checkpoint service
(`CheckpointService`), is replaced by an in-memory stub that serves the snapshot manifest and its three assets, so no stack,
accelerator or admitted environment is needed: the environment `preflight` (exact versions of torch, transformers and the rest)
is replaced by a fixed capability map, which is a deviation of the harness, not of the server code that is being compared.

Every request is semantic-only: `layers=[4]` (the semantic layer), the model named explicitly, no presence gate. An empty layer
list is never sent; the harness asserts that. Results recorded here are LLM-only (semantic-only) results.

Subcommands (host Python, for example `evaluation/.venv-v1-v3-pipeline`; `--generated` or `PRIVOKE_GENERATED` names the generated
protobuf clients, that is a directory holding `privoke/v1` and `privoke/experimental`):

  analyze-synthetic   committed golden: the synthetic V3 package of `rust/crates/privoke-semantic/tests/fixtures/v3_synthetic`
                      (an admitted-tier lookalike is impossible, so the harness relaxes the tier pins of `validate_manifest`),
                      the 195 synthetic prompts of `generate_semantic_golden.py`, and the edge cases (empty text, over-length,
                      visibility hints, wrong model, request aborts). Output:
                      `rust/services/v3-runtime/tests/fixtures/v3_runtime_analyze_golden.json`.
  analyze-real        LOCAL golden, git-ignored: the pinned standard releases on the recorded sets (the stage 14 selection:
                      synthetic and fuzz prompts, evenly spaced rows of the recorded sets, the stress prompts). The files hold
                      prompt text, so the output is never committed.

  fit-synthetic       committed golden: `FitCandidate` over the synthetic V3 package with the real frozen BC01 schedule built from the
                      committed pinned inputs of `rust/crates/privoke-curriculum/tests/fixtures` (pilot policy: two AdamW steps over one
                      block of 64 rows and a guard of 16), once per scope, plus the requests the server refuses (bad scope, replay of an
                      identity, wrong source commitment, wrong model). Records the request, the response, the two staged payloads with
                      their manifest and the `fits` rows. Output: `rust/services/v3-runtime/tests/fixtures/v3_runtime_fit_golden.json`.
  fit-real            LOCAL golden, git-ignored: the same on a real ORIGINAL package (`--package`, a directory with `manifest.json`,
                      `config.json`, `vocab.txt`, `model.safetensors`), with the pilot policy and the frozen 64-step policy, both scopes.

Usage:
  python evaluation/generate_v3_runtime_golden.py analyze-synthetic --generated <dir>
  python evaluation/generate_v3_runtime_golden.py analyze-real --releases-root <main checkout>/models/standard-releases \\
      --data-root <main checkout> --sets development personalized openai piimb dolly15k oasst2 stress --limit 300 \\
      --out rust/services/v3-runtime/tests/local/analyze --generated <dir>
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import json
import os
import sys
import tempfile
import threading
from pathlib import Path

EVALUATION = Path(__file__).resolve().parent
ROOT = EVALUATION.parent
SERVICE_SRC = ROOT / "services" / "pretrained-v3" / "src"
SEMANTIC_FIXTURES = ROOT / "rust" / "crates" / "privoke-semantic" / "tests" / "fixtures"
SYNTHETIC_PACKAGE = SEMANTIC_FIXTURES / "v3_synthetic"
SERVICE = ROOT / "rust" / "services" / "v3-runtime"
SYNTHETIC_ANALYZE = SERVICE / "tests" / "fixtures" / "v3_runtime_analyze_golden.json"
THREADS = 4  # the paper's Torch 2.11 CPU setting
SEMANTIC = 4
TIERS = ("efficient", "balanced", "quality")
SET_NAMES = ["development", "personalized", "openai", "piimb", "dolly15k", "oasst2", "stress"]


def asset(path: Path) -> bytes:
    """The bytes of a package file as a Linux checkout holds them (the text assets are LF whatever the host checked out)."""
    raw = path.read_bytes()
    return raw.replace(b"\r\n", b"\n") if SYNTHETIC_PACKAGE in path.parents and path.suffix in (".json", ".txt") else raw


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def bootstrap(generated: Path | None) -> None:
    """Make the service's own modules importable the way the service imports them."""
    source = generated or (Path(os.environ["PRIVOKE_GENERATED"]) if os.environ.get("PRIVOKE_GENERATED") else None)
    if source is not None:
        os.environ["V3_GENERATED"] = str(source)
    if str(SERVICE_SRC) in sys.path:
        sys.path.remove(str(SERVICE_SRC))
    sys.path.insert(0, str(SERVICE_SRC))
    if str(EVALUATION) not in sys.path:
        sys.path.append(str(EVALUATION))
    import common  # noqa: F401,PLC0415 - puts the generated clients, shared/python and the runtime sources on sys.path


class Aborted(Exception):
    """`context.abort(code, details)`."""

    def __init__(self, code, details):
        super().__init__(details)
        self.code = code
        self.details = details


class Context:
    def abort(self, code, details):
        raise Aborted(code, details)

    def is_active(self):
        return True


class Checkpoint:
    """The checkpoint service in memory: the current snapshot of a model and the blobs by digest."""

    def __init__(self, common, pb):
        self.common = common
        self.pb = pb
        self.blobs = {}
        self.current = None
        self.calls = []

    def put(self, payload: bytes) -> str:
        sha256 = sha(payload)
        self.blobs[sha256] = payload
        return sha256

    # The `CheckpointServiceStub` surface that `RuntimeServer` uses.
    def Health(self, request, timeout=None):
        return self.pb.HealthResponse(ready=True, role="stub")

    def ResolveCurrent(self, request, timeout=None):
        self.calls.append("resolve:" + request.model_id)
        return self.pb.Ref(sha256=self.current)

    def FetchBlob(self, request, timeout=None):
        self.calls.append("fetch:" + request.sha256)
        return iter(list(self.common.chunks(self.blobs[request.sha256])))

    def StageCheckpoint(self, iterator, timeout=None):
        chunks = list(iterator)
        payload = b"".join(chunk.data for chunk in chunks)
        manifest = chunks[0].manifest_json if chunks else b""
        sha256 = self.put(payload)
        self.calls.append("stage:" + sha256)
        self.staged.append({"sha256": sha256, "payload": payload, "manifest": manifest})
        return self.pb.Ref(sha256=sha256)

    staged: list = []


def relaxed_manifest(contract):
    """`validate_manifest` without the admitted-tier pins: the key set, the schema and the architecture (synthetic packages)."""
    keys = {"schema", "architecture", "model_id", "tier", "parent", "original", "blob", "config", "vocab", "source", "tensors",
            "parameter_count", "scope", "evidence"}

    def validate(value):
        if not isinstance(value, dict) or set(value) != keys or value["schema"] != contract.SCHEMA or value["architecture"] != contract.ARCHITECTURE:
            raise ValueError("Unsupported v3 manifest schema.")
        for key in ("blob", "config", "vocab"):
            contract.check_sha(value[key])
        return value

    return validate


class Harness:
    """The real `RuntimeServer`, constructed with the environment preflight and the channel replaced."""

    def __init__(self, generated: Path | None, relaxed: bool, state: Path):
        bootstrap(generated)
        import torch  # noqa: PLC0415

        torch.set_num_threads(THREADS)
        self.torch = torch
        self.common = importlib.import_module("common")
        self.contract = importlib.import_module("privoke_model.v3_contract")
        self.module = importlib.import_module("runtime_server")
        self.pb = self.common.pb
        self.runtime_pb2 = self.common.runtime_pb2
        self.checkpoint = Checkpoint(self.common, self.pb)
        self.checkpoint.staged = []
        capabilities = {"harness": "generate_v3_runtime_golden.py", "torch": torch.__version__, "device": "cpu", "threads": str(THREADS)}
        self.module.preflight = lambda device: dict(capabilities)
        self.module.channel = lambda target: None
        self.common.rpc.CheckpointServiceStub = lambda channel: self.checkpoint
        self.module.rpc.CheckpointServiceStub = lambda channel: self.checkpoint
        if relaxed:
            validate = relaxed_manifest(self.contract)
            self.module.validate_manifest = validate
            importlib.import_module("src.v3.model").validate_manifest = validate
            training = importlib.import_module("src.v3.training")
            training.validate_execution = lambda evidence, finalized=True: evidence
        self.server = self.module.RuntimeServer("stub:0", str(state), "cpu")

    def analyze(self, request):
        """The recorded outcome of one `AnalyzePrompt` call."""
        assert list(request.layers) == [SEMANTIC], "every request selects exactly the semantic layer"
        try:
            response = self.server.AnalyzePrompt(request, Context())
        except Aborted as aborted:
            return {"abort": [aborted.code.name, aborted.details]}
        response.elapsed_ms = 0.0
        return {"ok": b64(response.SerializeToString(deterministic=True))}

    def raw_confidence(self, sha256: str, text: str):
        """The unrounded confidence of the loaded model (informational: the boundary rule of a rounding difference)."""
        torch = self.torch
        model = self.server.cache[sha256][1]
        with torch.no_grad():
            logits = model([text])
            values = torch.cat((logits["sensitivity"].softmax(-1)[0], logits["category"].sigmoid()[0]))
        return float(values.max())

    def request(self, text, model_id, **fields):
        runtime_pb2 = self.runtime_pb2
        return runtime_pb2.AnalyzePromptRequest(text=text, semantic_model_id=model_id, layers=[SEMANTIC], **fields)


def case(harness: Harness, label: str, request, sha256: str | None = None) -> dict:
    outcome = harness.analyze(request)
    record = {"id": label, "request": b64(request.SerializeToString(deterministic=True)), "outcome": outcome}
    if "ok" in outcome and sha256 is not None and request.text is not None:
        decoded = harness.runtime_pb2.AnalyzePromptResponse.FromString(base64.b64decode(outcome["ok"]))
        if not decoded.error:
            record["raw_confidence"] = harness.raw_confidence(sha256, request.text)
    return record


def semantic_module():
    return importlib.import_module("generate_semantic_golden")


def synthetic_manifest(harness: Harness, package: Path, model_id: str) -> tuple[bytes, dict]:
    """A manifest of the package in the layout `validate_manifest` reads, canonical bytes as the checkpoint service stores them."""
    from safetensors.torch import load_file  # noqa: PLC0415

    model_module = importlib.import_module("src.v3.model")
    state = load_file(str(package / "model.safetensors"), device="cpu")
    tensors = model_module.inventory(state)
    count = sum(int(__import__("math").prod(entry["shape"])) for entry in tensors.values())
    contract = harness.contract
    manifest = {
        "schema": 1, "architecture": contract.ARCHITECTURE, "model_id": model_id, "tier": model_id.removeprefix("privoke-v3-"),
        "parent": "", "original": "", "blob": sha(asset(package / "model.safetensors")),
        "config": sha(asset(package / "config.json")), "vocab": sha(asset(package / "vocab.txt")),
        "source": {"repository": "synthetic/v3", "revision": "0" * 40, "weights_sha256": sha(b"synthetic backbone"),
                   "config_sha256": sha(asset(package / "config.json")), "vocab_sha256": sha(asset(package / "vocab.txt"))},
        "tensors": tensors, "parameter_count": count, "scope": "original", "evidence": "",
    }
    return contract.canonical(manifest), manifest


def serve_package(harness: Harness, package: Path, manifest_bytes: bytes, manifest: dict) -> str:
    harness.checkpoint.put(asset(package / "model.safetensors"))
    harness.checkpoint.put(asset(package / "config.json"))
    harness.checkpoint.put(asset(package / "vocab.txt"))
    sha256 = harness.checkpoint.put(manifest_bytes)
    harness.checkpoint.current = sha256
    return sha256


def synthetic_cases(harness: Harness, sha256: str, model_id: str) -> list[dict]:
    semantic = semantic_module()
    rows = []
    for row_id, text in semantic.prompt_rows():
        if semantic.has_surrogate(text):
            continue
        rows.append(case(harness, row_id, harness.request(text, model_id, request_id="req-" + row_id), sha256))
    # The request shapes around the prompt.
    long_text = " ".join(["word"] * 600)
    named = [
        ("empty", harness.request("", model_id, request_id="req-empty")),
        ("over-length", harness.request(long_text, model_id, request_id="req-long")),
        ("hint-PU", harness.request("hello there", model_id, visibility_hint="PU", request_id="req-hint")),
        ("hint-P0", harness.request("hello there", model_id, visibility_hint="P0", request_id="req-hint")),
        ("hint-P2", harness.request("my salary is 90000 and my password is hunter2", model_id, visibility_hint="P2")),
        ("hint-P4", harness.request("my salary is 90000 and my password is hunter2", model_id, visibility_hint="P4")),
        ("hint-lowercase", harness.request("hello there", model_id, visibility_hint="p2", request_id="req-bad-hint")),
        ("hint-unknown", harness.request("hello there", model_id, visibility_hint="it's", request_id="req-bad-hint")),
        ("wrong-model", harness.request("hello there", "privoke-v3-balanced", request_id="req-wrong-model")),
        ("pinned", harness.request("my address is 12 Elm Street", model_id, request_id="req-pinned", metadata={"v3_checkpoint": sha256})),
        ("pin-malformed", harness.request("hello there", model_id, request_id="req-pin", metadata={"v3_checkpoint": "XYZ"})),
        ("with-source", harness.request("hello there", model_id, request_id="req-src", source="chat", target_app="app", metadata={"a": "b"})),
    ]
    for label, request in named:
        rows.append(case(harness, label, request, sha256))
    # Requests the server aborts before it analyses anything. These bypass `request()` on purpose: they are the malformed shapes,
    # and the harness only asserts "semantic layer" for requests the oracle is meant to accept.
    runtime_pb2 = harness.runtime_pb2
    aborted = [
        ("abort-no-layers", runtime_pb2.AnalyzePromptRequest(text="x", semantic_model_id=model_id)),
        ("abort-regex-layer", runtime_pb2.AnalyzePromptRequest(text="x", semantic_model_id=model_id, layers=[2])),
        ("abort-two-layers", runtime_pb2.AnalyzePromptRequest(text="x", semantic_model_id=model_id, layers=[3, 4])),
        ("abort-no-model", runtime_pb2.AnalyzePromptRequest(text="x", layers=[SEMANTIC])),
        ("abort-gate", runtime_pb2.AnalyzePromptRequest(text="x", semantic_model_id=model_id, layers=[SEMANTIC],
                                                        semantic_presence_gate=runtime_pb2.SemanticPresenceGate())),
    ]
    for label, request in aborted:
        try:
            outcome = {"ok": b64(harness.server.AnalyzePrompt(request, Context()).SerializeToString(deterministic=True))}
        except Aborted as error:
            outcome = {"abort": [error.code.name, error.details]}
        assert "abort" in outcome, label
        rows.append({"id": label, "request": b64(request.SerializeToString(deterministic=True)), "outcome": outcome})
    return rows


def cmd_analyze_synthetic(args) -> None:
    model_id = "privoke-v3-efficient"
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as scratch:
        harness = Harness(Path(args.generated) if args.generated else None, True, Path(scratch) / "state")
        manifest_bytes, manifest = synthetic_manifest(harness, SYNTHETIC_PACKAGE, model_id)
        sha256 = serve_package(harness, SYNTHETIC_PACKAGE, manifest_bytes, manifest)
        rows = synthetic_cases(harness, sha256, model_id)
        golden = {
            "meta": {"torch": harness.torch.__version__, "threads": THREADS, "layers": ["semantic"], "model_id": model_id,
                     "package": "rust/crates/privoke-semantic/tests/fixtures/v3_synthetic", "manifest_sha256": sha256},
            "manifest": b64(manifest_bytes),
            "rows": rows,
        }
    SYNTHETIC_ANALYZE.parent.mkdir(parents=True, exist_ok=True)
    SYNTHETIC_ANALYZE.write_text(json.dumps(golden, separators=(",", ":")) + "\n", encoding="utf8", newline="\n")
    print("wrote", SYNTHETIC_ANALYZE, len(rows), "rows")


def cmd_analyze_real(args) -> None:
    semantic = semantic_module()
    ner = importlib.import_module("generate_ner_golden")
    texts_by_set = ner.load_sets(args.sets, Path(args.data_root))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for tier in args.tiers:
        release = Path(args.releases_root) / f"privoke-v3-{tier}"
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as scratch:
            harness = Harness(Path(args.generated) if args.generated else None, False, Path(scratch) / "state")
            manifest_bytes = (release / "manifest.json").read_bytes()
            manifest = json.loads(manifest_bytes)
            sha256 = serve_package(harness, release, manifest_bytes, manifest)
            model_id = "privoke-v3-" + tier
            groups = {"synthetic": [(row_id, text) for row_id, text in semantic.prompt_rows() if not semantic.has_surrogate(text)]}
            for set_name in args.sets:
                picked = [(f"{set_name}:{i}", t) for i, t in semantic.sample(texts_by_set[set_name], args.limit) if not semantic.has_surrogate(t)]
                groups[set_name] = picked
            for group, picked in groups.items():
                rows = [case(harness, row_id, harness.request(text, model_id, request_id=row_id), sha256) for row_id, text in picked]
                document = {"meta": {"tier": tier, "set": group, "torch": harness.torch.__version__, "threads": THREADS,
                                     "layers": ["semantic"], "manifest_sha256": sha256},
                            "rows": rows}
                (out / f"{tier}-{group}.json").write_text(json.dumps(document, separators=(",", ":")) + "\n", encoding="utf8", newline="\n")
                print(f"{tier} {group}: {len(rows)} rows", flush=True)


def fit_harness(args, relaxed: bool, scratch: Path) -> Harness:
    """A harness whose `validate_schedule` reads the pinned BC01 inputs from the committed fixtures (the same bytes as the pins)."""
    harness = Harness(Path(args.generated) if args.generated else None, relaxed, scratch / "state")
    fuzzer = importlib.import_module("generate_v3_fuzzer_golden")
    harness.fuzzer = fuzzer
    harness.inputs = fuzzer.prepare_input_root(scratch)
    training = importlib.import_module("fuzzer_training")
    harness.training = training
    original = training.validate_schedule
    harness.module.validate_schedule = lambda rows, guard, source, policy: original(rows, guard, source, policy, harness.inputs)
    return harness


def fit_request(harness: Harness, steps: int, scope: int, request_id: str, base: str, model_id: str):
    """The fit request that the V3 fuzzer builds: the frozen schedule, its policy and source record, semantic-only."""
    policy = harness.fuzzer.frozen_policy(steps)
    training, guard, source = harness.training.schedule(20261123, policy, harness.inputs)
    source_json = harness.contract.canonical(source)
    return harness.pb.FitRequest(
        request_id=request_id, model_id=model_id, base=base, scope=scope, layers=[SEMANTIC], train=training, guard=guard,
        policy_json=harness.contract.canonical(policy), source_commitment=sha(source_json), source_json=source_json)


def fit_case(harness: Harness, label: str, request) -> dict:
    harness.checkpoint.staged.clear()
    record = {"id": label, "request": b64(request.SerializeToString(deterministic=True))}
    try:
        response = harness.server.FitCandidate(request, Context())
        record["outcome"] = {"ok": b64(response.SerializeToString(deterministic=True))}
    except Aborted as aborted:
        record["outcome"] = {"abort": [aborted.code.name, aborted.details]}
    except Exception as error:  # a raised exception is UNKNOWN to the caller
        record["outcome"] = {"raise": type(error).__name__ + ": " + str(error)}
    record["staged"] = [{"sha256": item["sha256"], "payload": b64(item["payload"]), "manifest": b64(item["manifest"])}
                        for item in harness.checkpoint.staged]
    return record


def fit_rows(harness: Harness) -> list:
    return [list(row) for row in harness.server.db.execute("SELECT id,fingerprint,status,candidate,reason FROM fits ORDER BY id")]


def fit_cases(harness: Harness, base: str, model_id: str, steps_list) -> list:
    cases = []
    for steps in steps_list:
        for name, scope in (("heads", 1), ("full", 2)):
            label = f"{name}-{steps}"
            cases.append(fit_case(harness, label, fit_request(harness, steps, scope, "fit-" + label, base, model_id)))
    return cases


def refusals(harness: Harness, base: str, model_id: str) -> list:
    cases = []
    good = fit_request(harness, 2, 1, "fit-refused", base, model_id)

    def variant(label, **changes):
        request = harness.pb.FitRequest()
        request.CopyFrom(good)
        for key, value in changes.items():
            if key == "layers":
                del request.layers[:]
                request.layers.extend(value)
            else:
                setattr(request, key, value)
        cases.append(fit_case(harness, label, request))

    variant("refuse-no-layers", request_id="fit-r1", layers=[])
    variant("refuse-bad-scope", request_id="fit-r2", scope=0)
    variant("refuse-no-identity", request_id="")
    variant("refuse-long-identity", request_id="x" * 201)
    variant("refuse-commitment", request_id="fit-r3", source_commitment="0" * 64)
    variant("refuse-wrong-model", request_id="fit-r4", model_id="privoke-v3-balanced")
    variant("refuse-bad-base", request_id="fit-r5", base="XYZ")
    cases.append(fit_case(harness, "replayed-identity", fit_request(harness, 2, 1, "fit-heads-2", base, model_id)))
    return cases


def write_fit(path: Path, harness: Harness, base_bytes: bytes, base: str, cases: list, meta: dict) -> None:
    golden = {"meta": dict(meta, torch=harness.torch.__version__, threads=THREADS, layers=["semantic"], base=base),
              "base_manifest": b64(base_bytes), "cases": cases, "rows": fit_rows(harness)}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(golden, separators=(",", ":")) + "\n", encoding="utf8", newline="\n")
    print("wrote", path, len(cases), "cases")


SYNTHETIC_FIT = SERVICE / "tests" / "fixtures" / "v3_runtime_fit_golden.json"


def cmd_fit_synthetic(args) -> None:
    model_id = "privoke-v3-efficient"
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as scratch:
        harness = fit_harness(args, True, Path(scratch))
        manifest_bytes, manifest = synthetic_manifest(harness, SYNTHETIC_PACKAGE, model_id)
        base = serve_package(harness, SYNTHETIC_PACKAGE, manifest_bytes, manifest)
        cases = fit_cases(harness, base, model_id, (2,)) + refusals(harness, base, model_id)
        meta = {"model_id": model_id, "package": "rust/crates/privoke-semantic/tests/fixtures/v3_synthetic"}
        write_fit(SYNTHETIC_FIT, harness, manifest_bytes, base, cases, meta)


def cmd_fit_real(args) -> None:
    package = Path(args.package)
    model_id = args.model_id
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as scratch:
        harness = fit_harness(args, False, Path(scratch))
        manifest_bytes = (package / "manifest.json").read_bytes()
        base = serve_package(harness, package, manifest_bytes, json.loads(manifest_bytes))
        cases = fit_cases(harness, base, model_id, [int(steps) for steps in args.steps])
        write_fit(Path(args.out), harness, manifest_bytes, base, cases, {"model_id": model_id, "package": str(package)})


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--generated", help="directory with the generated protobuf clients, when this checkout has none")
    sub = parser.add_subparsers(dest="command", required=True)
    synthetic = sub.add_parser("analyze-synthetic")
    synthetic.set_defaults(func=cmd_analyze_synthetic)
    real = sub.add_parser("analyze-real")
    real.add_argument("--releases-root", required=True, help="models/standard-releases of the checkout that holds the releases")
    real.add_argument("--data-root", required=True, help="checkout that holds the ignored dataset files")
    real.add_argument("--sets", nargs="+", choices=SET_NAMES, default=SET_NAMES)
    real.add_argument("--tiers", nargs="+", choices=TIERS, default=list(TIERS))
    real.add_argument("--limit", type=int, default=300, help="evenly spaced rows per set (0 = all)")
    real.add_argument("--out", default=str(SERVICE / "tests" / "local" / "analyze"))
    real.set_defaults(func=cmd_analyze_real)
    fit_synthetic = sub.add_parser("fit-synthetic")
    fit_synthetic.set_defaults(func=cmd_fit_synthetic)
    fit_real = sub.add_parser("fit-real")
    fit_real.add_argument("--package", required=True, help="an ORIGINAL package directory: manifest.json, config.json, vocab.txt, model.safetensors")
    fit_real.add_argument("--model-id", default="privoke-v3-efficient")
    fit_real.add_argument("--steps", nargs="+", default=["2", "64"], choices=["2", "64", "256", "512"])
    fit_real.add_argument("--out", default=str(SERVICE / "tests" / "local" / "fit" / "efficient.json"))
    fit_real.set_defaults(func=cmd_fit_real)
    args = parser.parse_args(argv)
    sys.path.insert(0, str(EVALUATION))
    args.func(args)


if __name__ == "__main__":
    main()
