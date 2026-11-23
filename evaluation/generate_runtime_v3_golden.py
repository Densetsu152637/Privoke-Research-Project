"""LOCAL golden of the Rust runtime worker's semantic layer on the pinned standard V3 releases (RUST-S17H).

The oracle is the unchanged Python W1 worker (``worker_main.Dispatcher`` over W1 frames, ``generate_runtime_worker_golden.Worker``)
reading the pinned release packages through its own read-only ``LocalModelProvider`` (``<root>/privoke-v3-<tier>/manifest.json``,
admitted by the real pins). Every request is ``AnalyzePrompt`` with ``layers=[SEMANTIC]`` and the release named explicitly: an LLM-only
(semantic-only) row; the harness asserts the selection and, for an answered row, that the returned execution is exactly the semantic
layer. No empty layer list is ever sent. ``elapsed_ms`` is cleared, as in the other worker goldens.

The selection is the stage 14 one (``generate_semantic_golden.py releases`` and ``sets``): the synthetic and fuzz prompts, evenly
spaced rows of the recorded sets and the stress prompts, minus texts with surrogates. The files hold prompt text, so the output is
LOCAL and git-ignored (``rust/services/runtime/tests/local/v3``) and is never committed.

Usage (host Python with Torch and the client runtime requirements, for example ``evaluation/.venv-v1-v3-pipeline``)::

    python evaluation/generate_runtime_v3_golden.py real --releases-root <main checkout>/models/standard-releases \\
        --data-root <main checkout> --sets development personalized openai piimb dolly15k oasst2 stress --limit 300 \\
        [--generated <dir with privoke/v1>]
"""
from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path

EVALUATION = Path(__file__).resolve().parent
sys.path.insert(0, str(EVALUATION))
REPO = EVALUATION.parent
DEFAULT_OUT = REPO / "rust" / "services" / "runtime" / "tests" / "local" / "v3"
TIERS = ("efficient", "balanced", "quality")
SET_NAMES = ["development", "personalized", "openai", "piimb", "dolly15k", "oasst2", "stress"]
SEMANTIC = 4


def cmd_real(args) -> None:
    worker_golden = importlib.import_module("generate_runtime_worker_golden")
    semantic = importlib.import_module("generate_semantic_golden")
    ner = importlib.import_module("generate_ner_golden")
    if args.generated:
        sys.path.insert(0, str(Path(args.generated)))
    texts_by_set = ner.load_sets(args.sets, Path(args.data_root))
    releases = Path(args.releases_root)
    worker = worker_golden.Worker([releases])
    pb = worker.pb
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    groups = {"synthetic": [(row_id, text) for row_id, text in semantic.prompt_rows() if not semantic.has_surrogate(text)]}
    for set_name in args.sets:
        groups[set_name] = [(f"{set_name}:{i}", text) for i, text in semantic.sample(texts_by_set[set_name], args.limit)
                            if not semantic.has_surrogate(text)]
    for tier in args.tiers:
        model_id = f"privoke-v3-{tier}"
        for group, picked in groups.items():
            rows = []
            for row_id, text in picked:
                request = pb.AnalyzePromptRequest(text=text, layers=[SEMANTIC], request_id=row_id, semantic_model_id=model_id)
                assert list(request.layers) == [SEMANTIC], "a semantic-only row must name exactly the semantic layer"
                record = worker.call(1, request)
                if "response" in record:
                    response = pb.AnalyzePromptResponse.FromString(worker_golden.base64.b64decode(record["response"]))
                    if not response.error:
                        executed = [(layer.layer, layer.status) for layer in response.layers]
                        assert executed == [(SEMANTIC, "ok")], f"{row_id}: executed {executed}"
                rows.append({"id": row_id, "text": text, "request": record["request"],
                             **{key: record[key] for key in ("response", "error_code") if key in record}})
            meta = {"tier": tier, "set": group, "layers": ["semantic"], "scope": "llm_only"}
            (out / f"{tier}-{group}.json").write_text(json.dumps({"meta": meta, "rows": rows}, ensure_ascii=False, separators=(",", ":")) + "\n",
                                                      encoding="utf-8", newline="\n")
            print(f"{tier} {group}: {len(rows)} rows", flush=True)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    real = sub.add_parser("real")
    real.add_argument("--releases-root", required=True, help="models/standard-releases of the checkout that holds the releases")
    real.add_argument("--data-root", default=str(REPO), help="checkout that holds the ignored dataset files")
    real.add_argument("--sets", nargs="+", choices=SET_NAMES, default=SET_NAMES)
    real.add_argument("--tiers", nargs="+", choices=TIERS, default=list(TIERS))
    real.add_argument("--limit", type=int, default=300, help="evenly spaced rows per set (0 = all)")
    real.add_argument("--out", default=str(DEFAULT_OUT))
    real.add_argument("--generated", help="directory with the generated protobuf clients, when this checkout has none")
    real.set_defaults(func=cmd_real)
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
