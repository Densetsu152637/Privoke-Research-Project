"""Reference side of the parity gate. Run with the read-only reference environment:

    evaluation/.venv-v1-v3-pipeline/Scripts/python.exe -I -B reference_dump.py --impl ../python/privoke_spacy_impl.py \
        --sets <work>/sets --out <work>/reference --shard 0 --shards 4

It runs plain `spacy.load("en_core_web_sm")` and the same `analyze_body` function the worker runs, for every document of
every set and both selections, and writes the SHA-256 of each result (one hex line per document of this shard). The
worker side writes the same lines from the bytes it received over the pipe. Nothing is written inside the reference
environment (-B, and the output directory is elsewhere).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import time
from pathlib import Path


def load_impl(path: Path):
    spec = importlib.util.spec_from_file_location("privoke_spacy_impl", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["privoke_spacy_impl"] = module
    spec.loader.exec_module(module)
    return module


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--impl", type=Path, required=True)
    parser.add_argument("--sets", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--shard", type=int, default=0)
    parser.add_argument("--shards", type=int, default=1)
    args = parser.parse_args()
    impl = load_impl(args.impl)
    args.out.mkdir(parents=True, exist_ok=True)

    blis = impl.blis_target()  # before spacy imports blis, as the worker does
    import spacy

    nlp = spacy.load("en_core_web_sm")
    order = json.loads((args.sets / "sets.json").read_text(encoding="utf-8"))["order"]
    identity = {
        "python": sys.version, "spacy": spacy.__version__, "model": nlp.meta["name"], "model_version": nlp.meta["version"],
        "blis_target": blis, "shard": args.shard, "shards": args.shards,
    }  # fmt: skip
    if args.shard == 0:
        (args.out / "identity.json").write_text(json.dumps(identity, indent=1), encoding="utf-8")
        (args.out / "lemma_index.sha256").write_text(hashlib.sha256(impl.lemma_index_body(nlp).encode("ascii")).hexdigest() + "\n")
    for name in order:
        texts = [json.loads(line) for line in open(args.sets / f"{name}.jsonl", encoding="utf-8")]
        for selection in ("full", "tagger"):
            started = time.time()
            with open(args.out / f"{name}.{selection}.{args.shard}of{args.shards}.hashes", "w", encoding="ascii", newline="\n") as out:
                for index in range(args.shard, len(texts), args.shards):
                    body = impl.analyze_body(nlp, texts[index], selection)
                    out.write(hashlib.sha256(body.encode("utf-8")).hexdigest() + "\n")
            print(f"[shard {args.shard}] {name} {selection}: {time.time() - started:.0f}s", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
