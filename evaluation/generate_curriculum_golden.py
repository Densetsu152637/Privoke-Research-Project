"""Narrow golden generator for the Rust `privoke-curriculum` crate (stage 20).

Single process, standard library for `random`; `recorded` and `live` import the maintained Python fuzzer sources
(the oracle) through the host environment. Nothing here edits recorded evidence: it only reads it and writes compact
digests under `rust/crates/privoke-curriculum/tests/golden/`.

Subcommands
  random    per-method draw-stream digests of CPython `random` (10**6 draws per method and seed)
  recorded  schedule and sampling digests recorded in retained evidence (read-only results directory)
  live      digests computed by the maintained Python fuzzer for further seeds

Usage (host Python, e.g. evaluation/.venv-v1-v3-pipeline):
  python evaluation/generate_curriculum_golden.py random
  python evaluation/generate_curriculum_golden.py recorded --results <main checkout>/evaluation/results
  python evaluation/generate_curriculum_golden.py live --results <main checkout>/evaluation/results
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import struct
import sys
from array import array
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "rust/crates/privoke-curriculum/tests/golden"
DRAWS = 1_000_000
SEEDS = (0, 42, 2**32, 2**64 - 59)


def digest_array(values: array) -> str:
    if sys.byteorder != "little":
        values.byteswap()
    return hashlib.sha256(values.tobytes()).hexdigest()


def stream(name, rng, make):
    """Run one method for DRAWS draws and hash the little-endian stream of its outputs."""
    return {"method": name, "draws": DRAWS, "sha256": make(rng)}


def u64_stream(fn):
    def run(rng):
        out = array("Q")
        for _ in range(DRAWS):
            out.append(fn(rng))
        return digest_array(out)
    return run


def i64_stream(fn):
    def run(rng):
        out = array("q")
        for _ in range(DRAWS):
            out.append(fn(rng))
        return digest_array(out)
    return run


def f64_stream(fn):
    def run(rng):
        out = array("d")
        for _ in range(DRAWS):
            out.append(fn(rng))
        return digest_array(out)
    return run


def shuffle_stream(length):
    # Consecutive in-place shuffles of one list; each call spends length-1 draws, so about DRAWS draws in all.
    def run(rng):
        calls = DRAWS // (length - 1)
        items = list(range(length))
        out = array("I")
        for _ in range(calls):
            rng.shuffle(items)
            out.extend(items)
        return digest_array(out)
    return run, DRAWS // (length - 1)


def sample_stream(n, k):
    def run(rng):
        population = list(range(n))
        out = array("I")
        for _ in range(DRAWS // k):
            out.extend(rng.sample(population, k))
        return digest_array(out)
    return run


def choices_stream(kind, weights, k):
    def run(rng):
        population = list(range(len(weights) if weights else 17))
        out = array("I")
        calls = DRAWS // k
        if kind == "cum":
            cumulative = []
            total = 0
            for w in weights:
                total += w
                cumulative.append(total)
            for _ in range(calls):
                out.extend(rng.choices(population, cum_weights=cumulative, k=k))
        elif kind == "weights":
            for _ in range(calls):
                out.extend(rng.choices(population, weights=weights, k=k))
        else:
            for _ in range(calls):
                out.extend(rng.choices(population, k=k))
        return digest_array(out)
    return run


def random_golden():
    entries = []
    for seed in SEEDS:
        methods = [("random", f64_stream(lambda r: r.random()))]
        for bits in (1, 7, 31, 32, 33, 53, 64):
            methods.append((f"getrandbits_{bits}", u64_stream(lambda r, b=bits: r.getrandbits(b))))
        for n in (1, 2, 3, 10, 1000, 2**31 + 1, 2**40 + 3, 2**63 + 5):
            methods.append((f"randbelow_{n}", u64_stream(lambda r, n=n: r._randbelow(n))))
        for length in (1, 5, 100003):
            seq = list(range(length))
            methods.append((f"choice_{length}", u64_stream(lambda r, s=seq: r.choice(s))))
        for length in (7, 100, 1000):
            run, calls = shuffle_stream(length)
            methods.append((f"shuffle_{length}", run))
        for n, k in ((10, 3), (50, 10), (1000, 20), (100, 100)):
            methods.append((f"sample_{n}_{k}", sample_stream(n, k)))
        methods.append(("randrange_10", i64_stream(lambda r: r.randrange(10))))
        methods.append(("randrange_5_1000003", i64_stream(lambda r: r.randrange(5, 1000003))))
        methods.append(("randrange_m50_50_7", i64_stream(lambda r: r.randrange(-50, 50, 7))))
        methods.append(("randrange_100_m100_m9", i64_stream(lambda r: r.randrange(100, -100, -9))))
        methods.append(("randint_m3_3", i64_stream(lambda r: r.randint(-3, 3))))
        methods.append(("uniform_0_1", f64_stream(lambda r: r.uniform(0.0, 1.0))))
        methods.append(("uniform_m3.5_7.25", f64_stream(lambda r: r.uniform(-3.5, 7.25))))
        weights = [1, 2, 3.5, 0.25, 10]
        methods.append(("choices_cum_5_k10", choices_stream("cum", weights, 10)))
        methods.append(("choices_weights_5_k1", choices_stream("weights", weights, 1)))
        methods.append(("choices_uniform_17_k4", choices_stream("uniform", [], 4)))
        for name, run in methods:
            rng = random.Random(seed)
            entries.append({"seed": seed, "method": name, "draws": DRAWS, "sha256": run(rng)})
    # A negative int seeds from its absolute value.
    negative = random.Random(-17)
    positive = random.Random(17)
    assert [negative.random() for _ in range(5)] == [positive.random() for _ in range(5)]
    # Version-2 seeding of str and bytes values (the curriculum epoch order seeds Random with a hex digest string).
    strings = []
    for seed in ("", "abc", "naïve ☃", hashlib.sha256(b"epoch").hexdigest(), "x" * 1000):
        for source in (seed, seed.encode("utf-8")):
            rng = random.Random(source)
            out = array("d")
            for _ in range(100_000):
                out.append(rng.random())
            strings.append({"seed": seed, "kind": "str" if isinstance(source, str) else "bytes", "draws": 100_000,
                            "sha256": digest_array(out)})
    return {"python": sys.version.split()[0], "string_seeds": strings, "layout": "little-endian stream of each call's output; see the Rust test",
            "draws_per_method": DRAWS, "seeds": [str(s) for s in SEEDS], "entries": entries}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("random", "recorded", "live"))
    parser.add_argument("--results", type=Path, help="evaluation/results directory of the checkout holding the retained evidence")
    args = parser.parse_args()
    GOLDEN.mkdir(parents=True, exist_ok=True)
    if args.command == "random":
        out = GOLDEN / "pyrandom.json"
        out.write_text(json.dumps(random_golden(), indent=1) + "\n", encoding="utf-8")
        print("wrote", out)
    else:
        from curriculum_golden_oracle import recorded_golden, live_golden  # noqa: PLC0415 - maintained oracle imports
        if args.results is None:
            parser.error("--results is required")
        result = recorded_golden(args.results) if args.command == "recorded" else live_golden(args.results)
        out = GOLDEN / f"{args.command}.json"
        out.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print("wrote", out)


if __name__ == "__main__":
    main()
