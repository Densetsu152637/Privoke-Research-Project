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


# --------------------------------------------------------------------------------------------------------------
# Oracle part: the maintained Python fuzzer is imported and run; recorded evidence is only read.
# --------------------------------------------------------------------------------------------------------------

FIXTURES = ROOT / "rust/crates/privoke-curriculum/tests/fixtures"
BC01 = "evaluation/results/iterative_fuzzer_20261011"
TAXONOMY_RELEASE = f"{BC01}/taxonomy-coverage/release/taxonomy-coverage-v1.json"
BENIGN_POOL = f"{BC01}/train-benign-coverage/pool-authored.json"
BENIGN_MANIFEST = f"{BC01}/train-benign-coverage/r1/benign-manifest.json"
BENIGN_PROOF = f"{BC01}/train-benign-coverage/r1/exclusion-proof.json"
PINNED_BENIGN_MANIFEST = "c817db3579b93f88ac2028d1f226884e3882ec9405b3bd2a868bdd5fa0a38ec9"
RECORDED_SOURCES = (
    "controlled_studies_20261014/adaptation-02/steps2-seed42-source.json",
    "controlled_studies_20261014/adaptation-02/steps64-seed42-source.json",
    "controlled_studies_20261014/adaptation-02/steps64-seed43-source.json",
    "controlled_studies_20261014/adaptation-02/steps64-seed44-source.json",
    "audience_v3_20261013/pilots/implementation-01/v3-full-01-source.json",
    "audience_v3_20261013/pilots/implementation-02/v3-heads-02-source.json",
)


def setup_oracle(generated: Path):
    import os
    os.environ.setdefault("V3_GENERATED", str(generated))
    sys.path.insert(0, str(ROOT / "services/pretrained-v3/src"))
    import common  # noqa: F401,PLC0415 - extends sys.path with the fuzzer, client runtime and shared sources


def canon(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def rows_digest(rows) -> str:
    """Digest of ordered examples: text, packed target, weight and metadata."""
    return sha(canon([[r.text, r.expected_packed_classification, float(r.weight), dict(r.metadata)] for r in rows]))


def partition_digest(training, heldout) -> dict:
    return {"training_sha256": rows_digest(training), "heldout_sha256": rows_digest(heldout),
            "training": len(training), "heldout": len(heldout)}


def recorded_golden(results: Path) -> dict:
    from prompt_generation import audience_coverage as audience  # noqa: PLC0415
    import audience_schedule  # noqa: PLC0415
    from privoke_model.v3_contract import POLICY  # noqa: PLC0415

    release = audience.load_release()
    sources = []
    for relative in RECORDED_SOURCES:
        data = json.loads((results / relative).read_text(encoding="utf-8"))
        batches = data["ordered_original_count"] // 32
        policy = dict(POLICY, steps=2, window_batches=1, epochs=2) if batches == 1 else dict(POLICY)
        _, _, live = audience_schedule.build(data["seed"], policy, release)
        # The live Python build must agree with the recorded source on everything except the Python source bytes.
        live["source_hashes"] = data["source_hashes"]
        sources.append({
            "file": relative, "seed": data["seed"], "window_batches": batches, "live_python_agrees": canon(live) == canon(data),
            "source_commitment": sha(canon(data)), "sidecar_sha256": data["sidecar_sha256"],
            "train_wire_sha256": data["train_wire_sha256"], "guard_wire_sha256": data["guard_wire_sha256"],
            "source_hashes": data["source_hashes"], "audience_manifest": data["inputs"]["audience_manifest"],
            "groups_sha256": sha(canon({"train": data["train_groups"], "guard": data["guard_groups"]})),
            "counts": {k: data[k] for k in ("train_occurrences", "original_occurrences", "unique_source_ids",
                                            "repeated_source_occurrences", "unique_normalized_texts",
                                            "repeated_text_occurrences", "guard_occurrences", "guard_unique_source_ids")},
        })
    return {"audience_sources": sources, "retained_audits": recorded_audits(results)}


def recorded_audits(results: Path) -> list:
    from prompt_generation import anchor_rehearsal as anchor, benign_coverage as benign, taxonomy_coverage as taxonomy  # noqa: PLC0415
    from training.trainer import iter_training_examples  # noqa: PLC0415
    from training.types import BatchTrainingConfig  # noqa: PLC0415

    base = results.parents[1]
    root = results / "iterative_fuzzer_20261011"
    dataset = taxonomy.load_dataset(base / TAXONOMY_RELEASE)
    manifest = anchor.load_snapshot(anchor.prepare_manifest(dataset), dataset)
    release = benign.load_release(base / BENIGN_POOL, base / BENIGN_MANIFEST, base / BENIGN_PROOF, dataset)
    seen, entries = set(), []
    for kind, folder in (("benign", "benign-audits"), ("rehearsal", "rehearsal-audits")):
        for path in sorted(root.glob(f"**/{folder}/*.json")):
            if path.name in seen:
                continue
            seen.add(path.name)
            record = json.loads(path.read_bytes())
            audit = record["audit"]
            seed = int(audit["sampling_seed"])
            config = BatchTrainingConfig(seed=seed)
            variant = "pinned"
            if kind == "rehearsal":
                training, guard = anchor.generate_partition(dataset, manifest, seed)
                expanded = list(iter_training_examples(training, (), config))
                live = anchor.audit_expanded(dataset, manifest, training, expanded, guard, config)
            else:
                use = release
                if audit["benign_manifest_sha256"] != PINNED_BENIGN_MANIFEST:
                    variant = audit["benign_manifest_sha256"][:8]
                    target = FIXTURES / f"benign-{variant}"
                    target.mkdir(parents=True, exist_ok=True)
                    for name, key in (("pool-authored.json", "pool_utf8"), ("benign-manifest.json", "manifest_utf8"),
                                      ("exclusion-proof.json", "proof_utf8")):
                        (target / name).write_bytes(record[key].encode("utf-8"))
                    use = benign.load_release(target / "pool-authored.json", target / "benign-manifest.json",
                                              target / "exclusion-proof.json", dataset)
                training, guard = benign.generate_partition(dataset, use, seed)
                expanded = list(iter_training_examples(training, (), config))
                live = benign.audit_expanded(dataset, use, training, expanded, guard, config)
            entries.append({"file": path.name, "strategy": audit["contextual_sampling_strategy"], "seed": seed, "variant": variant,
                            "audit_sha256": sha(canon(audit)), "live_python_agrees": live == audit, "keys": len(audit)})
    return sorted(entries, key=lambda item: (item["strategy"], item["seed"], item["file"]))


def live_golden(results: Path) -> dict:
    from prompt_generation import (anchor_rehearsal as anchor, audience_coverage as audience, benign_coverage as benign,  # noqa: PLC0415
                                   generator, taxonomy_coverage as taxonomy, privacy_heads_curriculum as heads,
                                   presence as presence_module)
    from training.trainer import iter_training_examples  # noqa: PLC0415
    from training.types import BatchTrainingConfig, BatchTrainingExample  # noqa: PLC0415
    from privoke_contracts.classification import Classification  # noqa: PLC0415
    import audience_schedule, fuzzer_training  # noqa: PLC0415,E401
    from privoke_model.v3_contract import POLICY  # noqa: PLC0415

    base = results.parents[1]
    out = {}
    # (a) the legacy random generator on the built-in dataset
    legacy = []
    for seed in (1, 7, 42, 1337, 20261017):
        for count in (5, 32, 100):
            legacy.append({"seed": seed, "count": count, "sha256": rows_digest(generator.generate_training_prompts(count, seed))})
        training, heldout = generator.generate_training_partition(32, 16, seed)
        legacy.append({"seed": seed, "partition": partition_digest(training, heldout)})
    out["generator_default"] = legacy

    # (b) taxonomy, anchor rehearsal and benign partitions on the pinned fixtures
    dataset = taxonomy.load_dataset(base / TAXONOMY_RELEASE)
    manifest = anchor.load_snapshot(anchor.prepare_manifest(dataset), dataset)
    release = benign.load_release(base / BENIGN_POOL, base / BENIGN_MANIFEST, base / BENIGN_PROOF, dataset)
    seeds = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 100, 1000, 20261017]
    taxonomy_entries = []
    for seed in seeds:
        training, guard = taxonomy.generate_partition(dataset, seed)
        taxonomy_entries.append({"seed": seed, **partition_digest(training, guard),
                                 "audit_sha256": sha(canon(taxonomy.audit_originals(dataset, training, guard)))})
    out["taxonomy_partitions"] = taxonomy_entries
    out["anchor_partitions"] = [{"seed": s, **partition_digest(*anchor.generate_partition(dataset, manifest, s))} for s in seeds]
    out["benign_partitions"] = [{"seed": s, **partition_digest(*benign.generate_partition(dataset, release, s))} for s in seeds]
    out["rehearsal_manifest_sha256"] = manifest.sha256
    out["benign_release_sha256"] = release.sha256
    out["taxonomy_dataset_sha256"] = dataset.sha256
    out["legacy_snapshot_commitment"] = benign.legacy_snapshot_commitment(dataset)

    # (c) AU3 partitions, expansions and schedules
    audience_release = audience.load_release()
    au3 = []
    for seed in (1, 2, 3, 42, 43, 44, 99, 2026):
        for count in (32, 64):
            training, guard = audience.generate_partition(audience_release, seed, count)
            audit = audience.audit_originals(audience_release, training, guard, seed)
            audit.pop("audience_implementation_sha256")
            config = BatchTrainingConfig(seed=seed)
            expanded = list(iter_training_examples(training, (), config))
            expanded_audit = audience.audit_expanded(audience_release, training, expanded, guard, config)
            expanded_audit.pop("audience_implementation_sha256")
            au3.append({"seed": seed, "count": count, **partition_digest(training, guard), "audit_sha256": sha(canon(audit)),
                        "expanded_audit_sha256": sha(canon(expanded_audit))})
    out["audience_partitions"] = au3
    out["audience_release"] = {"sha256": audience_release.sha256, "train_rows": len(audience_release.train),
                               "rehearsal_rows": len(audience_release.rehearsal),
                               "train_sha256": sha(b"".join(audience.canonical(r) for r in audience_release.train)),
                               "guard_sha256": sha(b"".join(audience.canonical(r) for r in audience_release.guard))}
    schedules = []
    pilot = dict(POLICY, steps=2, window_batches=1, epochs=2)
    for seed in (7, 42, 99, 2026, 4242):
        for label, policy in (("pilot", pilot), ("steps64", dict(POLICY))):
            _, _, source = audience_schedule.build(seed, policy, audience_release)
            schedules.append(schedule_entry("au3", seed, label, source))
    # (d) BC01 common stream on the pinned inputs
    for seed in (42, 3090, 2026):
        for label, policy in (("pilot", pilot), ("steps64", dict(POLICY))):
            _, _, source = fuzzer_training.schedule(seed, policy, input_root=base)
            schedules.append(schedule_entry("bc01", seed, label, source))
    out["v3_schedules"] = schedules

    # (e) PH3 fact-contrast pools from the committed scenario resource
    resource = json.loads((ROOT / "evaluation/datasets/privacy-heads-v3-scenarios-v1.json").read_text(encoding="utf-8"))
    pools = heads.build(resource)
    out["privacy_heads"] = {split: {"rows": len(rows), "sha256": sha(b"".join(heads.canonical(r) for r in rows))}
                            for split, rows in pools.items()}
    out["privacy_heads_components"] = heads.audit_components(resource)

    # (f) the seeded augmentation stream
    examples = [BatchTrainingExample(f"Please note that John Doe lives at number {i}.", Classification(28), 1.0 + i / 10, {"i": str(i)})
                for i in range(24)]
    augmentation = []
    for seed in (1, 42, 7):
        for per in (0, 1, 3):
            config = BatchTrainingConfig(seed=seed, transformations_per_example=per)
            augmentation.append({"seed": seed, "transformations": per,
                                 "sha256": rows_digest(list(iter_training_examples(examples, examples[:4], config)))})
    out["augmentation"] = augmentation

    # (g) synthetic fixtures: role-quota dataset, presence dataset and a curriculum, with their Python goldens
    FIXTURES.mkdir(parents=True, exist_ok=True)
    out["role_quota"] = role_quota_golden(generator)
    out["presence"] = presence_golden(presence_module)
    out["curriculum"] = curriculum_golden()
    return out


def schedule_entry(sampler, seed, label, source):
    return {"sampler": sampler, "seed": seed, "policy": label, "source_hashes": source["source_hashes"],
            "source_commitment": sha(canon(source)), "sidecar_sha256": source["sidecar_sha256"],
            "train_wire_sha256": source["train_wire_sha256"], "guard_wire_sha256": source["guard_wire_sha256"]}


def role_quota_golden(generator):
    rows = []

    def add(group, variant, role, sensitive):
        classification = {"sensitivity": "S2" if sensitive else "S0", "visibility": "P2" if variant else "PU",
                          "categories": ["FINANCIAL"] if sensitive else []}
        rows.append({"template": f"Record {role[:4]} group {group} variant {variant} mentions {{city}} and {{relative}}.",
                     "classification": classification, "metadata": {"training_role": role, "group_id": f"{role[:4]}-{group:03d}"}})

    for group in range(48):
        for variant in range(2):
            add(group, variant, "authored_contrastive_context", True)
            add(group + 100, variant, "authored_contrastive_context", False)
    for group in range(100):
        add(group, 0, "public_annotation_negative", False)
        add(group, 0, "existing_bootstrap_replay", group % 2 == 1)
    path = FIXTURES / "role-quota-synthetic.json"
    path.write_text(json.dumps({"prompts": rows}, indent=0) + "\n", encoding="utf-8")
    result = []
    for seed in (1, 2, 3):
        training, heldout = generator.generate_training_partition(256, 16, seed, path, sampling_strategy="contextual_role_quota_v1")
        result.append({"seed": seed, **partition_digest(training, heldout),
                       "audit_sha256": sha(canon(generator.contextual_sampling_audit(training)))})
    return {"dataset": "role-quota-synthetic.json", "partitions": result}


def presence_golden(module):
    rows = []
    for index in range(120):
        sensitive = index % 3 == 0
        rows.append({"id": f"p{index}",
                     "text": f"Presence sample {index} {'discloses a diagnosis' if sensitive else 'asks for a recipe'} number {index * 7}",
                     "sensitive": sensitive, "group_id": f"g{index // 2}"})
    path = FIXTURES / "presence-synthetic.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    result = []
    for seed in (1, 2, 3, 42):
        for count, heldout in ((8, 4), (30, 10)):
            selected, held = module.generate_presence_training_partition(count, heldout, seed, path)
            result.append({"seed": seed, "count": count, "heldout": heldout,
                           "selected": [r.example_id for r in selected], "held": [r.example_id for r in held]})
    return {"dataset": "presence-synthetic.jsonl", "partitions": result}


def curriculum_golden():
    import tempfile
    from privoke.v1 import parameters_pb2  # noqa: PLC0415
    from prompt_generation.curriculum import load_curriculum, reserve_batch, request_fingerprint  # noqa: PLC0415

    folder = FIXTURES / "curriculum"
    folder.mkdir(parents=True, exist_ok=True)
    splits = {}
    for split, count in (("train", 192), ("replay", 64), ("heldout", 16)):
        rows = []
        for index in range(count):
            role = ("grammar", "teacher", "evolved")[(index // 2) % 3] if split == "train" else split
            rows.append({"id": f"{split}-{index}", "text": f"{split} family {index} unique fact",
                         "classification": {"sensitivity": "S1" if index % 2 else "S0", "visibility": "P2",
                                            "categories": ["IDENTITY"] if index % 2 else []},
                         "metadata": {"group_id": f"{split}-family-{index // 2}", "parent_id": "", "generator": "fixture",
                                      "label_status": "assistant_provisional", "curriculum_role": role}})
        payload = "".join(json.dumps(row) + "\n" for row in rows).encode()
        (folder / f"{split}.jsonl").write_bytes(payload)
        splits[split] = {"path": f"{split}.jsonl", "sha256": sha(payload)}
    manifest = {"schema_version": 1, "curriculum_id": "fixture", "splits": splits}
    (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    curriculum = load_curriculum(str(folder / "manifest.json"))
    plans = [
        ("round1", {}), ("round2", {}), ("round3", {"curriculum_stage": "teacher"}),
        ("seeded1", {"curriculum_sampler_policy": "seeded_family_v1", "curriculum_sampler_seed": "7"}),
        ("seeded2", {"curriculum_sampler_policy": "seeded_family_v1", "curriculum_sampler_seed": "7"}),
        ("seeded3", {"curriculum_sampler_policy": "seeded_family_v1", "curriculum_sampler_seed": "99"}),
        ("hard1", {"curriculum_hard_ids": json.dumps(["train-0", "train-9"])}),
    ]
    calls = []
    with tempfile.TemporaryDirectory() as directory:
        state = str(Path(directory) / "state.sqlite3")
        for identity, metadata in plans:
            for count in (32, 64):
                request = parameters_pb2.FuzzerTrainingRequest(request_id=f"{identity}-{count}", source_id="study",
                                                               model_id="privoke-balanced", prompt_count=32, seed=1337,
                                                               metadata=metadata)
                batch = reserve_batch(curriculum, state, request, count)
                calls.append({"request_id": f"{identity}-{count}", "metadata": metadata, "count": count,
                              "fingerprint": request_fingerprint(request, curriculum, {"count": count, "replay_fraction": 0.25}),
                              "examples_sha256": rows_digest(batch.examples), "replay_sha256": rows_digest(batch.replay),
                              "heldout_sha256": rows_digest(batch.heldout), "audit": batch.audit})
        # A retry of the first request must reuse its reservation.
        request = parameters_pb2.FuzzerTrainingRequest(request_id="round1-32", source_id="study", model_id="privoke-balanced",
                                                       prompt_count=32, seed=1337)
        retry = reserve_batch(curriculum, state, request, 32)
        calls.append({"request_id": "round1-32", "metadata": {}, "count": 32, "retry": True, "examples_sha256": rows_digest(retry.examples),
                      "replay_sha256": rows_digest(retry.replay), "heldout_sha256": rows_digest(retry.heldout), "audit": retry.audit,
                      "fingerprint": request_fingerprint(request, curriculum, {"count": 32, "replay_fraction": 0.25})})
    return {"manifest": "curriculum/manifest.json", "manifest_sha256": curriculum.manifest_sha256, "calls": calls}


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
        if args.results is None:
            parser.error("--results is required")
        setup_oracle(args.results.parents[1] / "extension/client-runtime/generated")
        result = recorded_golden(args.results) if args.command == "recorded" else live_golden(args.results)
        out = GOLDEN / f"{args.command}.json"
        out.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print("wrote", out)


if __name__ == "__main__":
    main()
