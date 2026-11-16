"""Build the fresh, never-scored evaluation sets F2 (natural prompts), F3 (SPY) and the dev-span file.

F1 (the group-disjoint PIIMB sample) is built by ``fresh_set_plan.py draw``; this module covers the rest of the
registration in ``docs/research/preregistration-detector-v2-20261024.md``:

  f2          Draw natural prompts (oasst2 initial prompts, Dolly instructions, WildChat first user turns).
  adjudication  Write blinded adjudication packets, a coordinator key and a seeded audit order for F2.
  f3          Rebuild SPY prompt-style positives with a seeded Faker fill and character spans.
  dev-spans   Re-join the locked DEVELOPMENT partition (never final) with PIIMB by id to recover entity spans.

Everything here reads local files only (no network).  Downloaded files are treated as data; nothing shipped
inside a dataset (including ``SPY.py``) is executed.  Ranking is by ``sha256(seed:key)`` so results do not depend
on file order.  Row texts are never printed.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import random
import sys
import unicodedata
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fresh_set_plan import ENGLISH, _parse_entities, normalise_text_and_spans  # noqa: E402

F2_SEED = 9102026
F3_SEED = 10102026
F2_QUOTAS = {"oasst2": 2000, "wildchat": 2500, "dolly": 1500}
SPY_ENTITY_TYPES = ("NAME", "EMAIL", "PHONE_NUM", "ADDRESS", "URL", "USERNAME", "ID_NUM")


def rank(seed: int, key: str) -> str:
    return hashlib.sha256(f"{seed}:{key}".encode()).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def text_key(text: str) -> str:
    return hashlib.blake2b(text.encode("utf-8"), digest_size=16).hexdigest()


def normalise_prompt(raw: object) -> str:
    return unicodedata.normalize("NFC", raw.strip()) if isinstance(raw, str) else ""


def write_jsonl(path: Path, records: list[dict]) -> str:
    content = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records)
    path.write_text(content, encoding="utf-8")
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def refuse_existing(path: Path) -> None:
    if path.exists():
        raise SystemExit(f"Refusing to overwrite {path}")


# ------------------------------------------------------------------- F2

def piimb_length_cap(sentences: Path, quantile: float = 0.99) -> tuple[int, int]:
    """Length (characters, stripped) at the given quantile of all English PIIMB sentences."""
    lengths: list[int] = []
    with sentences.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            if str(row.get("language", "")).strip().lower().replace("_", "-") in ENGLISH:
                lengths.append(len(str(row.get("text", "")).strip()))
    lengths.sort()
    return lengths[max(0, -(-int(len(lengths) * quantile * 1000) // 1000) - 1)], len(lengths)


def read_oasst2(path: Path):
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            pii = ((row.get("labels") or {}).get("pii") or {})
            yield {"source": "oasst2", "source_id": str(row["message_id"]), "group_id": f"oasst2:{row.get('message_tree_id')}",
                   "raw": row.get("text"),
                   "eligible": row.get("lang") == "en" and row.get("role") == "prompter" and not row.get("deleted")
                   and row.get("parent_id") is None,
                   "hint": {"oasst_pii_value": pii.get("value"), "oasst_pii_count": pii.get("count")}}


def read_dolly(path: Path):
    with path.open(encoding="utf-8") as handle:
        for index, line in enumerate(handle):
            row = json.loads(line)
            yield {"source": "dolly", "source_id": str(index), "group_id": f"dolly:{index}", "raw": row.get("instruction"),
                   "eligible": True, "hint": {"dolly_category": row.get("category")}}


def read_wildchat(path: Path):
    import pyarrow.parquet as pq
    parquet = pq.ParquetFile(path)
    for batch in parquet.iter_batches(batch_size=512, columns=["conversation_hash", "conversation", "language"]):
        for row in batch.to_pylist():
            turns = row.get("conversation") or []
            first = turns[0] if turns else {}
            yield {"source": "wildchat", "source_id": str(row["conversation_hash"]),
                   "group_id": f"wildchat:{row['conversation_hash']}", "raw": first.get("content"),
                   "eligible": row.get("language") == "English" and first.get("role") == "user"
                   and str(first.get("language")) == "English" and not first.get("toxic"),
                   "hint": {"wildchat_redacted": bool(first.get("redacted"))}}


def cmd_f2(args: argparse.Namespace) -> int:
    out = Path(args.output)
    refuse_existing(out)
    sentences = Path(args.piimb_sentences)
    cap, n_piimb_english = piimb_length_cap(sentences)
    readers = {"oasst2": lambda: read_oasst2(Path(args.oasst2)), "dolly": lambda: read_dolly(Path(args.dolly)),
               "wildchat": lambda: read_wildchat(Path(args.wildchat))}
    funnel: dict[str, Counter] = {name: Counter() for name in ('oasst2', 'dolly', 'wildchat')}
    best: dict[str, dict] = {}          # text key -> lowest-rank record
    for name, reader in readers.items():
        counts = funnel[name]
        for item in reader():
            counts["rows"] += 1
            if not item["eligible"]:
                counts["not_english_or_not_initial_user_prompt"] += 1
                continue
            text = normalise_prompt(item["raw"])
            if not text:
                counts["empty"] += 1
                continue
            counts["eligible_language"] += 1
            if len(text) > cap:
                counts["over_length_cap"] += 1
                continue
            counts["within_cap"] += 1
            record = {"id": f"f2:{name}:{item['source_id']}", "text": text, "source": name,
                      "source_id": item["source_id"], "group_id": item["group_id"], "length": len(text),
                      "_hint": item["hint"], "_key": text_key(text)}
            record["_rank"] = rank(args.seed, record["id"])
            previous = best.get(record["_key"])
            if previous is None or record["_rank"] < previous["_rank"]:
                if previous is not None:
                    funnel[previous["source"]]["duplicate_removed"] += 1
                    funnel[previous["source"]]["within_cap_after_dedupe"] -= 1
                best[record["_key"]] = record
                counts["within_cap_after_dedupe"] += 1
            else:
                counts["duplicate_removed"] += 1
    chosen: list[dict] = []
    for name, quota in F2_QUOTAS.items():
        pool = sorted((r for r in best.values() if r["source"] == name), key=lambda r: r["_rank"])
        if len(pool) < quota:
            raise SystemExit(f"{name}: only {len(pool)} eligible prompts, {quota} requested")
        chosen.extend(pool[:quota])
    chosen.sort(key=lambda r: rank(args.seed, "o:" + r["id"]))
    out.mkdir(parents=True)
    hints = [{"id": r["id"], **r["_hint"]} for r in chosen]
    public = [{k: v for k, v in r.items() if not k.startswith("_")} | {"expected_has_pii": None,
              "label_status": "unlabelled - human adjudication pending", "protocol_partition": "f2_natural_prompts"}
              for r in chosen]
    f2_sha = write_jsonl(out / "f2_natural_prompts.jsonl", public)
    hints_sha = write_jsonl(out / "f2_dataset_native_hints.jsonl", hints)
    lengths = sorted(r["length"] for r in chosen)
    manifest = {
        "set": "F2", "label_status": "UNLABELLED - blind human adjudication pending (docs/research/fresh-evaluation-sources-20261024.md 4.1)",
        "seed": args.seed, "quotas": F2_QUOTAS, "length_cap_chars": cap,
        "length_cap_rule": "99th percentile of stripped length over all English PIIMB sentences "
                           f"(n={n_piimb_english}); prompts longer than the cap are excluded, not truncated",
        "inputs": {k: {"path": str(getattr(args, k if k != "piimb_sentences" else "piimb_sentences")), }
                   for k in ("oasst2", "dolly", "wildchat")},
        "input_sha256": {k: file_sha256(Path(getattr(args, k))) for k in ("oasst2", "dolly", "wildchat", "piimb_sentences")},
        "funnel": {k: dict(v) for k, v in funnel.items()},
        "selected": {"rows": len(chosen), "by_source": dict(Counter(r["source"] for r in chosen)),
                     "length_median": lengths[len(lengths) // 2], "length_p90": lengths[int(len(lengths) * 0.9)],
                     "length_max": lengths[-1], "groups": len({r["group_id"] for r in chosen})},
        "outputs_sha256": {"f2_natural_prompts.jsonl": f2_sha, "f2_dataset_native_hints.jsonl": hints_sha},
        "notes": ["Dataset-native flags (oasst pii label, WildChat redacted) are stored in a separate hints file and are "
                  "stratification hints only, never labels.",
                  "WildChat first user turns come from shard train-00000-of-00014 only."],
        "script_sha256": file_sha256(Path(__file__)),
    }
    (out / "manifest_f2.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({k: manifest[k] for k in ("length_cap_chars", "funnel", "selected", "outputs_sha256")}, indent=1))
    return 0


def cmd_adjudication(args: argparse.Namespace) -> int:
    source = Path(args.f2)
    out = Path(args.output)
    refuse_existing(out)
    rows = [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines() if line.strip()]
    order = sorted(rows, key=lambda r: rank(args.seed, "adj:" + r["id"]))
    opaque = {r["id"]: f"a{index:05d}" for index, r in enumerate(order, start=1)}
    audit_order = [opaque[r["id"]] for r in sorted(rows, key=lambda r: rank(args.seed, "audit:" + r["id"]))]
    (out / "packets").mkdir(parents=True)
    (out / "coordinator").mkdir()
    packets = []
    for number, start in enumerate(range(0, len(order), args.packet_size), start=1):
        block = order[start:start + args.packet_size]
        name = f"packet-{number:03d}.jsonl"
        sha = write_jsonl(out / "packets" / name,
                          [{"item": opaque[r["id"]], "text": r["text"]} for r in block])
        packets.append({"packet": name, "items": len(block), "first": opaque[block[0]["id"]],
                        "last": opaque[block[-1]["id"]], "sha256": sha})
    key = {"seed": args.seed, "key": {v: k for k, v in opaque.items()}, "audit_order": audit_order}
    (out / "coordinator" / "adjudication_key.json").write_text(json.dumps(key), encoding="utf-8")
    manifest = {"set": "F2", "purpose": "blinded rating packets; items carry only an opaque id and the prompt text",
                "packets": packets, "packet_size": args.packet_size, "items": len(order),
                "coordinator_key_sha256": file_sha256(out / "coordinator" / "adjudication_key.json"),
                "audit_rule": "audit sample = first 400 items of coordinator audit_order that no frozen configuration flags",
                "f2_sha256": file_sha256(source), "script_sha256": file_sha256(Path(__file__))}
    (out / "coordinator" / "packets_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"packets": len(packets), "items": len(order),
                      "key_sha256": manifest["coordinator_key_sha256"]}))
    return 0


# ------------------------------------------------------------------- F3

def spy_value_makers(fake):
    return {
        "EMAIL": [fake.ascii_email, fake.ascii_free_email],
        "NAME": [fake.name],
        "URL": [lambda: fake.uri(deep=1), lambda: fake.uri(deep=2)],
        "PHONE_NUM": [fake.phone_number],
        "ID_NUM": [fake.ripe_id, fake.msisdn, fake.ssn, fake.sbn9, fake.isbn10, fake.isbn13, fake.credit_card_number,
                   fake.aba, fake.bban, fake.iban],
        "ADDRESS": [fake.street_address],
        "USERNAME": [fake.user_name],
    }


def fill_spy_row(row: dict, row_key: str, seed: int):
    """Replace B- placeholders by Faker values (one value per entity type per row, as in SPY.py)."""
    from faker import Faker
    fake = Faker()
    fake.seed_instance(int(rank(seed, row_key)[:15], 16))
    chooser = random.Random(int(rank(seed, "choice:" + row_key)[:15], 16))
    makers = spy_value_makers(fake)
    values: dict[str, str] = {}
    pieces: list[str] = []
    spans: list[tuple[int, int, str]] = []
    position = 0
    for token, tag, trailing in zip(row["tokens"], row["ent_tags"], row["trailing_whitespaces"]):
        if tag.startswith("B-"):
            entity = tag[2:]
            if entity not in makers:
                raise ValueError(f"unknown SPY entity type {entity}")
            if entity not in values:
                values[entity] = " ".join(chooser_pick(chooser, makers[entity])().split())
            token = values[entity]
            spans.append((position, position + len(token), entity))
        elif tag != "O":
            raise ValueError(f"unexpected tag {tag}")
        pieces.append(token)
        position += len(token)
        if trailing:
            pieces.append(" ")
            position += 1
    text = "".join(pieces)
    lead = len(text) - len(text.lstrip())
    stripped = text.strip()
    spans = [(max(0, s - lead), min(len(stripped), e - lead), l) for s, e, l in spans]
    assert all(stripped[s:e] and stripped[s:e] == stripped[s:e].strip() for s, e, _ in spans)
    return stripped, spans


def chooser_pick(chooser: random.Random, funcs: list):
    return funcs[chooser.randrange(len(funcs))]


def cmd_f3(args: argparse.Namespace) -> int:
    from importlib.metadata import version as package_version
    faker_version = package_version("faker")
    out = Path(args.output)
    refuse_existing(out)
    domains = {"legal_questions": Path(args.legal), "medical_consultations": Path(args.medical)}
    chosen: list[dict] = []
    stats: dict[str, dict] = {}
    for domain, path in domains.items():
        candidates = []
        total = 0
        with path.open(encoding="utf-8") as handle:
            for index, line in enumerate(handle):
                total += 1
                candidates.append((rank(args.seed, f"{domain}:{index}"), index, line))
        candidates.sort()
        taken = 0
        malformed = 0
        for _, index, line in candidates:
            if taken >= args.per_domain:
                break
            row = json.loads(line)
            try:
                text, spans = fill_spy_row(row, f"{domain}:{index}", args.seed)
            except (ValueError, AssertionError):
                malformed += 1
                continue
            if not spans:
                malformed += 1
                continue
            row_id = f"spy:{domain}:{index}"
            chosen.append({"id": row_id, "group_id": row_id, "text": text, "expected_has_pii": True,
                           "expected_categories": sorted({label for _, _, label in spans}),
                           "entities": [{"start": s, "end": e, "label": l} for s, e, l in spans],
                           "source_dataset": "mks-logic/SPY", "domain": domain, "language": "en",
                           "protocol_partition": "f3_spy"})
            taken += 1
        stats[domain] = {"rows_in_file": total, "selected": taken, "malformed_skipped": malformed}
    chosen.sort(key=lambda r: rank(args.seed, "o:" + r["id"]))
    out.mkdir(parents=True)
    f3_sha = write_jsonl(out / "f3_spy.jsonl", chosen)
    lengths = sorted(len(r["text"]) for r in chosen)
    by_label = Counter(e["label"] for r in chosen for e in r["entities"])
    manifest = {
        "set": "F3", "seed": args.seed, "per_domain": args.per_domain, "faker_version": faker_version,
        "fill": "reimplemented from reading SPY.py (not executed): one Faker value per entity type per row, value function "
                "chosen per row from the SPY.py function lists by a seeded RNG; Faker instance seeded per row from "
                "sha256(seed:domain:index). SPY.py itself fills with an unseeded random.shuffle, so exact SPY values are not reproduced.",
        "input_sha256": {"legal": file_sha256(Path(args.legal)), "medical": file_sha256(Path(args.medical))},
        "domains": stats,
        "selected": {"rows": len(chosen), "entity_count": sum(by_label.values()), "entities_by_label": dict(by_label),
                     "length_median": lengths[len(lengths) // 2], "length_p90": lengths[int(len(lengths) * 0.9)],
                     "length_max": lengths[-1]},
        "label_basis": "SPY BIO tags converted to character spans; every row contains at least one entity (no clean rows)",
        "output_sha256": f3_sha, "script_sha256": file_sha256(Path(__file__)),
    }
    (out / "manifest_f3.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest["selected"] | {"domains": stats, "faker": faker_version}, indent=1))
    return 0


# -------------------------------------------------------------- dev spans

def cmd_dev_spans(args: argparse.Namespace) -> int:
    dev_path = Path(args.development)
    if dev_path.name != "development.jsonl":
        raise SystemExit("dev-spans accepts only development.jsonl (final.jsonl is held out)")
    out = Path(args.output)
    refuse_existing(out)
    dev = [json.loads(line) for line in dev_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    wanted = {row["id"][len("piimb:"):]: row for row in dev}
    found: dict[str, list[dict]] = {}
    with Path(args.sentences).open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            raw = json.loads(line)
            uid = str(raw.get("uid"))
            if uid in wanted:
                found.setdefault(uid, []).append(raw)
    records, stats = [], Counter()
    for uid, row in wanted.items():
        # uids are not unique in the PIIMB file: pick the row whose normalised text equals the locked text.
        matches = []
        for raw in found.get(uid, []):
            text, spans = normalise_text_and_spans(raw["text"], _parse_entities(raw.get("entities"), len(raw["text"])))
            if text == row["text"]:
                matches.append((text, spans))
        if len(found.get(uid, [])) > 1:
            stats["uid_with_multiple_piimb_rows"] += 1
        if not found.get(uid):
            stats["not_found_in_piimb"] += 1
            continue
        if not matches:
            stats["text_mismatch"] += 1
            continue
        if len({json.dumps(m[1]) for m in matches}) > 1:
            stats["ambiguous_identical_text_different_spans"] += 1
            continue
        text, spans = matches[0]
        if bool(spans) != bool(row["expected_has_pii"]):
            stats["label_mismatch"] += 1
            continue
        stats["joined"] += 1
        records.append({"id": row["id"], "group_id": row["group_id"], "text": text,
                        "expected_has_pii": row["expected_has_pii"],
                        "expected_categories": row["expected_categories"],
                        "entities": [{"start": s, "end": e, "label": l} for s, e, l in spans],
                        "source_dataset": row.get("source_dataset"), "protocol_partition": "development_spans",
                        "note": "development partition only; for span-harness development, NOT held out"})
    out.parent.mkdir(parents=True, exist_ok=True)
    sha = write_jsonl(out, records)
    summary = {"development_rows": len(dev), **dict(stats), "output_sha256": sha,
               "development_sha256": file_sha256(dev_path), "sentences_sha256": file_sha256(Path(args.sentences)),
               "script_sha256": file_sha256(Path(__file__))}
    out.with_suffix(".manifest.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=1))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("f2")
    p.add_argument("--oasst2", required=True)
    p.add_argument("--dolly", required=True)
    p.add_argument("--wildchat", required=True)
    p.add_argument("--piimb-sentences", required=True)
    p.add_argument("--seed", type=int, default=F2_SEED)
    p.add_argument("--output", required=True)
    p.set_defaults(func=cmd_f2)
    a = sub.add_parser("adjudication")
    a.add_argument("--f2", required=True)
    a.add_argument("--seed", type=int, default=F2_SEED)
    a.add_argument("--packet-size", type=int, default=100)
    a.add_argument("--output", required=True)
    a.set_defaults(func=cmd_adjudication)
    f = sub.add_parser("f3")
    f.add_argument("--legal", required=True)
    f.add_argument("--medical", required=True)
    f.add_argument("--seed", type=int, default=F3_SEED)
    f.add_argument("--per-domain", type=int, default=1000)
    f.add_argument("--output", required=True)
    f.set_defaults(func=cmd_f3)
    d = sub.add_parser("dev-spans")
    d.add_argument("--development", required=True)
    d.add_argument("--sentences", required=True)
    d.add_argument("--output", required=True)
    d.set_defaults(func=cmd_dev_spans)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
