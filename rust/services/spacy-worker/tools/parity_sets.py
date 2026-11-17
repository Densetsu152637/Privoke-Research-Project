"""The recorded NER sets, extracted once into an ignored work directory that both sides of the parity gate read.

Sources are read-only files in the main checkout (they are ignored by Git there). Each is checked against the SHA-256 the
records give, where they give one, and the observed hash is recorded in sets.json otherwise. Texts are written as one JSON
string per line, so the bundle and the reference environment see the same documents byte for byte.

Recorded NER sets covered, with the record that names them:

  development   evaluation/results/locked-public/development.jsonl, 502 rows (docs/experiments/ner-postfilter-20261024.md;
                the dev-TUNE and dev-CHECK halves are subsets). final.jsonl is a locked partition and is not opened.
  personalized  evaluation/datasets/privoke_personalized_synthetic.jsonl, 2000 rows (ner-postfilter, ner-pattern-detector)
  openai        evaluation/datasets/privoke_openai_synthetic.jsonl, 1000 rows (ner-postfilter, ner-pattern-detector)
  piimb         evaluation/results/external-data/piimb/<rev>/test_sentences.jsonl, 150022 rows: the pool that F1, F3 and F4
                of paper/research/detector-precision-heldout-20261025.md were drawn from (their exact row lists are not stored)
  dolly15k      the instructions and contexts of databricks-dolly-15k, the source of the F2 sample
  oasst2        the prompter messages of oasst2, the source of the F2 sample

Not covered: the WildChat part of F2 (a 230 MB parquet shard; no parquet reader exists in the bundle or the reference
environment, and the sampled rows are not stored).
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import random
from pathlib import Path

SMOKE_SEED = 20261116
SMOKE_QUOTA = {"development": 40, "personalized": 30, "openai": 30, "piimb": 40, "dolly15k": 20}

DEV_SHA = "65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095"  # evaluation/results/locked-public/manifest.json
PIIMB_SHA = "5ff46f3a80316318794f94596fa374060d70f2f32a85909f958cbabc70bae41f"  # piimb provenance.json


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stress_documents() -> list[str]:
    """The synthetic stress set: URLs, emoji, CJK, zero-width characters, casing extremes and odd whitespace."""
    zwsp, zwnj, zwj, bom, lrm, rlm = "\u200b", "\u200c", "\u200d", "\ufeff", "\u200e", "\u200f"
    return [
        "Visit https://www.example.com/path/to/page?x=1&y=two#frag or http://192.168.0.1:8080/admin now.",
        "Mail alice.smith+tag@mail.example.org, cc: bob@example.co.uk; see ftp://files.example.net/a_b-c.txt",
        "www.openai.com and example.com/a(b)c and https://t.co/AbC123 (short link).",
        "Alice met Bob in Paris \U0001F600 on Monday \U0001F1EB\U0001F1F7 and flew to New York \u2708\ufe0f.",
        "Family \U0001F468\u200d\U0001F469\u200d\U0001F467\u200d\U0001F466 at Disneyland \U0001F3F3\ufe0f\u200d\U0001F308 with Dr. Jane Doe \U0001F44D\U0001F3FD.",
        "\U0001F600\U0001F601\U0001F602\U0001F923\U0001F60A\U0001F60D",
        "\u6211\u53eb\u5f20\u4f1f\uff0c\u4f4f\u5728\u5317\u4eac\u5e02\u6d77\u6dc0\u533a\u3002\u6211\u7684\u7535\u8bdd\u662f13800138000\u3002",
        "\u79c1\u306e\u540d\u524d\u306f\u7530\u4e2d\u592a\u90ce\u3067\u3059\u3002\u6771\u4eac\u90fd\u6e0b\u8c37\u533a\u306b\u4f4f\u3093\u3067\u3044\u307e\u3059\u3002",
        "\uc800\ub294 \uae40\ubbfc\uc218\uc785\ub2c8\ub2e4. \uc11c\uc6b8\uc5d0 \uc0b4\uace0 \uc788\uc5b4\uc694.",
        "Mixed: Tom visited \u6771\u4eac and met \u5f20\u4f1f at Google in London \U0001F30D.",
        "\U00020000\U00020001 is outside the BMP; so is \U0001D400\U0001D401 (math bold) near Berlin.",
        f"Jo{zwsp}hn Sm{zwnj}ith l{zwj}ives in Lon{zwsp}don.",
        f"{bom}Maria{lrm} Garcia{rlm} works at Micro{zwsp}soft in Seattle.",
        f"{zwsp}{zwsp}{zwsp}",
        f"a{zwsp}b{zwsp}c{zwsp}d{zwsp}e",
        "Cafe\u0301 Mu\u0308nchen and Jose\u0301 A\u0301lvarez live near Zu\u0308rich; Re\u0301ne\u0301e too.",
        "e\u0301\u0301\u0301\u0301 x\u0308\u0308\u0308 combining stack",
        "ALICE SMITH LIVES IN PARIS AND WORKS AT GOOGLE. HER PHONE IS 555-0100.",
        "alice smith lives in paris and works at google. her phone is 555-0100.",
        "MIXED Case sENTence WiTh RaNdOm CaPs In New YORK",
        "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG NEAR BARCELONA",
        "the quick brown fox jumps over the lazy dog near barcelona",
        "My name is Priya Raman. I work at Infosys in Bengaluru. Call +91 98765 43210.",
        "Dear Dr. Okafor,\n\nI am writing from Lagos.\n\nSincerely,\nAda Lovelace\n",
        "Name:\tJohn Smith\nCity:\tChicago\nState:\tIL\n\n\n\nZip:\t60601",
        "   leading and trailing spaces   ",
        "tabs\tand\r\nwindows\r\nnewlines\x0b\x0c done",
        "a" * 5000,
        "word " * 800,
        "Hello, \u0645\u0631\u062d\u0628\u0627 \u0628\u0643 \u0641\u064a \u0627\u0644\u0642\u0627\u0647\u0631\u0629 \u064a\u0627 \u0645\u062d\u0645\u062f.",
        "\u0417\u0434\u0440\u0430\u0432\u0441\u0442\u0432\u0443\u0439\u0442\u0435, \u043c\u0435\u043d\u044f \u0437\u043e\u0432\u0443\u0442 \u0418\u0432\u0430\u043d \u0418\u0432\u0430\u043d\u043e\u0432 \u0438\u0437 \u041c\u043e\u0441\u043a\u0432\u044b.",
        "!!! ??? ... --- ((( ))) [[[ ]]] {{{ }}} <<< >>> ### $$$ %%% ^^^ &&& *** +++",
        "1234567890 3.14159 1,000,000 $5.99 \u20ac20 \u00a350 \u00a5100 50% 1/2 3rd 22nd",
        "x" * 20,
        "ctrl\x01chars\x02inside\x1f text and a NUL \x00 byte",
        "O'Brien, D'Angelo and McDonald's; Jean-Luc Picard of Saint-Denis; \u00d1u\u00f1ez in Sa\u0303o Paulo",
        "I live at 221B Baker Street, London NW1 6XE, near the British Museum.",
        "Born 12/03/1985 in Springfield, Illinois. SSN 078-05-1120. IBAN GB82 WEST 1234 5698 7654 32.",
        "\U0001F1FA\U0001F1F8 \U0001F1EC\U0001F1E7 \U0001F1EF\U0001F1F5 flags next to USA, UK and Japan",
        "\u3000\u3000\u5168\u89d2\u7a7a\u683c\u3068\u534a\u89d2\u30ab\u30bf\u30ab\u30ca\uff76\uff80\uff76\uff85 mixed width \uff21\uff22\uff23",
    ]


def read_jsonl(path: Path, field: str) -> list[str]:
    return [json.loads(line)[field] for line in open(path, encoding="utf-8") if line.strip()]


def extract(root: Path) -> tuple[dict[str, list[str]], dict[str, dict]]:
    sets: dict[str, list[str]] = {}
    info: dict[str, dict] = {}

    def add(name: str, path: Path, texts: list[str], expected: str | None, rule: str) -> None:
        observed = sha256_file(path)
        if expected is not None and observed != expected:
            raise SystemExit(f"{name}: {path} has SHA-256 {observed}, the record says {expected}")
        sets[name] = texts
        info[name] = {
            "source": str(path.relative_to(root)).replace("\\", "/"),
            "source_sha256": observed,
            "source_sha256_basis": "recorded" if expected else f"observed at gate time (the records give no hash)",
            "rule": rule,
        }

    add("development", root / "evaluation/results/locked-public/development.jsonl",
        read_jsonl(root / "evaluation/results/locked-public/development.jsonl", "text"), DEV_SHA, "row['text']")  # fmt: skip
    for name, file in (("personalized", "privoke_personalized_synthetic.jsonl"), ("openai", "privoke_openai_synthetic.jsonl")):
        path = root / "evaluation/datasets" / file
        add(name, path, read_jsonl(path, "text"), None, "row['text']")
    piimb = next((root / "evaluation/results/external-data/piimb").glob("*/test_sentences.jsonl"))
    add("piimb", piimb, read_jsonl(piimb, "text"), PIIMB_SHA, "row['text']")
    dolly = next((root / "evaluation/results/external-data/dolly15k").glob("*/databricks-dolly-15k.jsonl"))
    rows = [json.loads(line) for line in open(dolly, encoding="utf-8") if line.strip()]
    add("dolly15k", dolly, [r["instruction"] for r in rows] + [r["context"] for r in rows if r["context"]],
        None, "every row['instruction'], then every non-empty row['context']")  # fmt: skip
    oasst = next((root / "evaluation/results/external-data/oasst2").glob("*/*.jsonl.gz"))
    texts = [m["text"] for m in (json.loads(line) for line in gzip.open(oasst, "rt", encoding="utf-8")) if m["role"] == "prompter"]
    add("oasst2", oasst, texts, None, "text of every message with role 'prompter'")
    sets["stress"] = stress_documents()
    info["stress"] = {"source": "tools/parity_sets.py stress_documents()", "rule": "synthetic: URLs, emoji, CJK, zero-width, casing, whitespace"}
    return sets, info


def encodable(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False  # a lone surrogate: Rust strings cannot carry it
    return bool(text)


def write_set(path: Path, texts: list[str]) -> str:
    digest = hashlib.sha256()
    with open(path, "w", encoding="utf-8", newline="\n") as out:
        for text in texts:
            line = json.dumps(text, ensure_ascii=True) + "\n"
            digest.update(line.encode("ascii"))
            out.write(line)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, default=Path("D:/Git Repositories/Privoke-Research-Project"), help="main checkout, read-only")
    parser.add_argument("--out", type=Path, required=True, help="ignored work directory")
    parser.add_argument("--smoke", action="store_true", help="write the 200-document smoke set instead of the full sets")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    raw, info = extract(args.source_root)
    sets: dict[str, list[str]] = {}
    for name, texts in raw.items():
        kept = [t for t in texts if encodable(t)]
        info[name]["rows"] = len(texts)
        info[name]["skipped_empty_or_unencodable"] = len(texts) - len(kept)
        sets[name] = kept
    if args.smoke:
        rng = random.Random(SMOKE_SEED)
        smoke: list[str] = []
        origin: list[dict] = []
        for name, quota in SMOKE_QUOTA.items():
            for index in sorted(rng.sample(range(len(sets[name])), quota)):
                smoke.append(sets[name][index])
                origin.append({"set": name, "index": index})
        smoke.extend(sets["stress"])
        origin.extend({"set": "stress", "index": i} for i in range(len(sets["stress"])))
        sets = {"smoke": smoke}
        info = {"smoke": {"rule": f"seed {SMOKE_SEED}; quotas {SMOKE_QUOTA} from the recorded sets plus the {len(origin) - sum(SMOKE_QUOTA.values())} stress documents",
                          "origin": origin, "sources": {k: v for k, v in info.items() if k != "stress"}, "rows": len(smoke)}}  # fmt: skip
    manifest = {"order": list(sets), "sets": info}
    for name, texts in sets.items():
        info[name]["documents"] = len(texts)
        info[name]["texts_sha256"] = write_set(args.out / f"{name}.jsonl", texts)
    (args.out / "sets.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    for name, texts in sets.items():
        print(f"{name}: {len(texts)} documents")


if __name__ == "__main__":
    main()
