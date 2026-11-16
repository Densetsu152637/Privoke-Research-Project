"""Golden output for the Rust ``privoke-semantic`` crate (RUST-S14).

The Rust crate ports semantic inference of the client runtime: the V3 pretrained BERT encoder with its task heads
(``extension/client-runtime/src/v3/model.py``) and the legacy Tiny transformer
(``extension/client-runtime/src/model.py``, ``transformer_encoder.py``, ``task_readout.py``). This tool produces
everything the crate is checked against, from the unchanged Python client runtime and host Python
(``evaluation/.venv-v1-v3-pipeline``, read only).

Every pipeline run selects the layer explicitly: ``pipeline.analyse_text(text, layers=["semantic"])`` and the returned
layer execution is asserted to be exactly one ``semantic`` layer with status ``ok`` or ``error``. The regex and NER
layers are never requested, and an empty layer list is never sent (an empty list means the whole detector pipeline).
Results recorded here are LLM-only (semantic-only) results; they are not product-pipeline results.

The pipeline obtains its semantic detector from the model-streaming service. Here the detector hook
(``pipeline._detector_for``) hands back the product's own model class (``PretrainedV3`` or the streamed Tiny wrapper
``StreamedTransformerPrivacyModel``) built from local files, so that no service is needed; the normalisation, layer
execution and span remapping are the unchanged pipeline code.

Subcommands::

    synthetic   write the committed synthetic fixtures: a seeded small BERT V3 release (config, vocabulary,
                safetensors, heads) with its golden, and seeded Tiny models of both readouts plus the golden of the
                tracked legacy models (``models/privoke-*.json``) on synthetic prompts
    releases    golden for the pinned V3 releases (``--releases-root``, local only) on the synthetic prompts, into an
                ignored directory
    sets        golden for the recorded sets (V3 tiers, tracked Tiny models) into an ignored directory

Recorded-set golden goes under ``evaluation/results/`` (ignored by Git) and is never committed. ``final.jsonl`` is
never opened. The protobuf clients are not needed.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import random
import sys
import types
import unicodedata
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CRATE = REPO / "rust" / "crates" / "privoke-semantic"
FIXTURES = CRATE / "tests" / "fixtures"
THREADS = 4  # the paper's Torch 2.11 CPU setting
SYNTHETIC_SEED = 20261117
TIERS = ("efficient", "balanced", "quality")
TINY_MODELS = ("privoke-baseline", "privoke-efficient", "privoke-balanced", "privoke-quality")
LABELS = {
    "sensitivity": ["S0", "S1", "S2", "S3"],
    "visibility": ["P0", "P1", "P2", "P3", "P4", "PU"],
    "category": ["HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL", "SEXUAL", "CHILD", "LOCATION", "IDENTITY", "THIRD_PARTY"],
}
SET_NAMES = ["development", "personalized", "openai", "piimb", "dolly15k", "oasst2", "stress"]


GENERATED: list[Path] = []  # protobuf clients (evaluation/setup-host.py), when they are not in this checkout


def bootstrap() -> None:
    from_environment = [Path(os.environ["PRIVOKE_GENERATED"])] if os.environ.get("PRIVOKE_GENERATED") else []
    for path in (REPO / "extension" / "client-runtime", REPO / "shared" / "python", REPO / "evaluation",
                 REPO / "extension" / "client-runtime" / "generated", *GENERATED, *from_environment):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))


def runtime_modules():
    bootstrap()
    import torch

    torch.set_num_threads(THREADS)
    from src import pipeline

    return torch, pipeline


def has_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(ch) < 0xE000 for ch in text)


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")


# --- prompts ---------------------------------------------------------------------------------------------------
def synthetic_texts() -> list[str]:
    """Generic prompts that exercise tokenisation (case, accents, CJK, emoji, specials) and the heads."""
    zwsp, bom = "​", "﻿"
    texts = [
        "",
        " ",
        "hello",
        "Hello, World!",
        "My name is John Smith and I live at 12 Main Street in London.",
        "Call me on 555-0100 or email john.smith@example.com tomorrow.",
        "The patient has diabetes and takes insulin twice a day.",
        "I voted for the other party in the last election and I attend church every week.",
        "My salary is 85,000 dollars and my credit card number is on file.",
        "She was arrested in 2019 and my son is only seven years old.",
        "What is the capital of France?",
        "Write a poem about the sea.",
        "Summarise the following article in three sentences.",
        "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG",
        "Café München, Zählen, naive resume, über and été",
        "Niño año mañana — an en dash – and a bullet • here",
        "我叫张伟，住在北京市。",
        "私の名前は田中です。",
        "저는 김민수입니다.",
        "مرحبا بك يا محمد",
        "Здравствуйте, я Иван.",
        "Emoji \U0001F600 and flags \U0001F1EB\U0001F1F7 and family \U0001F468‍\U0001F469‍\U0001F467 test",
        "Fullwidth ＡＢＣ and １２３ and ① and ﬁ ligature and ½",
        f"Zero{zwsp}width{zwsp}space and {bom}byte order mark",
        "[CLS] [SEP] [MASK] [UNK] [PAD] are special words",
        "[cls] token [sep] markers in lower case",
        "don't can't won't it's O'Brien rock'n'roll",
        "foo_bar baz-qux a.b.c 3.14159 1e10 0xFF 1,000,000",
        "https://www.example.com/path?x=1&y=2#frag and ftp://files.example.net/a_b.txt",
        "x" * 150,
        "supercalifragilisticexpialidocious " * 3,
        "tabs\tand\nnewlines\r\nand\x0b\x0cvertical",
        "a\x00b�c control and replacement characters",
        "Sentence one. Sentence two! Sentence three? (parenthetical) {braces} [brackets] <angles>",
        "1 2 3 4 5 6 7 8 9 0",
        "The meeting is at 10:30 on 2026-11-17 in room B12.",
        "I am pregnant and afraid to tell my employer in Chicago.",
        "My password is hunter2 and the API key is sk-test-0000000000.",
        "Patient 4471: HIV positive, referred to counselling, lives alone.",
        "My daughter, aged 6, goes to Greenfield Primary School.",
        "I earn about 4,200 a month and owe 12,000 on a loan.",
        "Translate to French: the weather is nice today.",
        "word " * 300,
    ]
    texts.append("the " * 600)  # 602 WordPiece tokens: over the 512 limit
    texts.append("Z" * 2000)
    return texts


def fuzz_texts(count: int = 150, seed: int = SYNTHETIC_SEED) -> list[str]:
    """Seeded random texts built from words, accents, CJK, digits and punctuation."""
    rng = random.Random(seed)
    words = ["name", "John", "Mary", "london", "street", "doctor", "salary", "church", "party", "son", "daughter", "email", "phone",
             "loan", "diabetes", "arrest", "school", "home", "work", "the", "a", "of", "and", "is", "my", "I", "we", "they"]
    pieces = ["é", "ü", "ñ", "中", "文", "あ", "\U0001F600", "-", ".", ",", "!", "?", "'", "(", ")", "#", "@", "_", "/",
              "123", "4567", "0", "ABC", "xyz", "́", "​", "\t"]
    rows = []
    for _ in range(count):
        parts = []
        for _ in range(rng.randint(1, 40)):
            parts.append(rng.choice(words) if rng.random() < 0.6 else rng.choice(pieces))
        rows.append(rng.choice([" ", " ", "", "\n"]).join(parts))
    return rows


def prompt_rows() -> list[tuple[str, str]]:
    rows = [(f"s{i:03d}", text) for i, text in enumerate(synthetic_texts())]
    rows += [(f"f{i:03d}", text) for i, text in enumerate(fuzz_texts())]
    return rows


# --- results ---------------------------------------------------------------------------------------------------
def result_record(result) -> dict:
    return {
        "span": list(result.span) if result.span is not None else None,
        "text": result.section_of_text,
        "packed": result.classification.pack(),
        "confidence": result.confidence,
        "reasoning": result.reasoning,
    }


def run_layer(pipeline, findings, text: str) -> dict:
    """``analyse_text(text, layers=["semantic"])`` with the model hook; asserts the returned layer execution."""
    original = pipeline._detector_for
    pipeline._detector_for = lambda layer, semantic_model_id=None: findings
    try:
        analysis = pipeline.analyse_text(text, layers=["semantic"])
    finally:
        pipeline._detector_for = original
    layers = analysis.layers
    assert len(layers) == 1 and layers[0].layer == "semantic", [layer.layer for layer in layers]
    assert layers[0].status in ("ok", "error"), layers[0].status
    return {"status": layers[0].status, "error": layers[0].error, "results": [result_record(r) for r in layers[0].results]}


def float_list(values) -> list[float]:
    return [float(v) for v in values]


# --- V3 --------------------------------------------------------------------------------------------------------
def v3_row(torch, pipeline, model, row_id: str, text: str) -> dict:
    row: dict = {"id": row_id, "text": text}
    try:
        encoded = model.tokenize([text])
        row["ids"] = [int(i) for i in encoded["input_ids"][0]]
        with torch.no_grad():
            pooled = model.encoder(**encoded).pooler_output
            logits = {task: pooled @ model.heads[task + "_weight"].T + model.heads[task + "_bias"] for task in LABELS}
            sensitivity = logits["sensitivity"].softmax(-1)
            visibility = logits["visibility"].softmax(-1)
            categories = logits["category"].sigmoid()
            raw = float(torch.cat((sensitivity[0], categories[0])).max())
        forward = model([text])
        for task in LABELS:  # the forward pass must be the pooled-and-heads pass the record is built from
            assert torch.equal(forward[task], logits[task]), task
        row["pooled"] = float_list(pooled[0])
        row["logits"] = {task: float_list(logits[task][0]) for task in LABELS}
        classification, confidence = model.predictions([text])[0]
        row["decision"] = {
            "packed": classification.pack(),
            "sensitivity": LABELS["sensitivity"][int(sensitivity[0].argmax())],
            "visibility": LABELS["visibility"][int(visibility[0].argmax())],
            "categories": [name for name, p in zip(LABELS["category"], categories[0]) if p >= 0.5],
            "confidence_raw": raw,
            "confidence": confidence,
        }
    except ValueError as exc:
        row["error"] = str(exc)
    identity = {"model_id": "synthetic"}
    row["layer"] = run_layer(pipeline, lambda t: model.findings(t, identity), text)
    return row


def synthetic_vocab() -> list[str]:
    letters = "abcdefghijklmnopqrstuvwxyz"
    punct = list("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
    words = """the a an of and or to in on at is are was were be my your his her our their i you he she it we they me us them
    name names john mary smith london paris france capital street road main avenue number phone call email mail home work
    salary dollars card credit password key file loan debt doctor patient diabetes insulin hospital health church party vote
    election voted political religion arrested crime police court child children son daughter school year years old age
    pregnant afraid tell employer poem sea write summarise article sentences weather nice today translate french meeting room
    morning evening tomorrow yesterday month week day time money bank account live lives living tested positive counselling
    lonely alone family friend brother sister mother father wife husband""".split()
    suffixes = ["ing", "ed", "s", "er", "ly", "tion", "ment", "son", "ith", "ana", "ize", "ness", "es"]
    vocab = ["[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]"] + punct + list("0123456789") + list(letters)
    vocab += ["##" + c for c in letters + "0123456789"] + ["##" + s for s in suffixes]
    vocab += sorted(set(words))
    seen: set[str] = set()
    out = []
    for token in vocab:
        if token not in seen:
            seen.add(token)
            out.append(token)
    return out


def build_synthetic_v3(directory: Path):
    """A seeded small BERT with random heads, built and saved through the product's own classes."""
    torch, pipeline = runtime_modules()
    from transformers import BertConfig, BertModel
    from src.v3.model import PretrainedV3

    vocab = synthetic_vocab()
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "vocab.txt").write_text("\n".join(vocab) + "\n", encoding="utf-8", newline="\n")
    config = {
        "attention_probs_dropout_prob": 0.1, "hidden_act": "gelu", "hidden_dropout_prob": 0.1, "hidden_size": 32,
        "initializer_range": 0.02, "intermediate_size": 64, "layer_norm_eps": 1e-12, "max_position_embeddings": 512,
        "model_type": "bert", "num_attention_heads": 4, "num_hidden_layers": 3, "pad_token_id": 0, "type_vocab_size": 2,
        "vocab_size": len(vocab),
    }
    (directory / "config.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8", newline="\n")
    generator = torch.Generator().manual_seed(SYNTHETIC_SEED)
    encoder = BertModel(BertConfig(**config), add_pooling_layer=True)
    state = {}
    for name, value in encoder.state_dict().items():
        if name.endswith("LayerNorm.weight"):
            state[name] = 1.0 + 0.1 * torch.randn(value.shape, generator=generator)
        elif name.endswith(".bias"):
            state[name] = 0.1 * torch.randn(value.shape, generator=generator)
        elif "embeddings" in name:
            state[name] = 0.8 * torch.randn(value.shape, generator=generator)
        else:
            state[name] = 0.6 * torch.randn(value.shape, generator=generator)
    heads = {}
    for task, labels in LABELS.items():
        heads[task + "_weight"] = 1.0 * torch.randn((len(labels), config["hidden_size"]), generator=generator)
        heads[task + "_bias"] = 0.2 * torch.randn((len(labels),), generator=generator)
    model = PretrainedV3(config, state, directory / "vocab.txt", heads=heads)
    inventory = model.export(directory / "model.safetensors")
    return torch, pipeline, model, inventory, config


def cmd_synthetic(args) -> None:
    import platform

    out = Path(args.out)
    torch, pipeline, model, inventory, config = build_synthetic_v3(out / "v3_synthetic")
    rows = [v3_row(torch, pipeline, model, row_id, text) for row_id, text in prompt_rows()]
    meta = {
        "python": sys.version.split()[0], "torch": torch.__version__, "threads": THREADS, "unicode": unicodedata.unidata_version,
        "seed": SYNTHETIC_SEED, "platform": platform.platform(), "layers": ["semantic"],
        "tensors": len(inventory), "config": config,
    }
    write_json(out / "v3_synthetic" / "golden.json", {"meta": meta, "rows": rows})
    print(f"wrote {out / 'v3_synthetic'}: {len(rows)} rows, {len(inventory)} tensors")
    write_tiny_synthetic(out, torch, pipeline)


# --- Tiny ------------------------------------------------------------------------------------------------------
def tiny_config(readout: str | None) -> dict:
    config = {
        "category_labels": LABELS["category"], "category_threshold": 0.42, "hidden_size": 16, "intermediate_size": 32,
        "max_tokens": 40, "num_attention_heads": 2, "num_layers": 2, "sensitivity_labels": LABELS["sensitivity"],
        "visibility_labels": LABELS["visibility"], "vocab_size": 64,
    }
    if readout is not None:
        config["readout"] = readout
    return config


def tiny_artifact(readout: str | None, seed: int) -> dict:
    import numpy as np

    config = tiny_config(readout)
    rng = np.random.default_rng(seed)
    hidden, inner = config["hidden_size"], config["intermediate_size"]
    shapes = {"token_embedding": (config["vocab_size"], hidden), "position_embedding": (config["max_tokens"], hidden)}
    for task, labels in LABELS.items():
        shapes[f"head.{task}.weight"] = (hidden, len(labels))
        shapes[f"head.{task}.bias"] = (len(labels),)
    for layer in range(config["num_layers"]):
        prefix = f"layers.{layer}."
        for name, shape in {
            "attention.query.weight": (hidden, hidden), "attention.key.weight": (hidden, hidden),
            "attention.value.weight": (hidden, hidden), "attention.output.weight": (hidden, hidden),
            "attention.output.bias": (hidden,), "ffn.input.weight": (hidden, inner), "ffn.input.bias": (inner,),
            "ffn.output.weight": (inner, hidden), "ffn.output.bias": (hidden,),
        }.items():
            shapes[prefix + name] = shape
    if readout is not None:
        for task in LABELS:
            shapes[f"readout.{task}.query"] = (hidden,)
    parameters = {}
    for name in sorted(shapes):
        scale = 0.6 if "embedding" in name or "query" in name and name.startswith("readout") else 0.35
        values = (scale * rng.standard_normal(shapes[name])).astype(np.float32)
        parameters[name] = {"shape": list(shapes[name]), "values": values.ravel().tolist()}
    return {
        "architecture": "privoke_tiny_transformer_v2" if readout is not None else "privoke_tiny_transformer_v1",
        "config": config, "model_id": f"synthetic-tiny-{readout or 'legacy'}", "version": f"synthetic-{seed}", "parameters": parameters,
        "metadata": {"weight_format": "json-float32"}, "schema_version": 1,
    }


def tiny_model(artifact: dict):
    """The product's streamed Tiny wrapper, built from a local artifact instead of a service snapshot."""
    bootstrap()
    from src.LLM.privoke.streamed_model import StreamedTransformerPrivacyModel

    parameters = {name: tensor["values"] for name, tensor in artifact["parameters"].items()}
    shapes = {name: tensor["shape"] for name, tensor in artifact["parameters"].items()}
    metadata = {"model_config": json.dumps(artifact["config"]), "architecture": artifact["architecture"], "artifact_checksum": "local"}
    snapshot = types.SimpleNamespace(
        model_id=artifact["model_id"], version=artifact["version"], parameters=parameters, shapes=shapes, metadata=metadata,
        parameter_count=sum(len(v) for v in parameters.values()), fingerprint="local",
    )
    return StreamedTransformerPrivacyModel(snapshot)


def tiny_row(pipeline, wrapper, row_id: str, text: str) -> dict:
    row: dict = {"id": row_id, "text": text}
    inner = wrapper.model
    ids = inner.token_ids(text)
    prediction = inner.predict(text)
    row["ids"] = [int(i) for i in ids]
    row["logits"] = {task: float_list(prediction.task_logits[i]) for i, task in enumerate(LABELS)}
    row["pooled"] = float_list(prediction.pooled)
    row["decision"] = {
        "sensitivity": prediction.sensitivity, "visibility": prediction.visibility, "categories": list(prediction.categories),
        "confidence_raw": prediction.confidence,
        "sensitivity_probabilities": float_list(prediction.sensitivity_probabilities),
        "category_probabilities": float_list(prediction.category_probabilities),
    }
    row["layer"] = run_layer(pipeline, wrapper.classify, text)
    return row


def write_tiny_synthetic(out: Path, torch, pipeline) -> None:
    import numpy as np

    rows_text = prompt_rows()
    for readout, seed in ((None, SYNTHETIC_SEED + 1), ("residual_task_query_v1", SYNTHETIC_SEED + 2)):
        artifact = tiny_artifact(readout, seed)
        name = "legacy" if readout is None else "task_query"
        write_json(out / f"tiny_synthetic_{name}.json", artifact)
        wrapper = tiny_model(artifact)
        rows = [tiny_row(pipeline, wrapper, row_id, text) for row_id, text in rows_text]
        meta = {"python": sys.version.split()[0], "numpy": np.__version__, "unicode": unicodedata.unidata_version, "layers": ["semantic"],
                "model": artifact["model_id"], "readout": readout or "legacy_pool_v1"}
        write_json(out / f"tiny_synthetic_{name}.golden.json", {"meta": meta, "rows": rows})
        print(f"wrote tiny_synthetic_{name}: {len(rows)} rows")
    # The tracked legacy models, on the synthetic prompts only (the models are committed, so the golden can be).
    tracked = {}
    for name in TINY_MODELS:
        artifact = json.loads((REPO / "models" / f"{name}.json").read_text(encoding="utf-8"))
        wrapper = tiny_model(artifact)
        tracked[name] = [tiny_row(pipeline, wrapper, row_id, text) for row_id, text in rows_text]
        print(f"tracked {name}: {len(tracked[name])} rows")
    write_json(out / "tiny_tracked.golden.json",
               {"meta": {"python": sys.version.split()[0], "numpy": np.__version__, "layers": ["semantic"],
                         "sha256": {n: hashlib.sha256((REPO / "models" / f"{n}.json").read_bytes()).hexdigest() for n in TINY_MODELS}},
                "models": tracked})


# --- pinned releases and recorded sets -------------------------------------------------------------------------
def load_release(torch, releases_root: Path, tier: str):
    from src.v3.model import PretrainedV3

    directory = releases_root / f"privoke-v3-{tier}"
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    return PretrainedV3.load(manifest, directory / "model.safetensors", directory / "config.json", directory / "vocab.txt", device="cpu")


def sample(rows: list, limit: int) -> list:
    if limit <= 0 or len(rows) <= limit:
        return list(enumerate(rows))
    step = len(rows) / limit
    return [(int(i * step), rows[int(i * step)]) for i in range(limit)]


def cmd_releases(args) -> None:
    torch, pipeline = runtime_modules()
    out = Path(args.out)
    for tier in args.tiers:
        model = load_release(torch, Path(args.releases_root), tier)
        rows = [v3_row(torch, pipeline, model, row_id, text) for row_id, text in prompt_rows()]
        write_json(out / f"v3-{tier}-synthetic.json", {"meta": {"tier": tier, "torch": torch.__version__, "threads": THREADS, "layers": ["semantic"]}, "rows": rows})
        print(f"v3-{tier}: {len(rows)} synthetic rows")


def cmd_sets(args) -> None:
    torch, pipeline = runtime_modules()
    ner = importlib.import_module("generate_ner_golden")
    texts_by_set = ner.load_sets(args.sets, Path(args.data_root))
    out = Path(args.out)
    models: dict[str, tuple[str, object]] = {}
    for tier in args.tiers:
        models[f"v3-{tier}"] = ("v3", load_release(torch, Path(args.releases_root), tier))
    for name in args.tiny:
        artifact = json.loads((Path(args.data_root) / "models" / f"{name}.json").read_text(encoding="utf-8"))
        models[f"tiny-{name}"] = ("tiny", tiny_model(artifact))
    for set_name in args.sets:
        picked = [(i, t) for i, t in sample(texts_by_set[set_name], args.limit) if not has_surrogate(t)]
        for key, (kind, model) in models.items():
            if kind == "v3":
                rows = [v3_row(torch, pipeline, model, f"{set_name}:{i}", text) for i, text in picked]
            else:
                rows = [tiny_row(pipeline, model, f"{set_name}:{i}", text) for i, text in picked]
            write_json(out / f"{key}-{set_name}.json", {"meta": {"set": set_name, "model": key, "torch": torch.__version__, "threads": THREADS, "layers": ["semantic"]}, "rows": rows})
            print(f"{key} {set_name}: {len(rows)} rows", flush=True)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    synthetic = sub.add_parser("synthetic")
    synthetic.add_argument("--out", default=str(FIXTURES))
    synthetic.set_defaults(func=cmd_synthetic)
    releases = sub.add_parser("releases")
    releases.add_argument("--releases-root", required=True, help="models/standard-releases of the checkout that holds the releases")
    releases.add_argument("--tiers", nargs="+", choices=TIERS, default=list(TIERS))
    releases.add_argument("--out", default=str(REPO / "evaluation" / "results" / "semantic-golden-20261117"))
    releases.set_defaults(func=cmd_releases)
    sets = sub.add_parser("sets")
    sets.add_argument("sets", nargs="+", choices=SET_NAMES)
    sets.add_argument("--data-root", default=str(REPO), help="checkout that holds the ignored dataset files")
    sets.add_argument("--releases-root", required=True)
    sets.add_argument("--tiers", nargs="*", choices=TIERS, default=list(TIERS))
    sets.add_argument("--tiny", nargs="*", choices=TINY_MODELS, default=list(TINY_MODELS))
    sets.add_argument("--limit", type=int, default=500, help="evenly spaced rows per set (0 = all)")
    sets.add_argument("--out", default=str(REPO / "evaluation" / "results" / "semantic-golden-20261117"))
    sets.set_defaults(func=cmd_sets)
    parser.add_argument("--generated", help="directory with the generated protobuf clients, when this checkout has none")
    args = parser.parse_args(argv)
    if args.generated:
        GENERATED.append(Path(args.generated))
    args.func(args)


if __name__ == "__main__":
    main()
