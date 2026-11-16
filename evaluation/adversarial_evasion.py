"""ADVEVADE-20261116: end-to-end adversarial privacy-evasion evaluation of the PriVoke product pipeline.

Scope: PRODUCT PIPELINE (regex + NER + semantic V3 standard `privoke-v3-balanced`) through the
client runtime's native gRPC servicer, called in process on the host (no Docker, no network).
Never LLM-only evidence. Every request names the three layers explicitly and the harness asserts
the executed layers of every response (never an empty layer list).

Sub-commands::

    python evaluation/adversarial_evasion.py build   --seed-file F4.jsonl --out DIR [--per-source N]
    python evaluation/adversarial_evasion.py score   --set DIR --expected-sha256 H --arm defaults|flags
    python evaluation/adversarial_evasion.py analyse --set DIR --out-json J

``build`` freezes the transformed set and prints its sha256. ``score`` refuses to run unless the
frozen file hashes to ``--expected-sha256``. ``analyse`` re-derives every table from the per-arm
per-row score files and the frozen manifest; ``--check`` re-derives from the stored JSON only.

Definitions
-----------
* intended action of a prompt = the action of the UNTRANSFORMED prompt under shipped defaults;
  protected = intended action is WARN or BLOCK.
* a transformed prompt evades when its protected original (defaults baseline) is answered ALLOW.
* a transformed prompt is downgraded when the intended action is BLOCK and the answer is WARN.
* conditional ASR = evaded / protected applicable pairs; unconditional ASR = evaded / all
  applicable pairs of the family (applicable = the transform changed the text).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import adversarial_evasion_transforms as tx  # noqa: E402

RECORD_ID = "ADVEVADE-20261116"
SEED = tx.SEED
LAYERS = ("regex", "ner", "semantic")
PROTO_LAYER_VALUES = (2, 3, 4)  # DETECTION_LAYER_REGEX, _NER, _SEMANTIC
SEMANTIC_MODEL_ID = "privoke-v3-balanced"
ACTIONS = ("ALLOW", "WARN", "BLOCK")
RANK = {name: index for index, name in enumerate(ACTIONS)}
ARMS = ("defaults", "flags")
FLAG_ENV = {"PRIVOKE_STRIP_FORMAT_CHARS": "1", "PRIVOKE_CANONICALISE_DIGITS": "1",
            "PRIVOKE_CANONICALISE_EMAIL_WORDS": "1", "PRIVOKE_NER_CASELESS_GATE": "1"}
FLAG_ATTRS = {"PRIVOKE_STRIP_FORMAT_CHARS": "strip_format_chars", "PRIVOKE_CANONICALISE_DIGITS": "canonicalise_digits",
              "PRIVOKE_CANONICALISE_EMAIL_WORDS": "canonicalise_email_words", "PRIVOKE_NER_CASELESS_GATE": "ner_caseless_gate"}
PRODUCT_ENV = {"PRIVOKE_WAIT_FOR_REGEX": "true", "PRIVOKE_REGEX_PRESIDIO": "true", "PRIVOKE_REGEX_GITLEAKS": "true",
               "MODEL_STREAMING_CACHE_TTL_SECONDS": "604800", "LLM_CHOICE": "streamed", "HF_HUB_OFFLINE": "1",
               "TRANSFORMERS_OFFLINE": "1", "PRIVOKE_MODEL_DEVICE": "cpu", "PRIVOKE_MAX_PROMPT_CHARS": "20000"}
SEED_SET_SHA256 = "d4bed756790c7b000fc5e8b6028e3f962c8dbfabe3f607a7180224d55356589d"  # F4, on-disk bytes
BASELINE = "baseline"
BENIGN_VARIANTS = ("spelling", "paraphrase", "ctx_window_middle", "ctx_long_start", "ctx_long_middle", "ctx_long_end")


# ---------------------------------------------------------------- statistics
def wilson(successes: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion (95 % by default)."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = successes / n
    denominator = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return (max(0.0, centre - half), min(1.0, centre + half))


def rate(successes: int, n: int) -> dict:
    low, high = wilson(successes, n)
    return {"k": successes, "n": n, "rate": (successes / n if n else None),
            "wilson_low": (None if n == 0 else low), "wilson_high": (None if n == 0 else high)}


def exact_mcnemar(b: int, c: int) -> float:
    """Two-sided exact McNemar p from the discordant counts."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


# ---------------------------------------------------------------- layer assertion and scoring records
class LayerAssertionError(AssertionError):
    pass


def assert_executed_layers(layers: list[dict], expected_checksum: str | None = None, metadata: dict | None = None) -> dict:
    """Assert a response carries exactly regex, ner, semantic in order and return their statuses.

    ``layers`` is a list of ``{"layer": name, "status": s, "error": e}``. A layer may be ``ok``,
    ``skipped`` (only after regex returned BLOCK, the product's regex-first order) or ``error``
    (kept as a recorded outcome: the runtime then fails closed). Any other shape is an assertion
    failure. When the semantic layer ran, its admitted model identity must match.
    """
    names = [item["layer"] for item in layers]
    if names != list(LAYERS):
        raise LayerAssertionError(f"executed layers {names} differ from the requested {list(LAYERS)}")
    statuses = {item["layer"]: item["status"] for item in layers}
    for name, status in statuses.items():
        if status not in ("ok", "skipped", "error"):
            raise LayerAssertionError(f"layer {name} has status {status!r}")
    if statuses["regex"] != "ok":
        raise LayerAssertionError("regex layer did not run")
    if statuses["regex"] == "ok" and any(s == "skipped" for s in (statuses["ner"], statuses["semantic"])):
        if statuses["ner"] != statuses["semantic"]:
            raise LayerAssertionError("regex-first skip must skip both later layers")
    if statuses["semantic"] == "ok" and expected_checksum is not None:
        if (metadata or {}).get("privoke.semantic.artifact_checksum") != expected_checksum:
            raise LayerAssertionError("semantic layer executed with an unexpected model identity")
    return statuses


def layer_actions(layers: list[dict]) -> dict:
    return {item["layer"]: max((r["action"] for r in item.get("results", [])), key=RANK.get, default="ALLOW")
            for item in layers}


def score_record(vid: str, response: dict, expected_checksum: str | None) -> dict:
    layers = response["layers"]
    statuses = assert_executed_layers(layers, expected_checksum, response.get("metadata"))
    per_layer = layer_actions(layers)
    detect = max(per_layer.values(), key=RANK.get)
    errored = [name for name, status in statuses.items() if status == "error"]
    return {"vid": vid, "action": response["action"], "detect_action": detect, "layer_status": statuses,
            "layer_action": per_layer, "errored": errored, "failed_closed": bool(errored) and detect == "ALLOW"
            and response["action"] != "ALLOW"}


# ---------------------------------------------------------------- build (frozen set)
def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def canonical_line(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_shard_items(path: Path, shards: int, shard: int) -> list[dict]:
    """Stream the frozen set and keep only this shard's items (bounded memory per scoring process)."""
    items = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            item = json.loads(line)
            if shard_of(item["row_id"], shards) == shard:
                items.append(item)
    return items


def stratified_sample(rows: list[dict], per_source: int | None, seed: int = SEED) -> list[dict]:
    """Seeded sample of at most ``per_source`` rows from each source_dataset; all rows when None."""
    if per_source is None:
        return sorted(rows, key=lambda r: r["id"])
    by_source: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_source[row["source_dataset"]].append(row)
    chosen: list[dict] = []
    for source in sorted(by_source):
        ordered = sorted(by_source[source], key=lambda r: hashlib.sha256(f"{seed}:sample:{r['id']}".encode()).hexdigest())
        chosen.extend(ordered[:per_source])
    return sorted(chosen, key=lambda r: r["id"])


def build_items(rows: list[dict], variants: dict | None = None) -> list[dict]:
    variants = variants or tx.VARIANTS
    items = []
    for row in rows:
        items.append({"vid": f"{row['id']}::{BASELINE}", "row_id": row["id"], "variant": BASELINE,
                      "family": BASELINE, "applicable": True, "text": row["text"]})
        for name, (family, _fn, _removing) in variants.items():
            text = tx.apply_variant(name, row)
            items.append({"vid": f"{row['id']}::{name}", "row_id": row["id"], "variant": name, "family": family,
                          "applicable": text is not None and text != row["text"], "text": text if text is not None else row["text"]})
    return items


def cmd_build(args) -> int:
    seed_path = Path(args.seed_file)
    seed_hash = file_sha256(seed_path)
    if args.verify_seed_sha and seed_hash != SEED_SET_SHA256:
        raise SystemExit(f"seed file hash {seed_hash} differs from the declared F4 hash")
    rows = read_jsonl(seed_path)
    if args.benign:  # specificity control: labelled clean rows, entity-free variants only
        rows = [r for r in rows if not r.get("expected_has_pii")]
        variants = {k: tx.VARIANTS[k] for k in BENIGN_VARIANTS}
    else:
        assert all(r.get("expected_has_pii") for r in rows), "seed set must contain only labelled sensitive rows"
        variants = tx.VARIANTS
    sample = stratified_sample(rows, args.per_source)
    items = build_items(sample, variants)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    frozen = out / "frozen_set.jsonl"
    payload = "\n".join(canonical_line(i) for i in items) + "\n"
    if frozen.exists() and frozen.read_text(encoding="utf-8") != payload:
        raise SystemExit("frozen set exists and differs; refusing to overwrite")
    frozen.write_text(payload, encoding="utf-8", newline="\n")
    manifest = {
        "record": RECORD_ID, "seed": SEED, "generator_revision": tx.GENERATOR_REVISION,
        "seed_file": str(seed_path).replace("\\", "/"), "seed_file_sha256": seed_hash,
        "seed_rows_total": len(rows), "seed_rows_used": len(sample), "per_source": args.per_source,
        "rows_by_source": dict(sorted(Counter(r["source_dataset"] for r in sample).items())),
        "label_family_mapping_sha256": tx.label_family_file_sha256(),
        "transform_module_sha256": file_sha256(HERE / "adversarial_evasion_transforms.py"),
        "benign_control": bool(args.benign),
        "variants": {name: {"family": fam, "value_removing": removing} for name, (fam, _fn, removing) in variants.items()},
        "items": len(items), "frozen_set_sha256": file_sha256(frozen),
        "applicable_by_variant": dict(sorted(Counter(i["variant"] for i in items if i["applicable"]).items())),
        "row_group": {r["id"]: r["group_id"] for r in sample},
        "row_source": {r["id"]: r["source_dataset"] for r in sample},
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True), encoding="utf-8")
    print(manifest["frozen_set_sha256"])
    return 0


# ---------------------------------------------------------------- runtime (host, in process)
class Runtime:
    """In-process product pipeline: native gRPC servicer, shipped layers, semantic V3 balanced."""

    def __init__(self, release_dir: Path, arm: str, generated: Path):
        for key, value in PRODUCT_ENV.items():
            os.environ[key] = value
        if arm == "flags":
            os.environ.update(FLAG_ENV)
        else:
            for key in FLAG_ENV:
                os.environ.pop(key, None)
        for relative in ("shared/python", "extension/client-runtime", "evaluation"):
            path = str(ROOT / relative)
            if path not in sys.path:
                sys.path.insert(0, path)
        if str(generated) not in sys.path:
            sys.path.append(str(generated))
        from src.config import GLOBAL_CONFIG
        self.config = GLOBAL_CONFIG
        for env_name, attr in FLAG_ATTRS.items():
            expected = arm == "flags"
            if getattr(GLOBAL_CONFIG, attr) is not expected:
                raise RuntimeError(f"flag {env_name} is not {expected} in the loaded configuration")
        self.arm = arm
        self.flags = {env: getattr(GLOBAL_CONFIG, attr) for env, attr in FLAG_ATTRS.items()}
        self._load_semantic(Path(release_dir))
        from privoke.v1 import runtime_pb2
        from src.hosting.grpc_server import PrivokeRuntimeService
        self.pb = runtime_pb2
        self.service = PrivokeRuntimeService(max_text_chars=20_000)
        if not GLOBAL_CONFIG.wait_for_regex:
            raise RuntimeError("shipped default is regex-first (waitForRegex true)")

    def _load_semantic(self, release: Path) -> None:
        import time as _time
        from privoke_eval import pipeline_v1_v3 as core
        from privoke_eval.pipeline_v1_v3_serving import V3SemanticAdapter
        from src.LLM.privoke.parameter_stream import ModelParameterStreamer
        from src.LLM.privoke.streamed_model import GLOBAL_STREAMED_MODEL_CACHE, _CachedModel
        from src.v3.model import PretrainedV3
        directory = release / SEMANTIC_MODEL_ID
        manifest = core.read(directory / "manifest.json")
        sha = core.file_hash(directory / "manifest.json")
        model = PretrainedV3.load(manifest, directory / "model.safetensors", directory / "config.json", directory / "vocab.txt", device="cpu")
        model.eval()
        for parameter in model.parameters():
            parameter.requires_grad_(False)
        identity = core.model_identity(manifest, sha)
        if identity["model_id"] != SEMANTIC_MODEL_ID:
            raise RuntimeError("release directory does not hold the requested model")
        adapter = V3SemanticAdapter(model, identity)
        self.config.llm_choice = "streamed"
        streamer = ModelParameterStreamer(model_id=identity["model_id"])
        GLOBAL_STREAMED_MODEL_CACHE.clear()
        GLOBAL_STREAMED_MODEL_CACHE._models[(streamer.target, streamer.model_id)] = _CachedModel(
            identity["parameter_fingerprint"], adapter, _time.monotonic())
        self.identity = identity
        self.release_files = {name: core.file_hash(directory / name) for name in
                              ("manifest.json", "model.safetensors", "config.json", "vocab.txt")}

    def analyse(self, text: str, request_id: str) -> dict:
        request = self.pb.AnalyzePromptRequest(
            request_id=request_id, text=text, layers=list(PROTO_LAYER_VALUES),
            regex_execution_order=self.pb.REGEX_EXECUTION_ORDER_FIRST, semantic_model_id=SEMANTIC_MODEL_ID)
        response = self.service.AnalyzePrompt(request, None)
        layer_name = {2: "regex", 3: "ner", 4: "semantic"}
        layers = [{"layer": layer_name[item.layer], "status": item.status, "error": item.error,
                   "results": [{"action": r.action} for r in item.results]} for item in response.layers]
        return {"action": response.action, "layers": layers, "metadata": dict(response.metadata), "error": response.error,
                "request_id": response.request_id}


def shard_of(row_id: str, shards: int) -> int:
    return int(hashlib.sha256(f"{SEED}:shard:{row_id}".encode()).hexdigest(), 16) % shards


def score_files(set_dir: Path, arm: str) -> list[Path]:
    return sorted(set_dir.glob(f"scores_{arm}_s*.jsonl"))


def load_arm_scores(set_dir: Path, arm: str) -> dict[str, dict]:
    scores: dict[str, dict] = {}
    for path in score_files(set_dir, arm):
        scores.update(load_scores(path))
    return scores


def cmd_score(args) -> int:
    set_dir = Path(args.set)
    frozen = set_dir / "frozen_set.jsonl"
    actual = file_sha256(frozen)
    if actual != args.expected_sha256:
        raise SystemExit(f"frozen set hash {actual} does not match the declared {args.expected_sha256}; refusing to score")
    items = read_shard_items(frozen, args.shards, args.shard)
    out = set_dir / f"scores_{args.arm}_s{args.shard}of{args.shards}.jsonl"
    runtime = Runtime(Path(args.release_dir), args.arm, Path(args.generated))
    expected_checksum = runtime.identity["artifact_checksum"]
    existing = load_scores(out) if out.exists() else {}
    done = set(existing)
    baselines = [i for i in items if i["variant"] == BASELINE]
    handle = out.open("a", encoding="utf-8", newline="\n")
    started = time.time()
    count = 0

    def run(item: dict) -> None:
        nonlocal count
        if item["vid"] in done:
            return
        record = score_record(item["vid"], runtime.analyse(item["text"], item["vid"]), expected_checksum)
        record["chars"] = len(item["text"])
        handle.write(canonical_line(record) + "\n")
        handle.flush()
        count += 1
        if count % 500 == 0:
            print(f"{args.arm} shard {args.shard}: {count} scored in {time.time() - started:.0f}s", flush=True)

    if args.phase in ("baseline", "all"):
        for item in baselines:
            run(item)
    if args.phase in ("variants", "all"):
        default_scores = load_arm_scores(set_dir, "defaults")
        protected_rows = {i["row_id"] for i in baselines
                          if args.all_rows or default_scores[i["vid"]]["action"] != "ALLOW"}
        for item in items:
            if item["variant"] == BASELINE or not item["applicable"] or item["row_id"] not in protected_rows:
                continue
            if args.max_items and count >= args.max_items:
                break
            run(item)
    handle.close()
    meta = {"arm": args.arm, "shard": args.shard, "shards": args.shards, "phase": args.phase, "flags": runtime.flags, "identity": runtime.identity, "release_files": runtime.release_files,
            "elapsed_s": time.time() - started, "scored_this_run": count, "frozen_set_sha256": actual}
    (set_dir / f"run_meta_{args.arm}_s{args.shard}of{args.shards}_{args.phase}.json").write_text(json.dumps(meta, indent=1, sort_keys=True), encoding="utf-8")
    return 0


# ---------------------------------------------------------------- analysis (pure)
def load_scores(path: Path) -> dict[str, dict]:
    return {r["vid"]: r for r in map(json.loads, path.read_text(encoding="utf-8").splitlines()) if r}


def evaluate_arm(items: list[dict], intended: dict[str, str], arm_scores: dict[str, dict], detect_level: bool = False) -> dict:
    """Pairs (row, variant) over applicable variants; ``after`` is None where the pair was not scored.

    ``detect_level`` ignores fail-closed errors: a protection that exists only because a layer
    errored (no layer found anything) is counted as ALLOW, i.e. as a missed detection.
    """
    pairs = []
    for item in items:
        if item["variant"] == BASELINE or not item["applicable"]:
            continue
        before = intended[item["row_id"]]
        record = arm_scores.get(item["vid"])
        pairs.append({"row": item["row_id"], "variant": item["variant"], "family": item["family"],
                      "before": before, "scored": record is not None,
                      "after": None if record is None else ("ALLOW" if detect_level and record["failed_closed"] else record["action"]),
                      "failed_closed": bool(record and record["failed_closed"])})
    return pairs


def summarise_pairs(pairs: list[dict]) -> dict:
    """Counts and rates for one group of applicable pairs (scored only when the original is protected)."""
    protected = [p for p in pairs if p["before"] != "ALLOW"]
    unscored = [p for p in protected if not p["scored"]]
    if unscored:
        raise ValueError(f"{len(unscored)} protected pairs have no score")
    evaded = sum(p["after"] == "ALLOW" for p in protected)
    block = [p for p in protected if p["before"] == "BLOCK"]
    downgraded = sum(p["after"] == "WARN" for p in block)
    return {"applicable": len(pairs),
            "protected_pairs": len(protected), "evaded": evaded,
            "asr_conditional": rate(evaded, len(protected)),
            "asr_unconditional": rate(evaded, len(pairs)),
            "block_pairs": len(block), "downgraded_block_to_warn": downgraded,
            "downgrade_rate": rate(downgraded, len(block)),
            "weakened_conditional": rate(evaded + downgraded, len(protected)),
            "failed_closed_after": sum(p["failed_closed"] for p in protected)}


def group_pairs(pairs: list[dict], key: str) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for pair in pairs:
        groups[pair[key]].append(pair)
    return dict(groups)


def cluster_bootstrap(pairs: list[dict], groups: dict[str, str], replicates: int = 2000, seed: int = SEED) -> tuple[float, float]:
    """95 % percentile interval of the conditional ASR, resampling whole source-document groups."""
    by_group: dict[str, list[dict]] = defaultdict(list)
    for pair in pairs:
        if pair["before"] != "ALLOW":
            by_group[groups[pair["row"]]].append(pair)
    keys = sorted(by_group)
    if not keys:
        return (float("nan"), float("nan"))
    stats = {k: (sum(p["after"] == "ALLOW" for p in by_group[k]), len(by_group[k])) for k in keys}
    rng = random.Random(seed)
    values = []
    for _ in range(replicates):
        k_sum = n_sum = 0
        for _i in range(len(keys)):
            k, n = stats[keys[rng.randrange(len(keys))]]
            k_sum += k
            n_sum += n
        values.append(k_sum / n_sum if n_sum else 0.0)
    values.sort()
    return (values[int(0.025 * replicates)], values[int(0.975 * replicates) - 1])


def per_row_any(pairs: list[dict]) -> dict:
    rows: dict[str, bool] = {}
    for pair in pairs:
        if pair["before"] != "ALLOW":
            rows[pair["row"]] = rows.get(pair["row"], False) or pair["after"] == "ALLOW"
    return rate(sum(rows.values()), len(rows))


def analyse(set_dir: Path, manifest: dict | None = None) -> dict:
    manifest = manifest or json.loads((set_dir / "manifest.json").read_text(encoding="utf-8"))
    items = read_jsonl(set_dir / "frozen_set.jsonl")
    scores = {arm: load_arm_scores(set_dir, arm) for arm in ARMS}
    return analyse_from(items, scores, manifest)


def analyse_from(items: list[dict], scores: dict[str, dict], manifest: dict) -> dict:
    baseline_items = [i for i in items if i["variant"] == BASELINE]
    intended = {i["row_id"]: scores["defaults"][i["vid"]]["action"] for i in baseline_items}
    sources = manifest["row_source"]
    groups = manifest["row_group"]
    variants_meta = manifest["variants"]
    n_rows = len(baseline_items)
    protected_rows = [r for r, a in intended.items() if a != "ALLOW"]

    def baseline_block(arm: str) -> dict:
        actions = Counter(scores[arm][i["vid"]]["action"] for i in baseline_items)
        by_source = {}
        for source in sorted(set(sources.values())):
            rows = [i for i in baseline_items if sources[i["row_id"]] == source]
            kept = sum(scores[arm][i["vid"]]["action"] != "ALLOW" for i in rows)
            by_source[source] = rate(kept, len(rows))
        layer_rates = {layer: rate(sum(scores[arm][i["vid"]]["layer_action"][layer] != "ALLOW" for i in baseline_items), n_rows)
                       for layer in LAYERS}
        return {"actions": {a: actions.get(a, 0) for a in ACTIONS}, "protected": rate(n_rows - actions.get("ALLOW", 0), n_rows),
                "by_source": by_source, "layer_nonallow_rate_when_run": layer_rates,
                "errored_rows": sum(bool(scores[arm][i["vid"]]["errored"]) for i in baseline_items)}

    result = {"rows": n_rows, "protected_rows": len(protected_rows), "arms": {},
              "baseline": {arm: baseline_block(arm) for arm in ARMS},
              "intended_actions": {a: sum(v == a for v in intended.values()) for a in ACTIONS}}
    for arm in ARMS:
        arm_result = {}
        for level_name, detect_level in (("action_level", False), ("detection_level", True)):
            pairs = evaluate_arm(items, intended, scores[arm], detect_level=detect_level)
            by_variant = {v: summarise_pairs(g) for v, g in sorted(group_pairs(pairs, "variant").items())}
            by_family = {f: summarise_pairs(g) for f, g in sorted(group_pairs(pairs, "family").items())}
            keep = [p for p in pairs if not variants_meta[p["variant"]]["value_removing"]]
            overall = summarise_pairs(pairs)
            overall_excl = summarise_pairs(keep)
            low, high = cluster_bootstrap(pairs, groups)
            overall["asr_conditional_cluster_bootstrap_95"] = [low, high]
            low, high = cluster_bootstrap(keep, groups)
            overall_excl["asr_conditional_cluster_bootstrap_95"] = [low, high]
            arm_result[level_name] = {
                "overall": overall, "overall_excluding_value_removing": overall_excl,
                "by_family": by_family, "by_variant": by_variant,
                "best_of_all_variants_per_row": per_row_any(pairs)}
            if arm == "defaults" and level_name == "action_level":
                arm_result["by_source_overall"] = {
                    s: summarise_pairs([p for p in pairs if sources[p["row"]] == s]) for s in sorted(set(sources.values()))}
        result["arms"][arm] = arm_result
    # paired comparison of the two arms (action level): same pairs, discordance on evasion
    paired = {}
    d_pairs = {(p["row"], p["variant"]): p for p in evaluate_arm(items, intended, scores["defaults"])}
    f_pairs = {(p["row"], p["variant"]): p for p in evaluate_arm(items, intended, scores["flags"])}
    for scope, selector in (("overall", lambda p: True),) + tuple((f, (lambda f: lambda p: p["family"] == f)(f)) for f in tx.FAMILIES):
        b = c = both = neither = 0
        for key, dp in d_pairs.items():
            if dp["before"] == "ALLOW" or not selector(dp):
                continue
            d_ev, f_ev = dp["after"] == "ALLOW", f_pairs[key]["after"] == "ALLOW"
            b += d_ev and not f_ev
            c += f_ev and not d_ev
            both += d_ev and f_ev
            neither += (not d_ev) and (not f_ev)
        paired[scope] = {"evaded_defaults_only": b, "evaded_flags_only": c, "evaded_both": both, "evaded_neither": neither,
                         "exact_mcnemar_p": exact_mcnemar(b, c)}
    result["paired_arms"] = paired
    # fail-closed: protection that exists only because a layer errored
    result["fail_closed"] = {arm: {
        "baseline_rows_error": sum(bool(scores[arm][i["vid"]]["errored"]) for i in baseline_items),
        "scored_pairs_error": sum(bool(r["errored"]) for v, r in scores[arm].items() if not v.endswith("::" + BASELINE)),
        "scored_pairs_failed_closed": sum(r["failed_closed"] for v, r in scores[arm].items() if not v.endswith("::" + BASELINE)),
        "scored_pairs": sum(1 for v in scores[arm] if not v.endswith("::" + BASELINE))} for arm in ARMS}
    result["layer_status_counts"] = {arm: {layer: dict(Counter(r["layer_status"][layer] for r in scores[arm].values()))
                                           for layer in LAYERS} for arm in ARMS}
    return result


# ---------------------------------------------------------------- command line
def analyse_control(items: list[dict], scores: dict[str, dict]) -> dict:
    """Non-ALLOW rates of the product on benign rows, baseline and applicable variants, per arm."""
    out: dict = {}
    for arm in ARMS:
        by_variant: dict[str, list[dict]] = defaultdict(list)
        for item in items:
            if item["applicable"]:
                by_variant[item["variant"]].append(scores[arm][item["vid"]])
        out[arm] = {v: {"non_allow": rate(sum(r["action"] != "ALLOW" for r in recs), len(recs)),
                        "block": rate(sum(r["action"] == "BLOCK" for r in recs), len(recs)),
                        "non_allow_detection_level": rate(sum((r["action"] != "ALLOW") and not r["failed_closed"] for r in recs), len(recs)),
                        "failed_closed": sum(r["failed_closed"] for r in recs)}
                     for v, recs in sorted(by_variant.items())}
    return out


def cmd_analyse(args) -> int:
    set_dir = Path(args.set)
    manifest = json.loads((set_dir / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("benign_control"):
        items = read_jsonl(set_dir / "frozen_set.jsonl")
        scores = {arm: load_arm_scores(set_dir, arm) for arm in ARMS}
        payload = {"record": RECORD_ID, "control": True, "frozen_set_sha256": manifest["frozen_set_sha256"],
                   "manifest": {k: v for k, v in manifest.items() if k not in ("row_group", "row_source")},
                   "results": analyse_control(items, scores)}
        Path(args.out_json).write_text(json.dumps(payload, indent=1, sort_keys=True), encoding="utf-8")
        print(f"wrote {args.out_json}")
        return 0
    result = analyse(set_dir, manifest)
    payload = {"record": RECORD_ID, "seed": SEED, "frozen_set_sha256": manifest["frozen_set_sha256"],
               "manifest": {k: v for k, v in manifest.items() if k not in ("row_group", "row_source")},
               "results": result}
    for arm in ARMS:
        metas = sorted(set_dir.glob(f"run_meta_{arm}_s*.json"))
        if metas:
            payload.setdefault("run_meta", {})[arm] = [json.loads(m.read_text(encoding="utf-8")) for m in metas]
    Path(args.out_json).write_text(json.dumps(payload, indent=1, sort_keys=True), encoding="utf-8")
    print(f"wrote {args.out_json}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("--seed-file", required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--per-source", type=int, default=None)
    b.add_argument("--verify-seed-sha", action="store_true")
    b.add_argument("--benign", action="store_true", help="build the specificity control from clean rows")
    b.set_defaults(fn=cmd_build)
    s = sub.add_parser("score")
    s.add_argument("--set", required=True)
    s.add_argument("--expected-sha256", required=True)
    s.add_argument("--arm", choices=ARMS, required=True)
    s.add_argument("--release-dir", required=True)
    s.add_argument("--generated", required=True)
    s.add_argument("--max-items", type=int, default=0)
    s.add_argument("--all-rows", action="store_true", help="score every applicable variant (benign control)")
    s.add_argument("--shard", type=int, default=0)
    s.add_argument("--shards", type=int, default=1)
    s.add_argument("--phase", choices=("baseline", "variants", "all"), default="all")
    s.set_defaults(fn=cmd_score)
    a = sub.add_parser("analyse")
    a.add_argument("--set", required=True)
    a.add_argument("--out-json", required=True)
    a.set_defaults(fn=cmd_analyse)
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
