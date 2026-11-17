"""Plan fresh, never-scored evaluation data (stdlib only, no network).

Subcommands
-----------
power  Exact paired-test power / sample-size tables for the fresh-set design.
draw   Draw a balanced, group-disjoint sample from a LOCAL copy of the pinned PIIMB
       ``data/test_sentences.jsonl`` file, excluding every group id listed in the
       supplied exclusion files.
scan   Collect every PIIMB group-id token found in json/jsonl artifacts under given roots
       (tokens only, never text) to extend the exclusion set with groups used for
       training, validation or earlier studies.
hash   Print the sha256 of the sorted, newline-joined group ids of an exclusion file.

The draw never contacts the network.  It mirrors the row filters of
``privoke_eval.datasets.load_piimb`` (English only, valid entity offsets, NFC/strip
text normalisation, identical-text duplicates and conflicting duplicate labels removed)
but caps sentences per source document (default one) and ranks rows by a seeded hash
instead of file-order reservoir sampling, so the result does not depend on row order.
Entity spans are re-based onto the stored (stripped, NFC) text so that span-level
scoring is possible; the locked partitions did not store spans.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
import unicodedata
from collections import Counter
from pathlib import Path

PIIMB_REVISION = "4a13e9ffe6fd0d275efbde8afd4d8d8f1ffc2133"
PIIMB_SENTENCES_SHA256 = "5ff46f3a80316318794f94596fa374060d70f2f32a85909f958cbabc70bae41f"
PIIMB_SENTENCES_BYTES = 60412185
ENGLISH = {"en", "eng", "english", "en-us", "en-gb", "en-ca"}
GROUP_TOKEN = re.compile(r"(?:piimb:)?((?:nemotron-pii|ai4privacy-en|ai4privacy-multi|ai4privacy|gretel|privy|mapa-eur-lex-pii|mapa-eur-lex):[A-Za-z0-9_.\-]+)")


# ---------------------------------------------------------------- statistics

_LF = [0.0]


def _log_factorial(n: int) -> float:
    while len(_LF) <= n:
        _LF.append(_LF[-1] + math.log(len(_LF)))
    return _LF[n]


def _binom_pmf_list(m: int, p: float) -> list[float]:
    """pmf of Binomial(m, p) for k = 0..m (log-space, no underflow of the start term)."""
    _log_factorial(m)
    if p <= 0.0:
        return [1.0] + [0.0] * m
    if p >= 1.0:
        return [0.0] * m + [1.0]
    lp, lq = math.log(p), math.log1p(-p)
    lfm = _LF[m]
    return [math.exp(lfm - _LF[k] - _LF[m - k] + k * lp + (m - k) * lq) for k in range(m + 1)]


_CRIT_CACHE: dict[tuple[int, float], int] = {}


def _critical_value(m: int, alpha: float) -> int:
    """Largest k with a two-sided exact sign-test p-value <= alpha (reject if x<=k or x>=m-k)."""
    key = (m, alpha)
    if key not in _CRIT_CACHE:
        pmf = _binom_pmf_list(m, 0.5)
        cumulative, k = 0.0, -1
        for j in range(m // 2 + 1):
            cumulative += pmf[j]
            if 2.0 * cumulative <= alpha:
                k = j
            else:
                break
        _CRIT_CACHE[key] = k
    return _CRIT_CACHE[key]


def mcnemar_power(n: int, delta: float, psi: float, alpha: float = 0.05) -> float:
    """Exact power of the two-sided exact McNemar test.

    n      number of paired items of the relevant class (negatives for specificity,
           positives for recall)
    delta  true improvement of the new configuration (p10 - p01), as a proportion
    psi    true discordant proportion (p10 + p01), psi >= |delta|
    """
    if psi < abs(delta) or psi <= 0.0 or psi > 1.0:
        raise ValueError("require 0 < psi <= 1 and psi >= |delta|")
    q = (psi + delta) / (2.0 * psi)
    mean = n * psi
    sd = math.sqrt(max(n * psi * (1 - psi), 1e-12))
    lo = max(1, int(mean - 7 * sd))
    hi = min(n, int(mean + 7 * sd) + 1)
    _log_factorial(n)
    lpsi, lqsi = math.log(psi), math.log1p(-psi) if psi < 1.0 else -math.inf
    total = 0.0
    for m in range(lo, hi + 1):
        k = _critical_value(m, alpha)
        if k < 0:
            continue
        weight = math.exp(_LF[n] - _LF[m] - _LF[n - m] + m * lpsi + (n - m) * lqsi)
        pmf = _binom_pmf_list(m, q)
        total += weight * (sum(pmf[: k + 1]) + sum(pmf[m - k:]))
    return min(1.0, total)


def required_n_mcnemar(delta: float, psi: float, power: float = 0.80, alpha: float = 0.05,
                       n_max: int = 400000) -> int:
    """Smallest n giving at least the target power, robust to the saw-tooth of the exact test.

    Bracket by doubling, bisect, then walk down while the power at the candidate and at
    +1 %/+2 % stays above the target.
    """
    hi = 32
    while mcnemar_power(hi, delta, psi, alpha) < power:
        hi *= 2
        if hi > n_max:
            raise ValueError("n_max exceeded")
    lo = hi // 2
    while hi - lo > max(1, hi // 200):
        mid = (lo + hi) // 2
        if mcnemar_power(mid, delta, psi, alpha) >= power:
            hi = mid
        else:
            lo = mid
    for candidate in range(lo, hi + 1):
        if all(mcnemar_power(candidate + int(candidate * f), delta, psi, alpha) >= power
               for f in (0.0, 0.01, 0.02)):
            return candidate
    return hi


def _norm_ppf(p: float) -> float:
    # Acklam's rational approximation; |relative error| < 1.2e-9.
    a = [-3.969683028665376e+01, 2.209460984245205e+02, -2.759285104469687e+02,
         1.383577518672690e+02, -3.066479806614716e+01, 2.506628277459239e+00]
    b = [-5.447609879822406e+01, 1.615858368580409e+02, -1.556989798598866e+02,
         6.680131188771972e+01, -1.328068155288572e+01]
    c = [-7.784894002430293e-03, -3.223964580411365e-01, -2.400758277161838e+00,
         -2.549732539343734e+00, 4.374664141464968e+00, 2.938163982698783e+00]
    d = [7.784695709041462e-03, 3.224671290700398e-01, 2.445134137142996e+00, 3.754408661907416e+00]
    if p < 0.02425:
        q = math.sqrt(-2 * math.log(p))
        return (((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) / ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1)
    if p > 1 - 0.02425:
        q = math.sqrt(-2 * math.log(1 - p))
        return -(((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) / ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1)
    q = p - 0.5
    r = q * q
    return (((((a[0]*r+a[1])*r+a[2])*r+a[3])*r+a[4])*r+a[5])*q / (((((b[0]*r+b[1])*r+b[2])*r+b[3])*r+b[4])*r+1)


def _norm_cdf(x: float) -> float:
    return 0.5 * math.erfc(-x / math.sqrt(2.0))


def noninferiority_n(true_delta: float, psi: float, margin: float, power: float = 0.80,
                     alpha: float = 0.025) -> int:
    """Paired non-inferiority sample size, Wald approximation.

    H0: d <= -margin   vs   H1: d > -margin, with d = new - old in recall (or specificity).
    Var(d_hat) = (psi - d^2) / n.  n = (z_{1-a} + z_{1-b})^2 * (psi - d^2) / (d + margin)^2.
    """
    gap = true_delta + margin
    if gap <= 0:
        raise ValueError("true_delta must exceed -margin")
    z = _norm_ppf(1 - alpha) + _norm_ppf(power)
    return math.ceil(z * z * (psi - true_delta ** 2) / (gap * gap))


def noninferiority_power(n: int, true_delta: float, psi: float, margin: float,
                         alpha: float = 0.025) -> float:
    se = math.sqrt(max(psi - true_delta ** 2, 1e-12) / n)
    return _norm_cdf((true_delta + margin) / se - _norm_ppf(1 - alpha))


def simulate_noninferiority(n: int, true_delta: float, psi: float, margin: float, trials: int = 4000,
                            alpha: float = 0.025, seed: int = 20261024) -> float:
    """Monte-Carlo check of the Wald NI test (multinomial paired outcomes)."""
    import random
    rng = random.Random(seed)
    p_gain = (psi + true_delta) / 2.0
    p_loss = (psi - true_delta) / 2.0
    z = _norm_ppf(1 - alpha)
    hits = 0
    for _ in range(trials):
        gain = loss = 0
        for _ in range(n):
            u = rng.random()
            if u < p_gain:
                gain += 1
            elif u < p_gain + p_loss:
                loss += 1
        d_hat = (gain - loss) / n
        var = max((gain + loss) / n - d_hat ** 2, 1e-12) / n
        if (d_hat + margin) / math.sqrt(var) > z:
            hits += 1
    return hits / trials


def cmd_power(args: argparse.Namespace) -> int:
    rows = []
    print("Superiority (exact two-sided McNemar, alpha=0.05, power=0.80): n = items of the class")
    print("delta = true gain (p10-p01), psi = discordant proportion")
    for delta in args.deltas:
        for psi in args.psis:
            if psi < delta:
                continue
            n = required_n_mcnemar(delta, psi, args.power)
            rows.append({"kind": "superiority", "delta": delta, "psi": psi, "n": n,
                         "power_at_n": round(mcnemar_power(n, delta, psi), 4)})
            print(f"  delta={delta:.3f} psi={psi:.3f} -> n={n:>7d} (power {rows[-1]['power_at_n']:.3f})")
    print(f"Non-inferiority (one-sided alpha=0.025, power={args.power}, margin={args.margin})")
    for true_delta in args.ni_deltas:
        for psi in args.psis:
            if psi < abs(true_delta):
                continue
            n = noninferiority_n(true_delta, psi, args.margin, args.power)
            rows.append({"kind": "non_inferiority", "delta": true_delta, "psi": psi,
                         "margin": args.margin, "n": n})
            print(f"  true_delta={true_delta:+.3f} psi={psi:.3f} -> n={n:>7d}")
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=1), encoding="utf-8")
    return 0


# ----------------------------------------------------------------- group sets

def load_group_set(path: Path) -> set[str]:
    """Read group ids from a JSON ({"groups": [...]}) or JSONL (group_id / metadata.group_id) file."""
    text = path.read_text(encoding="utf-8")
    groups: set[str] = set()
    if path.suffix == ".json":
        payload = json.loads(text)
        items = payload.get("groups", []) if isinstance(payload, dict) else payload
        groups.update(str(item) for item in items)
        return groups
    for line in text.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        group = row.get("group_id") or (row.get("metadata") or {}).get("group_id")
        if group is not None:
            groups.add(str(group))
    return groups


def normalise_group(token: str) -> str:
    token = token[len("piimb:"):] if token.startswith("piimb:") else token
    return re.sub(r"_s\d+$", "", token)


def groups_sha256(groups: set[str]) -> str:
    return hashlib.sha256("\n".join(sorted(groups)).encode()).hexdigest()


_SCAN_CHUNK = 16 * 1024 * 1024
_SCAN_OVERLAP = 512


def scan_file_groups(path: str) -> set[str]:
    """Group-id tokens (normalised) found in one file; read in chunks, never keeps text."""
    import gzip
    found: set[str] = set()
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="ignore") as handle:
        carry = ""
        block = handle.read(_SCAN_CHUNK)
        while block:
            following = handle.read(_SCAN_CHUNK)
            window = carry + block
            for match in GROUP_TOKEN.finditer(window):
                # A match touching the window end may be cut off; the next window re-finds it whole.
                if following and match.end() == len(window):
                    continue
                found.add(normalise_group(match.group(1)))
            carry = window[-_SCAN_OVERLAP:]
            block = following
    return found


def _scan_worker(path: str) -> tuple[str, list[str] | None]:
    try:
        return path, sorted(scan_file_groups(path))
    except OSError:
        return path, None


SCAN_SUFFIXES = (".json", ".jsonl", ".json.gz", ".jsonl.gz", ".csv", ".tsv", ".csv.gz", ".tsv.gz")
SCAN_NOT_READ_SUFFIXES = (".parquet", ".bin", ".pt", ".pth", ".safetensors", ".onnx", ".npz", ".npy", ".pkl", ".whl",
                          ".gguf", ".ckpt")
SCAN_PRUNED_DIRS = ("__pycache__", "node_modules", ".git", "snapshots", "blobs")


def cmd_scan(args: argparse.Namespace) -> int:
    """Collect PIIMB group-id tokens (never text) from text data files under the roots.

    Reads json/jsonl/csv/tsv (optionally gzip) up to --max-bytes; counts, but does not read, parquet and binary
    weight formats; prunes virtual environments, .git and Hugging Face cache directories.
    """
    import os
    from collections import defaultdict
    from multiprocessing import Pool
    skip_files = {os.path.normcase(os.path.abspath(p)) for p in args.skip}
    skip_dirs = [os.path.normcase(os.path.abspath(p)) for p in args.skip_dir]
    coverage: Counter[str] = Counter()

    def walk_paths():
        for root in args.roots:
            for directory, dirnames, files in os.walk(root):
                norm_dir = os.path.normcase(os.path.abspath(directory))
                if any(norm_dir == d or norm_dir.startswith(d + os.sep) for d in skip_dirs):
                    coverage["skipped_dirs"] += 1
                    dirnames[:] = []
                    continue
                dirnames[:] = [d for d in dirnames if not (d.startswith(".venv") or d in SCAN_PRUNED_DIRS)]
                for name in files:
                    lowered = name.lower()
                    full = os.path.join(directory, name)
                    if lowered.endswith(SCAN_NOT_READ_SUFFIXES):
                        coverage["not_read:" + lowered.rsplit(".", 1)[-1]] += 1
                    elif lowered.endswith(SCAN_SUFFIXES):
                        if os.path.normcase(os.path.abspath(full)) in skip_files:
                            coverage["skipped_file_by_name"] += 1
                            continue
                        try:
                            if os.path.getsize(full) > args.max_bytes:
                                coverage["skipped_over_max_bytes"] += 1
                                continue
                        except OSError:
                            coverage["unreadable"] += 1
                            continue
                        coverage["queued:" + ("gz" if lowered.endswith(".gz") else lowered.rsplit(".", 1)[-1])] += 1
                        yield full

    found: set[str] = set()
    unreadable = 0
    scanned = 0
    per_top: dict[str, set[str]] = defaultdict(set)
    base = os.path.dirname(os.path.abspath(args.roots[0]))
    with Pool(args.workers) as pool:
        # Streamed: files are read while the (slow) directory walk is still running.
        for path, groups in pool.imap_unordered(_scan_worker, walk_paths(), chunksize=16):
            if groups is None:
                unreadable += 1
                continue
            scanned += 1
            found.update(groups)
            top = "/".join(os.path.relpath(os.path.abspath(path), base).replace("\\", "/").split("/")[:3])
            per_top[top].update(groups)
    Path(args.output).write_text(json.dumps({"groups": sorted(found)}), encoding="utf-8")
    summary = {"roots": [str(r) for r in args.roots], "skip_dirs": list(args.skip_dir), "skip_files": list(args.skip),
               "max_bytes": args.max_bytes, "files_read": scanned, "files_unreadable": unreadable,
               "coverage": dict(sorted(coverage.items())), "n_groups": len(found),
               "groups_sha256": groups_sha256(found),
               "top_level_dirs_with_groups": {k: len(v) for k, v in sorted(per_top.items()) if v}}
    if args.summary:
        Path(args.summary).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary))
    return 0


def cmd_hash(args: argparse.Namespace) -> int:
    groups = set()
    for path in args.files:
        groups |= load_group_set(Path(path))
    print(json.dumps({"n_groups": len(groups), "groups_sha256": groups_sha256(groups)}))
    return 0


# ----------------------------------------------------------------------- draw

def _parse_entities(value, raw_length: int):
    if value in (None, "", []):
        return []
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, list):
        raise ValueError("entities must be a list")
    out = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("non-object entity")
        start, end = item.get("start"), item.get("end")
        label = item.get("label") or item.get("type")
        if (isinstance(start, bool) or isinstance(end, bool) or not isinstance(start, int)
                or not isinstance(end, int) or start < 0 or end <= start or end > raw_length):
            raise ValueError("invalid entity offsets")
        if not label:
            raise ValueError("entity without label")
        out.append((start, end, str(label)))
    return out


def normalise_text_and_spans(raw: str, entities):
    """Mirror _example(): strip then NFC; re-base entity offsets onto the stored text."""
    stripped = raw.strip()
    lead = len(raw) - len(raw.lstrip())
    spans = []
    for start, end, label in entities:
        start, end = max(0, start - lead), min(len(stripped), end - lead)
        if end > start:
            spans.append((start, end, label))
    text = unicodedata.normalize("NFC", stripped)
    if text != stripped:
        spans = [(len(unicodedata.normalize("NFC", stripped[:s])), len(unicodedata.normalize("NFC", stripped[:e])), l)
                 for s, e, l in spans]
        spans = [(s, e, l) for s, e, l in spans if e > s]
    return text, spans


def _rank(seed: int, key: str) -> str:
    return hashlib.sha256(f"{seed}:{key}".encode()).hexdigest()


def cmd_draw(args: argparse.Namespace) -> int:
    source = Path(args.sentences)
    digest = hashlib.sha256()
    with source.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    if digest.hexdigest() != args.expect_sha256:
        raise SystemExit(f"sha256 mismatch: {digest.hexdigest()} != {args.expect_sha256}")
    excluded: set[str] = set()
    for path in args.exclude:
        excluded |= {normalise_group(g) for g in load_group_set(Path(path))}
    if not args.count_only and not args.output:
        raise SystemExit("--output is required unless --count-only is given.")
    output = Path(args.output) if args.output else None
    if output is not None and output.exists():
        raise SystemExit("Refusing to overwrite an existing fresh-set directory.")

    seen: dict[bytes, bool | None] = {}
    stats: Counter[str] = Counter()
    candidates: dict[tuple[bool, str], tuple[str, dict]] = {}  # (label, group) -> (rank, record)
    with source.open(encoding="utf-8") as handle:
        for index, line in enumerate(handle):
            if not line.strip():
                continue
            row = json.loads(line)
            stats["rows_seen"] += 1
            language = str(row.get("language", "")).strip().lower().replace("_", "-")
            if language not in ENGLISH:
                stats["non_english"] += 1
                continue
            raw = row.get("text")
            if not isinstance(raw, str) or not raw.strip():
                stats["malformed"] += 1
                continue
            try:
                entities = _parse_entities(row.get("entities"), len(raw))
            except (ValueError, json.JSONDecodeError):
                stats["malformed"] += 1
                continue
            text, spans = normalise_text_and_spans(raw, entities)
            has_pii = bool(entities)
            key = hashlib.blake2b(text.encode("utf-8"), digest_size=16).digest()
            if key in seen:
                stats["duplicate"] += 1
                if seen[key] is not None and seen[key] != has_pii:
                    seen[key] = None
                    stats["conflicting_duplicate"] += 1
                continue
            seen[key] = has_pii
            group = str(row.get("parent_id") or row.get("source_uid") or row.get("uid", index))
            if group in excluded or normalise_group(group) in excluded:  # privy ids are per-sentence uids ending in _sN
                stats["excluded_group"] += 1
                continue
            uid = str(row.get("uid", index))
            record = {"id": f"piimb:{uid}", "group_id": group, "text": text, "expected_has_pii": has_pii,
                      "expected_categories": sorted({label for _, _, label in spans}),
                      "entities": [{"start": s, "end": e, "label": l} for s, e, l in spans],
                      "source_dataset": row.get("source_dataset"), "task_name": row.get("task_name"),
                      "language": row.get("language"), "protocol_partition": args.name,
                      "text_blake2b": key.hex()}
            rank = _rank(args.seed, record["id"])
            kept = candidates.setdefault((has_pii, group), [])
            kept.append((rank, record))
            kept.sort(key=lambda item: item[0])
            del kept[args.max_per_group:]
            stats["eligible_rows"] += 1

    # Conflicting duplicates found late invalidate earlier candidates with that text key.
    conflicted = {k for k, v in seen.items() if v is None}
    candidates = {k: [item for item in v if bytes.fromhex(item[1]["text_blake2b"]) not in conflicted]
                  for k, v in candidates.items()}

    if args.count_only:
        report = {"cap": args.max_per_group, "exclusion_groups": len(excluded),
                  "exclusion_groups_sha256": groups_sha256(excluded), "population": dict(sorted(stats.items()))}
        for label, name in ((True, "positive"), (False, "clean")):
            kept_rows = [record for (lab, _), rows in candidates.items() if lab is label for _, record in rows]
            report[name] = {"rows": len(kept_rows), "groups": len({r["group_id"] for r in kept_rows}),
                            "by_source_rows": dict(sorted(Counter(r["source_dataset"] for r in kept_rows).items())),
                            "by_source_groups": dict(sorted(Counter(
                                src for src, _ in {(r["source_dataset"], r["group_id"]) for r in kept_rows}).items()))}
        print(json.dumps(report, indent=1))
        return 0

    chosen: list[dict] = []
    used_groups: set[str] = set()
    for label, quota in ((True, args.positives), (False, args.negatives)):
        pool = sorted((_rank(args.seed, "g:" + group), group, rows)
                      for (lab, group), rows in candidates.items()
                      if lab is label and rows and (args.share_groups_across_classes or group not in used_groups))
        available = sum(len(rows) for _, _, rows in pool)
        if available < quota:
            raise SystemExit(f"Only {available} eligible {'positive' if label else 'clean'} rows "
                             f"in {len(pool)} groups; {quota} requested.")
        taken = 0
        for _, group, rows in pool:
            if taken >= quota:
                break
            used_groups.add(group)
            for _, record in rows[: quota - taken]:
                chosen.append(record)
                taken += 1
    # PIIMB uids are not unique (distinct sentences can share a uid): keep ids unique by suffixing a text hash.
    id_counts = Counter(r["id"] for r in chosen)
    for record in chosen:
        if id_counts[record["id"]] > 1:
            record["id"] = f"{record['id']}#{record['text_blake2b'][:8]}"
    stats["ids_disambiguated"] = sum(1 for r in chosen if "#" in r["id"])
    chosen.sort(key=lambda r: _rank(args.seed, "o:" + r["id"]))
    for record in chosen:
        del record["text_blake2b"]
    per_group = Counter((r["expected_has_pii"], r["group_id"]) for r in chosen)
    if any(r["group_id"] in excluded or normalise_group(r["group_id"]) in excluded for r in chosen) or max(per_group.values()) > args.max_per_group:
        raise SystemExit("Post-selection check failed (excluded group or group cap exceeded).")

    output.mkdir(parents=True)
    content = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in chosen)
    (output / f"{args.name}.jsonl").write_text(content, encoding="utf-8")
    manifest = {
        "dataset": "piimb", "revision": PIIMB_REVISION, "source_file": "data/test_sentences.jsonl",
        "source_file_sha256": digest.hexdigest(), "seed": args.seed, "name": args.name,
        "quota": {"positives": args.positives, "negatives": args.negatives}, "max_per_group": args.max_per_group,
        "share_groups_across_classes": args.share_groups_across_classes,
        "groups_in_both_classes": len({r["group_id"] for r in chosen if r["expected_has_pii"]}
                                      & {r["group_id"] for r in chosen if not r["expected_has_pii"]}),
        "exclusion_files": [str(p) for p in args.exclude], "exclusion_groups": len(excluded),
        "exclusion_groups_sha256": groups_sha256(excluded),
        "population": dict(sorted(stats.items())),
        "selected": {"rows": len(chosen), "positives": sum(r["expected_has_pii"] for r in chosen),
                     "groups": len({r["group_id"] for r in chosen}),
                     "by_source": dict(Counter(f"{r['source_dataset']}|{'pii' if r['expected_has_pii'] else 'clean'}"
                                               for r in chosen)),
                     "entity_count": sum(len(r["entities"]) for r in chosen)},
        "output_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({k: manifest[k] for k in ("population", "selected", "output_sha256")}, indent=1))
    return 0


def _identity_sets(path: Path) -> tuple[set[str], set[str], set[bytes]]:
    """(normalised groups, ids, blake2b text keys) of a fresh-set JSONL file; text is only hashed, never kept."""
    groups: set[str] = set()
    ids: set[str] = set()
    texts: set[bytes] = set()
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            groups.add(normalise_group(str(row["group_id"])))
            ids.add(str(row["id"]).split("#", 1)[0])
            texts.add(hashlib.blake2b(row["text"].encode("utf-8"), digest_size=16).digest())
    return groups, ids, texts


def cmd_disjoint(args: argparse.Namespace) -> int:
    left, right = _identity_sets(Path(args.left)), _identity_sets(Path(args.right))
    report = {"left_groups": len(left[0]), "right_groups": len(right[0]),
              "shared_groups": len(left[0] & right[0]), "shared_ids": len(left[1] & right[1]),
              "shared_texts": len(left[2] & right[2])}
    print(json.dumps(report))
    return 0 if not (report["shared_groups"] or report["shared_ids"] or report["shared_texts"]) else 1


def cmd_ni_power(args: argparse.Namespace) -> int:
    """Non-inferiority power at a fixed n (Wald), with an optional cluster design effect and Monte-Carlo check."""
    rows = []
    for psi in args.psis:
        for true_delta in args.true_deltas:
            effective = int(args.n / args.design_effect)
            record = {"n": args.n, "design_effect": args.design_effect, "effective_n": effective, "psi": psi,
                      "true_delta": true_delta, "margin": args.margin,
                      "power_wald": round(noninferiority_power(effective, true_delta, psi, args.margin), 4),
                      "n_for_80pct": noninferiority_n(true_delta, psi, args.margin, 0.80)}
            if args.simulate:
                record["power_simulated"] = simulate_noninferiority(effective, true_delta, psi, args.margin,
                                                                   trials=args.simulate)
            rows.append(record)
            print(json.dumps(record))
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=1), encoding="utf-8")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("power")
    p.add_argument("--deltas", type=float, nargs="+", default=[0.005, 0.01, 0.02])
    p.add_argument("--psis", type=float, nargs="+", default=[0.01, 0.02, 0.04, 0.08])
    p.add_argument("--ni-deltas", type=float, nargs="+", default=[0.0, -0.005])
    p.add_argument("--margin", type=float, default=0.01)
    p.add_argument("--power", type=float, default=0.80)
    p.add_argument("--json")
    p.set_defaults(func=cmd_power)
    npw = sub.add_parser("ni-power", help="non-inferiority power at a fixed n")
    npw.add_argument("--n", type=int, required=True)
    npw.add_argument("--psis", type=float, nargs="+", required=True)
    npw.add_argument("--true-deltas", type=float, nargs="+", default=[0.0, -0.005])
    npw.add_argument("--margin", type=float, required=True)
    npw.add_argument("--design-effect", type=float, default=1.0)
    npw.add_argument("--simulate", type=int, default=0, help="Monte-Carlo trials (0 = skip)")
    npw.add_argument("--json")
    npw.set_defaults(func=cmd_ni_power)
    sc = sub.add_parser("scan")
    sc.add_argument("roots", nargs="+")
    sc.add_argument("--output", required=True)
    sc.add_argument("--workers", type=int, default=8)
    sc.add_argument("--max-bytes", type=int, default=500_000_000, help="files above this size are skipped and counted")
    sc.add_argument("--summary", help="write the coverage summary (roots, extensions, skipped counts) to this JSON file")
    sc.add_argument("--skip", nargs="*", default=[], help="files never to open (e.g. a held-out partition)")
    sc.add_argument("--skip-dir", nargs="*", default=[], help="directories never entered (e.g. the raw PIIMB download)")
    sc.set_defaults(func=cmd_scan)
    h = sub.add_parser("hash")
    h.add_argument("files", nargs="+")
    h.set_defaults(func=cmd_hash)
    d = sub.add_parser("draw")
    d.add_argument("--sentences", required=True, help="local data/test_sentences.jsonl at the pinned revision")
    d.add_argument("--expect-sha256", default=PIIMB_SENTENCES_SHA256)
    d.add_argument("--exclude", nargs="+", required=True, help="group-id files (json {groups:[]} or jsonl)")
    d.add_argument("--seed", type=int, required=True)
    d.add_argument("--positives", type=int, required=True)
    d.add_argument("--negatives", type=int, required=True)
    d.add_argument("--max-per-group", type=int, default=1,
                   help="cap on sentences per source document (analyse with the grouped bootstrap if > 1)")
    d.add_argument("--share-groups-across-classes", action="store_true",
                   help="last-resort relaxation: a source document may supply both positive and clean sentences "
                        "(still at most --max-per-group per class); analyse with the grouped bootstrap")
    d.add_argument("--name", default="piimb_fresh_v1")
    d.add_argument("--output", help="fresh-set directory to create (required unless --count-only)")
    d.add_argument("--count-only", action="store_true",
                   help="print the eligible pool (rows and groups per class and source at the given cap) and write nothing")
    d.set_defaults(func=cmd_draw)
    j = sub.add_parser("disjoint", help="count group, id and text overlaps between two fresh-set files (counts only)")
    j.add_argument("left")
    j.add_argument("right")
    j.set_defaults(func=cmd_disjoint)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
