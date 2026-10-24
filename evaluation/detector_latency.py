"""Host-process detector-layer latency harness (regex, NER; no semantic layer, no Docker, no network).

Scope: detector-layer latency of the frozen Wave 3 configurations measured in-process on the host.
This is NOT installed-client end-to-end latency and NOT LLM latency.

Orchestrator (``run``) spawns one fresh worker process per (configuration, repeat), in a seeded
block-randomised order, and checks CPU load before each. The worker (``worker``) measures:
  * cold start: parent spawn -> first ``analyse_text`` result (interpreter + imports + model load + first call),
    split into import / detector construction / first call in the worker;
  * warm-up on 50 prompts, then per-prompt latency on the sample for ``layers=["regex","ner"]`` (combined,
    ``regex_first=False``, the pipeline's own layer thread pool), ``["regex"]`` alone and ``["ner"]`` alone;
  * peak working set of the process.
Native math threads are pinned to 1 (OMP/MKL/OPENBLAS; torch.set_num_threads(1) for the transformer model).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path

# Frozen environment variables per configuration: docs/research/fresh-sets-freeze-addendum-20261024.md section 5.
FLAG_ENV = ("PRIVOKE_STRIP_FORMAT_CHARS", "PRIVOKE_CANONICALISE_DIGITS", "PRIVOKE_CANONICALISE_EMAIL_WORDS",
            "PRIVOKE_NER_CASELESS_GATE", "PRIVOKE_NER_MODEL")
_ALL4 = {"PRIVOKE_STRIP_FORMAT_CHARS": "1", "PRIVOKE_CANONICALISE_DIGITS": "1",
         "PRIVOKE_CANONICALISE_EMAIL_WORDS": "1", "PRIVOKE_NER_CASELESS_GATE": "1"}
CONFIGS: dict[str, dict] = {
    "O": {"tree": "O", "env": {}, "venv": "sm"},
    "N": {"tree": "N", "env": {}, "venv": "sm"},
    "N+strip": {"tree": "C", "env": {"PRIVOKE_STRIP_FORMAT_CHARS": "1"}, "venv": "sm"},
    "N+digits": {"tree": "C", "env": {"PRIVOKE_CANONICALISE_DIGITS": "1"}, "venv": "sm"},
    "N+email": {"tree": "C", "env": {"PRIVOKE_CANONICALISE_EMAIL_WORDS": "1"}, "venv": "sm"},
    "N+caseless": {"tree": "C", "env": {"PRIVOKE_NER_CASELESS_GATE": "1"}, "venv": "sm"},
    "N+all": {"tree": "C", "env": dict(_ALL4), "venv": "sm"},
    "N+lg": {"tree": "C", "env": {"PRIVOKE_NER_MODEL": "en_core_web_lg"}, "venv": "sm"},
    "N+trf": {"tree": "C", "env": {"PRIVOKE_NER_MODEL": "en_core_web_trf"}, "venv": "trf"},
}
COMBINED = ["regex", "ner"]
WARMUP = 50
THREAD_VARS = ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "NUMEXPR_NUM_THREADS")


def load_jsonl(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def build_sample(data_root: Path, seed: int = 20261025, n_dev: int = 502, n_syn: int = 498) -> tuple[list[str], dict]:
    """All development rows plus a seeded sample of personalized/openai rows (never fresh sets, never final)."""
    dev_path = data_root / "evaluation/results/locked-public/development.jsonl"
    syn_paths = [data_root / "evaluation/datasets/privoke_personalized_synthetic.jsonl",
                 data_root / "evaluation/datasets/privoke_openai_synthetic.jsonl"]
    dev = load_jsonl(dev_path)
    if len(dev) != n_dev:
        raise SystemExit(f"development.jsonl has {len(dev)} rows, expected {n_dev}")
    syn = [row for path in syn_paths for row in load_jsonl(path)]
    picked = random.Random(seed).sample(range(len(syn)), n_syn)
    texts = [row["text"] for row in dev] + [syn[i]["text"] for i in picked]
    digest = hashlib.sha256("\n".join(texts).encode("utf-8")).hexdigest()
    lengths = [len(t) for t in texts]
    meta = {"seed": seed, "n": len(texts), "n_dev": len(dev), "n_synthetic": n_syn, "text_sha256": digest,
            "chars_mean": statistics.mean(lengths), "chars_median": statistics.median(lengths), "chars_max": max(lengths)}
    return texts, meta


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return float("nan")
    pos = (len(ordered) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


def summarise(ms: list[float]) -> dict:
    return {"n": len(ms), "median_ms": statistics.median(ms), "p95_ms": percentile(ms, 0.95),
            "p99_ms": percentile(ms, 0.99), "mean_ms": statistics.fmean(ms), "max_ms": max(ms)}


def peak_working_set_mb() -> float | None:
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD), ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t), ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t), ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t)]

    counters = Counters()
    counters.cb = ctypes.sizeof(Counters)
    handle = ctypes.windll.kernel32.GetCurrentProcess()
    ok = ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.c_void_p(handle), ctypes.byref(counters), counters.cb)
    return counters.PeakWorkingSetSize / 2**20 if ok else None


def timed_pass(analyse, texts: list[str], layers: list[str]) -> list[float]:
    out = []
    for text in texts:
        t0 = time.perf_counter()
        analysis = analyse(text, layers=layers, regex_first=False)
        out.append((time.perf_counter() - t0) * 1000.0)
        if [e.layer for e in analysis.layers] != layers or any(e.status != "ok" for e in analysis.layers):
            raise SystemExit(f"layer anomaly: requested {layers}, got "
                             f"{[(e.layer, e.status, getattr(e, 'error', None)) for e in analysis.layers]}")
    return out


def command_worker(args) -> None:
    t_start = time.time()
    p0 = time.perf_counter()
    cfg = CONFIGS[args.config]
    for key in FLAG_ENV:
        os.environ.pop(key, None)
    os.environ.update(cfg["env"])
    for var in THREAD_VARS:
        os.environ[var] = "1"
    tree = args.trees_root / cfg["tree"]
    sys.path[:0] = [str(tree / "extension/client-runtime"), str(tree / "shared/python"), str(args.generated)]
    import spacy  # noqa: F401  pre-import in the main thread
    try:
        import torch
        torch.set_num_threads(1)
    except Exception:  # torch is optional in the sm/lg environment
        pass
    from src import pipeline
    from src.config import GLOBAL_CONFIG
    from src.NER import EntityNERDetector
    from src.regex.rule_detector import RuleDetector
    p_import = time.perf_counter()
    texts = json.loads(Path(args.sample).read_text(encoding="utf-8"))["texts"]
    RuleDetector()
    EntityNERDetector()
    p_built = time.perf_counter()
    first = pipeline.analyse_text(texts[0], layers=COMBINED, regex_first=False)
    p_first = time.perf_counter()
    t_first = time.time()
    flags = {a: getattr(GLOBAL_CONFIG, a, None) for a in
             ("case_preserving_detectors", "ner_postfilter", "ner_model", "strip_format_chars", "canonicalise_digits",
              "canonicalise_email_words", "ner_caseless_gate")}
    layers_seen = [getattr(e, "layer", None) for e in first.layers]
    for text in texts[:WARMUP]:
        pipeline.analyse_text(text, layers=COMBINED, regex_first=False)
    analyse = pipeline.analyse_text
    result = {
        "config": args.config, "repeat": args.repeat, "t_start": t_start, "t_first_result": t_first,
        "worker_import_s": p_import - p0, "worker_build_s": p_built - p_import, "worker_first_call_s": p_first - p_built,
        "flags": flags, "layers_first_result": layers_seen,
        "combined": summarise(timed_pass(analyse, texts, COMBINED)),
        "regex": summarise(timed_pass(analyse, texts, ["regex"])),
        "ner": summarise(timed_pass(analyse, texts, ["ner"])),
        "peak_rss_mb": peak_working_set_mb(),
    }
    print("RESULT_JSON " + json.dumps(result))


def cpu_load_percent(seconds: float = 3.0) -> float | None:
    """System-wide CPU utilisation over ``seconds`` (Windows typeperf-free: GetSystemTimes)."""
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    def sample():
        idle, kernel, user = (wintypes.FILETIME() for _ in range(3))
        ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user))
        val = lambda f: (f.dwHighDateTime << 32) | f.dwLowDateTime
        return val(idle), val(kernel), val(user)

    a = sample()
    time.sleep(seconds)
    b = sample()
    idle, kernel, user = (b[i] - a[i] for i in range(3))
    total = kernel + user
    return 100.0 * (total - idle) / total if total else None


def other_python_processes() -> list[str]:
    """Python processes other than this one, its launcher parent and its own children (venv launchers)."""
    if os.name != "nt":
        return []
    me = os.getpid()
    cmd = ("Get-CimInstance Win32_Process | Where-Object {$_.Name -like 'python*'} | "
           "ForEach-Object { \"$($_.ProcessId) $($_.ParentProcessId) $($_.Name)\" }")
    rows = [line.split() for line in subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                                                    capture_output=True, text=True).stdout.splitlines() if line.strip()]
    parent_of_me = next((int(r[1]) for r in rows if int(r[0]) == me), -1)
    return [f"{r[0]} {r[2]}" for r in rows if int(r[0]) not in (me, parent_of_me) and int(r[1]) != me]


def environment_record() -> dict:
    rec = {"python_orchestrator": sys.version, "platform": platform.platform(), "cpu_count_logical": os.cpu_count()}
    if os.name == "nt":
        def ps(cmd):
            return subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True).stdout.strip()
        rec["cpu"] = ps("(Get-CimInstance Win32_Processor).Name")
        rec["cores_physical"] = ps("(Get-CimInstance Win32_Processor).NumberOfCores")
        rec["ram_gb"] = ps("[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB,1)")
        rec["power_plan"] = subprocess.run(["powercfg", "/getactivescheme"], capture_output=True, text=True).stdout.strip()
    return rec


def package_versions(python: Path) -> dict:
    code = ("import importlib.metadata as m,sys,json;names=['spacy','thinc','numpy','torch','spacy-transformers',"
            "'en-core-web-sm','en-core-web-lg','en-core-web-trf','presidio-analyzer'];out={'python':sys.version.split()[0]}\n"
            "for n in names:\n"
            "    try: out[n]=m.version(n)\n"
            "    except Exception: pass\n"
            "print(json.dumps(out))")
    return json.loads(subprocess.run([str(python), "-c", code], capture_output=True, text=True).stdout)


def command_run(args) -> None:
    texts, meta = build_sample(args.data_root)
    sample_path = args.scratch / "sample.json"
    args.scratch.mkdir(parents=True, exist_ok=True)
    sample_path.write_text(json.dumps({"texts": texts}), encoding="utf-8")
    pythons = {"sm": args.data_root / "evaluation/.venv-v1-v3-pipeline/Scripts/python.exe",
               "trf": args.data_root / "evaluation/.venv-ner-models/Scripts/python.exe"}
    configs = args.configs or list(CONFIGS)
    rng = random.Random(args.order_seed)
    schedule = []
    for repeat in range(args.repeats):
        block = list(configs)
        rng.shuffle(block)
        schedule += [(c, repeat) for c in block]
    checkpoint = args.scratch / "checkpoint.json"
    state = json.loads(checkpoint.read_text(encoding="utf-8")) if checkpoint.exists() else {"runs": [], "checks": []}
    runs, checks = state["runs"], state["checks"]
    done = {(r["config"], r["repeat"]) for r in runs}
    for config, repeat in schedule:
        if (config, repeat) in done:
            continue
        cfg = CONFIGS[config]
        waits = 0
        while True:  # pause (do not time) while the machine is busy; record every busy observation
            others = other_python_processes()
            load = cpu_load_percent(3.0)
            busy = bool(others) or (load is not None and load > args.max_load)
            checks.append({"config": config, "repeat": repeat, "cpu_load_pct_before": load, "other_python": others,
                           "paused": busy})
            if not busy:
                break
            waits += 1
            print(f"PAUSED before {config} r{repeat}: load={load} other_python={others}", flush=True)
            if waits > args.max_waits:
                raise SystemExit("contention persisted; stopping")
            time.sleep(20)
        env = dict(os.environ)
        cmd = [str(pythons[cfg["venv"]]), "-u", str(Path(__file__).resolve()), "worker", "--config", config,
               "--repeat", str(repeat), "--sample", str(sample_path), "--trees-root", str(args.trees_root),
               "--generated", str(args.generated)]
        t_spawn = time.time()
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        marker = [line for line in proc.stdout.splitlines() if line.startswith("RESULT_JSON ")]
        if proc.returncode or not marker:
            raise SystemExit(f"worker failed for {config} r{repeat}: {proc.stderr[-2000:]}")
        result = json.loads(marker[0][len("RESULT_JSON "):])
        result["cold_start_s"] = result["t_first_result"] - t_spawn
        result["load_pct_before"] = load
        result["load_pct_after"] = cpu_load_percent(1.0)
        result["pauses_before"] = waits
        runs.append(result)
        checkpoint.write_text(json.dumps({"runs": runs, "checks": checks}), encoding="utf-8")
        print(f"{config} r{repeat}: cold {result['cold_start_s']:.2f}s combined median {result['combined']['median_ms']:.2f} ms "
              f"p95 {result['combined']['p95_ms']:.2f} rss {result['peak_rss_mb']:.0f} MB load {load:.1f}%", flush=True)
    after = {"cpu_load_pct_after": cpu_load_percent(3.0), "other_python": other_python_processes()}
    payload = {"scope": "host-process detector-layer latency (regex, NER); not installed-client end-to-end, not LLM",
               "sample": meta, "warmup_prompts": WARMUP, "repeats": args.repeats, "schedule": schedule,
               "order_seed": args.order_seed, "environment": environment_record(),
               "packages": {k: package_versions(v) for k, v in pythons.items()},
               "trees": {t: (args.trees_root / t / "EXPORT_SHA").read_text().strip() for t in ("O", "N", "C")},
               "contention_checks": checks, "after": after, "runs": runs, "aggregate": aggregate(runs)}
    args.out_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print("wrote", args.out_json)


def aggregate(runs: list[dict]) -> dict:
    """Per configuration: median across repeats of each statistic (and the range), cold start and memory."""
    out: dict[str, dict] = {}
    for config in dict.fromkeys(r["config"] for r in runs):
        mine = [r for r in runs if r["config"] == config]
        row: dict = {"repeats": len(mine), "cold_start_s": [r["cold_start_s"] for r in mine],
                     "peak_rss_mb": [r["peak_rss_mb"] for r in mine]}
        for part in ("combined", "regex", "ner"):
            row[part] = {k: {"median_of_repeats": statistics.median(r[part][k] for r in mine),
                             "min": min(r[part][k] for r in mine), "max": max(r[part][k] for r in mine)}
                         for k in ("median_ms", "p95_ms", "p99_ms", "mean_ms")}
        out[config] = row
    base = out.get("N")
    for config, row in out.items():
        for ref_name in ("N", "O"):
            ref = out.get(ref_name)
            if ref and config != ref_name and not (ref_name == "O" and config != "N"):
                row[f"delta_vs_{ref_name}"] = {
                    part: {k: row[part][k]["median_of_repeats"] - ref[part][k]["median_of_repeats"]
                           for k in ("median_ms", "p95_ms", "mean_ms")} for part in ("combined", "regex", "ner")}
                row[f"delta_vs_{ref_name}"]["cold_start_s"] = (statistics.median(row["cold_start_s"])
                                                              - statistics.median(ref["cold_start_s"]))
                row[f"delta_vs_{ref_name}"]["peak_rss_mb"] = (statistics.median(row["peak_rss_mb"])
                                                             - statistics.median(ref["peak_rss_mb"]))
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run")
    run.add_argument("--data-root", type=Path, required=True)
    run.add_argument("--trees-root", type=Path, required=True)
    run.add_argument("--generated", type=Path, required=True)
    run.add_argument("--scratch", type=Path, required=True)
    run.add_argument("--out-json", type=Path, required=True)
    run.add_argument("--repeats", type=int, default=3)
    run.add_argument("--order-seed", type=int, default=20261025)
    run.add_argument("--max-load", type=float, default=25.0)
    run.add_argument("--max-waits", type=int, default=90)
    run.add_argument("--configs", nargs="*", choices=sorted(CONFIGS))
    worker = sub.add_parser("worker")
    worker.add_argument("--config", choices=sorted(CONFIGS), required=True)
    worker.add_argument("--repeat", type=int, default=0)
    worker.add_argument("--sample", type=Path, required=True)
    worker.add_argument("--trees-root", type=Path, required=True)
    worker.add_argument("--generated", type=Path, required=True)
    args = parser.parse_args()
    {"run": command_run, "worker": command_worker}[args.cmd](args)


if __name__ == "__main__":
    main()
