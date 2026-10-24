# Detector-layer latency of the Wave 3 configurations (2026-10-25)

Scope: **host-process detector-layer latency** (regex and NER, in-process, host Python). It is **not** installed-client end-to-end latency (the installed-browser study is separate) and not LLM or semantic-layer latency. Pre-registration promotion criterion 5 (latency) consumes this record.

User instruction (24 Oct 2026): "Test all of these in parallel and integrate promising ones" (items 1-7), "including the full-product rerun"; Wave 3 configurations as frozen in `docs/research/fresh-sets-freeze-addendum-20261024.md` section 5.

## Method
- Harness `evaluation/detector_latency.py` (unit tests `evaluation/tests/test_detector_latency.py`). Aggregate and per-run data: `docs/experiments/detector-latency-20261025.json`.
- Input: 1,000 prompts = all 502 development rows + 498 rows sampled (seed 20261025) from personalized+openai synthetic. No fresh set, no `final.jsonl`. Text sha256 `88727a7e...da7de`; mean 134 chars, median 124.5, max 922.
- Trees: O = export of `e6c177ff`, N = `e70e3a2e`, C = `058942e0` (research/w3-candidate); flag variables exactly as in the addendum (N+strip/digits/email/caseless/all via the four PRIVOKE_* flags; N+lg and N+trf via `PRIVOKE_NER_MODEL`). sm, lg: `.venv-v1-v3-pipeline`; trf: `.venv-ner-models`. spaCy 3.7.5, en_core_web_sm/lg 3.7.1, trf 3.7.3, torch 2.11.
- One fresh worker process per (configuration, repeat); 9 configurations x 3 repeats, order randomised per repeat block (seed 20261025). Per worker: cold start (parent spawn to first `analyse_text` result: interpreter, imports, model load, first call); 50 warm-up prompts; then three timed passes over the 1,000 prompts: `layers=["regex","ner"], regex_first=False` (combined, the pipeline's own layer thread pool), `["regex"]` alone, `["ner"]` alone. Every call asserts the returned layer list and status. Native math threads pinned to 1 (OMP/MKL/OPENBLAS, torch.set_num_threads(1)).
- Peak RSS = peak working set of the worker. Reported per-configuration figures are medians of the three repeat-level statistics.
- Host: Intel Core i7-13700KF (16 cores / 24 threads), 63.8 GB RAM, Windows 11, power plan Ultimate Performance.

## Results (ms per prompt, median of 3 repeats)
| Config | Cold start s (median; repeat 0) | Combined median | Combined p95 | Combined p99 | Combined mean | Regex alone median | NER alone median | Peak RSS MB |
|---|---|---|---|---|---|---|---|---|
| O | 4.4; 4.5 | 27.3 | 33.9 | 81.2 | 28.3 | 23.05 | 3.3 | 383 |
| N | 4.6; 4.6 | 27.5 | 36.4 | 83.7 | 29.2 | 23.51 | 3.7 | 387 |
| N+strip | 4.3; 7.2 | 26.9 | 33.4 | 82.0 | 28.0 | 23.0 | 3.5 | 388 |
| N+digits | 4.6; 4.6 | 27.8 | 37.8 | 85.0 | 29.7 | 23.43 | 3.8 | 388 |
| N+email | 4.4; 4.6 | 27.4 | 34.6 | 84.1 | 28.7 | 23.45 | 3.7 | 388 |
| N+caseless | 4.3; 4.6 | 27.2 | 33.9 | 81.9 | 28.3 | 22.9 | 3.5 | 388 |
| N+all | 4.5; 4.6 | 27.4 | 34.0 | 82.4 | 28.4 | 23.27 | 3.6 | 388 |
| N+lg | 5.0; 9.7 | 27.6 | 34.5 | 84.4 | 28.8 | 23.38 | 3.8 | 1149 |
| N+trf | 6.0; 53.6 | 77.6 | 153.7 | 386.9 | 88.0 | 23.14 | 54.5 | 2792 |

Incremental cost (median combined / p95 combined / cold median / RSS):
- N vs O: +0.24 ms / +2.5 ms / +0.19 s / +4 MB.
- N+strip, +digits, +email, +caseless, +all vs N: median -0.6 to +0.26 ms, p95 -2.95 to +1.46 ms, RSS +0.5 to +1.1 MB. All within run-to-run noise (the O/N/N+R spread across repeats is about 1 ms); the flags add no measurable cost.
- N+lg vs N: +0.07 ms median, -1.8 ms p95, cold +0.4 s (+5 s on the first, file-cache-cold run), +762 MB.
- N+trf vs N: +50.1 ms median, +117 ms p95, p99 387 ms (+303 ms), +58.7 ms mean, cold +1.45 s warm-cache (53.6 s on the first run, loading from disk), +2.4 GB.

## Observations and caveats
- Regex dominates runtime (about 23 ms per prompt versus 3.5 ms for NER sm); the combined call runs layers in parallel threads, so combined latency tracks the slower layer (regex) except for trf, where NER (54 ms) dominates. The sum of the separate layer medians does not equal the combined median by design.
- Only trf changes latency materially; lg changes memory and cold start only.
- Cold start repeat 0 of the first config to use a model (strip, lg, trf) includes OS file-cache effects (7.2, 9.7, 53.6 s); later repeats are warm-cache. Cold start therefore measures a warm-disk-cache process start, except where stated.
- Contention: before each run the harness requires no other python process and system CPU load <= 25 % over 3 s (background desktop apps held 5-24 %). It paused twice before launching (loads 28 % and 45 %) and then waited. Pre-run loads of the 27 timed runs: max 20.4 %; post-run loads up to 44 %, recorded per run in the JSON. No other python process was present at any check; the machine was not otherwise quiescent (browser/desktop apps), so absolute values may be slightly inflated; the first repeat shows the highest p95 values (see JSON). A first attempt (pilot) was aborted at a 54 % load spike before it was resumed by restarting; its eight results were discarded, not used.
- Single machine, one dataset of short prompts (median 125 chars); the sm/lg/regex paths are Python-bound and pinned math threads may understate multi-threaded trf speed. Peak working set includes interpreter and imported libraries.
