# Detector-layer latency of the v3 rework configurations K and K+all (2026-10-25)

Scope: **host-process detector-layer latency** (regex + NER, in-process). Not installed-client end-to-end latency, not LLM latency. Registered latency criterion (promotion criterion 5): regression below 20 %. Same harness and method as `detector-latency-20261025.md` (`evaluation/detector_latency.py`, which gains configurations K and K+all and an `--allow-pids` option); data in `detector-latency-v3-20261025.json`.

Configurations: N = `e70e3a2e` (reference, re-timed in the same session); K = `research/wt-k-rework` `b7e716c3` (tree `59b92ab9`); K+all = `research/v3-candidate` `4e695783` with the four flags `PRIVOKE_STRIP_FORMAT_CHARS`, `PRIVOKE_CANONICALISE_DIGITS`, `PRIVOKE_CANONICALISE_EMAIL_WORDS`, `PRIVOKE_NER_CASELESS_GATE` set to 1 (freeze addendum v3). Same 1,000-prompt development sample (text sha256 `88727a7e...`), 50 warm-up prompts, 3 repeats, randomised order (seed 20261026), fresh worker per run, math threads pinned to 1, `sm` environment.

| Config | Cold start s (median) | Combined median ms | p95 | p99 | mean | Regex alone median | NER alone median | Peak RSS MB |
|---|---|---|---|---|---|---|---|---|
| N | 4.59 | 27.77 | 35.02 | 85.31 | 29.18 | 23.37 | 3.74 | 388 |
| K | 4.51 | 27.76 | 34.97 | 85.73 | 28.99 | 23.45 | 3.74 | 387 |
| K+all | 4.57 | 27.83 | 35.16 | 86.15 | 29.12 | 23.51 | 3.80 | 388 |

Incremental cost vs N (medians of 3 repeats): K -0.00 ms median, -0.05 ms p95, -0.19 ms mean, cold -0.08 s, RSS -0.5 MB; K+all +0.06 ms median (+0.2 %), +0.14 ms p95 (+0.4 %), -0.06 ms mean, cold -0.02 s, RSS +0.7 MB. Regex-layer alone: +0.08 ms (K), +0.13 ms (K+all) on 23.4 ms. All differences are far inside run-to-run noise (about 1 ms between repeats in the earlier session).

**Criterion 5 verdict (regression < 20 %): met for K and K+all.** Largest observed regression is +0.4 % (K+all p95 versus N); no measurable change in memory or cold start.

Contention: 10 pre-run checks (9 runs; one pause at 29.8 % system load before K+all repeat 2, then waited), max pre-run load 21.5 %, post-run loads 12-25 %. No unrelated python process other than the two tolerated foreign `server.py` processes (PIDs 7148, 40184; not stopped). Their CPU time rose by 0.00-0.02 s per run (idle) and is recorded per run in the JSON. Caveats as in the first record: single machine, other desktop apps present, short prompts, cold start in warm-file-cache conditions (K repeat 0: 8.1 s, first run of a new tree).
