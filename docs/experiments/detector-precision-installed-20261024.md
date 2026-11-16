# Installed detector precision: shipped-configuration evaluation (2026-10-24)

**Scope: detector layers only (regex + NER). This is not LLM-only or semantic evidence and not a full-pipeline measurement.**

## What is installed

Commit `6a0c9ca3` makes two switches default on: `PRIVOKE_CASE_PRESERVING_DETECTORS` (regex and NER receive case-preserved normalised text; semantic/LLM input stays lowercased) and `PRIVOKE_NER_POSTFILTER` (per-span cleaning plus category-combination rules over spaCy entities). Setting either variable to `0` disables it. The regex precision repairs (`docs/detectors/regex.md`, "Precision Rules") ship unconditionally.

Branch commits: regex repairs `ca565f19`, `dad5f30b`, `8db88e06`, `f6544774`; case-preserving option `a4bb58d1` (ablation record `6cf8e1cd`, `46d7cee8`); post-filter freeze `50fc51e6`; post-filter results v1 `de7b5a1a`; post-review fixes `89996623`; harness `4c26b52c`; v2 results `c4311b74`; defaults-on freeze `6a0c9ca3`; evaluation script `89c358fd`.

## Method

- Script: `evaluation/evaluate_installed_detectors.py`. Each prompt runs `pipeline.analyse_text(layers=["regex","ner"], regex_first=False)`; the layer list is explicit and never empty; no semantic layer; host Python (`evaluation/.venv-v1-v3-pipeline`, spaCy `en_core_web_sm`); no Docker. Runtime flags are not set by the script; the observed values are recorded in the JSON.
- Positive = any hit with sensitivity != S0, or with categories. Union = regex OR NER.
- **old default**: clean export of `e6c177ff` (original regex rules, lowercased input, no post-filter; flags absent). **new default**: this branch at `89c358fd` (differs from the freeze `6a0c9ca3` only by the evaluation script); observed flags both `true`.
- dev = `development.jsonl` (502 rows, 264 positive); TUNE/CHECK are its halves by `sha256(group_id) % 2` (same as `evaluation/compare_ner_postfilter.py`), computed from the same pass. Latency is the per-prompt mean of one sequential pass; timings are single-run.
- Dataset sha256: development `65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095`; personalized `fd045ac1bd77fa278ad207a1bc1208f71fced017b9ab4fc174a2074f7d8f1281`; openai `8e8e611b9d40f7d554726d577449585faefb9aec97f5dd4ffb051af1a6da2c3b`; final `613a78b9e5fa677904125b4c056fb8d57d15fb6ebd9c443a75f406ae3ac05515`.
- Aggregates: `detector-precision-installed-20261024.json` (beside this file).

## Held-out final: one-shot note

`final.jsonl` (498 rows, 236 positive) was scored once, after the defaults freeze, for both fixed configurations in the same session, using `--allow-final-once`. Only aggregate counts and timing were computed; no row was inspected and nothing was stored per row. No rule or code was changed afterwards, whatever the result.

### Regex only

| Split | n (pos) | Config | TP | TN | FP | FN | Recall | Specificity |
|---|---|---|---|---|---|---|---|---|
| dev (full) | 502 (264) | old default | 172 | 231 | 7 | 92 | 0.652 | 0.971 |
| dev (full) | 502 (264) | new default | 169 | 234 | 4 | 95 | 0.640 | 0.983 |
| dev-TUNE | 267 (148) | old default | 96 | 115 | 4 | 52 | 0.649 | 0.966 |
| dev-TUNE | 267 (148) | new default | 95 | 117 | 2 | 53 | 0.642 | 0.983 |
| dev-CHECK | 235 (116) | old default | 76 | 116 | 3 | 40 | 0.655 | 0.975 |
| dev-CHECK | 235 (116) | new default | 74 | 117 | 2 | 42 | 0.638 | 0.983 |
| personalized | 2000 (1000) | old default | 1000 | 977 | 23 | 0 | 1.000 | 0.977 |
| personalized | 2000 (1000) | new default | 1000 | 1000 | 0 | 0 | 1.000 | 1.000 |
| openai | 1000 (500) | old default | 460 | 346 | 154 | 40 | 0.920 | 0.692 |
| openai | 1000 (500) | new default | 448 | 466 | 34 | 52 | 0.896 | 0.932 |
| **held-out final** | 498 (236) | old default | 154 | 258 | 4 | 82 | 0.653 | 0.985 |
| **held-out final** | 498 (236) | new default | 151 | 261 | 1 | 85 | 0.640 | 0.996 |

### NER only

| Split | n (pos) | Config | TP | TN | FP | FN | Recall | Specificity |
|---|---|---|---|---|---|---|---|---|
| dev (full) | 502 (264) | old default | 55 | 232 | 6 | 209 | 0.208 | 0.975 |
| dev (full) | 502 (264) | new default | 65 | 230 | 8 | 199 | 0.246 | 0.966 |
| dev-TUNE | 267 (148) | old default | 35 | 117 | 2 | 113 | 0.236 | 0.983 |
| dev-TUNE | 267 (148) | new default | 41 | 115 | 4 | 107 | 0.277 | 0.966 |
| dev-CHECK | 235 (116) | old default | 20 | 115 | 4 | 96 | 0.172 | 0.966 |
| dev-CHECK | 235 (116) | new default | 24 | 115 | 4 | 92 | 0.207 | 0.966 |
| personalized | 2000 (1000) | old default | 800 | 1000 | 0 | 200 | 0.800 | 1.000 |
| personalized | 2000 (1000) | new default | 695 | 1000 | 0 | 305 | 0.695 | 1.000 |
| openai | 1000 (500) | old default | 145 | 492 | 8 | 355 | 0.290 | 0.984 |
| openai | 1000 (500) | new default | 85 | 497 | 3 | 415 | 0.170 | 0.994 |
| **held-out final** | 498 (236) | old default | 56 | 255 | 7 | 180 | 0.237 | 0.973 |
| **held-out final** | 498 (236) | new default | 50 | 253 | 9 | 186 | 0.212 | 0.966 |

### Union (regex OR NER)

| Split | n (pos) | Config | TP | TN | FP | FN | Recall | Specificity |
|---|---|---|---|---|---|---|---|---|
| dev (full) | 502 (264) | old default | 193 | 225 | 13 | 71 | 0.731 | 0.945 |
| dev (full) | 502 (264) | new default | 201 | 226 | 12 | 63 | 0.761 | 0.950 |
| dev-TUNE | 267 (148) | old default | 113 | 113 | 6 | 35 | 0.764 | 0.950 |
| dev-TUNE | 267 (148) | new default | 118 | 113 | 6 | 30 | 0.797 | 0.950 |
| dev-CHECK | 235 (116) | old default | 80 | 112 | 7 | 36 | 0.690 | 0.941 |
| dev-CHECK | 235 (116) | new default | 83 | 113 | 6 | 33 | 0.716 | 0.950 |
| personalized | 2000 (1000) | old default | 1000 | 977 | 23 | 0 | 1.000 | 0.977 |
| personalized | 2000 (1000) | new default | 1000 | 1000 | 0 | 0 | 1.000 | 1.000 |
| openai | 1000 (500) | old default | 471 | 343 | 157 | 29 | 0.942 | 0.686 |
| openai | 1000 (500) | new default | 459 | 463 | 37 | 41 | 0.918 | 0.926 |
| **held-out final** | 498 (236) | old default | 181 | 251 | 11 | 55 | 0.767 | 0.958 |
| **held-out final** | 498 (236) | new default | 180 | 252 | 10 | 56 | 0.763 | 0.962 |

### Mean latency, ms/prompt (regex + NER, sequential single process)

| Split | old | new |
|---|---|---|
| dev (full) | 45.9 | 46.3 |
| dev-TUNE | 46.7 | 46.1 |
| dev-CHECK | 45.1 | 46.5 |
| personalized | 47.6 | 47.4 |
| openai | 52.4 | 51.5 |
| **held-out final** | 44.3 | 46.5 |

## Reading the results

- Union on the held-out final is essentially unchanged: TP 181 to 180, FP 11 to 10 (specificity 0.958 to 0.962, recall 0.767 to 0.763). The gain is concentrated in regex-only specificity (FP 4 to 1 on final; 154 to 34 on openai; 23 to 0 on personalized), at a recall cost of 3 to 22 points on the synthetic openai set and about 1 point on dev and final.
- NER-only is not improved on the held-out final (FP 7 to 9, recall 0.237 to 0.212) and loses recall on the synthetic sets (openai 0.290 to 0.170). The post-filter and case preservation were tuned on dev-TUNE and personalized; on dev-CHECK the NER layer's FP count is unchanged (4) while its recall improves slightly. Net NER-layer benefit is therefore not established by this held-out run; the union result is dominated by regex.
- The trade-off is specificity for recall, as expected; claims should be limited to that.

## Limitations

- Single spaCy model (`en_core_web_sm`); results do not transfer to other NER models.
- Synthetic (personalized, openai) and PIIMB-derived labels are noisy; S1 counts as positive.
- dev-TUNE and personalized were design sets for the rules, so their gains are optimistic. dev-CHECK and openai were inspected after review of the first version (see `ner-postfilter-20261024.md`), so they are post-review, not fully blind. Only `final` is a clean one-shot.
- Detector-layer metrics ignore the semantic layer, regex-first short-circuiting and the enforcement policy, so they do not predict end-to-end product behaviour.
- Latency is a single sequential pass on one host.
