# NER model candidates: spaCy lg/trf and GLiNER PII small (2026-10-24)

**Scope: detector layers only (regex + NER). This is not LLM-only or semantic evidence and not a full-product measurement.** Every prompt ran through `pipeline.analyse_text(layers=["regex","ner"], regex_first=False)` with an explicit layer list (never empty, never semantic). `final.jsonl` was not opened; the harness cannot select it. Scouting and the download list: `docs/research/ner-model-candidates-20261024.md`.

## Goal and instructions

User instructions (24 Oct 2026): "Test all of these in parallel and integrate promising ones" (program item 5, NER model candidates); "you have my permission to download anything <5GB for testing, and if the tests are not integrated please delete the donwload". Question: does a stronger or differently-trained NER model improve the detector-layer union over the shipped `en_core_web_sm` + post-filter, with and without the post-filter?

## Method

- Backend: `PRIVOKE_NER_BACKEND=gliner` (default `spacy`, off), `src/NER/gliner_detector.py`, commit `398bc3d4`; spaCy models through the existing `PRIVOKE_NER_MODEL`. Configurations: `sm`, `lg`, `trf` (spaCy 3.7.5; `en_core_web_sm` 3.7.1, `en_core_web_lg` 3.7.1, `en_core_web_trf` 3.7.3) and `knowledgator/gliner-pii-small-v1.0` (gliner 0.2.29), each with the post-filter on (`pf1`) and off (`pf0`). Environment: `evaluation/.venv-ner-models` from `evaluation/requirements-ner-models.txt` (Python 3.11, torch 2.11.0 CPU wheel, transformers 4.57.6).
- GLiNER mapping (pre-registered before any scoring, `gliner_detector.py`): preset `core` asks for `name`, `location city/state/country/street/address`, `organization` and maps them to `PERSON`, `GPE`, `FAC`, `ORG`, so the existing use-case table and the post-filter apply unchanged (the post-filter gets a spaCy `Doc` from `en_core_web_sm` with its `ner` disabled and the GLiNER spans attached with `char_span(..., "expand")`). Preset `pii` adds 12 identifier labels (phone, email, ip, username, dob, ssn, passport, driver licence, password, credit card, account number, medical condition) emitted directly with fixed sensitivities (S2 contact-like, S3 government/financial/secret/health, mirroring the regex layer) and no post-filter. Grid: preset {core, pii} x threshold {0.3, 0.4, 0.5, 0.6, 0.7} x post-filter {on, off} = 20 GLiNER configurations; the model runs once per text and label set at threshold 0.3 and higher thresholds filter the cached spans (verified identical to direct runs: 321 comparisons over 120 dev-TUNE prompts and thresholds 0.4/0.5/0.7, 0 differences).
- Protocol (enforced in `evaluation/ner_model_study.py`): the **design** phase loads only dev-TUNE (`sha256(group_id) % 2 == 0`, n=267) and `personalized` (n=2000). `select` picked the GLiNER configuration on those splits only (highest mean union balanced accuracy, positive rule, ties by fewer design FP) and wrote `ner-models-20261024.freeze.json`. That file was **committed (freeze commit `f4f07c3c`) before** the **post-review** phase, which refuses to run unless the freeze file is committed and unmodified and loads only dev-CHECK (n=235) and `openai` (n=1000). dev-CHECK and `openai` are post-review, not strictly held-out (earlier work already measured the post-filter on them). The spaCy models have no tuned parameter; they were scored once per phase.
- Statistics: agent A's `detector_stats.py` (read-only, `wt-a-stats` at `bf5e24c1`): paired exact McNemar on positives and negatives, grouped (group_id) percentile bootstrap, 10,000 replicates, seed 20261024; baseline = shipped `sm-pf1`. Compact outputs in `ner-models-20261024.stats.json` (made with the `compact_comparison` version of the harness; the numerical code is unchanged).
- Reproduction checks: `sm-pf1` in the new environment reproduces the NEW-configuration cells of `ner-role-20261024.md` exactly (tune union 118/113/6/30, check 83/113/6/33, personalized 1000/1000/0/0); `lg-pf1` reproduces its NEW@lg rows (tune 120/112/7/28, check 87/117/2/29).
- Source SHAs: backend `398bc3d4`; harness at design time `fbf25e78` (design runs); freeze `f4f07c3c` (post-review runs). Datasets (sha256): development `65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095`, personalized `fd045ac1bd77fa278ad207a1bc1208f71fced017b9ab4fc174a2074f7d8f1281`, openai `8e8e611b9d40f7d554726d577449585faefb9aec97f5dd4ffb051af1a6da2c3b`.

Positive = any hit with sensitivity != S0 or with categories. "Union BLOCK" uses the runtime policy action (BLOCK only).

## Design splits (dev-TUNE, personalized): selection

Chosen and frozen: **`gliner-core-t0.5-pf1`** (preset `core`, threshold 0.5, post-filter on), mean union balanced accuracy 0.9280. The margin is tiny: `core` t0.3 0.9275, t0.4 0.9267, t0.6 0.9215 (`ner-models-20261024.freeze.json` has the full ranking). The `pii` preset was never competitive on the design splits (best `pii` configuration ranks 6th at 0.908): it adds recall (dev-TUNE NER-only recall 0.76 at t0.3) at a large specificity cost (personalized union specificity 0.79 at t0.3, 0.92 at t0.5) because identifier-shaped spans fire on benign numbers and the regex layer already owns most of them.

**dev-TUNE (n=267) and personalized (n=2000); selected configurations (the full 26-configuration grid is in the JSON)**

**tune**

| Config | NER TP | NER FP | NER recall | NER spec | Union TP | Union FP | Union recall | Union spec | Union BLOCK recall | Union BLOCK spec |
|---|---|---|---|---|---|---|---|---|---|---|
| sm-pf1 | 41 | 4 | 0.277 | 0.966 | 118 | 6 | 0.797 | 0.950 | 0.345 | 0.992 |
| sm-pf0 | 71 | 19 | 0.480 | 0.840 | 127 | 21 | 0.858 | 0.824 | 0.345 | 0.992 |
| lg-pf1 | 49 | 5 | 0.331 | 0.958 | 120 | 7 | 0.811 | 0.941 | 0.345 | 0.992 |
| lg-pf0 | 74 | 11 | 0.500 | 0.908 | 130 | 13 | 0.878 | 0.891 | 0.345 | 0.992 |
| trf-pf1 | 39 | 0 | 0.264 | 1.000 | 115 | 2 | 0.777 | 0.983 | 0.345 | 0.992 |
| trf-pf0 | 61 | 4 | 0.412 | 0.966 | 126 | 6 | 0.851 | 0.950 | 0.345 | 0.992 |
| gliner-core-t0.3-pf1 | 38 | 1 | 0.257 | 0.992 | 114 | 3 | 0.770 | 0.975 | 0.345 | 0.992 |
| gliner-core-t0.4-pf1 | 31 | 0 | 0.209 | 1.000 | 109 | 2 | 0.736 | 0.983 | 0.345 | 0.992 |
| gliner-core-t0.5-pf1 | 25 | 0 | 0.169 | 1.000 | 108 | 2 | 0.730 | 0.983 | 0.345 | 0.992 |
| gliner-core-t0.5-pf0 | 66 | 13 | 0.446 | 0.891 | 128 | 15 | 0.865 | 0.874 | 0.345 | 0.992 |
| gliner-core-t0.6-pf1 | 18 | 0 | 0.122 | 1.000 | 104 | 2 | 0.703 | 0.983 | 0.345 | 0.992 |
| gliner-core-t0.7-pf1 | 8 | 0 | 0.054 | 1.000 | 100 | 2 | 0.676 | 0.983 | 0.345 | 0.992 |
| gliner-pii-t0.3-pf1 | 112 | 12 | 0.757 | 0.899 | 128 | 14 | 0.865 | 0.882 | 0.493 | 0.899 |
| gliner-pii-t0.5-pf1 | 85 | 6 | 0.574 | 0.950 | 112 | 8 | 0.757 | 0.933 | 0.466 | 0.958 |
| gliner-pii-t0.7-pf1 | 39 | 1 | 0.264 | 0.992 | 100 | 3 | 0.676 | 0.975 | 0.385 | 0.983 |

**personalized**

| Config | NER TP | NER FP | NER recall | NER spec | Union TP | Union FP | Union recall | Union spec | Union BLOCK recall | Union BLOCK spec |
|---|---|---|---|---|---|---|---|---|---|---|
| sm-pf1 | 695 | 0 | 0.695 | 1.000 | 1000 | 0 | 1.000 | 1.000 | 0.928 | 1.000 |
| sm-pf0 | 871 | 81 | 0.871 | 0.919 | 1000 | 81 | 1.000 | 0.919 | 0.928 | 1.000 |
| lg-pf1 | 756 | 0 | 0.756 | 1.000 | 1000 | 0 | 1.000 | 1.000 | 0.928 | 1.000 |
| lg-pf0 | 835 | 81 | 0.835 | 0.919 | 1000 | 81 | 1.000 | 0.919 | 0.928 | 1.000 |
| trf-pf1 | 763 | 0 | 0.763 | 1.000 | 1000 | 0 | 1.000 | 1.000 | 0.928 | 1.000 |
| trf-pf0 | 777 | 24 | 0.777 | 0.976 | 1000 | 24 | 1.000 | 0.976 | 0.928 | 1.000 |
| gliner-core-t0.3-pf1 | 777 | 35 | 0.777 | 0.965 | 1000 | 35 | 1.000 | 0.965 | 0.928 | 1.000 |
| gliner-core-t0.4-pf1 | 777 | 13 | 0.777 | 0.987 | 1000 | 13 | 1.000 | 0.987 | 0.928 | 1.000 |
| gliner-core-t0.5-pf1 | 777 | 1 | 0.777 | 0.999 | 1000 | 1 | 1.000 | 0.999 | 0.928 | 1.000 |
| gliner-core-t0.5-pf0 | 789 | 438 | 0.789 | 0.562 | 1000 | 438 | 1.000 | 0.562 | 0.928 | 1.000 |
| gliner-core-t0.6-pf1 | 766 | 0 | 0.766 | 1.000 | 1000 | 0 | 1.000 | 1.000 | 0.928 | 1.000 |
| gliner-core-t0.7-pf1 | 664 | 0 | 0.664 | 1.000 | 1000 | 0 | 1.000 | 1.000 | 0.928 | 1.000 |
| gliner-pii-t0.3-pf1 | 1000 | 214 | 1.000 | 0.786 | 1000 | 214 | 1.000 | 0.786 | 1.000 | 0.897 |
| gliner-pii-t0.5-pf1 | 1000 | 78 | 1.000 | 0.922 | 1000 | 78 | 1.000 | 0.922 | 0.943 | 0.946 |
| gliner-pii-t0.7-pf1 | 926 | 29 | 0.926 | 0.971 | 1000 | 29 | 1.000 | 0.971 | 0.928 | 0.995 |


## Post-review splits (dev-CHECK, openai): frozen configuration and spaCy models

The frozen GLiNER configuration and its post-filter-off twin, and the spaCy models with the post-filter on and off, were each scored once. NER = NER layer alone; Union = regex OR NER.

**check**

| Config | NER TP | NER FP | NER recall | NER spec | Union TP | Union FP | Union recall | Union spec | Union BLOCK recall | Union BLOCK spec |
|---|---|---|---|---|---|---|---|---|---|---|
| sm-pf1 | 24 | 4 | 0.207 | 0.966 | 83 | 6 | 0.716 | 0.950 | 0.431 | 1.000 |
| sm-pf0 | 50 | 18 | 0.431 | 0.849 | 95 | 20 | 0.819 | 0.832 | 0.431 | 1.000 |
| lg-pf1 | 29 | 0 | 0.250 | 1.000 | 87 | 2 | 0.750 | 0.983 | 0.431 | 1.000 |
| lg-pf0 | 55 | 3 | 0.474 | 0.975 | 93 | 5 | 0.802 | 0.958 | 0.431 | 1.000 |
| trf-pf1 | 24 | 1 | 0.207 | 0.992 | 85 | 3 | 0.733 | 0.975 | 0.431 | 1.000 |
| trf-pf0 | 33 | 2 | 0.284 | 0.983 | 89 | 4 | 0.767 | 0.966 | 0.431 | 1.000 |
| gliner-core-t0.5-pf1 | 12 | 0 | 0.103 | 1.000 | 78 | 2 | 0.672 | 0.983 | 0.431 | 1.000 |
| gliner-core-t0.5-pf0 | 42 | 8 | 0.362 | 0.933 | 90 | 10 | 0.776 | 0.916 | 0.431 | 1.000 |

**openai**

| Config | NER TP | NER FP | NER recall | NER spec | Union TP | Union FP | Union recall | Union spec | Union BLOCK recall | Union BLOCK spec |
|---|---|---|---|---|---|---|---|---|---|---|
| sm-pf1 | 85 | 3 | 0.170 | 0.994 | 459 | 37 | 0.918 | 0.926 | 0.746 | 0.940 |
| sm-pf0 | 241 | 66 | 0.482 | 0.868 | 471 | 93 | 0.942 | 0.814 | 0.746 | 0.940 |
| lg-pf1 | 79 | 0 | 0.158 | 1.000 | 460 | 34 | 0.920 | 0.932 | 0.746 | 0.940 |
| lg-pf0 | 231 | 59 | 0.462 | 0.882 | 469 | 86 | 0.938 | 0.828 | 0.746 | 0.940 |
| trf-pf1 | 74 | 0 | 0.148 | 1.000 | 461 | 34 | 0.922 | 0.932 | 0.746 | 0.940 |
| trf-pf0 | 150 | 19 | 0.300 | 0.962 | 465 | 52 | 0.930 | 0.896 | 0.746 | 0.940 |
| gliner-core-t0.5-pf1 | 81 | 4 | 0.162 | 0.992 | 462 | 38 | 0.924 | 0.924 | 0.746 | 0.940 |
| gliner-core-t0.5-pf0 | 232 | 90 | 0.464 | 0.820 | 471 | 116 | 0.942 | 0.768 | 0.746 | 0.940 |


### Paired comparison against shipped `sm-pf1` (post-review splits)

Net flips are counted per prompt against the same labels; p values are exact two-sided McNemar on the discordant pairs of positives / negatives (uncorrected for the number of comparisons). Full numbers (cost, F2, cluster sign tests): `ner-models-20261024.stats.json`.

**Union (regex OR NER), positive rule; candidate minus `sm-pf1`**

| Split | Config | TP gained | TP lost | FP removed | FP added | McNemar p (positives) | McNemar p (negatives) | delta recall [95% CI] | delta specificity [95% CI] |
|---|---|---|---|---|---|---|---|---|---|
| check | lg-pf1 | 5 | 1 | 4 | 0 | 0.219 | 0.125 | +0.034 [-0.000, +0.078] | +0.034 [+0.008, +0.068] |
| check | trf-pf1 | 5 | 3 | 3 | 0 | 0.727 | 0.250 | +0.017 [-0.029, +0.068] | +0.025 [+0.000, +0.056] |
| check | gliner-core-t0.5-pf1 | 2 | 7 | 4 | 0 | 0.180 | 0.125 | -0.043 [-0.096, +0.008] | +0.034 [+0.008, +0.068] |
| check | sm-pf0 | 12 | 0 | 0 | 14 | 0.000 | 0.000 | +0.103 [+0.052, +0.162] | -0.118 [-0.182, -0.059] |
| check | lg-pf0 | 10 | 0 | 4 | 3 | 0.002 | 1.000 | +0.086 [+0.038, +0.142] | +0.008 [-0.035, +0.051] |
| check | trf-pf0 | 9 | 3 | 3 | 1 | 0.146 | 0.625 | +0.052 [-0.008, +0.114] | +0.017 [-0.016, +0.051] |
| check | gliner-core-t0.5-pf0 | 10 | 3 | 3 | 7 | 0.092 | 0.344 | +0.060 [+0.000, +0.123] | -0.034 [-0.088, +0.017] |
| openai | lg-pf1 | 1 | 0 | 3 | 0 | 1.000 | 0.250 | +0.002 [+0.000, +0.006] | +0.006 [+0.000, +0.014] |
| openai | trf-pf1 | 2 | 0 | 3 | 0 | 0.500 | 0.250 | +0.004 [+0.000, +0.010] | +0.006 [+0.000, +0.014] |
| openai | gliner-core-t0.5-pf1 | 3 | 0 | 2 | 3 | 0.250 | 1.000 | +0.006 [+0.000, +0.014] | -0.002 [-0.011, +0.006] |
| openai | sm-pf0 | 12 | 0 | 0 | 56 | 0.000 | 0.000 | +0.024 [+0.012, +0.038] | -0.112 [-0.140, -0.086] |
| openai | lg-pf0 | 10 | 0 | 2 | 51 | 0.002 | 0.000 | +0.020 [+0.008, +0.033] | -0.098 [-0.126, -0.072] |
| openai | trf-pf0 | 6 | 0 | 3 | 18 | 0.031 | 0.001 | +0.012 [+0.004, +0.022] | -0.030 [-0.048, -0.012] |
| openai | gliner-core-t0.5-pf0 | 12 | 0 | 0 | 79 | 0.000 | 0.000 | +0.024 [+0.012, +0.038] | -0.158 [-0.190, -0.127] |

**NER layer alone, positive rule; candidate minus `sm-pf1`**

| Split | Config | TP gained | TP lost | FP removed | FP added | McNemar p (positives) | McNemar p (negatives) | delta recall [95% CI] | delta specificity [95% CI] |
|---|---|---|---|---|---|---|---|---|---|
| check | lg-pf1 | 8 | 3 | 4 | 0 | 0.227 | 0.125 | +0.043 [-0.009, +0.101] | +0.034 [+0.008, +0.068] |
| check | trf-pf1 | 6 | 6 | 3 | 0 | 1.000 | 0.250 | +0.000 [-0.059, +0.061] | +0.025 [+0.000, +0.056] |
| check | gliner-core-t0.5-pf1 | 3 | 15 | 4 | 0 | 0.008 | 0.125 | -0.103 [-0.175, -0.035] | +0.034 [+0.008, +0.068] |
| check | sm-pf0 | 26 | 0 | 0 | 14 | 0.000 | 0.000 | +0.224 [+0.150, +0.305] | -0.118 [-0.182, -0.059] |
| check | lg-pf0 | 32 | 1 | 4 | 3 | 0.000 | 1.000 | +0.267 [+0.184, +0.353] | +0.008 [-0.035, +0.051] |
| check | trf-pf0 | 15 | 6 | 3 | 1 | 0.078 | 0.625 | +0.078 [+0.000, +0.157] | +0.017 [-0.016, +0.051] |
| check | gliner-core-t0.5-pf0 | 25 | 7 | 3 | 7 | 0.002 | 0.344 | +0.155 [+0.063, +0.248] | -0.034 [-0.088, +0.017] |
| openai | lg-pf1 | 5 | 11 | 3 | 0 | 0.210 | 0.250 | -0.012 [-0.028, +0.004] | +0.006 [+0.000, +0.014] |
| openai | trf-pf1 | 5 | 16 | 3 | 0 | 0.027 | 0.250 | -0.022 [-0.040, -0.004] | +0.006 [+0.000, +0.014] |
| openai | gliner-core-t0.5-pf1 | 8 | 12 | 2 | 3 | 0.503 | 1.000 | -0.008 [-0.026, +0.010] | -0.002 [-0.011, +0.006] |
| openai | sm-pf0 | 156 | 0 | 0 | 63 | 0.000 | 0.000 | +0.312 [+0.272, +0.353] | -0.126 [-0.155, -0.098] |
| openai | lg-pf0 | 148 | 2 | 2 | 58 | 0.000 | 0.000 | +0.292 [+0.252, +0.333] | -0.112 [-0.141, -0.084] |
| openai | trf-pf0 | 69 | 4 | 3 | 19 | 0.000 | 0.001 | +0.130 [+0.099, +0.162] | -0.032 [-0.051, -0.014] |
| openai | gliner-core-t0.5-pf0 | 151 | 4 | 0 | 87 | 0.000 | 0.000 | +0.294 [+0.253, +0.335] | -0.174 [-0.207, -0.142] |


## Findings

1. **No candidate gives a statistically reliable union improvement over the shipped `sm` + post-filter.** Every union difference on dev-CHECK and `openai` is within the bootstrap noise; the smallest exact McNemar p among the pf1 candidates is 0.125 (FP removed by `lg-pf1` on dev-CHECK, 4 vs 0). Positive prompts, and therefore recall, are small samples (116 on dev-CHECK).
2. **`en_core_web_lg` (pf1) is the only candidate that is no worse on any post-review union cell and has fewer FP on both**: union dev-CHECK TP +5/-1, FP -4 (0 added); `openai` TP +1/-0, FP -3. Design splits were neutral (dev-TUNE TP +2, FP +1; personalized unchanged). Pooling the two post-review splits (an informal, unregistered count) gives 7 FP removed and 0 added (exact sign p = 0.016). NER-only recall on `openai` is not significantly changed (-0.012, CI [-0.028, +0.004]). Latency is indistinguishable from `sm` (below). It costs no download.
3. **`en_core_web_trf` (pf1)** has a NER-only FP count like `lg` (0 on personalized and `openai`, 1 on dev-CHECK; `lg`: 0, 0, 0) but a lower NER-only recall on `openai` (-0.022, p = 0.027), so its union gain is comparable to `lg` (dev-CHECK TP +5/-3, FP -3; `openai` TP +2/-0, FP -3) at about 6x the NER-layer latency and a 457 MB wheel (497 MB weights) plus a torch dependency.
4. **GLiNER PII small (frozen `core`, t0.5, pf1) does not help**: the NER layer alone loses recall (dev-CHECK -0.103, p = 0.008; `openai` -0.008, n.s.), the union loses 5 net TP on dev-CHECK (+2/-7, p = 0.18) and is level on `openai` (TP +3/-0, FP -2/+3). Its FP counts are comparable to `sm-pf1` (dev-CHECK -4/+0, `openai` -2/+3). With the post-filter off the GLiNER spans are the least precise of all models (`openai` union FP 116 vs 93 for `sm-pf0`), so the post-filter generalises to a different span source and is what keeps the candidate usable.
5. **The post-filter matters for every model.** Turning the post-filter off (same model, `pf0` minus `pf1`) raises union recall (dev-CHECK +0.03 to +0.10, `openai` +0.01 to +0.02) and always costs union specificity (`openai`: `sm` -0.112, `lg` -0.104, `trf` -0.036, GLiNER -0.156); `trf-pf0` is the least costly.
6. **BLOCK decisions do not move.** With the `core` preset and with every spaCy model, NER entities are S1/S2 (WARN-level); union BLOCK recall and specificity are identical for all configurations on dev-CHECK and `openai` (all flips 0). Any NER model comparison here is a WARN-level comparison. (The `pii` preset's S3 identifier labels change the design-split BLOCK cells, e.g. dev-TUNE union BLOCK recall 0.493 vs 0.345 at the cost of BLOCK specificity 0.899 vs 0.992, but that preset was not frozen and was not scored post-review.)

## GLiNER training-data provenance and overlap risk

The model card (revision `d21aad5b`) states no training data. `gliner_config.json` records `train_data: data/pii_full.json` with undisclosed content; the card's benchmark set `synthetic-multi-pii-ner-v1` could not be read (HTTP 401 to an unauthenticated fetch; no gated access was requested). The checkpoint is a fine-tune of `jhu-clsp/ettin-encoder-68m` (config embedded; no backbone download occurred). Overlap with the development-set sources (ai4privacy, Gretel, nemotron-pii, privy, PIIMB) can neither be confirmed nor excluded from public documentation. Indirect evidence only: GLiNER shows no advantage on the development file relative to spaCy (dev-CHECK NER-only recall 0.10 vs 0.21), the opposite of what memorised sources would produce; `openai` and `personalized` are our own synthetic sets and cannot overlap by construction. Interpret any development-set GLiNER number with this unknown in mind; the fresh held-out set is the safe place to score it.

## Latency (rough, non-final)

`extract_entities` only (NER layer, post-filter on, case-preserved text), 120 dev-TUNE prompts (median about 10 words), single process, CPU, on a machine shared with other concurrent agents, so order of magnitude only (`ner-models-20261024.timing.json`). Not a timing claim; real timing is a separate serialized step.

| Config | median ms | p95 ms |
|---|---|---|
| sm | 3.2 | 6.1 |
| lg | 3.4 | 6.2 |
| trf | 19.0 | 43.2 |
| GLiNER core | 26.5 | 62.3 |
| GLiNER pii | 35.8 | 74.6 |

The int8 ONNX GLiNER file (79 MiB) was downloaded but not exercised (`onnxruntime` not installed).

## Mapping observations (qualitative, no dataset text)

With the `core` label set GLiNER sometimes labels non-name numbers as `location address` (a phone number became `FAC`) and the local part of an email address as `name`; the post-filter's `identifier` rule removes the former and the regex layer owns the latter. Output depends on the label set because labels are scored jointly with the text.

## Limitations

- dev-CHECK and `openai` are post-review, not strictly held-out; the fresh held-out set is the confirmatory step. Differences of a few prompts are not distinguishable from noise (see McNemar p values).
- One GLiNER checkpoint, one label vocabulary per preset, five thresholds; no per-label thresholds, no prompt-length study (all prompts are at most 160 words), English only.
- The post-filter was designed on `en_core_web_sm`; lg, trf and GLiNER inherit it unchanged.
- Latency numbers are contended single-process CPU timings.
- Scope is detector layers only: nothing here says anything about the semantic layer or the full product.

## Recommendation for the Wave 3 fresh held-out scoring

Carry **`en_core_web_lg` with the post-filter (`PRIVOKE_NER_MODEL=en_core_web_lg`)**: no download, same latency, consistent small gains on both post-review splits and neutral on the design splits. Carry **`en_core_web_trf` with the post-filter** only as the accuracy-ceiling comparator (cost: 457 MB wheel and about 6x NER latency). Do **not** carry GLiNER PII small: no union gain, lower NER recall, undocumented training data, and the `pii` preset is worse on the design splits. The backend stays in the tree behind `PRIVOKE_NER_BACKEND=gliner` (default off); remove it if it is not to be maintained. Changing the shipped NER model is a distribution decision for the user (lg adds about 550 MB over sm).

## Downloads (ledger)

| Path | Source | Size | Licence | Purpose |
|---|---|---|---|---|
| `models/experiments/ner-models-20261024/gliner-pii-small-v1.0/` (+ `provenance.json`, `gliner-sha256.txt`) | https://huggingface.co/knowledgator/gliner-pii-small-v1.0 @ `d21aad5b4a7ec82b3d0970fd1ac74a12c087d85e`; `pytorch_model.bin` sha256 `4e305dd9...6b02` | 326,195,231 B weights + 82,680,500 B ONNX (unused) + about 3.6 MB tokenizer/config | Apache-2.0 | GLiNER candidate |
| `evaluation/.venv-ner-models` (spaCy 3.7.5; `en_core_web_sm` 3.7.1 wheel 12.8 MB sha256 `86cc141f...3889`; `en_core_web_trf` 3.7.3 wheel 457,413,490 B sha256 `f72abb34...d68b`; torch 2.11.0 114.5 MB; transformers 12.0 MB; gliner 0.2.29; spacy-curated-transformers 0.2.2; small pure-Python packages) | PyPI; explosion/spacy-models GitHub releases | about 0.65 GB downloaded in total (venv size on disk not measured) | MIT / BSD / Apache-2.0 | study environment. `en_core_web_lg` came from the vendored wheel `models/experiments/paper_completion_20261014/vendor/` (no download) |

Not integrated into the product: delete the GLiNER weights directory; keep `.venv-ner-models` only if `trf` is carried to Wave 3.

## Reproduction

```
python evaluation/ner_model_study.py run --phase design --tree <root> --data-root <checkout> --generated <protobuf dir> --out <dir> --gliner-dir <weights> --cache <jsonl> --configs sm-pf1 ... gliner-core-t0.5-pf1
python evaluation/ner_model_study.py select --out <dir> --freeze docs/experiments/ner-models-20261024.freeze.json   # then commit it
python evaluation/ner_model_study.py run --phase post-review --freeze docs/experiments/ner-models-20261024.freeze.json ...
python evaluation/ner_model_study.py stats --out <dir> --stats-path <detector_stats.py> --stats-out <json> --labels ...
python evaluation/ner_model_study.py collect --out <dir> --phase design --dest <json>
```

Aggregates: `ner-models-20261024.design.json` (all 26 design configurations, counts only), `.post-review.json`, `.stats.json`, `.freeze.json`, `.timing.json`. Per-row outputs and the raw GLiNER prediction cache hold dataset text or ids and stay in the git-ignored scratch area.
