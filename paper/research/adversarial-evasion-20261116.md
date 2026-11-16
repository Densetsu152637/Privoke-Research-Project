# Adversarial privacy evasion of the PriVoke product pipeline (ADVEVADE-20261116)

**Record:** ADVEVADE-20261116. **Date:** 16 November 2026. **Scope label: PRODUCT PIPELINE** (regex + spaCy NER + semantic V3 standard `privoke-v3-balanced`, shipped layer set, regex-first). This is product end-to-end evidence for ASIACCS revision goal G6 (Stage 3 of the [revision plan](../../docs/plans/asiaccs-2027-revision.md)); it is **never LLM-only or semantic-only evidence** and is kept separate from every such unit. Machine-readable twin: [adversarial-evasion-20261116.json](adversarial-evasion-20261116.json). Experiment note: [docs/experiments/adversarial-evasion-20261116.md](../../docs/experiments/adversarial-evasion-20261116.md).

## Goal and exact request

Authorized by the 16 November 2026 entry of [REWRITE_SCOPE](../REWRITE_SCOPE.md): an end-to-end adversarial privacy-evasion evaluation reporting attack success rate (ASR), a product end-to-end task with results kept separate from LLM-only results. The supervisor's request (Paper Completion thread), verbatim: "Create sensitive prompts and transform them using Unicode substitutions, inserted spaces, spelling perturbations, paraphrasing, indirect references, encoded identifiers, long-context placement, and multilingual variants. Measure how often PriVoke fails to trigger the intended action", with ASR = N(sensitive prompts that evade intended protection) / N(adversarial sensitive prompts).

## Design

- **Seed set: F4 (the v3 fresh draw), all 8,646 labelled-sensitive rows, no subsample.** `evaluation/results/fresh_sets_20261025/f4_piimb/piimb_fresh_f4.jsonl`, sha256 `d4bed756790c7b000fc5e8b6028e3f962c8dbfabe3f607a7180224d55356589d`; PIIMB positives only (ai4privacy 2,950, Gretel 2,863, Privy 2,151, Nemotron-PII 682) with annotated entity spans.
- **Split provenance and disjointness.** The default-off robustness flags were designed on `development.jsonl` (dev-TUNE and dev-CHECK), the personalized synthetic set and the OpenAI synthetic set ([robustness-fixes-20261024](../../docs/experiments/robustness-fixes-20261024.md); the earlier [detector-robustness study](../../docs/experiments/detector-robustness-20261024.md) used the same three). F4 was drawn by the v3 registration with every group used in those sets, in the earlier fresh sets F1 to F3 and in any scanned training or study artifact excluded ([freeze record](../../docs/research/fresh-sets-freeze-v3-20261025.md): 21,399 excluded groups, zero overlap with F1). F4 is therefore disjoint from every flag-design set and was never seen when K (the shipped regex rework) was designed. The exclusion scan does not cover parquet or binary artifacts (stated in the freeze record), so disjointness from semantic V3 training data holds up to that scan.
- **Registered-endpoint status and why F4.** F1 to F4 were each scored by the registered detector studies, so no unscored fresh set remains; the locked `final` split was not touched. F4's registered use (hypotheses H7 and H8, configurations O, N, K and K+all, detector layers only) is complete and published. This record neither re-tests those hypotheses nor changes any detector, threshold or rule, and the v3 registration forbids only developing K further on F4 or re-scoring under its own hypotheses. Row text was handled programmatically by the transform functions; no F4 row text was printed or inspected. Using the same rows for a different measurement (product pipeline including semantic V3, transformed prompts) is a second use of F4, declared as a limitation.
- **Intended action.** The action PriVoke assigns to the untransformed prompt under shipped defaults (WARN or BLOCK; protected = non-ALLOW). A transformed variant evades when its original is protected and the variant is ALLOW. A downgrade is original BLOCK and variant WARN, reported separately.
- **Denominators.** A (row, variant) pair exists only when the transform changed the text ("applicable"). Conditional ASR = evaded / protected applicable pairs; unconditional ASR = evaded / all applicable pairs. Intervals are Wilson 95 % intervals over pairs (rows contribute up to 20 correlated pairs, so they are optimistic); a source-document cluster bootstrap is given for the overall rate. Variants of baseline-ALLOW rows are frozen but not scored, because they cannot count as evasions.
- **Transforms** (`evaluation/adversarial_evasion_transforms.py`, generator revision `advevade-transforms-1`, seed 20261116, per-row RNG `sha256(seed:variant:row id)`). They act on the annotated identifier spans (an attacker who knows which substring is the value) and never on PriVoke output:
  - unicode: `homoglyph` (Cyrillic or Greek lookalikes for 50 % of eligible characters), `zero_width` (format characters in 50 % of gaps between span characters); the character tables are reused read-only from `evaluation/robustness_probe.py`;
  - inserted_spaces: `spaces` (a space between every span character);
  - spelling: `spelling` (one transposition, deletion or doubling in span tokens and in 25 % of other 4+ letter tokens; an adjacent-digit swap in digit tokens);
  - paraphrase: `paraphrase` (a declared 35-entry lexicon plus one of six frames; template rules, not a language model);
  - indirect_reference: `indirect_partial` (initials, or "the one ending in" the last four characters) and `indirect_pointer` (the value replaced by a family-keyed pointer such as "the card I always pay with"; **value-removing**, so the prompt may no longer be sensitive, and the overall rows are therefore also reported without it);
  - encoded_identifier: `base64`, `hex`, `spelled_digits`;
  - long_context: `ctx_window_middle` (800 filler characters around the prompt, inside the 512-token semantic window) and `ctx_long_start`, `ctx_long_middle`, `ctx_long_end` (6,000 filler characters, beyond the window; filler from 20 declared digit-free benign sentences);
  - multilingual: `multilingual_{es,fr,de,pt,zh,ru}` (declared translation templates by label family, built from up to four entity values; the original context is dropped).

  The tables were written before any PriVoke output on these rows existed and were not edited afterward.
- **Frozen set.** 8,646 rows x 21 items (baseline plus 20 variants) = 181,566 items, 169,371 applicable transformed pairs, sha256 `5e4eac4c7c3117adf81a013fa9e4572484c9b0f41ab4b4f217ca960a82b634c2`, committed on this branch (`c3b63ef`) **before any scoring**; `score` refuses to run unless the file hashes to the declared value. Benign control set: 1,000 labelled-clean F1 rows (250 per source; `piimb_fresh_f1.jsonl` sha256 `4ff0832331f0b3f8d58026cca5cb26fd25833f98864b5822fb7c8d21172a9167`) with the entity-free variants only (spelling, paraphrase, four context placements), frozen sha256 `1e226aa5d8ac5b9afbcdec921b09764822adce74e8f0c26365f8516e1ce23878`.
- **Pipeline and layers.** In-process host execution of the client runtime's native gRPC servicer (`PrivokeRuntimeService.AnalyzePrompt`; no Docker, no network), with the semantic V3 balanced release (`manifest.json` sha256 `99b36171056bb0398584a0b0556d9d7ff2640d0acac4b124a126327451a80589`) loaded through the PIPE3 adapter into the runtime's streamed-model cache. Every request names `layers=[regex, ner, semantic]` explicitly, `semantic_model_id=privoke-v3-balanced` and regex-first order (shipped `waitForRegex`); an empty layer list is never sent. The harness asserts that the returned layer list equals `[regex, ner, semantic]`, that regex ran, that a skip occurs only for both later layers together, and that the semantic identity matches when it ran (unit-tested). Observed in the stored scores: regex `ok` on every item, NER and semantic `skipped` only after a regex BLOCK, semantic `error` on over-length input.
- **Arms (paired, separate processes).** `defaults`: the shipped configuration (K regex, case-preserving detectors and NER post-filter on, the four robustness flags unset). `+flags`: the same plus `PRIVOKE_STRIP_FORMAT_CHARS=1`, `PRIVOKE_CANONICALISE_DIGITS=1`, `PRIVOKE_CANONICALISE_EMAIL_WORDS=1` and `PRIVOKE_NER_CASELESS_GATE=1`; the harness asserts the loaded flag values per arm. The flags change only the case-preserved regex and NER view, so untransformed baselines are identical across arms.
- **Action versus detection level.** The runtime fails closed: when a layer errors and nothing else fires it returns BLOCK. V3 raises an error beyond 512 WordPiece tokens, so over-length prompts are BLOCKed whether or not anything sensitive is present. The **action level** (primary; what the user experiences) counts that BLOCK as protection. The **detection level** (secondary) counts a BLOCK that exists only because a layer errored as a missed detection.

## Commands (host Python; scoring code revision `98677cf`, base `f7ef145`)

```
PY="D:/Git Repositories/Privoke-Research-Project/evaluation/.venv-v1-v3-pipeline/Scripts/python.exe"
$PY -I evaluation/adversarial_evasion.py build --seed-file <F4 jsonl> --out evaluation/results/adversarial_evasion_20261116/main --verify-seed-sha
$PY -I evaluation/adversarial_evasion.py build --seed-file <F1 jsonl> --out evaluation/results/adversarial_evasion_20261116/control --benign --per-source 250
# 12 shards per phase, OMP_NUM_THREADS=2: defaults baseline, defaults variants, flags (all), then the control for both arms
$PY -I evaluation/adversarial_evasion.py score --set <set dir> --expected-sha256 <frozen hash> --arm defaults|flags --shards 12 --shard i --phase baseline|variants|all [--all-rows for the control] --release-dir <models/standard-releases> --generated <extension/client-runtime/generated>
$PY -I evaluation/adversarial_evasion.py analyse --set <set dir> --out-json <analysis json>      (main and control)
$PY -I evaluation/adversarial_evasion_report.py assemble --main <main> --control <control> --extra <provenance> --out paper/research/adversarial-evasion-20261116.json
$PY -I evaluation/adversarial_evasion_report.py check --json paper/research/adversarial-evasion-20261116.json --md paper/research/adversarial-evasion-20261116.md
$PY -I -m unittest discover -s evaluation/tests -p "test_adversarial_evasion*.py"
```

Environment: Python 3.11.9, torch 2.11.0+cpu, numpy 1.26.4, transformers 4.57.6, spaCy 3.7.5 with `en_core_web_sm` 3.7.1, presidio-analyzer 2.2.363; Windows 11, CPU. Runtime tree `extension/client-runtime` = git tree `0b2535c7`. Score-file hashes are in the JSON (`provenance.score_file_sha256`). Per-row scores and the frozen sets (which contain F4-derived text) stay in the gitignored `evaluation/results/adversarial_evasion_20261116/`.

## Results

Every number in this section is generated from the JSON by `adversarial_evasion_report.py render` and verified by `check`. Values are percentages; intervals are Wilson 95 % unless stated.

<!-- BEGIN GENERATED -->
#### Baseline detection on the untransformed prompts (intended action)

| Arm | Prompts | Protected (WARN or BLOCK) | WARN | BLOCK | ALLOW | Rows with a layer error |
|---|---|---|---|---|---|---|
| defaults | 8646 | 8299/8646 = 95.99 [95.55, 96.38] | 655 | 7644 | 347 | 1 |
| +flags | 8646 | 8299/8646 = 95.99 [95.55, 96.38] | 655 | 7644 | 347 | 1 |

Baseline protection by source dataset (shipped defaults):

| Source | Protected |
|---|---|
| ai4privacy/pii-masking-openpii-1m | 2794/2950 = 94.71 [93.84, 95.46] |
| gretelai/gretel-pii-masking-en-v1 | 2827/2863 = 98.74 [98.26, 99.09] |
| nvidia/Nemotron-PII | 624/682 = 91.50 [89.16, 93.36] |
| piimb/privy | 2054/2151 = 95.49 [94.53, 96.29] |

Share of baseline prompts with a non-ALLOW finding by layer (shipped defaults; a layer skipped after a regex BLOCK counts as no finding):

| Layer | Non-ALLOW finding |
|---|---|
| ner | 1200/8646 = 13.88 [13.17, 14.62] |
| regex | 5494/8646 = 63.54 [62.52, 64.55] |
| semantic | 3712/8646 = 42.93 [41.89, 43.98] |

Intended actions (shipped defaults, untransformed): WARN 655, BLOCK 7644, ALLOW 347 (8299 protected prompts form the conditional denominators).

#### ASR by transform family. Action level (primary): protection is any non-ALLOW action, including the runtime's fail-closed BLOCK on a layer error

| Family | Applicable (defaults) | Protected (defaults) | Conditional ASR (defaults) | Unconditional ASR (defaults) | Applicable (+flags) | Protected (+flags) | Conditional ASR (+flags) | Unconditional ASR (+flags) |
|---|---|---|---|---|---|---|---|---|
| unicode | 16448 | 15814 | 399/15814 = 2.52 [2.29, 2.78] | 399/16448 = 2.43 [2.20, 2.67] | 16448 | 15814 | 130/15814 = 0.82 [0.69, 0.98] | 130/16448 = 0.79 [0.67, 0.94] |
| inserted_spaces | 8642 | 8296 | 63/8296 = 0.76 [0.59, 0.97] | 63/8642 = 0.73 [0.57, 0.93] | 8642 | 8296 | 63/8296 = 0.76 [0.59, 0.97] | 63/8642 = 0.73 [0.57, 0.93] |
| spelling | 8488 | 8148 | 40/8148 = 0.49 [0.36, 0.67] | 40/8488 = 0.47 [0.35, 0.64] | 8488 | 8148 | 40/8148 = 0.49 [0.36, 0.67] | 40/8488 = 0.47 [0.35, 0.64] |
| paraphrase | 8084 | 7760 | 144/7760 = 1.86 [1.58, 2.18] | 144/8084 = 1.78 [1.52, 2.09] | 8084 | 7760 | 144/7760 = 1.86 [1.58, 2.18] | 144/8084 = 1.78 [1.52, 2.09] |
| indirect_reference | 17292 | 16598 | 2194/16598 = 13.22 [12.71, 13.74] | 2194/17292 = 12.69 [12.20, 13.19] | 17292 | 16598 | 2194/16598 = 13.22 [12.71, 13.74] | 2194/17292 = 12.69 [12.20, 13.19] |
| encoded_identifier | 23957 | 23106 | 649/23106 = 2.81 [2.60, 3.03] | 649/23957 = 2.71 [2.51, 2.92] | 23957 | 23106 | 336/23106 = 1.45 [1.31, 1.62] | 336/23957 = 1.40 [1.26, 1.56] |
| long_context | 34584 | 33196 | 1249/33196 = 3.76 [3.56, 3.97] | 1249/34584 = 3.61 [3.42, 3.81] | 34584 | 33196 | 1249/33196 = 3.76 [3.56, 3.97] | 1249/34584 = 3.61 [3.42, 3.81] |
| multilingual | 51876 | 49794 | 126/49794 = 0.25 [0.21, 0.30] | 126/51876 = 0.24 [0.20, 0.29] | 51876 | 49794 | 126/49794 = 0.25 [0.21, 0.30] | 126/51876 = 0.24 [0.20, 0.29] |
| ALL variants | 169371 | 162712 | 4864/162712 = 2.99 [2.91, 3.07] | 4864/169371 = 2.87 [2.79, 2.95] | 169371 | 162712 | 4282/162712 = 2.63 [2.55, 2.71] | 4282/169371 = 2.53 [2.45, 2.60] |
| ALL excl. value-removing (indirect_pointer) | 160725 | 154413 | 3725/154413 = 2.41 [2.34, 2.49] | 3725/160725 = 2.32 [2.25, 2.39] | 160725 | 154413 | 3143/154413 = 2.04 [1.97, 2.11] | 3143/160725 = 1.96 [1.89, 2.02] |

#### ASR by transform family. Detection level (secondary): a BLOCK that exists only because a layer errored counts as a missed detection

| Family | Applicable (defaults) | Protected (defaults) | Conditional ASR (defaults) | Unconditional ASR (defaults) | Applicable (+flags) | Protected (+flags) | Conditional ASR (+flags) | Unconditional ASR (+flags) |
|---|---|---|---|---|---|---|---|---|
| unicode | 16448 | 15814 | 399/15814 = 2.52 [2.29, 2.78] | 399/16448 = 2.43 [2.20, 2.67] | 16448 | 15814 | 130/15814 = 0.82 [0.69, 0.98] | 130/16448 = 0.79 [0.67, 0.94] |
| inserted_spaces | 8642 | 8296 | 63/8296 = 0.76 [0.59, 0.97] | 63/8642 = 0.73 [0.57, 0.93] | 8642 | 8296 | 63/8296 = 0.76 [0.59, 0.97] | 63/8642 = 0.73 [0.57, 0.93] |
| spelling | 8488 | 8148 | 41/8148 = 0.50 [0.37, 0.68] | 41/8488 = 0.48 [0.36, 0.65] | 8488 | 8148 | 41/8148 = 0.50 [0.37, 0.68] | 41/8488 = 0.48 [0.36, 0.65] |
| paraphrase | 8084 | 7760 | 144/7760 = 1.86 [1.58, 2.18] | 144/8084 = 1.78 [1.52, 2.09] | 8084 | 7760 | 144/7760 = 1.86 [1.58, 2.18] | 144/8084 = 1.78 [1.52, 2.09] |
| indirect_reference | 17292 | 16598 | 2194/16598 = 13.22 [12.71, 13.74] | 2194/17292 = 12.69 [12.20, 13.19] | 17292 | 16598 | 2194/16598 = 13.22 [12.71, 13.74] | 2194/17292 = 12.69 [12.20, 13.19] |
| encoded_identifier | 23957 | 23106 | 652/23106 = 2.82 [2.62, 3.04] | 652/23957 = 2.72 [2.52, 2.94] | 23957 | 23106 | 338/23106 = 1.46 [1.32, 1.63] | 338/23957 = 1.41 [1.27, 1.57] |
| long_context | 34584 | 33196 | 6989/33196 = 21.05 [20.62, 21.50] | 6989/34584 = 20.21 [19.79, 20.64] | 34584 | 33196 | 6989/33196 = 21.05 [20.62, 21.50] | 6989/34584 = 20.21 [19.79, 20.64] |
| multilingual | 51876 | 49794 | 126/49794 = 0.25 [0.21, 0.30] | 126/51876 = 0.24 [0.20, 0.29] | 51876 | 49794 | 126/49794 = 0.25 [0.21, 0.30] | 126/51876 = 0.24 [0.20, 0.29] |
| ALL variants | 169371 | 162712 | 10608/162712 = 6.52 [6.40, 6.64] | 10608/169371 = 6.26 [6.15, 6.38] | 169371 | 162712 | 10025/162712 = 6.16 [6.05, 6.28] | 10025/169371 = 5.92 [5.81, 6.03] |
| ALL excl. value-removing (indirect_pointer) | 160725 | 154413 | 9469/154413 = 6.13 [6.01, 6.25] | 9469/160725 = 5.89 [5.78, 6.01] | 160725 | 154413 | 8886/154413 = 5.75 [5.64, 5.87] | 8886/160725 = 5.53 [5.42, 5.64] |

#### ASR by variant, action level

| Variant | Protected (defaults) | Cond. ASR (defaults) | Protected (+flags) | Cond. ASR (+flags) | Cond. ASR (defaults, detection level) |
|---|---|---|---|---|---|
| base64 | 8299 | 98/8299 = 1.18 [0.97, 1.44] | 8299 | 98/8299 = 1.18 [0.97, 1.44] | 100/8299 = 1.20 [0.99, 1.46] |
| ctx_long_end | 8299 | 0/8299 = 0.00 [0.00, 0.05] | 8299 | 0/8299 = 0.00 [0.00, 0.05] | 1909/8299 = 23.00 [22.11, 23.92] |
| ctx_long_middle | 8299 | 0/8299 = 0.00 [0.00, 0.05] | 8299 | 0/8299 = 0.00 [0.00, 0.05] | 1904/8299 = 22.94 [22.05, 23.86] |
| ctx_long_start | 8299 | 0/8299 = 0.00 [0.00, 0.05] | 8299 | 0/8299 = 0.00 [0.00, 0.05] | 1889/8299 = 22.76 [21.87, 23.68] |
| ctx_window_middle | 8299 | 1249/8299 = 15.05 [14.30, 15.84] | 8299 | 1249/8299 = 15.05 [14.30, 15.84] | 1287/8299 = 15.51 [14.75, 16.30] |
| hex | 8299 | 27/8299 = 0.33 [0.22, 0.47] | 8299 | 27/8299 = 0.33 [0.22, 0.47] | 27/8299 = 0.33 [0.22, 0.47] |
| homoglyph | 7597 | 130/7597 = 1.71 [1.44, 2.03] | 7597 | 130/7597 = 1.71 [1.44, 2.03] | 130/7597 = 1.71 [1.44, 2.03] |
| indirect_partial | 8299 | 1055/8299 = 12.71 [12.01, 13.45] | 8299 | 1055/8299 = 12.71 [12.01, 13.45] | 1055/8299 = 12.71 [12.01, 13.45] |
| indirect_pointer | 8299 | 1139/8299 = 13.72 [13.00, 14.48] | 8299 | 1139/8299 = 13.72 [13.00, 14.48] | 1139/8299 = 13.72 [13.00, 14.48] |
| multilingual_de | 8299 | 1/8299 = 0.01 [0.00, 0.07] | 8299 | 1/8299 = 0.01 [0.00, 0.07] | 1/8299 = 0.01 [0.00, 0.07] |
| multilingual_es | 8299 | 24/8299 = 0.29 [0.19, 0.43] | 8299 | 24/8299 = 0.29 [0.19, 0.43] | 24/8299 = 0.29 [0.19, 0.43] |
| multilingual_fr | 8299 | 26/8299 = 0.31 [0.21, 0.46] | 8299 | 26/8299 = 0.31 [0.21, 0.46] | 26/8299 = 0.31 [0.21, 0.46] |
| multilingual_pt | 8299 | 6/8299 = 0.07 [0.03, 0.16] | 8299 | 6/8299 = 0.07 [0.03, 0.16] | 6/8299 = 0.07 [0.03, 0.16] |
| multilingual_ru | 8299 | 25/8299 = 0.30 [0.20, 0.44] | 8299 | 25/8299 = 0.30 [0.20, 0.44] | 25/8299 = 0.30 [0.20, 0.44] |
| multilingual_zh | 8299 | 44/8299 = 0.53 [0.40, 0.71] | 8299 | 44/8299 = 0.53 [0.40, 0.71] | 44/8299 = 0.53 [0.40, 0.71] |
| paraphrase | 7760 | 144/7760 = 1.86 [1.58, 2.18] | 7760 | 144/7760 = 1.86 [1.58, 2.18] | 144/7760 = 1.86 [1.58, 2.18] |
| spaces | 8296 | 63/8296 = 0.76 [0.59, 0.97] | 8296 | 63/8296 = 0.76 [0.59, 0.97] | 63/8296 = 0.76 [0.59, 0.97] |
| spelled_digits | 6508 | 524/6508 = 8.05 [7.42, 8.74] | 6508 | 211/6508 = 3.24 [2.84, 3.70] | 525/6508 = 8.07 [7.43, 8.75] |
| spelling | 8148 | 40/8148 = 0.49 [0.36, 0.67] | 8148 | 40/8148 = 0.49 [0.36, 0.67] | 41/8148 = 0.50 [0.37, 0.68] |
| zero_width | 8217 | 269/8217 = 3.27 [2.91, 3.68] | 8217 | 0/8217 = 0.00 [0.00, 0.05] | 269/8217 = 3.27 [2.91, 3.68] |

#### Action downgrades BLOCK to WARN, action level

| Family | BLOCK pairs (defaults) | BLOCK to WARN (defaults) | Evaded or downgraded, of protected (defaults) | BLOCK pairs (+flags) | BLOCK to WARN (+flags) | Evaded or downgraded, of protected (+flags) |
|---|---|---|---|---|---|---|
| unicode | 14551 | 405/14551 = 2.78 [2.53, 3.06] | 804/15814 = 5.08 [4.75, 5.44] | 14551 | 96/14551 = 0.66 [0.54, 0.80] | 226/15814 = 1.43 [1.26, 1.63] |
| inserted_spaces | 7642 | 60/7642 = 0.79 [0.61, 1.01] | 123/8296 = 1.48 [1.24, 1.77] | 7642 | 60/7642 = 0.79 [0.61, 1.01] | 123/8296 = 1.48 [1.24, 1.77] |
| spelling | 7505 | 61/7505 = 0.81 [0.63, 1.04] | 101/8148 = 1.24 [1.02, 1.50] | 7505 | 61/7505 = 0.81 [0.63, 1.04] | 101/8148 = 1.24 [1.02, 1.50] |
| paraphrase | 7152 | 273/7152 = 3.82 [3.40, 4.29] | 417/7760 = 5.37 [4.89, 5.90] | 7152 | 273/7152 = 3.82 [3.40, 4.29] | 417/7760 = 5.37 [4.89, 5.90] |
| indirect_reference | 15288 | 3146/15288 = 20.58 [19.94, 21.23] | 5340/16598 = 32.17 [31.47, 32.89] | 15288 | 3146/15288 = 20.58 [19.94, 21.23] | 5340/16598 = 32.17 [31.47, 32.89] |
| encoded_identifier | 21296 | 3239/21296 = 15.21 [14.73, 15.70] | 3888/23106 = 16.83 [16.35, 17.31] | 21296 | 2007/21296 = 9.42 [9.04, 9.82] | 2343/23106 = 10.14 [9.76, 10.54] |
| long_context | 30576 | 7001/30576 = 22.90 [22.43, 23.37] | 8250/33196 = 24.85 [24.39, 25.32] | 30576 | 7001/30576 = 22.90 [22.43, 23.37] | 8250/33196 = 24.85 [24.39, 25.32] |
| multilingual | 45864 | 78/45864 = 0.17 [0.14, 0.21] | 204/49794 = 0.41 [0.36, 0.47] | 45864 | 78/45864 = 0.17 [0.14, 0.21] | 204/49794 = 0.41 [0.36, 0.47] |
| ALL | 149874 | 14263/149874 = 9.52 [9.37, 9.67] | 19127/162712 = 11.76 [11.60, 11.91] | 149874 | 12722/149874 = 8.49 [8.35, 8.63] | 17004/162712 = 10.45 [10.30, 10.60] |

#### Cluster-bootstrap check of the overall conditional ASR (resampling source documents, 2,000 replicates, seed 20261116)

| Arm | Level | Scope | Conditional ASR % | Cluster-bootstrap 95 % interval |
|---|---|---|---|---|
| defaults | action_level | overall | 2.99 | [2.88, 3.10] |
| defaults | action_level | overall_excluding_value_removing | 2.41 | [2.31, 2.51] |
| defaults | detection_level | overall | 6.52 | [6.32, 6.73] |
| defaults | detection_level | overall_excluding_value_removing | 6.13 | [5.93, 6.34] |
| +flags | action_level | overall | 2.63 | [2.54, 2.73] |
| +flags | action_level | overall_excluding_value_removing | 2.04 | [1.95, 2.12] |
| +flags | detection_level | overall | 6.16 | [5.97, 6.36] |
| +flags | detection_level | overall_excluding_value_removing | 5.75 | [5.56, 5.95] |

#### Prompts evaded by at least one variant (best of all variants per protected prompt, action level)

| Arm | Prompts evaded by at least one variant |
|---|---|
| defaults | 3123/8299 = 37.63 [36.59, 38.68] |
| +flags | 3015/8299 = 36.33 [35.30, 37.37] |

#### Paired comparison of the arms (action level; same protected pairs)

| Scope | Evades only under defaults | Evades only under +flags | Evades under both | Evades under neither | Exact McNemar p |
|---|---|---|---|---|---|
| encoded_identifier | 314 | 1 | 335 | 22456 | 9.47e-93 |
| indirect_reference | 0 | 0 | 2194 | 14404 | 1 |
| inserted_spaces | 0 | 0 | 63 | 8233 | 1 |
| long_context | 0 | 0 | 1249 | 31947 | 1 |
| multilingual | 0 | 0 | 126 | 49668 | 1 |
| overall | 583 | 1 | 4281 | 157847 | 1.85e-173 |
| paraphrase | 0 | 0 | 144 | 7616 | 1 |
| spelling | 0 | 0 | 40 | 8108 | 1 |
| unicode | 269 | 0 | 130 | 15415 | 2.11e-81 |

#### Fail-closed behaviour and executed layers

| Arm | Scored transformed pairs | Pairs with a layer error | BLOCK only from a layer error | Regex status counts (all scored items) | NER status counts | Semantic status counts |
|---|---|---|---|---|---|---|
| defaults | 162712 | 11852 | 5744 | {'ok': 171358} | {'ok': 110278, 'skipped': 61080} | {'error': 11853, 'ok': 98425, 'skipped': 61080} |
| +flags | 162712 | 11851 | 5743 | {'ok': 171358} | {'ok': 104630, 'skipped': 66728} | {'error': 11852, 'ok': 92778, 'skipped': 66728} |

#### Specificity control: shipped-defaults non-ALLOW rate on clean prompts (F1 clean rows)

| Variant | Non-ALLOW (defaults) | BLOCK (defaults) | Non-ALLOW (+flags) | BLOCK (+flags) |
|---|---|---|---|---|
| baseline | 655/1000 = 65.50 [62.50, 68.38] | 520/1000 = 52.00 [48.90, 55.08] | 655/1000 = 65.50 [62.50, 68.38] | 520/1000 = 52.00 [48.90, 55.08] |
| ctx_long_end | 1000/1000 = 100.00 [99.62, 100.00] | 928/1000 = 92.80 [91.03, 94.24] | 1000/1000 = 100.00 [99.62, 100.00] | 928/1000 = 92.80 [91.03, 94.24] |
| ctx_long_middle | 1000/1000 = 100.00 [99.62, 100.00] | 917/1000 = 91.70 [89.83, 93.25] | 1000/1000 = 100.00 [99.62, 100.00] | 917/1000 = 91.70 [89.83, 93.25] |
| ctx_long_start | 1000/1000 = 100.00 [99.62, 100.00] | 920/1000 = 92.00 [90.15, 93.53] | 1000/1000 = 100.00 [99.62, 100.00] | 920/1000 = 92.00 [90.15, 93.53] |
| ctx_window_middle | 160/1000 = 16.00 [13.86, 18.40] | 40/1000 = 4.00 [2.95, 5.40] | 160/1000 = 16.00 [13.86, 18.40] | 40/1000 = 4.00 [2.95, 5.40] |
| paraphrase | 479/898 = 53.34 [50.07, 56.58] | 357/898 = 39.76 [36.60, 42.99] | 479/898 = 53.34 [50.07, 56.58] | 357/898 = 39.76 [36.60, 42.99] |
| spelling | 560/749 = 74.77 [71.53, 77.75] | 488/749 = 65.15 [61.67, 68.48] | 560/749 = 74.77 [71.53, 77.75] | 488/749 = 65.15 [61.67, 68.48] |
<!-- END GENERATED -->

## Reading of the results

1. **Baseline.** PriVoke protects 96.0 % of the untransformed F4 sensitive prompts (7,644 BLOCK, 655 WARN, 347 ALLOW); the 8,299 protected prompts form the conditional denominators. Protection is high partly because the product also flags most clean text: in the specificity control **65.5 % of clean F1 rows are already non-ALLOW** (52.0 % BLOCK). A protected transformed prompt therefore does not show that the identifier was recognised; ASR is the rate of reaching ALLOW, and it is bounded by how rarely the product answers ALLOW on this kind of text.
2. **Overall ASR is low but not zero: 2.99 % conditional (4,864 of 162,712 protected pairs, Wilson [2.91, 3.07]) with defaults and 2.63 % with the flags; unconditional 2.87 % and 2.53 %.** Without the value-removing `indirect_pointer`: 2.41 % and 2.04 %. At the detection level: 6.52 % and 6.16 %, driven by long context. About 37.6 % of protected prompts (3,123 of 8,299) are evaded by at least one of the 20 fixed variants, so trying several transforms succeeds far more often than any single one (best-of-N over fixed transforms, not an adaptive attack).
3. **By family, defaults (conditional, action level).** Indirect reference 13.22 % (`indirect_partial` 12.71 %, `indirect_pointer` 13.72 %); long context 3.76 %, all of it from the short-window placement `ctx_window_middle` (15.05 %), while the three 6,000-character placements are 0.00 % at action level because over-length input fails closed but 22.8 to 23.0 % at detection level; encoded identifiers 2.81 % (`spelled_digits` 8.05 %, `base64` 1.18 %, `hex` 0.33 %); unicode 2.52 % (`zero_width` 3.27 %, `homoglyph` 1.71 %); paraphrase 1.86 %; inserted spaces 0.76 %; spelling 0.49 %; multilingual 0.25 % (zh 0.53 %, de 0.01 %). Downgrades exceed evasions: 11.76 % of protected pairs are evaded or downgraded, and 9.52 % of BLOCK pairs fall to WARN (22.90 % for long context, 20.58 % for indirect references, 15.21 % for encodings).
4. **Short-window dilution (negative result for the semantic layer).** Padding a sensitive prompt with 800 characters of benign filler inside the 512-token window lets 15.05 % reach ALLOW, and the same padding lowers the non-ALLOW rate of clean prompts from 65.5 % to 16.0 %. The semantic layer's decision depends on prompt length as well as on the identifier, which is an evasion route for any attacker who can add benign context.
5. **Over-length input fails closed, indiscriminately.** 11,852 scored transformed pairs had a layer error and 5,744 of them were BLOCKs that exist only because of it. Every over-length clean prompt in the control is also non-ALLOW (1,000 of 1,000). This defeats long-context evasion at the action level but blocks all long benign prompts, and it is the only reason the 6,000-character action-level ASR is 0.00 %.
6. **Robustness flags (paired, action level).** The flags reduce overall conditional ASR from 2.99 % to 2.63 %: 583 pairs evade only under defaults and 1 only under the flags (exact McNemar p = 1.85e-173). The gain is confined to two variants: `zero_width` 3.27 % to 0.00 % and `spelled_digits` 8.05 % to 3.24 % (unicode as a family 2.52 % to 0.82 %, encoded identifiers 2.81 % to 1.45 %). Every other family is identical in both arms with no discordant pair: the flags do not touch homoglyphs, inserted spaces, base64, hex, spelling, paraphrase, indirect references, long context or multilingual variants. Zero-width and spelled-digit attacks are the families the flags were designed against on other sets, so this shows the flags generalise to F4, not that they were found independently.
7. **Source heterogeneity.** Baseline protection ranges from 91.5 % (Nemotron-PII) to 98.7 % (Gretel).

## Limitations

- **Specificity confound** (item 1): protection is cheap on this data because the product over-flags. ASR measures reaching ALLOW, not failing to recognise the identifier; low ASR does not imply recognition.
- **Fixed, non-adaptive transforms.** A stronger or adaptive attacker (optimising against PriVoke, richer paraphrases, mixed-language text, combinations) could do better. The paraphrase lexicon is small, translations cover six languages for identifier-carrying sentences only and drop the original context, and no language model generated text, so the ASR of those families is a floor rather than an estimate of a human or LLM attacker. `indirect_pointer` removes the value, so its transformed prompt may legitimately be non-sensitive; its ASR measures leniency toward residual context.
- **Row labels.** PIIMB labels include low-sensitivity entities (for example AGE, TITLE, GENDER); 347 of 8,646 "sensitive" rows are unprotected before any transform. The label-to-sensitivity relation is not independently adjudicated.
- **Dependence and intervals.** Rows contribute many pairs and cluster by source document (5,745 documents); Wilson intervals over pairs are optimistic. The cluster bootstrap (2,000 replicates) is also narrow because the sample is large, and neither covers a different attacker model.
- **F4 reuse** (see Design): F4 is not unscored; it is disjoint from every flag-design set and from K's design and was not used to change any code.
- **Not the installed client.** The runtime is called in process through its native servicer with the semantic model loaded by the PIPE3 adapter, not through the Chromium extension, native messaging or the Go streaming service, so installed-client handling of a runtime error is not measured. Under regex-first order NER and semantic are skipped after a regex BLOCK, so the layer-level baseline rates count skipped layers as no finding.
- **Execution notes (recorded deviations).** The first launch ran out of memory in 5 of 12 baseline shards because each process parsed the whole 227 MB frozen file; the loader was changed to stream per shard (`98677cf`) and scoring resumed. A second orchestration was started while the first was still running; scoring is deterministic per item and a dedupe pass found zero duplicate and zero conflicting records before the final run. The frozen sets, transforms and analysis definitions were not changed. One baseline prompt had a layer error (fail-closed). The full run (12 processes, about one hour) fit the time budget, so no subsample was used.
- **Flag arm.** Only the combination of the four flags was run, not each flag separately.
- **Scores are local.** Per-row scores and frozen sets are not committed (F4-derived text); the JSON carries aggregates and their file hashes, so the tables re-derive from the JSON, while recomputing from raw requires the local data and the commands above.
