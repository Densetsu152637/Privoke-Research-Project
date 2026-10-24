# Fresh held-out results: detector precision follow-ups (Wave 3, 2026-10-24/25)

**Scope: detector layers only (regex, NER, regex OR NER). Not LLM-only, not semantic, not full-product.** Registered in `docs/research/preregistration-detector-v2-20261024.md`; frozen by `docs/research/fresh-sets-freeze-20261024.md` (`57e3cb7b`) and the addendum `docs/research/fresh-sets-freeze-addendum-20261024.md` (commit `37b02251`, committed before any fresh row was scored). Machine-readable results: `docs/experiments/fresh-heldout-results-20261024.json` (all hypothesis records, per-configuration tables, span and perturbed results; the full aggregate and per-row outputs stay under the gitignored `evaluation/results/w3_scoring_20261024/`).

User instruction (24 Oct 2026): "Proceed with Wave 3 once S finishes and the addendum is committed; report natural-prompt flag rates descriptively and evaluate the natural-prompt hypotheses after human adjudication."

## 1. Execution record (incidents, stated plainly)

- **First launch (21:50) was interrupted** by a host session restart about 21:55 and produced no output at all (all output directories empty). It was restarted unchanged, with no change to code or configuration.
- **Second launch** (from 22:32): the nine configurations were scheduled four at a time. Six finished cleanly. **N exited 139 and N+all exited 139 (segmentation faults)** and **N+digits exited 127** (empty log, nothing written). The cause of the two segmentation faults was not identified; they did not recur when the configurations were run one at a time with `PYTHONFAULTHANDLER=1` (a diagnostic setting that does not affect results). N had written its F1 rows and spans; N+all had written F1, F3 and F2 and crashed during perturbed-item scoring. The code is unchanged (driver sha256 `12b1c596...`, analysis `1c12b4b8...`).
- **Reruns, one at a time, identical per-configuration command:** N resumed (kept its complete F1 output, scored F3, F2 and the perturbed items), N+digits ran in full, N+all resumed (perturbed items only). Resumption skips sets whose atomically written output exists (addendum item 9); no output was ever overwritten and no scored set was scored twice. Every configuration is complete: F1 16,446 rows and spans, F3 2,000, F2 6,000; N and the five N+R configurations each have 58,899 perturbed items (9,538 `zero_width`, 6,812 each of `digits_space`/`digits_dot`/`digits_dash`, 5,237 `digits_words`, 1,329 each of the three `email_*`, 9,811 `lowercase`, 9,890 `uppercase`; 10,000 distinct rows).
- The committed `w3_run.sh score` starts all nine at once; the actual runs used the same per-configuration command through a scheduling wrapper (invocation only). The script header demands `TREES_ROOT` for every stage; a dummy value was set for `pool` and `analyse`.
- No hypothesis, threshold or code was changed after scoring started. Row texts were never printed. Latency is not reported (separate step).

Configurations and sources: O = export of `e6c177ff`; N = export of `e70e3a2e`; N+R and N+lg/N+trf = `research/w3-candidate` `058942e0` with the registered flags (merge shown identical to N on 4,004 development-type rows). spaCy 3.7.5; `en_core_web_sm` 3.7.1, `en_core_web_lg` 3.7.1, `en_core_web_trf` 3.7.3. Data: F1 16,446 rows (10,000 positive, 6,446 clean, 8,184 clusters), F3 2,000 positive-only rows, F2 6,000 unlabelled prompts. 10,000 bootstrap replicates, seed 20261024, whole `group_id` clusters, 95 % percentile intervals; the lower (upper) limit is the one-sided 97.5 % bound.

## 2. Hypothesis results (deltas in percentage points, candidate minus reference)

| Hypothesis | Estimate [95 % CI] | Discordant counts / test | Verdict |
|---|---|---|---|
| **H1** regex-only specificity, N - O, F1 clean (n = 6,446) | **+1.75 [+1.42, +2.11]** (90.68 to 92.43) | 114 gained, 1 lost; exact McNemar p = 5.6e-33 | **pass** |
| H1b same on F2 benign | - | - | not evaluated (F2 unlabelled, adjudication pending) |
| (H1 side effect, not a gate) regex-only recall, N - O | -2.18 [-2.47, -1.90] (72.25 to 70.07) | 1 gained, 219 lost | reported |
| **H2** union recall non-inferiority, N - O, F1 positives (n = 10,000, margin 1.0) | **-1.37 [-1.95, -0.79]** (82.29 to 80.92) | 342 gained, 479 lost; McNemar p = 2.0e-6; Wald lower bound -1.93 (row), -1.95 (cluster) | **FAIL**: lower bound -1.95 is below -1.0; the whole interval is below 0 |
| **H2b** union specificity non-inferiority, N - O, F1 clean (margin 1.0) | **+3.32 [+2.60, +4.07]** (85.23 to 88.55) | 385 gained, 171 lost | **pass** on F1 (F2 part pending) |
| exploratory: union specificity superiority, N - O | +3.32 [+2.60, +4.07] | McNemar p = 5.8e-20 | exploratory, positive |
| **H3a** N+lg union specificity vs N, F1 clean | **+1.71 [+1.17, +2.24]** | 205 gained, 95 lost; p = 2.0e-10; Holm p < 1e-9 | **pass** |
| **H3b** N+lg NER-only specificity vs N, F1 clean | **+1.60 [+1.01, +2.20]** | 234 gained, 131 lost; p = 7.7e-8; Holm p < 1e-6 | **pass** |
| **H3c** N+lg union recall non-inferiority vs N, F1 | **+1.86 [+1.43, +2.30]** | 336 gained, 150 lost | **pass** (also a recall gain) |
| **H3c** same on F3 | 0.00 [0.00, 0.00] | recall is 100.00 % for every configuration | pass, **uninformative** (ceiling) |
| H3a' N+lg on F2 | - | - | not evaluated (adjudication pending) |
| N+trf (descriptive only) union specificity / NER-only specificity / union recall vs N | +3.32 [+2.85, +3.80] / +4.05 [+3.52, +4.58] / -0.04 [-0.52, +0.43] | spec +230/-16 (union); recall +289/-293 | descriptive; not promotable this round |
| **H4** character coverage N - O (leak non-inferiority, margin 1.0), F1 | **+2.87 [+2.35, +3.40]**; leak 39.33 to 36.46 | union spans, scope all | **pass** |
| **H4** over-masking N - O (characters outside annotated spans per 1,000 characters; margin +10) | **-12.75 [-16.69, -9.28]** (93.63 to 80.88) | | **pass** |
| **H5a** `N+strip` on `zero_width`, union recall vs N (9,538 items) | **+9.11 [+8.37, +9.87]** (72.18 to 81.30) | 1,114 gained, 245 lost; Holm p = 3.4e-132 | **pass** |
| **H5b** `N+digits` on the four `digits_*` (25,673 items, 6,979 rows) | **+17.82 [+17.28, +18.36]** (76.44 to 94.26) | 4,618 gained, 44 lost; Holm p < 1e-300 | **pass** |
| **H5c** `N+email` on the three `email_*` (3,987 items, 1,329 rows) | **+30.90 [+28.43, +33.36]** (69.05 to 99.95) | 1,232 gained, 0 lost; Holm p < 1e-300 | **pass** |
| **H5d** `N+caseless` on `lowercase` and `uppercase` (19,701 items, 9,984 rows) | **+1.30 [+1.05, +1.55]** (75.61 to 76.90) | 454 gained, 198 lost; Holm p = 4.5e-24 | **pass** (small; see section 3) |
| **H5e** `N+all` on all ten transforms (58,899 items, 10,000 rows) | **+11.77 [+11.43, +12.10]** (74.97 to 86.74) | 7,418 gained, 487 lost; Holm p < 1e-300 | **pass** |
| **H6** each N+R vs N on unperturbed F1 recall, F1 specificity, F3 recall (margin 1.0) | all lower bounds 0.00 | union flips: 0 on F1 (both classes) and 0 on F3 for all five | **pass on the three evaluated cells**; F2 cell pending |

Notes. (i) "p < 1e-300" means the exact test underflowed. (ii) On clean text the five N+R configurations match N on every union decision; the only differences are in the NER layer alone: `N+caseless` and `N+all` lose one F1 positive's NER hit (union unchanged) and flag one more F2 prompt each. (iii) The `ner-only` deltas next to H5: `N+strip` +0.81 [-0.04, +1.64], `N+digits` +0.24, `N+email` -1.15 [-1.53, -0.80], `N+caseless` +2.71 [+2.31, +3.11], `N+all` +1.06; the regex layer carries the strip, digits and email gains.

### Secondary tables (F1, positive rule; point estimates, 95 % intervals in the JSON)

| Layer / config | Recall | Specificity | Precision | F2 |
|---|---|---|---|---|
| regex O / N | 72.25 / 70.07 | 90.68 / 92.43 | 92.32 / 93.49 | 75.53 / 73.77 |
| NER O / N / N+lg / N+trf | 31.57 / 27.48 / 31.18 / 25.23 | 92.83 / 95.30 / 96.90 / 99.35 | 87.23 / 90.07 / 93.97 / 98.36 | 36.19 / 31.92 / 35.99 / 29.64 |
| union O | 82.29 | 85.23 | 89.63 | 83.66 |
| union N (= all N+R) | 80.92 | 88.55 | 91.64 | 82.86 |
| union N+lg | 82.78 | 90.26 | 92.95 | 84.63 |
| union N+trf | 80.88 | 91.87 | 93.92 | 83.19 |

Union recall on F3 is 100.00 % for all nine configurations (NER-only 99.65 to 99.95 %). Action level (secondary), N - O on F1: union `warn_or_block` recall -2.86 [-3.47, -2.25] and specificity +2.13 [+1.45, +2.82]; **`block` recall -1.90 [-2.18, -1.63] with 0 gained and 190 lost**, all from the regex layer, and `block` specificity +0.76 [+0.54, +1.00]. N+lg versus N, union `warn_or_block`: recall +1.56, specificity +1.66; `block` is identical.

Spans (secondary; `span_scoring`, scope all, minimum sensitivity 0). F1, N - O, union: overlap recall +1.19 [+0.76, +1.63], overlap precision 57.84 to 61.83, share of prompts with every gold span fully masked 37.31 to 37.16 (no significant change); regex-only character coverage -1.35 [-1.57, -1.15]; NER-only +2.62. N+lg vs N, union: overlap recall +1.79 [+1.46, +2.13], character coverage +2.33. P4 (NER extends regex masking only when the regex layer fired; descriptive, no hypothesis): on F1 for N it reaches character coverage 57.39 against 49.54 for regex only and 63.54 for the full union, i.e. it recovers part of the NER span gain and gives up 5.22 pt [4.88, 5.56] of overlap recall relative to the union. **F3 anomaly:** on the long F3 documents the old regex layer's spans cover nearly the whole text (character coverage 99.97 %, 955 over-masked characters per 1,000), so the F3 old-versus-new span deltas (union character coverage -29.09, over-masking 955.5 to 78.2 per 1,000) are dominated by that behaviour and are not a recall result; unmapped gold labels: none; spanless positive results: 0 in every layer.

## 3. Promotion verdicts (section 6 of the registration; criteria 4 and 5 and every F2 item remain pending)

- **N (shipped defaults): NOT promoted. Criterion 2 fails: H2 non-inferiority of union recall is not established (-1.37 pt, lower bound -1.95 against a -1.0 margin).** The owner exemption covers only the OpenAI-synthetic criterion and is conditional on H2 passing, so it does not rescue N. The pre-registered conclusion is the trade-off: the regex repairs and case preservation buy regex specificity +1.75 pt (114 gains vs 1 loss), union specificity +3.32 pt and less over-masking, and cost union recall -1.37 pt (342 gains, 479 losses), regex recall -2.18 pt and a 1.90 pt loss in BLOCK-level recall (190 flows from BLOCK to lesser action, none the other way). The registration's section 8 requires a documented decision on keeping the regex repairs; that decision belongs to the owner, and the defaults are not reverted here. Criterion 1 (H1) is met.
- **N+lg: criteria 1 to 3 met on F1/F3** (H3a and H3b pass after Holm; H3c passes on F1 with a recall gain, on F3 trivially at the ceiling; historical synthetic recall: personalized 1.000 to 1.000, openai 0.918 to 0.920). Conditional on H3a' (F2 adjudication), the critic review, latency, and the owner's distribution decision (about 550 MB more than `sm`). The declared training sources of `en_core_web_lg` contain no PIIMB source.
- **N+trf: not eligible** (pre-registered comparator). Descriptively it has the highest specificity (union 91.87, NER-only 99.35) at the lowest NER recall (25.23) and unchanged union recall.
- **N+strip, N+digits, N+email, N+caseless: each passes its H5 hypothesis after Holm, and H6 on the F1 and F3 cells**; conditional on the H6 F2 cell, the critic review and latency. `N+all` satisfies the registered rule (all four constituent flags pass H5 and H6 individually; H5e also passes). Caveats: `N+caseless` helps only uppercase text (74.3 to 76.8 on `uppercase`, 77.0 to 77.0 on `lowercase`) and its pooled gain is small (+1.30 pt); `N+strip` also loses 245 of 9,538 items. The pre-declared check at the frozen commit `b1975bc2` finds the per-flag unit tests (`test_robustness_fixes.py`) there; the flag documentation (`docs/detectors/preprocessing.md`, `ner.md`) is added by the docs-only follow-up `3f9aa450`, not by `b1975bc2` itself, so the strict reading of the check is met for tests and met for documentation only through that follow-up. Criterion 3 for N+R is the historical no-flip context (not re-scored).

Limits that bear on the verdicts: the perturbed items test the transforms the fixes were designed against, so H5 shows that each fix works on its own transform and says nothing about how often such inputs occur; F1 positives include attribute spans (age, title, gender) that PriVoke has no detector for, which is one reason recall is far from 100 %; F3 recall is saturated, so its non-inferiority cells carry no information; PIIMB label noise was not audited (the registered 200-row sensitivity sample is not done).

## 4. F2 natural prompts: descriptive flag rates only (no verdicts; unlabelled)

Flagged share of 6,000 prompts, union layer, positive rule (Wilson 95 %): O 24.4 % (1,465); N 16.7 % (1,001; Wilson [15.8, 17.6] %; O [23.3, 25.5] %; N+lg [16.4, 18.3] %); N+strip, N+digits, N+email 16.7 % (1,001); N+caseless and N+all 16.7 % (1,002); N+lg 17.3 % (1,037); N+trf 15.6 % (934). Layer rates (positive rule): regex O 6.6 %, N 4.1 %; NER O 20.0 %, N 13.6 %, N+lg 14.2 %, N+trf 12.3 %. Action level, union: `warn_or_block` O 20.3 %, N 11.7 %, N+lg 11.5 %, N+trf 10.3 %; `block` O 2.2 %, N 1.1 % (all N-derived configurations 65 prompts). By source, union positive, N: Dolly 255/1,500, oasst2 234/2,000, WildChat 512/2,500 (O: 438, 342, 685). Against N the union flag sets differ as follows: O +761 / -297 prompts, N+lg +247 / -211, N+trf +231 / -298; the N+R configurations differ from N in at most one prompt. These are flag rates, not error rates: whether a flagged natural prompt contains personal data is unknown until adjudication.

**Review pool (blinded, without labels):** 2,449 prompts = 2,049 prompts flagged by the union layer (positive rule) in at least one of the nine configurations + the 400-item seeded audit sample (first 400 items of the key's audit order flagged by none). 25 packets of up to 100 (`pool-packet-001..025.jsonl`, items hold only the opaque id and the text) under `evaluation/results/fresh_sets_20261024/f2_adjudication/pool/packets/`; the coordinator membership and per-configuration flag lists are under `pool/coordinator/` (not for raters). This is larger than the planning figure of about 1,500 because the old defaults flag 24 % of prompts. Hypotheses H1b, H2b (F2 part), H3a' and the F2 cell of H6 will be evaluated after adjudication.

## 5. Limitations and deviations

Deviations from the freeze record: the per-row version of `evaluate_installed_detectors.py` is used (addendum); the two crashes and the scheduling described in section 1; resumption of N and N+all. The perturbation statistics treat items of one row as one cluster; clusters are the stored `group_id` values (108 Privy and Gretel rows have ids ending in `_sN` and may over-split). Wald bounds agree with the bootstrap bounds throughout. F2 is unlabelled; no F2 verdict exists.
