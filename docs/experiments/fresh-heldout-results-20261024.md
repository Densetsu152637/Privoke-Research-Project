# Fresh held-out results: detector precision follow-ups (Wave 3, 2026-10-24/25)

**Scope: detector layers only (regex, NER, regex OR NER). Not LLM-only, not semantic, not full-product.** Registered in `docs/research/preregistration-detector-v2-20261024.md`; frozen by `docs/research/fresh-sets-freeze-20261024.md` (`57e3cb7b`) and the addendum `docs/research/fresh-sets-freeze-addendum-20261024.md` (commit `37b02251`, committed before any fresh row was scored). Machine-readable results: `docs/experiments/fresh-heldout-results-20261024.json` (all hypothesis records, per-configuration tables, span and perturbed results; the full aggregate and per-row outputs stay under the gitignored `evaluation/results/w3_scoring_20261024/`).

**Labelling convention (amended after the independent critic review).** Sections marked **REGISTERED** contain only tests, cells and decision rules fixed in the pre-registration and addendum before scoring (sections 2, 2.1 and 3, and the descriptive flag rates of section 4). Section 5 is **EXPLORATORY (post hoc)**: it was produced after the registered results were seen, uses no new data, and cannot satisfy, replace or rescue any registered hypothesis.

User instruction (24 Oct 2026): "Proceed with Wave 3 once S finishes and the addendum is committed; report natural-prompt flag rates descriptively and evaluate the natural-prompt hypotheses after human adjudication."

## 1. Execution record (incidents, stated plainly)

- **First launch (21:50) was interrupted** by a host session restart about 21:55 and produced no output at all (all output directories empty). It was restarted unchanged, with no change to code or configuration.
- **Second launch** (O and N+lg started 22:08, N+trf 22:09, N+strip 22:33, N+email 22:46, N+caseless 22:49; the start times of N and N+all were overwritten in their run metadata by the resumed runs, 04:41 and 05:58, and N+digits reran from 05:16): the nine configurations were scheduled four at a time. Six finished cleanly. **N exited 139 and N+all exited 139 (segmentation faults)** and **N+digits exited 127** (empty log, nothing written). The cause of the two segmentation faults was not identified; they did not recur when the configurations were run one at a time with `PYTHONFAULTHANDLER=1` (a diagnostic setting that does not affect results). N had written its F1 rows and spans; N+all had written F1, F3 and F2 and crashed during perturbed-item scoring. The code is unchanged (driver sha256 `12b1c596...`, analysis `1c12b4b8...`).
- **Reruns, one at a time, identical per-configuration command:** N resumed (kept its complete F1 output, scored F3, F2 and the perturbed items), N+digits ran in full, N+all resumed (perturbed items only). Resumption skips sets whose atomically written output exists (addendum item 9); no output was ever overwritten and no scored set was scored twice. Every configuration is complete: F1 16,446 rows and spans, F3 2,000, F2 6,000; N and the five N+R configurations each have 58,899 perturbed items (9,538 `zero_width`, 6,812 each of `digits_space`/`digits_dot`/`digits_dash`, 5,237 `digits_words`, 1,329 each of the three `email_*`, 9,811 `lowercase`, 9,890 `uppercase`; 10,000 distinct rows).
- The committed `w3_run.sh score` starts all nine at once; the actual runs used the same per-configuration command through a scheduling wrapper (invocation only). The script header demands `TREES_ROOT` for every stage; a dummy value was set for `pool` and `analyse`.
- No hypothesis, threshold or code was changed after scoring started. Row texts were never printed. Latency is taken from the separate record `docs/experiments/detector-latency-20261025.md` (section 3).

Configurations and sources: O = export of `e6c177ff`; N = export of `e70e3a2e`; N+R and N+lg/N+trf = `research/w3-candidate` `058942e0` with the registered flags (merge shown identical to N on 4,004 development-type rows). spaCy 3.7.5; `en_core_web_sm` 3.7.1, `en_core_web_lg` 3.7.1, `en_core_web_trf` 3.7.3. Data: F1 16,446 rows (10,000 positive, 6,446 clean, 8,184 clusters), F3 2,000 positive-only rows, F2 6,000 unlabelled prompts. 10,000 bootstrap replicates, seed 20261024, whole `group_id` clusters, 95 % percentile intervals; the lower (upper) limit is the one-sided 97.5 % bound.

## 2. REGISTERED: hypothesis results (deltas in percentage points, candidate minus reference)

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

### 2.1 REGISTERED secondary: source-stratified analysis (pre-registration section 10; not used for promotion)

Same tests as above within each F1 `source_dataset` (union and regex layers, positive rule; 10,000 replicates, seed 20261024; computed by `evaluation/w3_followup.py`). The registration lists this analysis as secondary; the first version of this record omitted it. Deltas in points with 95 % intervals.

| Source (positives / clean rows) | H1 regex specificity N-O | H2 union recall N-O | H2b union specificity N-O | H3a union specificity lg-N | H3b NER specificity lg-N | H3c union recall lg-N |
|---|---|---|---|---|---|---|
| ai4privacy (3,374 / 1,504) | +1.93 [+1.21, +2.72] | +1.96 [+0.95, +2.92] | +1.00 [-0.44, +2.43] | +3.66 [+2.64, +4.76] | +3.79 [+2.75, +4.90] | +2.58 [+1.77, +3.38] |
| Gretel (3,325 / 2,024) | +1.88 [+1.28, +2.56] | -0.45 [-1.30, +0.37] | +2.03 [+0.81, +3.29] | +1.88 [+1.03, +2.73] | +2.22 [+1.27, +3.18] | +0.42 [-0.15, +0.97] |
| Nemotron-PII (1,687 / 2,088) | +0.91 [+0.47, +1.39] | -4.86 [-6.36, -3.38] | +0.00 [-0.90, +0.88] | +2.54 [+1.87, +3.27] | +3.07 [+2.33, +3.85] | +1.19 [+0.36, +2.02] |
| Privy (1,614 / 830) | +3.25 [+2.12, +4.49] | -6.57 [-8.29, -4.93] | +19.04 [+15.95, +22.12] | -4.34 [-6.73, -1.91] | -7.59 [-10.37, -4.84] | +4.03 [+2.52, +5.58] |

Reading. The pooled union-recall loss (H2) is not uniform: ai4privacy +1.96 [+0.95, +2.92] (a gain), Gretel -0.45 [-1.30, +0.37] (inconclusive), Nemotron-PII -4.86 [-6.36, -3.38] and Privy -6.57 [-8.29, -4.93] (large losses). The N-O union specificity gain is likewise concentrated (Privy +19.04 [+15.95, +22.12]; the intervals for ai4privacy and Nemotron-PII include 0). The regex-only specificity gain (H1) is positive and its interval excludes 0 in all four sources, with regex recall falling in all four. For N+lg versus N, union specificity (H3a) and NER-only specificity (H3b) rise in ai4privacy, Gretel and Nemotron-PII but **fall in Privy** (H3a -4.34 [-6.73, -1.91], H3b -7.59 [-10.37, -4.84]), while union recall rises in all four. **The pooled H3a and H3b results therefore depend on the F1 source mix**: Privy is 12.9 % of the F1 clean rows and Nemotron-PII is 23 % of F1 against about 60 % of the locked development/final sets, so a pool with a different mix could change the size, and for a Privy-heavy mix the sign, of the specificity gain. The registration pooled sources without weighting; this table is the registered check on that choice and is a heterogeneity finding, not a verdict.

## 3. REGISTERED: promotion verdicts (section 6 of the registration)

Criterion 4 (critic review): an independent critic recomputed the numbers and confirmed every registered verdict and the determinism of the resumed runs; the critic's exploratory findings are in section 5. Criterion 5 (latency, `docs/experiments/detector-latency-20261025.md`: host-process detector-layer latency, 1,000 development-type prompts, 3 repeats; mean per-prompt time against the old mean of 28.3 ms): N +3.2 %, each N+R configuration at most +5 %, N+lg +1.8 % (all below the 20 % limit: **pass**), N+trf +211 % (**fails; not eligible**). Memory: N+lg +762 MB resident, N+trf +2.4 GB.

- **N (shipped defaults): NOT promoted. Criterion 2 fails: H2 non-inferiority of union recall is not established (-1.37 pt, lower bound -1.95 against a -1.0 margin).** The owner exemption covers only the OpenAI-synthetic criterion and is conditional on H2 passing, so it does not rescue N. The pre-registered conclusion is the trade-off: the regex repairs and case preservation buy regex specificity +1.75 pt (114 gains vs 1 loss), union specificity +3.32 pt and less over-masking, and cost union recall -1.37 pt (342 gains, 479 losses), regex recall -2.18 pt and a 1.90 pt loss in BLOCK-level recall (190 rows move from BLOCK to a lesser action, none the other way). Criteria 1 (H1) and 5 are met.
- **N+lg: criteria 1 to 3 and 5 met on F1/F3** (H3a and H3b pass after Holm; H3c passes on F1 with a recall gain and on F3 trivially at the ceiling; historical synthetic recall: personalized 1.000 to 1.000, openai 0.918 to 0.920; latency +1.8 %). Open: H3a' (F2 adjudication), the source heterogeneity of section 2.1 (the pooled gain does not hold in Privy), the owner's size decision (about 550 MB on disk, +762 MB resident), and the choice of base (below). The declared training sources of `en_core_web_lg` contain no PIIMB source.
- **N+trf: not eligible** (pre-registered comparator; +211 % latency). Descriptively it has the highest specificity (union 91.87, NER-only 99.35) at the lowest NER recall (25.23) and unchanged union recall.
- **N+strip, N+digits, N+email, N+caseless, N+all: H5 passes after Holm and H6 passes on the F1 and F3 cells, but the pre-declared documentation check is UNMET.** The registration requires the default-off flag documentation to exist at the frozen commit `b1975bc2`. At that commit only code comments in `config.py` and the unit tests (`test_robustness_fixes.py`, present) exist; the documentation (`docs/detectors/preprocessing.md`, `ner.md`) arrived in the docs-only follow-up `3f9aa450` (there is no runtime difference between `b1975bc2` and `b3d11a50`). Promoting any N+R candidate therefore **requires an owner waiver** of that check, plus the H6 F2 cell and criterion 4 sign-off. `N+all` satisfies the registered rule (all four constituent flags pass H5 and H6 individually; H5e also passes). Criterion 3 for N+R is the historical no-flip context (not re-scored). **Read H5 and H6 with the caveats of section 5.4: H5 is largely circular and H6 passes on zero flips.**

**Pending, by owner:**
1. Owner decisions: (a) keep, revert or rework the regex repairs, rule by rule, under section 8 of the registration (section 5.2 lists the rules); (b) waive the documentation check for the N+R candidates; (c) the model-size decision for N+lg; (d) whether N+lg is promoted on top of N or on the post-decision regex base.
2. Humans: the blinded F2 adjudication of the 2,449-prompt pool (H1b, H2b F2 part, H3a', H6 F2 cell) and the registered 200-row label-noise audit of flagged-clean F1 rows.

Limits that bear on the verdicts: the perturbed items test the transforms the fixes were designed against, so H5 shows that each fix works on its own transform and says nothing about how often such inputs occur; F1 positives include attribute spans (age, title, gender) that PriVoke has no detector for, which is one reason recall is far from 100 %; F3 recall is saturated, so its non-inferiority cells carry no information; PIIMB label noise was not audited.

## 4. F2 natural prompts: descriptive flag rates only (no verdicts; unlabelled)

Flagged share of 6,000 prompts, union layer, positive rule (Wilson 95 %): O 24.4 % (1,465); N 16.7 % (1,001; Wilson [15.8, 17.6] %; O [23.3, 25.5] %; N+lg [16.4, 18.3] %); N+strip, N+digits, N+email 16.7 % (1,001); N+caseless and N+all 16.7 % (1,002); N+lg 17.3 % (1,037); N+trf 15.6 % (934). Layer rates (positive rule): regex O 6.6 %, N 4.1 %; NER O 20.0 %, N 13.6 %, N+lg 14.2 %, N+trf 12.3 %. Action level, union: `warn_or_block` O 20.3 %, N 11.7 %, N+lg 11.5 %, N+trf 10.3 %; `block` O 2.2 %, N 1.1 % (all N-derived configurations 65 prompts). By source, union positive, N: Dolly 255/1,500, oasst2 234/2,000, WildChat 512/2,500 (O: 438, 342, 685). Against N the union flag sets differ as follows: O +761 / -297 prompts, N+lg +247 / -211, N+trf +231 / -298; the N+R configurations differ from N in at most one prompt. These are flag rates, not error rates: whether a flagged natural prompt contains personal data is unknown until adjudication.

**Review pool (blinded, without labels):** 2,449 prompts = 2,049 prompts flagged by the union layer (positive rule) in at least one of the nine configurations + the 400-item seeded audit sample (first 400 items of the key's audit order flagged by none). 25 packets of up to 100 (`pool-packet-001..025.jsonl`, items hold only the opaque id and the text) under `evaluation/results/fresh_sets_20261024/f2_adjudication/pool/packets/`; the coordinator membership and per-configuration flag lists are under `pool/coordinator/` (not for raters). This is larger than the planning figure of about 1,500 because the old defaults flag 24 % of prompts. Hypotheses H1b, H2b (F2 part), H3a' and the F2 cell of H6 will be evaluated after adjudication.

## 5. EXPLORATORY (post hoc; produced after the registered results were seen; not for promotion)

Everything in this section comes from `evaluation/w3_followup.py` (JSON key `exploratory_post_hoc`) and the critic's recomputation, on the same F1 outputs, under the positive rule; there is no new data. It explains the registered H2 result; it cannot rescue it.

### 5.1 Layer attribution of the H2 loss (exact layer swapping)

Union decision = regex layer of one configuration OR NER layer of another, compared with O on F1 (candidate minus O):

| Hybrid | Union recall | Union specificity |
|---|---|---|
| O-regex + N-NER | +0.08 [-0.43, +0.61] | +1.75 [+1.12, +2.41] |
| N-regex + O-NER | -1.49 [-1.73, -1.26] | +1.44 [+1.14, +1.76] |
| N (registered reference) | -1.37 [-1.95, -0.79] | +3.32 [+2.60, +4.07] |
| O-regex + lg-NER | +1.98 [+1.42, +2.55] | +3.48 [+2.90, +4.07] |
| N+lg (full) versus O | +0.49 [-0.13, +1.10] | +5.03 [+4.38, +5.71] |

The union-recall loss sits in the regex layer: keeping the old regex layer and taking the new NER layer gives +0.08. Of the 479 positives lost by N, 117 are regex-only hits in O, 29 hits in both layers and 333 NER-only hits in O; the 342 gains are all NER hits. The **146 regex-caused lost rows** (the old regex layer fired) are tabulated below; 90 of them have an old regex span on annotated PII, the other 56 were hits on text the annotation does not mark. The regex rule repairs and the case-preserving input are not separable here: that needs a new registered draw. The hybrid rows and the N+lg versus O row cannot substitute for H2, and N+lg versus O is not a registered comparison.

### 5.2 Per-rule table of the 146 regex-caused lost rows

| Old regex rule (O) | Lost rows containing rule | Lost rows where it is the only regex rule | Rule spans on / off annotated PII | Clean rows with union FP fixed (containing / sole) | BLOCK-lost rows with an S3 span of the rule |
|---|---|---|---|---|---|
| presidio_uslicenserecognizer_driver license - alphanumeric (weak) | 63 | 56 | 54 / 23 | 37 / 32 | 0 |
| iban | 37 | 22 | 29 / 8 | 8 / 0 | 139 |
| family_disclosure | 22 | 19 | 0 / 32 | 12 / 10 | 0 |
| concentrated_sensitive_data | 18 | 0 | 18 / 0 | 19 / 0 | 0 |
| child | 10 | 7 | 0 / 11 | 26 / 10 | 26 |
| presidio_creditcardrecognizer_all credit cards (weak) | 10 | 3 | 11 / 0 | 0 / 0 | 15 |
| ssn_formatted | 5 | 0 | 5 / 0 | 0 / 0 | 6 |
| presidio_ibanrecognizer_iban generic | 3 | 2 | 3 / 0 | 0 / 0 | 4 |
| presidio_usssnrecognizer_ssn3 (very weak) | 3 | 0 | 3 / 0 | 0 / 0 | 4 |
| presidio_usssnrecognizer_ssn5 (medium) | 3 | 0 | 3 / 0 | 0 / 0 | 4 |
| credit_card | 2 | 0 | 2 / 0 | 0 / 0 | 4 |
| financial_keyword | 2 | 2 | 0 / 2 | 13 / 13 | 0 |
| presidio_usssnrecognizer_ssn1 (very weak) | 2 | 0 | 2 / 0 | 0 / 0 | 2 |
| location_keyword | 1 | 1 | 0 / 1 | 0 / 0 | 0 |
| presidio_daterecognizer_mm/yy or m/yy | 1 | 0 | 1 / 0 | 3 / 3 | 0 |
| presidio_nhsrecognizer_nhs (medium) | 1 | 1 | 1 / 0 | 0 / 0 | 3 |
| structured_identity | 1 | 1 | 0 / 1 | 9 / 9 | 0 |
| personal_narrative | 0 | 0 | 0 / 0 | 1 / 1 | 0 |

Columns: rows among the 146 whose old regex output contains the rule (and where it is the only rule); old-rule spans on and off annotated PII on those rows; clean F1 rows whose union false positive disappears under N and in which the rule fired (385 clean union false positives are fixed in total: 283 through the NER layer alone, 88 through the regex layer alone, 14 where both layers fired); BLOCK-lost rows with an S3 span of the rule. The weak driver-licence, IBAN, concentrated-sensitive-data, credit-card and SSN recognisers are the main cost side (their lost hits are largely on annotated PII); `child`, `family_disclosure`, `financial_keyword` and `structured_identity` hits are entirely off annotated PII, so their removal costs 'positives' by label without losing a listed entity. A per-rule keep, revert or rework decision belongs to the owner (section 3).

### 5.3 BLOCK-level loss

190 positives are BLOCK under O and not under N, none the other way; every one is a BLOCK produced by the old regex layer. 107 become WARN and 83 ALLOW (maximum sensitivity S3 to S2: 107, to S1: 18, to S0: 65). S3 rules involved: IBAN 139 rows, child 26, weak credit-card recogniser 15, SSN recognisers 14, credit_card 4, generic IBAN recogniser 4, NHS 3.

### 5.4 H5 circularity and H6 triviality

- H5a: `N+strip` on `zero_width` is **identical** to N on the unperturbed text on all 9,538 items (0 mismatches, recall 81.30 % both ways): the flag undoes the transform the hypothesis was built from.
- H5b: `N+digits` gains come from `digits_dash` (56.5 to 91.2; N on the unperturbed rows 91.1) and `digits_words` (53.9 to 96.5; unperturbed 96.0). On `digits_space` N already scores 91.1 and the flag adds nothing; on `digits_dot` N already scores 99.0 (flag 98.8).
- H5c: `N+email` restores the three email transforms to the unperturbed level (68.7, 68.8, 69.7 to 100.0, 100.0, 99.85).
- H5d: `N+caseless` is a no-op on `lowercase` (77.0 to 77.0); on `uppercase` it moves 74.3 to 76.85, still below the unperturbed 80.9 on those rows. The pooled +1.30 pt is all uppercase.
- H6 passes because there are **zero union flips** on clean F1 and F3 (F3 sits at 100 % recall); it could only have failed if a flag changed clean-text decisions, so for default-off canonicalisations a pass is close to guaranteed and says little beyond that.

## 6. Limitations and deviations

Deviations from the freeze record: the per-row version of `evaluate_installed_detectors.py` is used (addendum); the pre-registration cites `research/wt-g-nermodels` `f4f07c3c` for N+lg and N+trf, but the NER-model option in the scored tree comes from `research/wt-d-nerrole` `ba660071` (via the candidate tree `058942e0`), which has the same `PRIVOKE_NER_MODEL` option without G's default-off GLiNER backend (the spaCy decisions are identical, as confirmed in the critic's review); the two crashes and the scheduling described in section 1; resumption of N and N+all. The perturbation statistics treat items of one row as one cluster; clusters are the stored `group_id` values (111 rows, 108 Privy and 3 Gretel, have ids ending in `_sN` and may over-split). Wald bounds agree with the bootstrap bounds throughout. F2 is unlabelled; no F2 verdict exists.

## 7. Post-scoring owner decisions (25 Oct 2026)

Recorded after the registered verdicts of sections 2 and 3 were produced. They do not change any registered result, verdict or number above; they decide what happens next. The owner was offered the options listed under "Pending, by owner" in section 3 and chose to rework the regex repairs. Verbatim, as stated by the owner:

> "Rework the regex rules that cost recall (validators that dropped real identifiers, driver-licence gate, child/family) with a general labelled-identifier rule, then test on a new registered draw of fresh positives. Waive the N+R doc check; hold lg for now."

| # | Pending item in section 3 | Owner decision | Consequence |
|---|---|---|---|
| (a) | Keep, revert or rework the regex repairs | **Rework**: replace the rules that cost recall (validators that dropped real identifiers, the driver-licence gate, child and family-disclosure) with a general labelled-identifier rule; call the result **configuration K**. K is designed on development data only by a separate agent (branch `research/wt-k-rework`); its freeze commit SHA is recorded in a v3 freeze addendum **before any F4 row is scored**. | N remains "not promoted" (H2 failed). K is tested on a new registered draw of fresh positives, **F4**, under `docs/research/preregistration-detector-v3-20261025.md` (H7 union-recall non-inferiority versus O with margin 1.0 pt, H8 BLOCK-level non-inferiority, H9 second-look specificity). The freeze record of F4 is `docs/research/fresh-sets-freeze-v3-20261025.md`. The F1 exploratory material of section 5 informed the decision to rework but is not scoring evidence for K. |
| (b) | Waive the documentation check for the N+R candidates (section 3, N+R paragraph) | **Waived by the owner.** | The pre-declared check "default-off flag documentation exists at the frozen commit `b1975bc2`" is no longer an obstacle to promoting an N+R candidate; it stays recorded here as UNMET at that commit and WAIVED by the owner on 25 Oct 2026 (documentation exists at `3f9aa450`). The waiver covers only this check: the H6 F2 cell and the critic sign-off (criterion 4) are still required for an N+R promotion, and the caveats of section 5.4 (H5 largely circular, H6 trivial) stand. |
| (c) | Size decision and promotion of N+lg | **Held.** Nothing is decided. | N+lg is neither promoted nor rejected; the registered N+lg results of sections 2 and 3, including the Privy heterogeneity of section 2.1, remain the evidence. It is not scored in the v3 registration. |
| (d) | F2 adjudication (H1b, H2b F2 part, H3a', H6 F2 cell) and the 200-row label-noise audit | **Unchanged: pending human raters.** | No F2 verdict and no label-noise sensitivity result exists yet. The v3 registration adds K to the F2 review pool (extra blinded prompts only) but does not replace the existing 2,449-prompt pool. |

The data pool bounds what can still be drawn: after the exclusion of every group used so far (including all F1 groups) the PIIMB pool holds 8,646 unused positive sentences (cap 3 per source document) and **no** clean sentence, so F4 is positives-only and K's false-positive behaviour can only be examined as a non-confirmatory second look (F1 clean rows, already consumed for O and N) and later on F2 after adjudication. Details: `docs/research/preregistration-detector-v3-20261025.md` and the freeze record.
