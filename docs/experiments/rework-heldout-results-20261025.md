# Regex rework (K) on the F4 fresh draw: results of the v3 registration (2026-10-25)

**Scope: detector layers only (regex, NER, regex OR NER). Not LLM-only, not semantic, not full-product.** Registered in `docs/research/preregistration-detector-v3-20261025.md`; data frozen by `docs/research/fresh-sets-freeze-v3-20261025.md`; K, trees and scoring code frozen by `docs/research/fresh-sets-freeze-addendum-v3-20261025.md` (commit `bf91b113`, committed before any F4 row was scored). Machine-readable results: `docs/experiments/rework-heldout-results-20261025.json` (hypothesis records, per-configuration tables, identities, exploratory tables, span summaries). Per-row outputs (ids, flags, spans only) and the full aggregate stay under the gitignored `evaluation/results/v3_scoring_20261025/` (`analysis_full.json` sha256 `4d2cf0e8...`).

Labelling: sections 2 to 4 are **REGISTERED** (tests, cells and rules fixed before scoring). Section 5 is **second-look** material (registered but non-confirmatory: not fresh for O, N or, through the published F1 record, K). Section 6 is **EXPLORATORY (post hoc)**: produced after the registered results were seen; it cannot satisfy, replace or rescue a registered hypothesis.

User instruction (25 Oct 2026, verbatim in the registration): "Rework the regex rules that cost recall (validators that dropped real identifiers, driver-licence gate, child/family) with a general labelled-identifier rule, then test on a new registered draw of fresh positives. Waive the N+R doc check; hold lg for now."

## 1. Execution record

- Configurations: O (export of `e6c177ff`), N (`e70e3a2e`), **K** (`b7e716c3`, tree `59b92ab9`), **K+all** (`research/v3-candidate` `4e695783`, K merged with the robustness commit and the four flags on). Equivalence of the merge with all flags off to K: 0 mismatches over 4,004 development-type rows and byte-identical per-row files (addendum section 2). Detector tests: 117 pass on K, 155 on the merged tree.
- Scoring: two configurations at a time (K and K+all, then O and N), `PYTHONFAULTHANDLER=1`, host Python 3.11.9 (`.venv-v1-v3-pipeline`), explicit layers `["regex","ner"]`, `regex_first=False`, no semantic layer, no Docker, no network. **No crash, no restart, no resumed run.** K and K+all took about 18 minutes each (F4, F1, F3, F2), O and N about 4 minutes each (F4). Latency is not a claim of this record (the elapsed times are not measurements).
- Completeness (the analysis refuses otherwise): F4 8,646 rows, all positive, for O, N, K, K+all; F1 16,446 (10,000 positive, 6,446 clean); F3 2,000; F2 6,000; identical id lists and labels across configurations. O and N reuse their Wave 3 per-row files for F1, F2, F3 (sha256 in the addendum); their F4 files are scored fresh.
- Row texts were never printed. No hypothesis, margin, threshold, code path or tree was changed after the addendum.
- Bootstrap: whole `group_id` clusters (F4: 5,745 source documents; S1: 3,805), 10,000 replicates, seed 20261024, 95 % percentile intervals; the lower limit is the one-sided 97.5 % bound. Deltas are candidate minus reference in percentage points.

## 2. REGISTERED: H7, H8 (primary, confirmatory, fresh F4)

| Hypothesis | n | rate O -> K (%) | delta pt [95 % CI] | gained / lost | margin | Wald lower (row / cluster) | Verdict |
|---|---|---|---|---|---|---|---|
| **H7** union recall K - O, rule `positive` | 8,646 | 84.05 -> 83.00 | **-1.05 [-1.70, -0.41]** | 342 / 433 | -1.0 pt | -1.68 / -1.70 | **INCONCLUSIVE** (lower bound -1.70 is below -1.0 and the upper limit -0.41 is above it; the point estimate is itself 0.05 pt beyond the margin) |
| **H8** union recall K - O, rule `block` | 8,646 | 50.71 -> 50.72 | **+0.01 [-0.33, +0.35]** | 104 / 103 | -0.5 pt | -0.31 / -0.33 | **PASS** |

H7 is not a pass (registration criterion 1): the interval includes both values above and below the margin, and the pre-registered conclusion for a non-pass is the trade-off, stated below. **Reading of the interval (stated plainly).** The upper bound -0.41 means K is **significantly worse than O on union recall, by roughly 0.4 to 1.7 pt** (exact McNemar p = 0.0012). "Inconclusive" holds only relative to the registered 1-pt non-inferiority margin: the data neither show a loss within 1 pt nor a loss beyond it. Power note: the observed discordance on F4 is 9.0 % (775 of 8,646) against the planned 8.2 %; power at a true zero effect was 90 % at 8.2 % and 83.7 % at 10 %, and a true effect of -0.5 pt was predicted to be inconclusive more often than not. The result is consistent with a true delta near -1 pt; it neither shows non-inferiority nor shows that the true loss exceeds 1 pt (that would need an upper limit at or below -1.0).

Context on the same rows (not hypotheses):

| Cell (union unless stated) | delta pt [95 % CI] | gained / lost | exact McNemar p |
|---|---|---|---|
| N - O, `positive` (what the shipped defaults cost) | -1.85 [-2.50, -1.21] | 308 / 468 | 1.0e-8 |
| N - O, `block` | -1.55 [-1.82, -1.30] | 0 / 134 | 9.2e-41 |
| **K - N, `positive`** | **+0.80 [+0.62, +0.99]** | 69 / 0 | 3.4e-21 |
| **K - N, `block`** | **+1.56 [+1.29, +1.84]** | 135 / 0 | 4.6e-41 |
| K - N, regex layer, `positive` | +1.04 [+0.83, +1.26] | 90 / 0 | 1.6e-27 |
| K - O, regex layer, `positive` | -1.26 [-1.58, -0.94] | 48 / 157 | 1.0e-14 |
| K - O, NER layer, `positive` (K and N have identical NER records on every row) | -4.58 [-5.67, -3.53] | 903 / 1,299 | 3.2e-17 |

Recall by configuration on F4 (point estimates, %): union `positive` O 84.05, N 82.20, K 83.00, K+all 83.00; union `block` O 50.71, N 49.16, K 50.72, K+all 50.72; regex-only `positive` O 73.63, N 71.33, K 72.37; NER-only `positive` O 34.70, N = K = 30.12.

**Reading.** K restores about 43 % of N's union-recall loss (N -1.85, K -1.05) and all of its BLOCK-level loss (N -1.55, K +0.01), and on F4 K dominates N on every recall rule (`positive` 69 gained / 0 lost, `block` 135 / 0, `warn_or_block` 82 / 0). These K - N recall cells are context, not registered hypotheses, and K is not better than N on every cell: it costs 5 clean rows on F1 clean (G2 -0.08 [-0.15, -0.02], all five from `labelled_identifier_generic`) and, secondarily, masks more text (span over-masking +10.82 per 1,000 characters, K - N). What remains of the K-O union gap is partly the NER layer (the NER-only recall falls 4.58 pt; the NER layer is identical for N and K) and partly regex rules K deliberately does not restore (section 6).

## 3. REGISTERED: false-positive guards G1, G2 (second look on S1 = F1 clean, 6,446 rows; not fresh, so a pass means "not contradicted")

| Guard | n | specificity ref -> K (%) | delta pt [95 % CI] | gained / lost | margin | Verdict |
|---|---|---|---|---|---|---|
| **G1** union specificity K - O | 6,446 | 85.23 -> 88.47 | **+3.24 [+2.53, +3.98]** | 385 / 176 | -1.0 pt | **PASS** |
| **G2** union specificity K - N | 6,446 | 88.55 -> 88.47 | **-0.08 [-0.15, -0.02]** | 0 / 5 | -2.0 pt (confirmed by root on 25 Oct 2026) | **PASS** (K keeps 98 % of N's +3.32 pt gain) |

## 4. REGISTERED: promotion verdict for K (registration section 6)

| Criterion | Status |
|---|---|
| 1. H7 passes | **NOT MET** (inconclusive, lower bound -1.70 pt) |
| 2. H8 passes | met (lower bound -0.33 pt) |
| 3. G1 and G2 on S1 | met (second look) |
| 4. Critic review | done: all registered cells recompute; no leakage found; see sections 7 and 8 |
| 5. Latency below 20 % | met per the separate record `docs/experiments/detector-latency-v3-20261025.md` (`efe0e719`; not measured by this scoring) |
| 6. Historical synthetic context (K's design sets, from `docs/experiments/regex-rework-20261025.md`) | met: personalized K 1.000 vs N 1.000; openai K 0.920 vs N 0.918 |

**K is NOT promoted** (criterion 1 fails). The pre-registered conclusion is the trade-off: relative to the pre-PR detector O, K buys union specificity +3.24 pt (S1, second look), regex-only specificity +1.68 pt, and keeps BLOCK-level recall level (+0.01 pt); it costs union recall -1.05 pt on F4 (342 gained, 433 lost; lower bound -1.70 pt), which the registration could not show to be within 1 pt. Relative to N, K dominates on every F4 recall rule (`positive` 69/0, `block` 135/0, `warn_or_block` 82/0) and costs 5 clean rows on S1 (G2 -0.08 [-0.15, -0.02], all from `labelled_identifier_generic`) and +10.82 over-masked characters per 1,000 (secondary); the K - N recall cells are context, not registered hypotheses. Nothing is changed automatically; the owner decides between keeping N, adopting K as a better but unpromoted regex layer, or a further rework with a new registration (the PIIMB pool can no longer supply a draw).

**K+all.** Identical to K on every F4 row (regex, NER and union records, 0 differences), on F3, and on F1 and F2 except one NER-only flip each (the caseless gate drops one F1 positive's NER hit with the union unchanged, and flags one more F2 prompt). Descriptive non-inferiority of K+all against O on F4 is the same inconclusive result (-1.05 [-1.70, -0.41]). Registered expectation (flips on clean text near zero): met (0 union flips on F1, F3, F4; +1 flagged F2 prompt). It does not alter any verdict.

### Per-source and source-standardised (registered secondaries; not used for promotion)

| Source | rows / documents | H7 K - O | H8 K - O | H7 N - O | H7 K - N | regex K - N |
|---|---|---|---|---|---|---|
| ai4privacy | 2,950 / 1,813 | +2.41 [+1.32, +3.56] (171/100) | -1.05 [-1.60, -0.52] (15/46) | +1.83 [+0.72, +2.97] | +0.58 [+0.31, +0.86] | +0.92 [+0.58, +1.28] |
| Gretel | 2,863 / 1,616 | +0.52 [-0.28, +1.33] (77/62) | +1.47 [+0.81, +2.13] (68/26) | -0.87 [-1.69, -0.07] | +1.40 [+0.98, +1.85] | +1.57 [+1.13, +2.05] |
| Privy | 2,151 / 2,071 | **-8.00 [-9.57, -6.41]** (69/241) | -1.12 [-1.58, -0.70] (0/24) | -8.04 [-9.63, -6.45] | +0.05 [+0.00, +0.14] | +0.05 [+0.00, +0.14] |
| Nemotron-PII (reported only, 682 rows) | 682 / 245 | -0.73 [-2.97, +1.49] (25/30) | +2.05 [+0.44, +3.74] (21/7) | -2.35 [-4.60, -0.15] | +1.61 [+0.72, +2.69] | +2.49 [+1.32, +3.78] |

**Heterogeneity finding (registered rule): Privy is a documented negative heterogeneity finding.** Its whole 95 % interval for union recall K - O (-9.57 to -6.41) lies below -1.0 pt (2,151 rows, above the 700-row floor). K - N in Privy is +0.05 (1 row), so K's regex rework does not change Privy; the Privy loss is the same as N's (-8.04 N - O) and **predates K**. The F1 record found the same Privy loss (-6.57 N - O). Any statement that the Privy loss is NER-dominant is **not** supported by the registered analysis (no per-source layer swap was registered); the critic's exploratory within-Privy layer swap is in section 6. The other sources are positive or inconclusive for K - O. The pooled H7 therefore averages a large Privy loss with gains in ai4privacy. No decision is made on a single stratum. The critic must address this finding. Note also the BLOCK-level K - O interval is below zero in ai4privacy (-1.05) and Privy (-1.12) while positive in Gretel and Nemotron-PII; the pooled H8 is level.

Source-standardised union recall K - O (stratified cluster bootstrap, 10,000 replicates): with the F1 positive mix (0.3374, 0.3325, 0.1687, 0.1614) **-0.43 [-1.06, +0.24]**; with equal weights **-1.45 [-2.23, -0.67]**. For N - O the same weights give -1.37 [-2.01, -0.71] and -2.36 [-3.12, -1.58]; for K - N +0.94 [+0.71, +1.19] and +0.91 [+0.64, +1.21]. (Information only: against -1.0 pt both K - O figures would be inconclusive, with the F1-mix point estimate inside the margin and the equal-weight one outside it; the pooled unweighted estimate -1.05 is close to the equal-weight figure. F4 is Privy-heavy, as the registration warned.)

## 5. Second-look cells (descriptive; non-confirmatory)

**H9 (S1 = F1 clean, 6,446 rows).** Specificity, positive rule, delta pt [95 % CI] (gained/lost): K - O regex +1.68 [+1.34, +2.03] (114/6), union +3.24 [+2.53, +3.98] (385/176); K - N regex -0.08 [-0.15, -0.02] (0/5), union -0.08 (0/5); N - O (context, equals the Wave 3 record) regex +1.75, union +3.32. Rules `warn_or_block`: K - O union +2.05 [+1.38, +2.74], K - N -0.08; `block`: K - O regex = union +0.76 [+0.54, +1.00] (49/0), K - N 0. Exact McNemar p for K - N is 0.0625 (five losses, no gains). K keeps part of N's regex precision gain, essentially all of it on these data; this is not a confirmatory specificity result.

**F1 positives (10,000 rows, second look).** Union recall K - O -0.36 [-0.94, +0.22] (396/432); K - N +1.01 [+0.81, +1.21] (101/0); N - O -1.37 [-1.95, -0.80] (reproduces Wave 3). `block` recall K - O -0.29 [-0.62, +0.04]; K - N +1.61 [+1.36, +1.87] (161/0). Regex-only recall K - O -0.89 [-1.20, -0.59], K - N +1.29 [+1.07, +1.52]. These numbers are close to non-inferiority on F1 but F1 is not the confirmatory set for K (the F1 per-rule table informed the rework).

**F3 (long documents, 2,000 positives).** Union recall 100.00 % for O, N, K, K+all (NER-only 99.80 O, 99.65 N = K); K and N per-row files are byte-identical on F3 and F2. Uninformative for recall.

**F2 natural prompts (6,000, unlabelled; flag rates, no verdict).** Union positive: O 24.4 % (1,465), N 16.7 % (1,001), **K 16.7 % (1,001)**, K+all 16.7 % (1,002); regex layer O 397, N = K 248; NER layer N = K 813; union `block` O 130, N = K 65. K flags exactly the same 1,001 prompts as N (0 differing). By source (union, K): Dolly 255, oasst2 234, WildChat 512. **Extra blinded packets for K: none are needed** (`pool-extra` set is empty: all 1,001 K-flagged prompts, and the one K+all-only prompt, are already in the 2,449-prompt pool). H9b stays "not evaluated" until the pending human adjudication.

**Spans (secondary, no hypothesis; scope all, minimum sensitivity 0, union).** F4: overlap recall K - O +2.93 [+2.48, +3.38], K - N +1.30 [+1.16, +1.45]; character coverage K - O +5.00 [+4.43, +5.56], K - N +1.47 [+1.33, +1.62]; over-masked characters per 1,000: K - N **+10.82 [+9.95, +11.72]** (K's labelled-identifier spans mask more surrounding text than N's; K - O -1.86 [-6.73, +2.54]). F1 shows the same pattern (K - N over-masking +8.91 per 1,000). On the long F3 documents the old regex layer's spans cover nearly everything, so the O-versus-K span deltas there (character coverage -28.18, over-masking -875.83 per 1,000) are dominated by that behaviour and are not a recall result (as in Wave 3). Details in the JSON.

## 6. EXPLORATORY (post hoc; no promotion use)

- **Layer attribution on F4 (exact layer swapping, union recall `positive` versus O).** O-regex + K-NER (= N-NER): -0.28 [-0.88, +0.31] (308/332); K-regex + O-NER: -0.59 [-0.84, -0.34] (36/87); N-regex + O-NER: -1.39 [-1.64, -1.14] (0/120); K (= K-regex + N-NER): -1.05. K's regex layer repairs 0.80 of the 1.39 pt that N's regex layer loses, leaving -0.59 in the regex layer; the NER-layer change contributes -0.28 on its own and the two do not add exactly (they overlap on rows both layers hit).
- **Privy layer swap and what the lost rows were (critic's exploratory analysis, `w3-critic/v3/privy.py`, recomputed from the per-row outputs; not registered).** Within Privy (union recall versus O): O-regex + K-NER -5.16 [-6.63, -3.73] (68/179); K-regex + O-NER -2.23 [-2.89, -1.62] (1/49); K -8.00 [-9.57, -6.41] (69/241). Outside Privy K - O is **+1.25 [+0.59, +1.92]** (273/192). So the Privy loss has both a NER-layer part and a regex-layer part (O's regex rules that N and K removed: of the 241 lost rows, 179 were NER-only in O, 36 regex-only, 26 both; the O regex rules on them were `family_disclosure` 38, weak driver-licence recogniser 29, `child` 8, `iban` 6). Of the 241 lost Privy rows, **164 had O NER spans that touch no annotated span** and about **77 (about 3.6 pt of Privy) had an O NER span touching an annotated one** (gold labels hit: LOCATION 44, PERSON 16, ORGANIZATION 12, NRP 3). On F1, O's NER fires on 31.8 % of Privy clean rows against 37 % of Privy positives, and O's union flags 48 % of Privy clean rows (N and K: 29 %), so much of O's Privy "recall" is indiscriminate flagging. Caveat: PIIMB annotation is incomplete by construction, so unannotated PII in the 164 rows cannot be ruled out; the loss may be partly a false-positive reduction and partly real misses.
- **Rules behind the K-O union-recall flips (F4).** Of 433 lost rows: 327 NER-only in O, 66 regex-only in O, 40 both. Regex-caused losses (rows where O's regex fired): `family_disclosure` 30 rows (29 as the only rule; 38 of 39 spans off annotated PII), `iban` 15 (8 spans on, 7 off annotated PII), `concentrated_sensitive_data` 8, `child` 4, `location_keyword` 2, weak credit-card recogniser 2, `presidio_daterecognizer` 2. Of 342 gained rows 306 are NER-only; the regex gains are `labelled_identifier_generic` (24 rows, 23 sole) and `labelled_identifier_sensitive` (13) plus `concentrated_sensitive_data` (6), with 37 of 38 labelled-identifier spans on annotated PII. BLOCK flips K-O: 104 gained, all `labelled_identifier_sensitive`; 103 lost: IBAN 77 rows, `child` 14, generic IBAN recogniser 5, weak card 3, SSN 3, NHS 2 (35 to ALLOW, 68 to WARN). K versus N: all 69 union gains and 135 BLOCK gains are regex hits (`labelled_identifier_generic` 41 rows, `labelled_identifier_sensitive` 22, `concentrated_sensitive_data` 13, `unverified_number_identifier` 6, `credit_card_unverified` 4, `ssn_unverified` 1, `iban_unverified` 1), all but one of the spans on annotated PII.
- **Not restored by K, by design:** `family_disclosure`, `child` and the unlabelled IBAN, card and NHS recognisers; these lost rows are mostly hits on text the annotation does not mark (family/child) or on values that look like identifiers by shape only (IBAN). K's development record states the same cost.
- **Strata (union recall K - O).** By length quartile: Q1 +0.09 [-1.37, +1.55], Q2 -0.83 [-1.99, +0.33], Q3 -0.28 [-1.47, +0.93], **Q4 (203+ characters) -3.21 [-4.46, -1.95]**; the loss concentrates in long sentences. By annotated category (rows may carry several): losses in LOCATION -9.62 [-12.48, -6.81], NRP -10.27, PERSON -6.65, ORGANIZATION -7.32, license_plate -5.81, DATE_TIME -2.92 (categories mostly carried by the NER layer; the per-category split by layer was not run); gains in GIVENNAME +5.60, SURNAME +4.94, last_name +7.95, first_name +5.39, BUILDINGNUM +3.59, STREET +3.20 (the NER layer carries them), `medical_record_number` +0.69 [+0.14, +1.38], and, by arithmetic on the K - O and N - O columns, K - N gains of about +7.5 pt in `customer_id` and +4.2 pt in `employee_id`. Full category table in the JSON.

## 7. Critic review notes (low-severity items and checks)

An independent critic recomputed every registered cell exactly (H7, H8, G1, G2, per-source, standardised, counts and discordances) and found no leakage or contamination. Additional notes:
- **Freeze order.** The F4 freeze commit (`8295a7ab`, 11:39:09) landed 13 s after the K code freeze (`b7e716c3`, 11:38:56). This has no effect: K was designed on development data only and the F4 file was drawn and hashed earlier.
- **K's qualifier lexicon** mirrors the label vocabulary of PIIMB that is present in the development spans (for example customer, employee, account, policy, member). The labelled-identifier gains on F4 are therefore tied to PIIMB labelling conventions and may not transfer to text that does not use such labels.
- **Out-of-distribution probe.** `labelled_identifier_generic` fires at S2 (WARN) on technical text such as `user_id=12345`, `?user_id=abc123` and `client id 0x1F2A3B` (as K's own record warned); the F2 flag set does not change (K = N on all 6,000 prompts). A regex stress test (long hyphen, space and label repetitions) showed no catastrophic backtracking (`w3-critic/v3/redos.py`).
- **Latency (criterion 5).** Met per `docs/experiments/detector-latency-v3-20261025.md` (`efe0e719`): K - N 0.00 ms median, K+all +0.06 ms; largest regression +0.4 %; K about +2.4 % against O across sessions. Criterion 5 is therefore met; criterion 4 is this critic review.

## 8. Critic summary for the owner (verbatim, w3-critic-2, 25 Oct 2026)

> K vs N: on fresh F4 positives, K catches every row N catches plus 69 more (+0.80 pt union recall, +1.56 pt BLOCK level). On the F1 clean rows (not fresh), it adds 5 false positives (−0.08 pt). On 6,000 natural prompts it flags exactly the same prompts as N.
>
> K vs O: K's union recall is lower by 1.05 pt [0.41, 1.70], and that loss is real. BLOCK-level recall is equal. Union specificity is +3.24 pt on F1 clean rows (not fresh).
>
> Where the gap comes from: mostly the NER changes (case preservation, post-filter) that K shares with N, concentrated in Privy text, where O's NER barely separates clean from positive rows.
>
> The choice: if PR #5 ships, ship K rather than N. Reverting to O buys back about 1 pt of union recall, mostly through O's noisy NER, and gives up about 3.2 pt of union specificity.

The decision belongs to the owner.

## 9. Limitations, deviations and incidents

- F4 is positives-only; false-positive behaviour rests on S1 (consumed for O and N, published before K was frozen) and on F2 flag rates (unlabelled). G1 and G2 passes are "not contradicted". The PIIMB pool is exhausted; a further confirmation needs a new source.
- Criterion 4 (critic review) and criterion 5 (latency) are addressed in sections 4, 7 and 8; they do not change the verdict, which fails on criterion 1. The F2 adjudication, the 200-row label-noise audit and the H9b cells remain pending human raters.
- Source mix: F4 is Privy-heavy (25 %) and Nemotron-light (8 %) relative to F1 and the locked sets, which the registration flagged as unfavourable; the Privy NER loss is the dominant reason for the H7 shortfall.
- Deviations: (1) the addendum is committed as `fresh-sets-freeze-addendum-v3-20261025.{md,json}` (the name used in the registration), not the order `freeze-v3-addendum` of the assignment text; (2) the first scripts commit (`b562f929`) had an unterminated string in a render-only line, fixed in `f1182a98` before the addendum and before any F4 row was scored (the addendum hashes the fixed file); (3) a scratch worktree `wt-v3-cand` (branch `research/v3-candidate`) was created to build the K+all merge; (4) the registration's "O and N reuse F1, F2, F3" was implemented by reading the Wave 3 files in place (hashes recorded), not by copying them.
- No rule, label mapping, threshold or code path was changed on the basis of F4 or second-look results. Bugs found after scoring: none.
