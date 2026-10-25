# Pre-registration v3: regex rework (configuration K) on a new fresh draw of positives (2026-10-25)

**Status: FROZEN at the commit that adds `docs/research/fresh-sets-freeze-v3-20261025.md` and `.json` (the F4 data were drawn and hashed first; no detector, NER model or LLM has been run on any F4 row). One slot is deliberately open: the freeze commit of configuration K, which is being designed on development data by another agent and is recorded in a v3 freeze addendum (section 9) before any F4 row is scored. Amendments are permitted only before any F4 row is scored and must be committed with a note in the freeze record or the addendum. Scope: detector layers (regex, NER, regex OR NER). Not LLM-only, not semantic-layer, not full-product.**

Parent registration: `docs/research/preregistration-detector-v2-20261024.md` (v2). Its results: `docs/experiments/fresh-heldout-results-20261024.md`. This document reuses v2's statistics, decision conventions and single-scoring rule unless it says otherwise, and does not reopen any v2 verdict.

## 1. Owner decisions that define this registration (25 Oct 2026)

The owner chose to rework the regex repairs. Verbatim:

> "Rework the regex rules that cost recall (validators that dropped real identifiers, driver-licence gate, child/family) with a general labelled-identifier rule, then test on a new registered draw of fresh positives. Waive the N+R doc check; hold lg for now."

Recorded as follows (the same table is in section 7 of the results record):

- (a) **Regex repairs: rework.** Configuration **K** replaces the rules that cost recall with a general labelled-identifier rule. K is designed on development data only (dev-TUNE and the personalized synthetic set; the dev-CHECK and OpenAI sets are post-review) by a separate agent on `research/wt-k-rework`. Its freeze commit SHA is recorded in a v3 addendum before scoring (section 9). The F1 to F3 sets and the locked final set are not design data.
- (b) **The N+R documentation check is waived by the owner.** It stays recorded as unmet at `b1975bc2` and waived on 25 Oct 2026. N+R candidates are not scored in v3.
- (c) **N+lg promotion is held, not decided.** N+lg and N+trf are not scored in v3.
- (d) **F2 adjudication and the 200-row F1 label-noise audit remain pending human raters.** No v3 claim depends on them, except where section 4 says "after adjudication".

## 2. Why a new registration, and what the evidence behind K is

v2 H2 failed for the shipped defaults N: union recall -1.37 pt versus O on F1 [-1.95, -0.79] (342 gained, 479 lost), with a BLOCK-level loss of 1.90 pt (190 rows, none gained). Post hoc (results record section 5, exploratory, no new data) the loss sits in the regex layer: the hybrid "O regex + N NER" is +0.08 pt [-0.43, +0.61] against O, and the hybrid "N regex + O NER" is -1.49. The per-rule table of the regex-caused lost rows names the rule families that cost annotated PII (weak driver-licence recogniser, IBAN, concentrated-sensitive-data, credit-card and SSN recognisers) and the families whose removal only costs hits on text the annotation does not mark (`child`, `family_disclosure`, `financial_keyword`, `structured_identity`). Those tables are exploratory and are **not** evidence for K; they are why the owner asked for a rework.

v2 section 7 says a second scoring "requires a new, separately registered fresh draw (new seed, disjoint groups, including disjoint from the F-sets)". F4 is that draw. v2 reserved the name F4 for an optional TAB ECHR set that was never built; in this document **F4 means the PIIMB draw of section 3** (identifier `F4-v3` where ambiguity matters). The TAB set stays unbuilt and unused.

## 3. Data

### 3.1 F4: new fresh positives (the confirmatory set)

| Item | Value |
|---|---|
| Source | PIIMB `data/test_sentences.jsonl` at revision `4a13e9ffe6fd0d275efbde8afd4d8d8f1ffc2133`, sha256 `5ff46f3a80316318794f94596fa374060d70f2f32a85909f958cbabc70bae41f` (the same file as F1; no new download) |
| Rows | **8,646 positive sentences** (every sentence has at least one annotated entity), 5,745 source documents, 23,534 annotated entity spans (kept) |
| Seed / cap | seed 11102026, at most 3 sentences per source document (the v2 ceiling; see 3.3) |
| Exclusion | every group used anywhere before: the v2 exclusion union (locked development and final groups, plus every group token found in training, validation and earlier-study artifacts; re-scanned on 25 Oct), **and every F1 group** (positives and clean). Normalised exclusion: 21,399 groups, sha256 `4017ce4d21c64b694db55b7b88e5dd109cdcd2c29405c2085694d8f186fec53e`. Post-draw check (`fresh_set_plan.py disjoint`): 0 shared groups, 0 shared ids, 0 shared text hashes with F1 |
| Labels | PIIMB entity spans (as v2). Positive means at least one annotated entity of any label; attribute labels PriVoke has no detector for (age, title, gender) count, which is why recall is far from 100 % (as in F1) |
| Source mix (rows / groups) | ai4privacy-OpenPII 2,950 rows / 1,813 documents / 10,823 spans; Gretel 2,863 / 1,616 / 6,493; Privy 2,151 / 2,071 / 4,922; Nemotron-PII 682 / 245 / 1,296 (row shares 34.1 %, 33.1 %, 24.9 %, 7.9 %). Sentences per document: 3,955 documents with 1, 679 with 2, 1,111 with 3. Text length: median 126, p90 332, max 1,433 characters |

Pool sizes (after exclusion, English, duplicates and conflicting duplicates removed; positives only):

| Cap per source document | Positive rows | Source documents | Clean rows |
|---|---|---|---|
| 1 | 5,745 | 5,745 | 0 |
| 2 | 7,535 | 5,745 | 0 |
| 3 | **8,646** | 5,745 | 0 |

By source at cap 3: ai4privacy-OpenPII 2,950, Gretel 2,863, Nemotron-PII 682, Privy 2,151. The pool is exhausted by F4: no further PIIMB draw (positive or clean) is possible after this registration.

### 3.2 Why the source mix matters, and how F4 differs from F1

The F1 source-stratified analysis showed that the N-O union-recall loss was concentrated in Nemotron-PII (-4.86 pt) and Privy (-6.57 pt) and absent or positive in ai4privacy (+1.96) and Gretel (-0.45), so the pooled result depends on the mix. F4's mix (ai4privacy 34 %, Gretel 33 %, Nemotron-PII 8 %, Privy 25 %) is Privy-heavy and Nemotron-light relative to F1 (34 / 33 / 17 / 16 %) and to the locked sets (about 60 % Nemotron-PII). Re-weighting the F1 per-source N-O recall deltas to the F4 mix predicts about -1.5 pt for N on F4 (arithmetic from the published table; a planning figure, not an F4 result). **The F4 mix is therefore unfavourable to a regex change of N's kind, and the registration does not correct for that in the primary analysis (unweighted pooled, as v2). The per-source and standardised secondaries below exist so that any source dependence is reported.**

### 3.3 Cap rule and size

The v2 rule increases the cap only when the pool is short of the target. The target is the sample size for 80 % power at true delta 0 with a discordance of 10 % (rather than the observed 8.2 %, for margin): 7,849 positives. Cap 1 (5,745) and cap 2 (7,535) are short; cap 3 (8,646) suffices, and the whole cap-3 pool is drawn (the seed therefore only orders rows and breaks within-document ties; it cannot select a favourable subset). No sampling of the pool is done after seeing any detector output.

### 3.4 Power (computed before any scoring; `fresh_set_plan.py ni-power`; Wald non-inferiority, one-sided alpha 0.025, Monte-Carlo checks within 2 points)

Observed on F1 for N versus O: 342 + 479 discordant of 10,000, psi = 8.2 %. K shares N's NER layer, so the NER-driven discordance (about 6.8 %) carries over; psi = 8.2 % is used, as instructed, with 10 % and 11 % as sensitivity.

**H7 (margin 1.0 pt, union recall, n = 8,646):**

| psi | true delta 0 | true delta -0.25 pt | true delta -0.5 pt | n for 80 % at delta 0 / -0.5 |
|---|---|---|---|---|
| 8.2 % | **90.1 %** | 68.3 % | 36.8 % | 6,437 / 25,737 |
| 10 % | 83.7 % | 59.7 % | 31.2 % | 7,849 / 31,388 |
| 11 % | 80.1 % | 55.7 % | 28.8 % | 8,634 / 34,528 |
| 8.2 %, cluster design effect 1.2 | 84.2 % | | 31.7 % | |

Power at true delta 0 is at least 80 % for every discordance up to 11 % when rows are independent, and 84.2 % at 8.2 % with a cluster design effect of 1.2; it falls to 76.6 % at 10 % discordance with that design effect (below the 80 % target, stated here rather than hidden). **Power for a true delta of -0.5 pt is only about 37 % (80 % power there would need 25,737 positives; the PIIMB pool holds 8,646).** The margin is not lowered and the shortfall is not hidden: if K's true effect is -0.5 pt, H7 is more likely than not to be inconclusive, and an inconclusive H7 is not a pass (v2 criterion 2). The v2 F1 data suggest a design effect near 1 (Wald row and cluster bounds -1.93 and -1.95).

**H8 (margin 0.5 pt, union recall under the `block` rule, n = 8,646):** the N-O BLOCK discordance on F1 was 190 of 10,000 (1.9 %, one-directional). At psi = 1.9 %: power 92.1 % at delta 0 (86.8 % with design effect 1.2), 39.2 % at -0.25 pt; at psi = 2.5 %: 83.7 %; at psi = 3 %: 76.6 %; n for 80 % at psi = 1.9 % and delta 0 is 5,966.

## 4. Second-look clean data (non-confirmatory) and why there is no fresh clean set

The PIIMB clean pool was exhausted at cap 3 for F1 (6,446 clean rows) and nothing remains after excluding F1's groups (table in 3.1: 0 clean rows). A genuinely fresh clean set cannot be built **without a detector or a human label** from sources already downloaded: unlabelled prompts (the unused part of oasst2 or Dolly) would need blind human adjudication to be called clean, which is the same bottleneck as F2, and no new download is requested. The registration therefore states plainly:

- **Second look S1 (non-confirmatory): the F1 clean subset, 6,446 rows, 3,805 source documents.** O and N were already scored on it in v2, so it is not fresh for them; K has never been scored on it, but the F1 results (including the per-rule exploratory table that names the rules fixing clean-row false positives) were published before K was frozen, so S1 cannot be called untouched for K either. S1 is used only for the H9 comparisons and the false-positive guards G1 and G2 of section 6. A pass there means "no evidence of a false-positive regression"; it is not a confirmatory specificity result and is reported with that label.
- **Second look S2 (F2 benign prompts, after adjudication).** K is scored once on F2 (6,000 natural prompts) for descriptive flag rates now. The blinded review pool of v2 (2,449 prompts: those flagged by any of nine configurations plus a 400-item audit sample) is extended with every prompt that K flags and that is not already in it, as extra blinded packets with the same format; raters stay blind to detector output. H9b (F2 specificity of K versus O and N, regex-only and union) is evaluated only if the adjudication is completed; otherwise "not evaluated".
- F1 positives and F3 are scored for K, O and N descriptively as well (second look, exploratory; F3 recall is at the 100 % ceiling and informative only for spans). They carry no hypothesis.

## 5. Configurations (frozen list; each scored once on F4)

All use explicit layers `["regex","ner"]`, `regex_first=False`, no semantic layer, no Docker, no network. A layer anomaly raises.

| Code | Configuration | Source |
|---|---|---|
| O | old default: clean export of `e6c177ff` | as v2 (the F4 run uses the same export; its tree digest is recorded in the addendum) |
| N | shipped defaults: export of `e70e3a2e` | as v2 |
| **K** | the reworked regex layer. NER layer, case-preserving input and post-filter exactly as N. | **OPEN SLOT: K freeze commit SHA and git tree**, on `research/wt-k-rework`; to be filled by the v3 addendum **before any F4 row is scored** (section 9) |
| K+all | K with the four input-robustness flags on (`PRIVOKE_STRIP_FORMAT_CHARS`, `PRIVOKE_CANONICALISE_DIGITS`, `PRIVOKE_CANONICALISE_EMAIL_WORDS`, `PRIVOKE_NER_CASELESS_GATE`, all `=1`); secondary only | a tree of K merged with the frozen robustness commit (`b3d11a50`, which contains `b1975bc2`), identified in the addendum; its all-flags-off behaviour is shown identical to K on the development sets, as the v2 addendum did for N |

Each of the four configurations is reported for regex, NER and union. Layers and rules are exactly those of v2 section 5: `positive` is the primary rule; `warn_or_block` and `block` are action-level, where `block` is H8's rule.

Scope requirement on K: the addendum lists the files K changes relative to `e70e3a2e`. If K changes anything outside the regex layer (rules, validators, their tests and `docs/detectors/regex.md`), the changed component is named and the layer attribution (regex-only deltas against N) is reported alongside H7; the hypotheses and thresholds do not change.

Out of scope and not claimed: N+R candidates other than K+all, N+lg, N+trf (held or dropped by the owner decisions or the v2 results), the LLM/semantic layer, policy enforcement, regex-first short-circuiting.

## 6. Hypotheses, margins and the promotion rule

Labels: a prompt is positive on F4 and F1 positives by construction. Flagged = the stated rule of `evaluation/detector_stats.py`. Delta = candidate minus reference, in points.

- **H7 (primary; decides the promotion of the rework).** Union recall of K is non-inferior to O on F4: the lower limit of the 95 % two-sided percentile paired grouped-bootstrap interval of recall(K) - recall(O) (the one-sided 97.5 % lower bound) exceeds **-1.0 pt**, rule `positive`. The margin is v2's H2 margin, unchanged: it was the pre-registered tolerance for the shipped defaults and the owner's wording ("fresh set shows union recall non-inferior within 1 point") fixes it. Expected effect, for the power calculation only: 0 pt (the exploratory O-regex plus N-NER hybrid gave +0.08) and -0.5 pt as a pessimistic case; N's observed -1.37 is the effect the rework must remove.
- **H8 (co-primary; BLOCK-level recall).** Union recall of K under the rule `block` is non-inferior to O on F4 with margin **-0.5 pt** (same test). Justification, fixed before scoring: BLOCK is the strongest runtime action and N's BLOCK-level loss (1.90 pt, 190 rows moved from BLOCK to a lesser action, none the other way, all from the regex layer) was the clearest harm of the repairs; the discordance of the BLOCK outcome is small (about 2 %), so the sample is large enough to detect a loss of half a point at 92 % power for a true zero; and a margin of 1.0 pt would allow K to lose about half of the BLOCK recall that N lost. The margin is half of H7's and about a quarter of N's observed BLOCK loss. H8 is a conjunct: it needs no multiplicity correction because H7 and H8 are required together (intersection-union), and a failure of either is a "not promoted" outcome.
- **H9 (second look; descriptive; non-confirmatory).** On S1 (F1 clean, 6,446 rows) report, for K against O and K against N: regex-only specificity and union specificity (positive rule; also `warn_or_block` and `block`), with n, discordant counts, delta, the 95 % paired grouped-bootstrap interval and the exact McNemar p-value. The v2 H1-style question "K keeps part of N's regex precision gain" is answered descriptively; there is no confirmatory regex-specificity hypothesis in v3. After adjudication, the same cells on F2 benign prompts (H9b).
- **False-positive guards for promotion (second look; evaluated on S1, both required).** **G1:** union specificity of K is non-inferior to O, margin 1.0 pt (K is no worse than the pre-PR detector at false positives). **G2:** union specificity of K is non-inferior to N with margin **2.0 pt** (K keeps at least about 40 % of N's observed +3.32 pt union-specificity gain over O). Margin rationale: the rework deliberately restores some rules that N removed, and those rules fixed false positives (the exploratory per-rule table lists 37 clean rows for the weak driver-licence recogniser, 12 for family disclosure and 26 for `child`), so a small give-back is expected and accepted; a loss of more than 2 pt of union specificity relative to N is judged a regression of the shipped gain. G1 and G2 use the same one-sided 97.5 % lower bound as H7. Because S1 is not fresh, a pass is "not contradicted", a fail blocks promotion.
- **Per-source secondaries (descriptive; not used for promotion).** For each of ai4privacy, Gretel, Nemotron-PII and Privy on F4: the H7 and H8 deltas of K versus O (and of N versus O and K versus N for context) with 95 % intervals and discordant counts. **Source-standardised H7:** the sum over sources of weight times the within-source delta of union recall K - O, with a stratified cluster bootstrap (resampling whole documents within each source, 10,000 replicates, seed 20261024), for two pre-set weight vectors: the F1 positive mix (0.3374, 0.3325, 0.1687, 0.1614) and equal weights (0.25 each). **Heterogeneity rule:** if the entire 95 % interval of a source's H7 delta lies below -1.0 pt, that source is a documented negative heterogeneity finding that the critic must address; no promotion decision is made on a single source stratum, and a source with fewer than 700 rows (Nemotron-PII) cannot satisfy this rule on power grounds and is reported only.
- **Secondary and exploratory (labelled).** K+all versus K (flips on clean text: expected zero) and K+all versus O (non-inferiority margin 1.0 pt, descriptive); layer attribution of the K-O recall difference (exact layer swapping as in the results record section 5.1, labelled exploratory); per-rule breakdowns; span metrics (`span_scoring`, secondary only, no hypothesis); category and length strata. None is used for promotion.

### Promotion rule for K (replacing N's regex layer as the shipped default; a recommendation to the owner)

K is recommended for promotion only if all hold:

1. **H7 passes** (lower bound above -1.0 pt). "Inconclusive" (lower bound not above -1.0 pt while the interval still includes values at or above -1.0 pt) is not a pass.
2. **H8 passes** (lower bound above -0.5 pt).
3. **G1 and G2 hold on S1** (the no-false-positive-regression guard).
4. **A critic review** of the evidence record finds no overfitting, leakage, label-contamination or reporting-selection problem, and in particular verifies: K was designed on development data only; K's freeze SHA and tree were recorded before the first F4 row was scored and are the code that was scored; the F4 draw is disjoint from F1 and every excluded group; the source-mix and heterogeneity results are reported with the same prominence as the pooled one.
5. **Latency:** union detector latency regression below 20 % of the old mean per-prompt time (a separate record, as `docs/experiments/detector-latency-20261025.md`; blocks promotion if exceeded).
6. **Historical synthetic context (v2 criterion 3, reference N):** K's recall on the personalized and OpenAI synthetic sets from its development record is not more than 1 pt below N's. These are K's design sets and are context, not generalisation evidence. The owner exemption of v2 for the OpenAI criterion applied to N only and does not extend to K.

If criterion 1 or 2 fails, the outcome is "not promoted" and the pre-registered conclusion is the trade-off, stated exactly. A promoted K does not decide N+lg (held) or the N+R flags (waiver recorded, not scored in v3).

## 7. Statistics

As v2 section 5 and the v2 addendum (item 7.1), with the code of the Wave 3 scoring (`detector_stats.py` sha `c9b79a43...`, the driver and analysis scripts extended for F4 and hashed in the v3 addendum):

- Paired comparison always on identical rows; delta = candidate - reference. Percentile grouped paired bootstrap, whole `group_id` clusters (F4 groups are source documents), 10,000 replicates, seed 20261024, 95 % interval. Exact McNemar on discordant counts reported, not used for non-inferiority. A Wald paired bound (row-level and cluster-robust) is reported alongside and does not decide.
- Non-inferiority passes when the lower limit of the 95 % two-sided percentile interval (the one-sided 97.5 % lower bound) exceeds the stated margin. A lower bound at or below the margin with an upper limit above the margin is "inconclusive", never a pass; an upper limit at or below the margin is a failure.
- H7 and H8 are an intersection-union pair (both must pass) at one-sided 2.5 % each, so no correction is applied to them; H9, the guards' arithmetic, per-source and standardised cells are not corrected and are labelled. A power shortfall (observed discordance larger than planned) is reported with the achieved power and is not turned into a pass.
- Reporting always gives n, discordant counts, delta and the interval together.

## 8. Single scoring, negative results

- Each of O, N, K and K+all is scored **once** on F4 (positives, all three rules, all layers). O and N reuse their v2 per-row outputs for F1, F2 and F3 (file hashes recorded in the addendum); K and K+all are scored once on F1, F2 and F3 for the second-look material. The driver refuses to rescore a set whose output exists. A crash is fixed without looking at labels and resumed only for sets without output.
- No row text is inspected before scoring; afterwards only aggregate or hashed per-row outputs are examined. No rule, threshold, label mapping or code path is changed on the basis of F4 or second-look results. Developing K further after the freeze is a new configuration and requires a new registration with a new draw, which the PIIMB pool can no longer supply (a new source would need a separately approved download).
- Every registered hypothesis is reported with n, discordant counts, delta, interval, test and the verdict (pass, fail, inconclusive), with a failed or null H7 or H8 given the same prominence as a pass, in `docs/experiments/` and the paper integration. A failed H7 or H8 does not trigger automatic code changes; the evidence record states what was and was not demonstrated and the owner decides between keeping N, reverting, or a further rework with a new registration.
- Post-hoc analyses are labelled exploratory and cannot meet the promotion rule.

## 9. Freeze procedure and the open K slot

1. This registration and the F4 freeze record (`docs/research/fresh-sets-freeze-v3-20261025.md` and `.json`: hashes of this document, `fresh_set_plan.py`, the exclusion sets, seed, commands, file hashes, per-source counts, pool sizes, and a statement of what was observed) are committed **before** the K freeze.
2. **The K slot.** A v3 freeze addendum (`docs/research/fresh-sets-freeze-addendum-v3-20261025.md` and `.json`), committed **before any F4 row is scored**, records: the K commit SHA and git tree, the list of files changed relative to `e70e3a2e`, the K development record and its attestation that K used development data only, K's unit-test result at the SHA, the K+all tree and the all-flags-off equivalence to K on the development sets, the exported tree digests for O, N, K and K+all, the sha256 of the scoring and analysis scripts as extended for F4, the sha256 of the O and N per-row outputs reused, the environments and package versions, and the exact commands. **If K changes after that addendum, the registration is invalid for K and a new one is required.**
3. Nothing in the F4 file or the exclusion sets may change after the freeze record. Any such change invalidates the registration.

## 10. Known threats

- **Source mix.** F4 is Privy-heavy and Nemotron-light (section 3.2); unfavourable to regex changes of N's kind; mitigated by pre-set per-source and standardised secondaries, not by weighting the primary.
- **Positives-only data.** F4 measures recall only. False positives are examined only on non-fresh (S1) or unlabelled (S2) data; the guards G1/G2 are consequently weak evidence and are labelled so.
- **Label noise in PIIMB.** Positives are defined by annotation; unannotated PII in clean rows is not relevant to F4. Attribute spans PriVoke does not detect depress recall equally for every configuration.
- **Contamination.** NER models trained on PIIMB sources would be advantaged, as in v2; the NER layer is identical across O/N/K up to the post-filter and case-preservation, which affect all three comparisons equally. K is design-independent of F4 by disjoint groups and by freeze order.
- **Information about F1 reaching the K designer.** The F1 results and the exploratory per-rule table are public in the repository. F4 is disjoint from F1 so this cannot leak into F4, but it does mean S1 is a second look. The K design record states what the designer read.
- **Pool exhaustion.** A repeat of this study on PIIMB is not possible; later users must obtain a new source.
- **Multiple stakeholders.** F4 is single-use for this registration.

## 11. Open items

- The K freeze SHA and the full list in section 9 item 2 (addendum, before scoring).
- F2 adjudication (including the K-only extra packets) and the 200-row label-noise audit: pending human raters.
- The N+lg decision: held by the owner.
