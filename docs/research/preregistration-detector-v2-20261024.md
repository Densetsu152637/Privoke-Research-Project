# Pre-registration: detector precision follow-ups on fresh data (draft, 2026-10-24)

**Status: DRAFT. Becomes binding only when the freeze record (section 9) is written, before any fresh row is scored. Scope: detector-layer (regex, NER, regex OR NER). Not LLM-only, not semantic-layer, not full-product. The full-product rerun is a separate study and is not covered by these hypotheses.**

Program: research follow-ups to PR #5 (`fix/regex-fp-reduction`), user-approved 24 Oct 2026 ("Test all of these in parallel and integrate promising ones", including the full-product rerun; downloads under 5 GB allowed for testing). Data plan and power: `docs/research/fresh-evaluation-sources-20261024.md`. Downloads: `docs/research/download-request-20261024.md`.

## 1. Background and why a registration

The shipped precision work (regex repairs, case-preserving detector input, NER post-filter) was designed on dev-TUNE and the personalized synthetic set, then examined on dev-CHECK and openai (post-review), and scored on the locked final set (consumed). On real text the observed differences are 3 to 30 discordant rows and none is distinguishable from zero (`docs/experiments/detector-uncertainty-20261024.md`). A registration fixes hypotheses, tests, data and decision rules before new rows are seen so that a positive result cannot come from choosing the metric, subset or threshold afterwards.

## 2. Data (all fresh, never scored)

| ID | Description | Size | Label basis | Seed |
|---|---|---|---|---|
| F1 | PIIMB sentences at revision 4a13e9ff..., group-disjoint from development and final and from all training/validation uses | 10,000 PII + 6,600 clean | PIIMB entity spans | 8102026 |
| F2 | Natural benign prompts: oasst2 2,000, WildChat 2,500, Dolly 1,500 | 6,000 | Pooled two-rater adjudication (protocol in the sources doc, section 4.1) | 9102026 |
| F3 | SPY legal and medical (optional, prompt-style positives) | up to 2,000 | SPY tags converted to spans | 10102026 |
| F4 | TAB ECHR test (optional) | up to 300 documents | TAB mentions | 11102026 |

Sample sizes follow the power analysis (sources doc, section 5): 10,000 positives give 84 % power for the union-recall non-inferiority test (margin 1 pt) when the true change is 0; 6,600 clean rows give 95 % power for union-specificity non-inferiority (margin 1 pt, psi 5 %) and more than 99 % for the regex specificity effect.

Old development, TUNE, CHECK, personalized, openai and final results stay as historical context and are never pooled with F-sets.

## 3. Configurations (frozen list; each scored once)

All use explicit layer lists (`layers=["regex","ner"]`, `regex_first=False`), never an empty list; no semantic layer.

| Code | Configuration | Source |
|---|---|---|
| O | old default: clean export of `e6c177ff` (original regex rules, lowercased input, no post-filter) | as in `detector-precision-installed-20261024.md` |
| N | new default: installed defaults at `e70e3a2e` (head of `fix/regex-fp-reduction`; regex repairs, the `student_id` identity rule added after `55cbd1e5`, `PRIVOKE_CASE_PRESERVING_DETECTORS`, `PRIVOKE_NER_POSTFILTER`), spaCy `en_core_web_sm` 3.7.5 | same |
| N+R | N plus the input-robustness canonicalisations frozen at `research/wt-r-robustfix` commit `b1975bc2` (default-off flags; documentation `docs/experiments/robustness-fixes-20261024.md` on that branch). Five configurations, each scored once: `N+strip` (`PRIVOKE_STRIP_FORMAT_CHARS=1`), `N+digits` (`PRIVOKE_CANONICALISE_DIGITS=1`), `N+email` (`PRIVOKE_CANONICALISE_EMAIL_WORDS=1`), `N+caseless` (`PRIVOKE_NER_CASELESS_GATE=1`), `N+all` (all four on). Each flag alone is a candidate, and all-on is a candidate. | `evaluate_installed_detectors.py` with the flags set in the environment |
| N+lg | N with `PRIVOKE_NER_MODEL=en_core_web_lg` (spaCy `en_core_web_lg` 3.7.1, spaCy 3.7.5), NER post-filter on. Candidate for promotion (H3). Frozen with the NER model study at `research/wt-g-nermodels` commit `f4f07c3c` (record `docs/experiments/ner-models-20261024.md` on that branch; cite the commit, not a path). | agent G |
| N+trf | N with `PRIVOKE_NER_MODEL=en_core_web_trf` (spaCy `en_core_web_trf` 3.7.3), post-filter on. **Comparator only, not promotable this round** (about 6x NER latency, 457 MB model); reported descriptively as an accuracy ceiling. | agent G |
| (dropped) | GLiNER-PII is dropped: no benefit on the design or post-review splits and unknown training-data provenance. It is not scored. | agent G |
| Layers | each of O and N is reported for regex, NER and union (regex OR NER) | `evaluation/evaluate_installed_detectors.py`, per-row output via `--per-row-dir` |

Out of scope and not claimed: semantic/LLM layer behaviour, policy enforcement, regex-first short-circuiting.

## 4. Hypotheses

Labels: a prompt is positive when `expected_has_pii` is true (F1), or adjudicated P (F2). Flagged = positive rule of `evaluation/detector_stats.py` (`RULES = positive`), the primary decision rule; `warn_or_block` and `block` are action-level secondaries.

- **H1 (regex specificity gain).** The shipped regex precision repairs raise regex-only specificity relative to O on F1 clean rows, delta = spec(N) - spec(O) > 0. Effect of interest: 1 pt. Replication H1b on F2 benign prompts, same test. Expected side effect, pre-declared: regex-only recall falls by about 1 pt (observed -1.3 pt on final, 0 gains vs 3 losses); recall of the regex layer alone is reported with its paired CI but is not a pass/fail gate, because the shipped detector is the union.
- **H2 (union non-inferiority).** Union recall of N is non-inferior to O on F1 positives with margin 1.0 pt: the lower bound of the one-sided 97.5 % confidence bound of recall(N) - recall(O) exceeds -1.0 pt. Co-requirement H2b: union specificity of N is non-inferior to O on F1 clean and F2 benign with margin 1.0 pt. Union specificity superiority (observed +0.4 pt) is exploratory: it would need about 25,000 negatives.
- **H3 (larger spaCy NER model, candidate N+lg).** Reference N, F1 and F2 as stated. **H3a (precision, superiority):** `N+lg` has higher union specificity than N on F1 clean rows (delta > 0; exact McNemar and the paired grouped-bootstrap 95 % CI excluding 0); replication H3a' on F2 benign is reported and must not contradict in sign. **H3b (NER-layer false positives):** the NER-only specificity of `N+lg` exceeds N on F1 clean rows (same test); descriptive on F2. **H3c (recall guard, non-inferiority):** union recall of `N+lg` is non-inferior to N on F1 positives with margin 1.0 pt (one-sided 97.5 % paired grouped-bootstrap bound, as H2), and union recall non-inferiority also holds on F3. H3a and H3b form the superiority family (Holm-Bonferroni across the two); H3c is a required guard (a conjunct, no correction). A larger recall by `N+lg` is exploratory, not a registered hypothesis. `N+trf` receives the same estimates as `N+lg` but is descriptive only: no hypothesis test is promoted and it is not eligible for promotion. The dev-CHECK and openai results for these models in the agent G record were obtained after review of those sets (post-review), so only F1, F2 and F3 count as confirmatory evidence.
- **H4 (span-level masking).** On F1 positives, N masks at least as many annotated PII characters as O up to a 1 pt margin (non-inferiority on the character-level leak rate = share of annotated PII characters not covered by any detected span from the union), and the over-masking share (detected characters outside annotated spans, per clean-plus-positive character) does not increase by more than 1 pt. Category mapping from PIIMB labels to PriVoke categories is frozen in a mapping file before scoring; unmapped labels count for presence but not for category-level scoring. Requires that the detectors expose character offsets; if a layer does not, that layer is excluded and the exclusion is recorded.

- **H5 (robustness canonicalisations, perturbed-recall superiority).** Perturbed copies of the frozen F1 positives are generated at scoring time by the seeded transforms of `evaluation/robustness_probe.py` (branch `research/wt-c-robust`, commit `33b6e6b5`, file sha256 `7dabcaa05050995bb35df2a569e2431e61ad343e805e7acb3a764d41ac63607f`; per-row RNG seeded by `sha256("20261024:<transform>:<row id>")`, so only the F1 file hash needs freezing). Transforms used: `zero_width`, `digits_space`, `digits_dot`, `digits_dash`, `digits_words`, `email_bracket`, `email_paren`, `email_word`, `lowercase`, `uppercase` (the others in that file are not registered). A perturbed item is a (positive row, transform) pair whose text the transform actually changed; this is a deterministic property of the text, not of any detector. Each hypothesis compares the candidate with N on identical perturbed items, union recall, delta = candidate - N, superiority at the stated level, exact McNemar on discordant items plus a grouped paired bootstrap (whole `group_id` clusters, items of one row stay together):
  - **H5a** `N+strip` on `zero_width`; **H5b** `N+digits` on the four `digits_*` transforms pooled; **H5c** `N+email` on the three `email_*` transforms pooled; **H5d** `N+caseless` on `lowercase` and `uppercase` pooled (NER-only recall is reported alongside as the layer the gate acts on).
  - **H5e** `N+all` on all ten transforms pooled. Per-transform cells are exploratory.
  Primary family for multiplicity: H5a-H5e, Holm-Bonferroni at familywise alpha 0.05 (two-sided exact McNemar p-values; the direction must be an improvement).
- **H6 (robustness candidates leave clean-text behaviour intact).** On the unperturbed frozen sets, each of the five N+R configurations is non-inferior to N with margin 1.0 pt (one-sided 97.5 % paired grouped-bootstrap bound, same method as H2) on all four of: union recall on F1 positives, union specificity on F1 clean, union specificity on F2 benign, union recall on F3 positives. H6 is a conjunction (intersection-union), so it needs no multiplicity correction: a candidate that fails any cell fails H6. The expectation, from the development record, is identical outcomes on clean text (zero flips); the registered claim is only non-inferiority.

No hypothesis is tested on a subset chosen after seeing results. Source-stratified (by `source_dataset`), category-stratified and length-stratified analyses are exploratory, labelled as such and not used for promotion.

## 5. Metrics and statistics

Primary data reductions use `evaluation/detector_stats.py` (agent A, branch `research/wt-a-stats`, commits `b1a5885e`, `bf5e24c1`), unchanged after freeze:

- Per-class point metrics: recall, specificity, precision, F2 (beta = 2, recall-weighted), and cost-weighted error with FN:FP ratios 2, 4, 9.
- Paired comparison is always baseline vs candidate on identical rows; delta = candidate - baseline.
- Uncertainty: percentile grouped paired bootstrap, whole `group_id` clusters resampled, 10,000 replicates, seed 20261024, 95 % CI; exact two-sided McNemar on discordant counts, separately on positives and negatives; cluster-level exact sign test as a conservative companion when more than one sentence per document is used.
- Non-inferiority tests (H2, H2b, H4): the lower limit of a one-sided 97.5 % paired grouped-bootstrap bound compared with the margin; a Wald paired test is reported alongside. Exact McNemar is not used for non-inferiority.
- Action level: the same metrics with `warn_or_block` and `block` as the flagged rule (the runtime's own aggregation, as in the per-row files), reported as secondary.
- Multiplicity: H1, H1b, H2, H2b, H4 are the primary family and are each tested at their stated level without correction because each maps to a different decision; H3a and H3b use Holm-Bonferroni across the two (H3c is a conjunct); H5a-H5e form a separate primary family with Holm-Bonferroni across the five (familywise 0.05); H6 is a conjunction needing no correction. Secondary (reported with CIs, not used for promotion): per-transform cells, NER-only and regex-only layers, action-level metrics, stratified analyses. All other cells are exploratory.
- Primary quantity: the 95 % CI of the target delta, not a p-value alone. Report n, discordant counts and the CI together.

## 6. Promotion criteria (draft, to be agreed at freeze)

A change (the shipped defaults for H1/H2; `N+lg` for H3; `N+trf` is not eligible) is promoted only if all hold:

1. The 95 % grouped-bootstrap CI of the primary target delta excludes 0 in the intended direction, and the exact McNemar p-value is below 0.05 (H1 on F1; H1b on F2 reported but must not contradict in sign).
2. Union recall non-inferiority (H2) holds with margin 1 pt; "inconclusive" (bound within the margin but power insufficient) is not a pass.
3. No recall regression of more than 1 pt on the synthetic sets (personalized, openai) for the promoted configuration relative to the configuration it replaces, using the existing historical numbers as context (they are not fresh and are not re-scored). Pre-declared fact: the shipped default N already violates this against O on openai (union recall 0.942 to 0.918, regex recall 0.920 to 0.896, NER recall 0.290 to 0.170); for new candidates (H3) the comparison is against N.

   **Owner decision (24 Oct 2026, recorded before freeze and before any fresh row is scored).** The project owner stated, verbatim: "Pre-register that the current defaults may be promoted despite the OpenAI synthetic recall drop, provided the fresh held-out set shows union recall non-inferior within 1 point." Accordingly, configuration N (the current PR #5 defaults) is exempt from the "no synthetic split regression of more than 1 pt" criterion for the OpenAI synthetic set only. Its promotion instead requires H2 (union recall non-inferiority of N versus O on F1 with a 1-point margin, using the pre-registered paired test) to pass on the fresh held-out set. The exemption does not cover the personalized synthetic set, any other configuration (including every H3 model), or any other promotion criterion; all of those are unchanged.
4. A critic review of the evidence record (profile `critic`) finds no overfitting, leakage, label-contamination or reporting-selection problem.
5. Latency regression of the union is below 20 % of the old mean per-prompt time (report only; blocks promotion if exceeded).

If criterion 2 or 3 fails, the outcome is "not promoted"; the pre-registered conclusion is the trade-off, stated exactly.

**Promotion of an N+R candidate** (`N+strip`, `N+digits`, `N+email`, `N+caseless` or `N+all`; reference N) requires: its H5 hypothesis passes after Holm adjustment (adjusted p < 0.05 with the CI of the recall delta excluding 0); H6 holds in all four cells; criteria 4 and 5 above; and a pre-declared check that the candidate's per-flag unit tests and the default-off flag documentation exist at the frozen commit `b1975bc2`. Criterion 3 applies with N as the reference (the historical clean-text dev/personalized/openai comparisons in `docs/experiments/robustness-fixes-20261024.md` on that branch show no outcome flips; they are context and are not re-scored). Flags are promoted individually; `N+all` is promoted only if each constituent flag individually passes or `N+all` itself passes H5e and H6 while no constituent flag fails H6.

## 7. Single-scoring rule

Each frozen configuration is scored once on each fresh set. No row text is inspected before scoring and, after scoring, only aggregate or hashed per-row outputs are examined; no rule, threshold, prompt, label mapping, model choice, post-filter or code path is changed on the basis of F-set results. A second scoring requires a new, separately registered fresh draw (new seed, disjoint groups, including disjoint from the F-sets). Pipeline crashes are fixed without looking at labels and the full run is repeated from scratch only if no scored output was written; the incident is recorded. Cleanup of pooled F2 adjudication does not count as inspection of F2 results because the raters are blind to detector output.

## 8. If results are negative or inconclusive

- Record every registered hypothesis with its n, discordant counts, delta, CI and test, whether it passed, failed or was inconclusive. Failed or null results are published with the same prominence as passes in `docs/experiments/` and in the paper integration step.
- The shipped defaults are not reverted automatically; the evidence record states what was and was not demonstrated. A failed H2 (recall loss of more than the margin) triggers a documented decision on whether to keep the regex repairs.
- No post-hoc rescue analyses are promoted. Post-hoc analyses are labelled exploratory and cannot meet the promotion criteria.
- A power shortfall (observed discordance larger than planned) is reported with the achieved power; it is not turned into a pass.

## 9. Freeze procedure

Before scoring, a freeze record `docs/research/preregistration-freeze-<date>.json` is committed containing:

1. sha256 of this document, `evaluation/fresh_set_plan.py`, `evaluation/detector_stats.py`, `evaluation/evaluate_installed_detectors.py`, the label guideline, the category mapping file.
2. Git commit SHAs of the code under test (O: `e6c177ff` export; N: `e70e3a2e` or the final integration head; N+R: `b1975bc2`; perturbation script: `33b6e6b5` with sha256 `7dabcaa0...`), package versions of the evaluation venv, spaCy model version, and for H3 each model's source URL, revision and weight sha256.
3. The data manifests: PIIMB source-file sha256 (`5ff46f3a80316318794f94596fa374060d70f2f32a85909f958cbabc70bae41f`), the exclusion-set sha256 (locked union groups `16e2006b...`, plus the training/validation group union), seeds, per-set counts, output sha256 of each F-set file, SPY Faker seed and version, WildChat shard names.
4. The list of configurations in section 3, the numeric margins, alpha levels, number of bootstrap replicates and seed.
5. A statement of what was and was not observed about the F-sets before freeze (expected: only counts and hashes).

After the freeze commit, any change to these items invalidates the registration; a new registration with a new draw is required.

## 10. Known threats and mitigations

- Label noise in PIIMB (annotation artifacts; clean sentences may contain unannotated PII): sensitivity analysis with a hand-checked random sample of 200 flagged-clean rows adjudicated blind; reported, not used to relabel the primary analysis.
- Nemotron dominance (about 60 % of the pool): source-stratified secondary analysis; no source weighting in the primary analysis.
- Contamination of NER models: models trained on ai4privacy, Gretel, Nemotron-PII or PIIMB sources would be advantaged on F1. The training data of `en_core_web_lg` and `en_core_web_trf` is recorded from their model cards at freeze (expected: OntoNotes-style news and web text, with no PIIMB source); if a card or later finding shows overlap, the F1 result of that model is labelled contaminated and only F2/F3 can support promotion.
- Sentence-level data may overstate document-level behaviour; F3 and F4 provide prompt-style and document-style checks.
- Annotator disagreement on F2: kappa reported; U (ambiguous) prompts analysed both ways.
- Multiple stakeholders may reuse the F-sets for other questions: they are single-use for this registration; later users must register new draws.
