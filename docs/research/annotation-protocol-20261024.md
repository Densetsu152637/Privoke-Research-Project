# Human double-annotation protocol for the RQ1 contextual targets

Date: 2026-10-24. Task w1-e-annot (item 7). Status: **prepared, not executed**. No item has been
annotated, no model is used as an annotator, and no filled sheet exists. Scope label: human
annotation of the authored contextual workload (not detector, semantic-only or full-product evidence).

User instruction (shared brief): prepare a human double-annotation study of the 1,560 authored cases
whose contextual targets are provisional; humans (the user and co-authors) annotate later.

## 1. What is being validated

The paper's RQ1 workload is the AU3 `fresh_eval` partition (release-07): 1,560 cases, 810 required
sensitive and 750 clean, 260 per audience class, 35 scenario families, 24 audience-expression groups.
File `evaluation/results/audience_v3_20261013/data/release-07/fresh_eval.jsonl` (gitignored, in the main
checkout), sha256 `e965c21a0d43babc0984f46eb70785c8d66d878e00e647eefb9565f219b2da0c`.
Provisional targets per case (all `assistant_provisional`, never adjudicated):

| Field | Values | Provisional distribution |
|---|---|---|
| `required_sensitive` | true / false | 810 / 750 |
| sensitivity | S0 750, S1 90, S2 144, S3 576 | |
| visibility (audience) | P0-P4, PU | 260 each |
| categories | subset of 10 | none for 840 cases |
| allowed actions | ALLOW (S0, S1; 840) or WARN/BLOCK (S2, S3; 720) | |

Control types: `actual_disclosure` 720, `mild_personal` 90, `quoted_synthetic_placeholder` 210,
`absent_record` 180, `unfilled_form` 180, `invented_scene` 180. Texts are short (mean 31, maximum 51
words) and templated, so agreement here may overstate agreement on free natural prompts; this is a
limitation to state with any result.

Rubric sources: `paper/research/contextual-labeling-rubric.md` (dimensions, S0-S3, visibility rules,
"two people label blinded and keep both labels through adjudication") and
`paper/research/contextual-cascade-rubric.md` (label meaning, unknown visibility is `PU`, never
inferred from the word "private"). The label space is the product contract in
`shared/python/privoke_model/v3_contract.py`.

## 2. What annotators label

Five judgements per item, from the text alone (`evaluation/annotation/annotation_schema.py`):

1. **disclosure** `yes|no|unclear`: does the text assert actual personal information about a real
   person (the writer or someone else)? `no` for absent, unfilled, invented, fictional or
   explicitly placeholder content, including a topic that merely names a sensitive domain. Maps to
   `required_sensitive`. `unclear` only when the text itself leaves real versus not-real open.
2. **sensitivity** `S0-S3`, applied to what the text discloses, independent of audience. S0 ordinary
   or general information, or nothing disclosed; S1 low-risk identifying or personal attributes;
   S2 sensitive personal information; S3 credentials, secrets or highly sensitive linked details
   (rubric definitions). Do not infer sensitivity from a topic keyword alone.
3. **visibility** `P0 P1 P2 P3 P4 PU`, from the audience the text itself states: P0 unrestricted
   public; P1 broad semi-public community; P2 access requires authentication but no closed invited
   recipient set; P3 closed invited group that includes other readers; P4 only the writer. `PU` when
   no audience is stated. First-person wording or the word "private" does not establish P4.
4. **categories**, multi-label from HEALTH, POLITICS, RELIGION, CRIMINAL, FINANCIAL, SEXUAL, CHILD,
   LOCATION, IDENTITY, THIRD_PARTY; `NONE` when nothing actual is disclosed. Written `A|B`.
5. **action** `ALLOW|WARN|BLOCK`: what the product should do before the text goes to an external
   model provider. ALLOW forwards silently; WARN asks the user first and then forwards; BLOCK does not
   transmit. The annotator uses judgement and is not given the runtime policy table (otherwise the
   field would be a deterministic function of sensitivity). A free-text `notes` cell records evidence
   or doubt (rubric: record the evidence span and rationale).

Matched contrasts in the rubric (public biography versus private disclosure, fictional versus
real-person context, general advice versus private history, explanation of a credential versus a
fake value) are covered by the sample's control strata. Section 2 is the source text of the annotator
guideline; before the pilot the coordinator adds one invented worked example per contrast (written
fresh, not taken from any dataset row) and freezes it as guideline v1.0.

## 3. Blinding and independence

- Annotators receive only the guideline, a glossary and a sheet with opaque ids (`it-` plus 10 hex
  characters of a salted hash) and text. Case ids, families, controls, audience class, strata,
  provisional targets, dataset names and any model output never reach annotators or adjudicators; they
  live only in `key/` (coordinator). Rows are in a different seeded order per annotator.
- Annotators work alone and do not discuss items until adjudication. No LLM, search engine or detector
  output may be consulted. Work in blocks of 60 with a break between blocks.
- Disclose familiarity: anyone who authored, reviewed or generated AU3 labels, or knows the template
  generator, records this. Their labels remain valid but a sensitivity analysis reports agreement
  with and without them, because label knowledge biases toward the provisional targets.
- Recommended people: two annotators plus a third adjudicator who did not annotate the item.

## 4. Procedure

1. **Sample.** Coordinator runs the sampler (section 7); distributes `sheets/*_<annotator>.csv` only.
2. **Training.** Each annotator reads the guideline and the invented worked examples (about 45 min).
3. **Calibration round.** A 30-item pilot (5 per audience), disjoint from the main sample, is labeled
   independently. Run `compute_iaa.py` on it; the pair then discusses every disagreement. Output: a
   dated guideline revision listing each clarification and the disagreement that caused it (this is the
   only permitted change to the guideline). Pilot labels are reported separately and never pooled.
   If sensitivity, visibility or disclosure kappa is below 0.6, revise and repeat once with
   `--pilot-seed` (main sample unchanged; check overlap with the first pilot in the key).
4. **Main round.** 360 items per annotator, same items, independent. Each returns a completed CSV.
   `annotation_schema.read_labels` rejects empty or invalid cells, so fix before submission.
5. **Agreement.** `compute_iaa.py` on the two sheets, with the key only for family clustering; also
   writes the adjudication worklist (items with any field disagreement) with final-label columns.
6. **Adjudication.** See section 5.
7. **Accuracy.** `provisional_accuracy.py` joins the key's provisional targets to the reference labels.
   The provisional targets are first revealed here, after all human labels are frozen.

## 5. Adjudication and disagreement handling

- Scope: every item where the annotators differ on any field (categories compared as sets).
- The adjudicator sees the text, both label sets (annotator names removed from the discussion copy,
  order randomised per item) and the guideline; not the provisional targets or model outputs.
- Decide each field by the guideline, record `resolution` (`consensus`, `third_adjudicator`,
  `rubric_clarification` when the guideline was silent, or `excluded_ambiguous` when the adjudicator
  judges the text genuinely underdetermined), a one-line `reason`, and the `adjudicator`. Original
  annotator sheets are never edited; adjudicated labels live only in the adjudication file.
- Classify each disagreement for the report: guideline gap, slip, true text ambiguity, or a question
  about the product policy itself (typically action). Report counts per type.
- Reference label per item = the shared label when annotators agree on every field, else the
  adjudicated label. `excluded_ambiguous` items are excluded from the primary accuracy and counted;
  a sensitivity analysis counts them as provisional errors.
- Report raw agreement, kappa and alpha with intervals and denominators, per-label agreement and the
  confusion matrices; with only these labels, the paper may say "adjudicated on a stratified 360-case
  sample", not "validated".

## 6. Sample design and size

**Frame:** all 1,560 cases. **Stratification:** equal allocation across the six audience classes
(60 each), then within an audience proportional allocation across the seven provisional
control/sensitivity cells with a floor of 4, so rare cells (mild S1, S2) are never empty. Within a cell
rows are drawn round-robin over shuffled scenario families (seeded), so every cell spreads across
families and category sets. Realised main sample (seed 20261024): 360 items, 186 provisional-sensitive
and 174 clean, all 35 families and all 24 expression groups. Per audience: actual S3 about 22, actual S2
5-6, mild S1 4, absent 7, unfilled 7, invented 7, quoted placeholder 8. Population totals per cell are
kept so accuracy can be reported as a design-weighted estimate. A pilot of 30 is drawn from the rest.

**Size for agreement.** Large-sample variance of Cohen's kappa for two raters is approximately
`po(1-po) / (n (1-pe)^2)`; the 95% half-width is `1.96 * sqrt(var * DEFF)`. The scenarios share family
structure (35 families), so a design effect `DEFF = 1.3` is allowed for. Required `n` for half-width 0.1:

| Expected po | pe | n (DEFF 1) | n (DEFF 1.3) | n (DEFF 1.5) | half-width at n=360 (DEFF 1.3) |
|---|---|---|---|---|---|
| 0.90 | 0.50 | 139 | 180 | 208 | 0.071 |
| 0.85 | 0.50 | 196 | 255 | 294 | 0.084 |
| 0.80 | 0.50 | 246 | 320 | 369 | 0.094 |
| 0.75 | 0.50 | 289 | 375 | 433 | 0.102 |
| 0.75 | 0.25 | 129 | 167 | 193 | 0.068 |

Worst realistic case (binary field, pe 0.5, po 0.75) needs 289 without and 375 with clustering;
**n = 360** gives a half-width 0.089 to 0.102 there and at most 0.07 for the four-to-six-level fields
(sensitivity, visibility) whose pe is near 0.25. Krippendorff's alpha has the same order of width; the
scripts report a family-cluster bootstrap interval, which replaces the formula once data exist.
Per-category kappas are wider (a category appears in 21-57 sampled items); report their counts.

**Size for provisional-target accuracy.** The same 360 items, after adjudication, estimate accuracy
(Wilson half-width, DEFF 1 / 1.5): at 90% accuracy 0.031 / 0.038 overall; 0.044 / 0.054 on a 180-item
half (sensitive versus clean); 0.076 / 0.093 for a 60-item audience stratum. At 50% accuracy the
overall half-width is 0.052 / 0.063. This is precise enough to separate "mostly correct" from
"unreliable" overall and per control family, not to rank individual audience classes finely.
Sample size is fixed before annotation: enlarging it later would not nest the first sample.

## 7. Tools (host Python, standard library only)

All in `evaluation/annotation/`; tests: `python -m unittest discover -s evaluation/annotation/tests`
(21 tests; hand-computed kappa 0.4 and 0.5, alpha 0.4 nominal and 17/24 ordinal, specific agreement,
Wilson, sample-size formula, determinism, disjointness, blinding, end-to-end fixtures).

```
python sample_annotation.py --input <fresh_eval.jsonl> --output-dir <dir> [--seed 20261024]
    -> sheets/{pilot,main}_<A|B>.csv (id, text, blank label columns); key/sampling_key.jsonl; key/manifest.json
python compute_iaa.py --sheet A=<doneA.csv> --sheet B=<doneB.csv> --key key/sampling_key.jsonl --split main \
    --out-json iaa.json --out-md iaa.md --disagreements-csv to_adjudicate.csv
python provisional_accuracy.py --key key/sampling_key.jsonl --sheet A=... --sheet B=... \
    --adjudicated adjudicated.csv --out-json accuracy.json --out-md accuracy.md
```

- Sheet columns: `item_id, text, disclosure, sensitivity, visibility, categories, action, notes`
  (CSV, or JSONL with the same keys). Adjudication columns: `item_id`, the five label columns
  (`final_*` also accepted), `resolution`, `reason`, `adjudicator`.
- IAA: raw agreement and Cohen's kappa per annotator pair; Krippendorff's alpha (nominal for
  disclosure and visibility, ordinal for sensitivity and action; any number of annotators, missing
  allowed); per-label specific agreement; confusion matrices; per-category binary kappa and alpha;
  exact category-set match and mean Jaccard. Intervals: percentile bootstrap resampling families.
- Accuracy: per field (disclosure, sensitivity, visibility, exact category set, action in the
  provisional allowed set, and joint), sample accuracy with Wilson interval, design-weighted
  estimate with family-cluster bootstrap, per-annotator accuracy, breakdown by audience, control type
  and provisional sensitivity, provisional-versus-reference confusion matrices and per-category
  true/false positive counts. A reference `unclear` disclosure counts against the provisional yes/no.
- Secondary analysis not automated: applying the runtime policy table to the human sensitivity labels
  to compare the implied action with the provisional allowed set.

## 8. Time estimate

Per item about 50 s once calibrated (about 31 words of text, five fields), 90 s in the pilot.

| Activity | Per annotator | Total (2 annotators) |
|---|---|---|
| Guideline and worked examples | 0.75 h | 1.5 h |
| Pilot (30 items) and discussion | 1.5 h | 3.0 h |
| Main round (360 items) | 5.0 h (4-6.5) | 10.0 h |
| Adjudication (about 30% of items, about 110, at 2.5 min) | 4.6 h per adjudicator | 4.6 h (one adjudicator) |
| **Total** | | **about 19 h** (range 16-28) |

If the two annotators adjudicate jointly instead of a third person, add about 4.6 h for the second
participant (about 24 h). Scripts and analysis add under an hour of coordinator time.

## 9. Interface recommendation

Requirements: controlled vocabularies (no free text in label cells), categories as a multi-select with
an explicit none option, one item per screen in the sheet's order, autosave and resume, a separate
store per annotator that no annotator can read, items served as text only (the provisional targets and
key are never sent to the client), per-item timestamps, export in exactly the sheet schema, and
the ability to revisit an item before final submission with the change logged.

- **(a) Offline spreadsheet/CSV.** Zero build; the sheets already match the validator. Needs dropdown
  data validation on the label cells, a locked `item_id`/`text` columns, and discipline not to sort,
  share or peek. Weaknesses: no enforced separation, no timing, categories typed by hand.
- **(b) Small shared web page** storing each annotator's labels separately. Satisfies every
  requirement, gives timing data to refine section 8, and removes cross-annotator leakage.

Recommendation: use (b) if a hosted page can be provided before the pilot, because blinding and input
validity are enforced rather than requested; otherwise run (a) with validated dropdowns and validate on
return with `read_labels`. Both paths produce the same file schema, so the analysis does not change.

## 10. Limitations and claims

Templated synthetic texts with a single generator lineage; two annotators drawn from the project team;
possible label knowledge; action is a policy-preference field with higher expected disagreement; the
reference is a human-adjudicated consensus, not an external ground truth. Even high accuracy supports
only the claim that the provisional targets match adjudicated human labels on this stratified sample of
authored cases. Product accuracy on the full 1,560 cases remains a development result on reused
authored material. Pre-registering this protocol before any annotation is advised: commit the
guideline, seed, sampler script hash (recorded in `key/manifest.json`) and this document first.
