# Annotation packet status, 16 November 2026 (goal G10)

Task ASIACCS-S8, part B. Status: **tooling ready, no human labels exist, execution blocked on people.**
No label was produced, simulated or imputed in this check, and no model acted as an annotator. The dated
[protocol of 24 October 2026](annotation-protocol-20261024.md) is unchanged and remains the authority for
every design decision (sample, label definitions, size, adjudication rules). This note records only what is
ready, the exact runbook, what waits on humans, and what the readiness check found.

Scope label: human annotation of the authored contextual workload (AU3 `fresh_eval`, release-07). It is
not detector, semantic-only or full-product evidence. The independent contextual dataset claim of the
paper stays unestablished until the steps below are done.

## 1. What the packet contains

| Item | Location | State |
| --- | --- | --- |
| Protocol, sample design, size and time estimates | `docs/research/annotation-protocol-20261024.md` | Final; pre-registration advised before annotation |
| Rubric sources | `paper/research/contextual-labeling-rubric.md`, `paper/research/contextual-cascade-rubric.md` | Present |
| Sampler (blinded sheets plus coordinator key) | `evaluation/annotation/sample_annotation.py` | Runs; deterministic |
| Label schema and sheet validator | `evaluation/annotation/annotation_schema.py` | Rejects empty or invalid cells |
| Agreement (Cohen's kappa, Krippendorff's alpha, intervals) and adjudication worklist | `evaluation/annotation/compute_iaa.py`, `agreement.py` | Tested on fixtures |
| Accuracy of provisional targets against reference labels | `evaluation/annotation/provisional_accuracy.py` | Tested on fixtures |
| Tests | `evaluation/annotation/tests/` (22 tests after this task) | Pass |
| Input population | `evaluation/results/audience_v3_20261013/data/release-07/fresh_eval.jsonl` (gitignored; main checkout only), sha256 `e965c21a...219b2da0c` | Present; hash verified by the sampler |

Not in the packet yet (section 4): the annotator guideline v1.0 with its invented worked examples and
glossary, the annotation interface, the recruited people.

## 2. Readiness check performed (no labels involved)

- `python -m unittest discover -s evaluation/annotation/tests` passes (22 tests: hand-computed kappa 0.4
  and 0.5, alpha 0.4 nominal and 17/24 ordinal, Wilson interval, sample-size formula, determinism,
  disjointness, blinding, end-to-end fixtures with 4 items and 2 annotators; the fixture labels exist only
  in test code).
- The sampler ran against the real, hash-pinned `fresh_eval.jsonl` into a temporary directory and wrote
  blank sheets only: 360 main and 30 pilot items for annotators A and B, a coordinator key of 390 rows and
  a manifest. A second run with identical arguments gave byte-identical sheets.
- `compute_iaa.py` on those blank sheets stops with `disclosure is empty`. That is the intended refusal: it
  cannot produce statistics from unlabelled data. Numerical behaviour of the scripts is covered by the
  fixture tests only.
- The temporary output was discarded. Nothing from the dry run is committed.

## 3. Runbook for two human annotators and a coordinator

Roles: coordinator (holds `key/`, never labels), annotators A and B (work alone), adjudicator (a third
person who did not annotate the item; the protocol covers joint adjudication if none is available). Run all
commands in the host Python environment from the repository root.

1. **Pre-register.** Before sampling, commit the annotator guideline v1.0 (section 4), the seed `20261024`
   and the protocol. The sampler writes its own hash to `key/manifest.json`.
2. **Sample and blind.**
   `python evaluation/annotation/sample_annotation.py --input <fresh_eval.jsonl> --output-dir <dir>`
   writes `sheets/{pilot,main}_{A,B}.csv` (columns `item_id,text` and blank labels) and `key/`. Items have
   salted opaque ids and a different seeded order per annotator. Send each annotator only their own
   `sheets/*_<A|B>.csv`. `key/` stays with the coordinator and never reaches annotators or adjudicators.
   Design: 360 main items, equal across six audience classes, floors per cell, all 35 families; plus a
   disjoint 30-item pilot.
3. **Train.** Each annotator reads guideline v1.0 and the worked examples (about 45 min). No LLM, search
   engine or detector output may be consulted. Each person declares any familiarity with the AU3 generator
   or labels.
4. **Label five fields per item**, from the text alone (controlled values; free text only in `notes`):
   - `disclosure`: `yes`, `no` or `unclear` (does the text assert actual personal information about a real
     person; absent, unfilled, invented, fictional and placeholder content is `no`);
   - `sensitivity`: `S0` to `S3`, judged on what is disclosed, independent of audience;
   - `visibility` (audience): `P0` to `P4`, or `PU` when no audience is stated; "private" or first person
     does not establish `P4`;
   - `categories`: any of HEALTH, POLITICS, RELIGION, CRIMINAL, FINANCIAL, SEXUAL, CHILD, LOCATION,
     IDENTITY, THIRD_PARTY joined as `A|B`, or `NONE`;
   - `action`: `ALLOW`, `WARN` or `BLOCK`, by judgement, without the runtime policy table.
   Work in blocks of 60 with breaks. Do not discuss items before adjudication.
5. **Calibrate on the pilot.** Both annotators label `pilot_*`. The coordinator runs
   `python evaluation/annotation/compute_iaa.py --sheet A=pilot_A_done.csv --sheet B=pilot_B_done.csv --split pilot --key key/sampling_key.jsonl --out-json pilot_iaa.json --out-md pilot_iaa.md`.
   The pair discusses every disagreement and the coordinator records a dated guideline revision (the only
   permitted change). If kappa for sensitivity, visibility or disclosure is below 0.6, revise and repeat
   once with `--pilot-seed`. Pilot labels are reported separately and never pooled with the main round.
6. **Main round.** Each annotator labels all 360 items of `main_*` and returns a completed CSV. Empty or
   invalid cells are rejected by the validator and must be fixed before submission.
7. **Agreement.**
   `python evaluation/annotation/compute_iaa.py --sheet A=main_A_done.csv --sheet B=main_B_done.csv --key key/sampling_key.jsonl --split main --out-json iaa.json --out-md iaa.md --disagreements-csv to_adjudicate.csv`
   reports raw agreement, Cohen's kappa per pair, Krippendorff's alpha (nominal for disclosure and
   visibility, ordinal for sensitivity and action), per-label agreement, confusion matrices and per-category
   kappa and alpha, with family-cluster bootstrap intervals. The key supplies family clustering only; no
   provisional target enters a statistic. Report agreement with and without any annotator who declared
   familiarity.
8. **Adjudicate** every item with any field difference (categories as sets), using `to_adjudicate.csv`.
   The adjudicator sees the text, both label sets (names removed, order randomised) and the guideline, not
   the provisional targets or model output. Record `resolution` (`consensus`, `third_adjudicator`,
   `rubric_clarification`, `excluded_ambiguous`), a one-line `reason` and the `adjudicator`. Original
   annotator sheets are never edited. Classify each disagreement as guideline gap, slip, true ambiguity or
   product-policy question and report the counts.
9. **Freeze before evaluating PriVoke.** Commit the two annotator sheets, the adjudicated file and
   `iaa.json`, record their sha256 values and the commit id, before any run of the product on the sampled
   items. The reference label is the shared label when annotators agree on every field, else the
   adjudicated label. Only after the freeze run
   `python evaluation/annotation/provisional_accuracy.py --key key/sampling_key.jsonl --sheet A=main_A_done.csv --sheet B=main_B_done.csv --adjudicated adjudicated.csv --out-json accuracy.json --out-md accuracy.md`,
   which reveals the provisional targets. Any evaluation of PriVoke against the human labels follows,
   using an explicit semantic-only layer selection for LLM-layer work.
10. **Report** with the wording of protocol section 10: the provisional targets agree with adjudicated
    human labels at the reported rate on a stratified 360-case sample of authored, templated cases labelled
    by two project-team annotators. Not "validated", and not product accuracy.

## 4. Blocked on humans (and on a coordinator decision)

- Two annotators and one adjudicator. None are recorded as recruited. Estimated effort is about 19 hours in
  total (16 to 28; about 24 if the two annotators adjudicate jointly), per protocol section 8.
- The annotator guideline v1.0 does not exist as a file in the repository. It must be assembled from
  protocol section 2, a glossary and one freshly invented worked example per matched contrast (public
  biography versus private disclosure, fictional versus real person, general advice versus private
  history, explanation of a credential versus a fake value), then committed before sampling. Worked
  examples must not be copied from any dataset row.
- An annotation interface. The protocol prefers a small web page that stores each annotator's labels
  separately, with a CSV that has dropdown validation as the fallback. Neither exists. The CSV path works
  now because `annotation_schema.read_labels` validates on return.
- The decision on the dataset marker in section 5, finding 1.
- Every label, the adjudicated file and every number of the report. None exist.

## 5. Tooling findings

1. **Dataset markers in annotator-facing text (not fixed; needs a decision).** All 1,560 `fresh_eval` texts
   contain a token of the form `fresh_eval-folio-NN` (24 distinct values, which follow the audience
   expression groups, not the audience class). It names the dataset partition, while the protocol says
   dataset names never reach annotators. The sampler cannot strip it without changing the text under test.
   The coordinator can accept and disclose it, or approve a documented normalisation applied identically
   to both annotators and recorded before pre-registration.
2. **Blinding audit added (fixed).** `sample_annotation.py` now writes `blinding_audit` (pattern, items
   checked, items with a marker) into `key/manifest.json` and prints a warning on stderr when annotator-facing
   text embeds a dataset or partition marker. New test: `test_blinding_audit_flags_dataset_markers`. On the
   real input it reports 390 of 390 items.
3. No defect found in label validation, determinism, key separation, the 360 and 30 sizes, or the refusal on
   blank sheets. The agreement and accuracy scripts have not run at realistic volume, which needs labels.
4. The pinned input exists only in the main checkout (gitignored), so run the sampler there or pass its
   path with `--input`.
