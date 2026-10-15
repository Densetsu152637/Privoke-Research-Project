# Measured public development results

These are development observations, not final test results or acceptance evidence.
All 502 selected rows were scored in each run, with zero runtime errors.
The frozen original-model comparisons use v0.3.0 and source `712ed72`, including
the personal-workplace correction. Later financial/location rule changes are
reported separately in [false-positive experiments](false-positive-experiments.md).

| Layer | TP | TN | FP | FN | Recall (%) | Specificity (%) |
| --- | --- | --- | --- | --- | --- | --- |
| ner | 55 | 232 | 6 | 209 | 20.83 | 97.48 |
| pipeline | 247 | 47 | 191 | 17 | 93.56 | 19.75 |
| regex-ner | 198 | 203 | 35 | 66 | 75.00 | 85.29 |
| regex | 179 | 208 | 30 | 85 | 67.80 | 87.39 |
| semantic | 169 | 60 | 178 | 95 | 64.02 | 25.21 |
| Independent Presidio (small English NLP model) | 208 | 189 | 49 | 56 | 78.79 | 79.41 |

## Independent transformed-example updates

| Seed | Semantic recall (%) | Semantic specificity (%) | Pipeline recall (%) | Pipeline specificity (%) |
| --- | --- | --- | --- | --- |
| 42 | 64.77 | 23.95 | 93.56 | 18.91 |
| 1337 | 64.77 | 23.53 | 93.56 | 18.49 |
| 2026 | 64.77 | 23.53 | 93.56 | 18.49 |

Each accepted 256-prompt cycle started from the same v0.3.0 artifact, with unique
request IDs and preserved receipts. Exact returned artifact checksums were
verified against archived model files, including when versions matched across
seeds. Paired source-cluster intervals are in `evaluation/results/paired_*.json`.
Pipeline predictions on annotated-positive rows were unchanged;
pipeline recall changes were zero, and specificity decreased by 0.84–1.26
percentage points. Semantic recall rose by 0.76 percentage points while clean
specificity fell by 1.26–1.68 points. These exploratory comparisons do not establish
useful update generalization or monotonic improvement.

The first-cycle results fail the predefined no-class-regression selection rule;
the original artifact was retained at that checkpoint. Later user-authorized
development selected a small anchored 0.003 update, reported separately.
Ordinary-example controls are reported below. Additional identical update cycles are not justified solely to
chase the numerical targets; the data/task mismatch and training distribution
need diagnosis first.

## Interpretation and limits

The full pipeline exceeds 90% recall but misses the 90% clean-specificity target
by a large margin. PIIMB labels annotated PII presence, while PriVoke also flags
privacy-sensitive topics and financial/location information. For example, some
benchmark-negative lines contain monetary amounts or unannotated dates. Those
labels are retained as provided; they are not relabeled to improve PriVoke scores.
Conversely, this mismatch cannot be used to dismiss all false alarms: independent
contextual evidence would be needed to decide which flags reflect intended policy.

These results argue against broad quality, usability or adaptation claims.
Presidio's rates use the same data but a disclosed upstream configuration; its
scores are not from Casper and do not establish superiority to closest work.
The final source-disjoint 498-row holdout is still unscored and must remain locked
until model/rule/protocol decisions are frozen.

## Recoverable evidence

Original runs: `evaluation/results/original_public_development_frozen/`.
Independent updates and exact models: `evaluation/results/original_updates_20261003/`
and matching per-seed measurement directories. Public split manifest:
`evaluation/results/locked-public/manifest.json`. Presidio raw predictions and
metrics are separate JSON files in `evaluation/results/`. Reports include raw
predictions, classifications, actions, source groups, runtime elapsed times and
returned model identity. These ignored local artifacts must be deliberately
archived before final figure generation. Invalidated automatic-training pilots
remain preserved and are excluded from this table.

## Ordinary-example control

| Seed | Semantic recall (%) | Semantic specificity (%) | Pipeline recall (%) | Pipeline specificity (%) |
| --- | --- | --- | --- | --- |
| 42 | 64.77 | 23.95 | 93.56 | 18.91 |
| 1337 | 64.77 | 23.95 | 93.56 | 18.91 |
| 2026 | 64.77 | 23.53 | 93.56 | 18.49 |

This control disables fuzzer transformations while retaining the same source
prompt count, seeds and original artifact. Augmentation adds transformed training
examples, so expanded example count and compute differ; the comparison evaluates
these exact update paths rather than proving a universal causal benefit of fuzzing.
Paired augmentation differences are archived in `paired_augmentation_*.json`.
The transformed path gave no additional pipeline recall and equal or lower
specificity than ordinary updates. Neither path met the development targets or
passed the no-class-regression selection criterion. Intervals are descriptive,
without a claim of family-wise significance across multiple comparisons.

The aggregation takes the maximum sensitivity and union of categories
(`pipeline.strongest_result` and shared `merge_classifications`). All 30 regex
false positives remain positive in the frozen pipeline. On these 238 clean rows,
the original fixed regex behavior therefore capped pipeline specificity at 87.39%,
even if the semantic layer adds no false alarms. More semantic-only cycles cannot
meet 90% specificity while these rules and this scoring task remain unchanged.
This is a historical diagnosis, not a final-test conclusion. Revised rules reduce
regex false positives to seven, removing this particular ceiling. The current
live revised-rule/selected-model pipeline gives TP247/TN54/FP184/FN17 (93.56%
recall, 22.69% specificity). See the separate experiment record for all attempts,
rejections, selection rules and exact artifact identity.
