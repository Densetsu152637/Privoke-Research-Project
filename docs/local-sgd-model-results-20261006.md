# Local-SGD model results, 6 October 2026

The 18 independent optimizer comparisons did not meet the qualifying standard. Nine head updates passed training guards; all nine last-block updates were rejected because the candidate was worse on the held-out evaluation set. No accepted candidate reached 90% validation pipeline recall. Selection was frozen with a null winner, no candidate development/fixture inference was performed, and no model was retained or promoted.

The [prospective protocol](local-sgd-fuzzer-study-20261006.md) fixed the exact original balanced train.2 base, role-quota curriculum, 256 training/16 whole-group held-out rows, class-balanced mean-category objective, .05 aggregate delta bound and unchanged safety guards. Each representation/seed comparison used identical ordered samples and explicit targets. Treatments were one step at .003, four recomputed steps at .003, and one step at .012. The latter two match nominal total learning rate; rounding, changing gradients and clipping can produce different actual displacement.

| Accepted head treatment | Seeds | Pipeline TP / TN / FP / FN | Recall / specificity |
| --- | --- | --- | --- |
| Fresh original reference | — | 427 / 143 / 350 / 48 | 89.89% / 29.01% |
| One step at .003 | 42, 1337, 2026 | 427 / 144 / 349 / 48 | 89.89% / 29.21% |
| Four steps at .003 | 42, 2026 | 426 / 145 / 348 / 49 | 89.68% / 29.41% |
| Four steps at .003 | 1337 | 426 / 147 / 346 / 49 | 89.68% / 29.82% |
| One step at .012 | 42 | 426 / 145 / 348 / 49 | 89.68% / 29.41% |
| One step at .012 | 1337 | 426 / 147 / 346 / 49 | 89.68% / 29.82% |
| One step at .012 | 2026 | 426 / 146 / 347 / 49 | 89.68% / 29.61% |

Validation contains 475 positives and 493 negatives. Eligibility required at least 428 true positives and more than 143 true negatives. Higher specificity in the larger-step treatments coincided with one additional pipeline miss. Their measured gains therefore do not satisfy the rule. Rejected models have no claimed validation accuracy or optimizer trajectory.

For seed 42, runtime-recorded same-batch objective loss fell from 1.97042655 to 1.96877548 with one small step, 1.96393795 with four steps, and 1.96388089 with one larger step. All nine accepted head trajectories had zero clipped coordinates. Their maximum final transported delta was 0.00297534, below the .05 bound. These observations do not support clipping as the limiting factor for accepted heads in this grid. Lower training loss did not improve recall. Intermediate trace hashes/scalars are runtime-recorded commitments rather than independent reconstruction of the trajectory; initial/final float32 identities and guarded publication were checked.

The dataset table compares the fresh original pipeline with four steps at .003, seed 1337, descriptively. This model was ineligible and is not a selected or retained winner. Every model and both layers appear in the [complete measured quality report](local-sgd-study-v1-quality-20261006.md).

| Dataset | Positive / negative support | Original recall / specificity | Four-step seed 1337 recall / specificity | Candidate FP / FN |
| --- | ---: | --- | --- | ---: |
| AI4Privacy/OpenPII | 133 / 39 | 93.23% / 33.33% | 92.48% / 35.90% | 25 / 10 |
| gretel | 98 / 54 | 96.94% / 20.37% | 96.94% / 22.22% | 42 / 3 |
| nemotron-pii | 206 / 384 | 84.95% / 29.17% | 84.95% / 29.69% | 270 / 31 |
| privy | 38 / 16 | 86.84% / 43.75% | 86.84% / 43.75% | 9 / 5 |

Gretel remains the lowest-specificity sampled source; nemotron-pii contributes the most absolute false positives and false negatives and dominates negative support. This identifies weaknesses in model/source combinations, not defective datasets. Annotation presence does not establish contextual severity, visibility, appropriate actions or complete span recovery.

The model has 36,756 parameters; accepted heads train 660 while freezing the encoder. Its encoder originates in seeded initialization. The fresh semantic reference has only 51.79% recall and 31.44% specificity. The [quality assessment](model-quality-assessment-20261006.md) explains why full-pipeline recall cannot hide this weakness. Complete quality evidence records exact identities, parameter trainability/changes, confusion counts, precision, F1, balanced accuracy, source supports, paired predictions, service latency, class-weight audits, sample coverage, task losses and optimizer traces. Provisional targets, reused exploratory splits, unestablished calibration/representative latency and absent untouched generalization remain material limits. Protected final examples and labels remain uninspected and unscored.

Fresh baseline predictions matched the preserved reference on all 968 validation rows in both layers. Original development and 48 fixture responses were archived before fitting; they are reference measurements, with no candidate endpoint assessment. Independent final restoration verified seven original payloads and five original image IDs. A 47-file paper-integrity comparison found zero changes.

Evidence is preserved in `evaluation/results/local_sgd_fuzzer_20261006_v1/`, including complete-quality.json, complete-quality.md, reporting-source.py, state/selection, all 18 prepared bases/inventories, request/response/receipt records, raw measurements and frozen computation. Complete JSON SHA-256 is `f3cc9b390a859a23ed83b1ec46ec3f69b6dc325addf20a65f46ae6eb5fe706b1`; Markdown is `572c82527ad0fa8165a7a180fd15cbfde04421ee017d211346156975d55bc5fd`; reporting source is `95e546e9107343b24748831c8cc694d131bc4f2a27ca969bc48363c7f3e847fc`. Earlier studies remain separate immutable archives. A follow-on computation hypothesis is under investigation and has no measured result yet.
