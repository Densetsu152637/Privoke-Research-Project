# Decision-margin model results, 6 October 2026

The six independent comparisons did not meet the qualifying standard. All six head updates passed training guards, but none reached 90% validation pipeline recall. Selection was frozen with a null winner. No candidate development or fixture inference was performed, and no model was retained or promoted.

The [prospective protocol](decision-margin-fuzzer-study-20261006.md) paired the mean-category control with a fixed-coefficient decision-margin auxiliary objective across seeds 42, 1337 and 2026. Each fit started from the exact original balanced train.2 model and used identical ordered quota samples: 256 training rows, 16 whole-group held-out rows, heads-only one-step SGD at .003 and the unchanged .05 transport bound. Decoder thresholds and safety guards were unchanged. The auxiliary term trains the non-S0/category union used for detection; it is a surrogate with known tie and numerical-boundary limitations.

| Model | Pipeline TP / TN / FP / FN | Recall / specificity | Precision / F1 / balanced accuracy |
| --- | --- | --- | --- |
| Fresh original reference | 427 / 143 / 350 / 48 | 89.89% / 29.01% | 54.95% / 68.21% / 59.45% |
| Mean-category controls, all three seeds | 427 / 144 / 349 / 48 | 89.89% / 29.21% | 55.03% / 68.27% / 59.55% |
| Decision-margin treatments, all three seeds | 427 / 145 / 348 / 48 | 89.89% / 29.41% | 55.10% / 68.32% / 59.65% |

Validation contains 475 positives and 493 negatives. Eligibility required at least 428 true positives and more than 143 true negatives. Each margin treatment gained one true negative over its fresh paired control, and two over the original, with no pipeline true-positive gain. The 0.41 percentage-point specificity gain against the original does not satisfy the recall requirement or establish statistical superiority.

Semantic-model quality remains weak. The original semantic model recorded 246 / 155 / 338 / 229, or 51.79% recall and 31.44% specificity. Mean controls recorded 246 / 156 / 337 / 229. Margin seeds 42 and 2026 recorded 245 / 157 / 336 / 230; seed 1337 recorded 246 / 157 / 336 / 229. Thus two margin treatments introduced one additional semantic miss, although other pipeline detectors recovered it. Pipeline metrics must not conceal that regression.

| Dataset | Positive / negative support | Original pipeline recall / specificity | Margin pipeline recall / specificity | Margin FP / FN |
| --- | ---: | --- | --- | ---: |
| AI4Privacy/OpenPII | 133 / 39 | 93.23% / 33.33% | 93.23% / 33.33% | 26 / 9 |
| gretel | 98 / 54 | 96.94% / 20.37% | 96.94% / 20.37% | 43 / 3 |
| nemotron-pii | 206 / 384 | 84.95% / 29.17% | 84.95% / 29.69% | 270 / 31 |
| privy | 38 / 16 | 86.84% / 43.75% | 86.84% / 43.75% | 9 / 5 |

All three margin treatments share these pipeline source counts. Both improved negative decisions occur in nemotron-pii. Gretel remains the lowest-specificity sampled source; nemotron-pii contributes the most absolute errors and dominates negative support. These observations identify model/source weaknesses, not defective datasets. Annotation presence does not establish contextual severity, visibility, appropriate action or complete span recovery.

For seed 42, runtime-recorded margin objective loss fell from 3.02415483 to 3.01991817, including auxiliary BCE from 1.05372828 to 1.05207447. All six trajectories had zero clipped coordinates; the maximum final transported delta was 0.00107536558. Lower training loss did not increase recall. Full totals for the mean and margin objectives have different components and cannot be compared as model quality. Initial/final float32 identities and publication were checked; intermediate trace scalars and hashes are runtime-recorded commitments rather than independent trajectory reconstruction.

The balanced model has 36,756 parameters; these fits train 660 head parameters while freezing the encoder, which originates in seeded initialization. The [complete measured quality report](decision-margin-study-v1-quality-20261006.md) supplies exact identities, both layers, source supports, confusion counts, precision, F1, balanced accuracy, paired prediction changes, parameter trainability, service latency, sample coverage, class-weight audits, task losses and optimizer traces. The [quality assessment](model-quality-assessment-20261006.md) discusses provisional labels, reused exploratory splits, missing calibration and untouched generalization, and latency limitations. Protected final examples and labels remain uninspected and unscored.

Fresh baseline predictions matched the preserved reference on all 968 validation rows in both layers. Original development and 48 fixture responses were archived before fitting as reference measurements. With no eligible candidate, candidate endpoint safety is unmeasured; training-guard acceptance does not imply fixture retention. Independent final restoration verified seven original payloads and five original image IDs. A 47-file paper-integrity comparison found zero changes.

Evidence is preserved in `evaluation/results/decision_margin_fuzzer_20261006_v1/`, including complete-quality.json/md, reporting-source.py, state/selection, six prepared bases/inventories, request/response/receipt records, raw measurements and frozen computation. Complete JSON SHA-256 is `b30bcef2554fa68b172e1e6004100eef520b09c7e364be205b6e15e92ecaba5f`; Markdown is `0d3366ae0a0dbae41400f566b46b876b6cb5218f32147ad8b8f7c8b2300cb1d2`; reporting source is `e676d0e9dee4481f574ce4a82184bd0f101b3feb430c9826412a5059431d8a01`. Restoration and paper checks are in the sibling preflight directory. Earlier studies remain separate immutable archives.
