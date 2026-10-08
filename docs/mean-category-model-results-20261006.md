# Mean-category fuzzer results and model quality

Phase 03 completed with five accepted and seven rejected updates, and no eligible candidate. All six final-block updates were rejected. Selection froze over all 12 attempts with no winner; no candidate development or fixture inference occurred and no artifact was retained. The experiment fails the requested improvement target. The [prospective protocol](mean-category-fuzzer-study-20261006.md), initial 54-attempt study and [class-balanced 24-attempt study](class-balanced-model-results-20261006.md) remain separate evidence. The [complete measured quality report](mean-category-study-v1-quality-20261006.md) records every outcome and all available quality measurements.

The highest accepted recall is 89.89%, with specificity up to 29.41%; the highest specificity is 29.82%, with recall 89.68%. These are descriptive extrema, not selected winners. Against the fresh baseline, the latter adds four true negatives and loses one true positive. The accepted semantic models remain weak, with recall 51.16–51.79% and specificity 31.64–32.25%. No accepted model reaches the 428/475 true positives needed for 90% validation recall. Rejected responses do not disclose precise candidate subgate measurements, so no accuracy or specific failed subgate is invented.

The new computation averages category binary cross-entropy over ten labels alongside sensitivity and visibility cross-entropy. It retains the preceding study's class-balanced training weights and all existing update and safety guards. Numerical checks establish that this computation is implemented correctly; they do not establish better model quality. Historical summed-category controls use identical ordered training and held-out samples, but were run earlier and were not contemporaneously randomized or refitted.

Every attempt starts independently from live `privoke-balanced`, version `v0.3.0+train.2`, file SHA-256 `87065d573970eec9b753102599789ebcb199b9b9d75e787b3b06e914137cdd92`. This model has 36,756 parameters and uses a repository-owned seeded encoder with authored bootstrap supervision and prior training. Head-only attempts train six head tensors; final-block attempts also train the last encoder block. Names, parameter counts and accepted updates do not establish quality.

Fresh feature-image inference reproduced all 968 original validation semantic and pipeline classifications, presence decisions and actions with zero per-case differences before fitting. Fresh original development and all 48 contextual fixture responses were also captured before the grid. The baseline is:

| Partition / layer | Positive / negative support | TP / TN / FP / FN | Recall | Specificity |
| --- | ---: | --- | ---: | ---: |
| Validation / semantic | 475 / 493 | 246 / 155 / 338 / 229 | 51.79% | 31.44% |
| Validation / pipeline | 475 / 493 | 427 / 143 / 350 / 48 | 89.89% | 29.01% |
| Development / semantic | 264 / 238 | 146 / 76 / 162 / 118 | 55.30% | 31.93% |
| Development / pipeline | 264 / 238 | 242 / 69 / 169 / 22 | 91.67% | 28.99% |

The full pipeline conceals substantial semantic-model weakness. Dataset grouping makes further differences visible. These are sampled originating-dataset strata within the benchmark, not complete evaluations of each upstream dataset:

| Validation source / full pipeline | Positive / negative support | TP / TN / FP / FN | Recall | Specificity |
| --- | ---: | --- | ---: | ---: |
| AI4Privacy / OpenPII | 133 / 39 | 124 / 13 / 26 / 9 | 93.23% | 33.33% |
| Gretel | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% |
| Nemotron | 206 / 384 | 175 / 112 / 272 / 31 | 84.95% | 29.17% |
| Privy | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% |

Poor scores identify model/source mismatch. They do not establish defective datasets or contextual privacy truth. Recall and specificity use their respective class supports; absent classes must have unavailable rates. Annotation-presence labels do not establish severity, visibility, action correctness or complete entity-span recovery.

Model-quality reporting includes semantic and pipeline confusion counts, recall, specificity, precision, F1 and balanced accuracy for every accepted model and originating source; paired prediction changes; model identities and trainability; actual training coverage; row-based held-out guards; class-weight audits; and the three optimized task losses. The legacy classification-distance diagnostic and optimized loss are separately labelled. Rejected updates receive no invented model-quality score. Service-only latency does not establish production latency, and calibration has not been measured.

Selection requires at least 428/475 validation true positives and strictly more clean true negatives than the fresh original baseline. Only the frozen winner may receive candidate development and fixture inference. Retention requires at least 238/264 development true positives, strictly improved development specificity and no newly introduced casewise fixture failures. The provisional quantitative gate covers 41 cases and excludes seven ambiguous cases from the 48 collected responses. Existing fixture failures remain visible; repairs cannot offset new harms.

Evidence lives in `evaluation/results/mean_category_fuzzer_20261006_v1`; read-only reconciliation uses `evaluation/report-mean-category-fuzzer-study.py`. Complete JSON, Markdown and reporter-source exports are preserved there. Independent baseline and completed-stage restoration verified all seven original model payloads and five serving image IDs. Training positives are sparse and labels provisional; reused validation/development partitions cannot establish untouched generalization or statistical superiority. The protected final examples and labels remain uninspected and unscored. All 47 paper files match their saved snapshot.

The next hypothesis is to increase authored contextual exposure at the same batch size and class-balanced objective, rather than only increasing those rows' weights. Current sampled batches contain eight authored contrasts in total. A metadata audit of the unchanged curriculum finds sufficient authored private and clean rows after existing held-out-group exclusions for 32 of each, plus 192 public/bootstrap rows, without replacement. This remains a prospective changed-exposure experiment: it adds no independently reviewed labels and establishes no improvement yet.
