# Model quality assessment, 6 October 2026

The current evidence shows weak semantic classification despite substantially higher full-pipeline recall. Model quality therefore needs separate semantic, pipeline and contextual-action measurements. A successful training update, lower loss or a larger named profile does not establish better quality.

The latest [decision-margin comparison](decision-margin-model-results-20261006.md) completed six accepted updates with zero eligible candidates: pipeline specificity rose to 29.41% from 29.01%, while recall remained 89.89%. Two treatments introduced one additional semantic miss recovered by the pipeline. No candidate endpoint safety result or retained improvement is claimed. The [training-signal diagnosis](fuzzer-training-signal-diagnosis-20261006.md) documents a separate, untested explanation for the plateau.

The following measurements use the fresh original `privoke-balanced` version `v0.3.0+train.2` from the local-SGD study, before candidate fitting. Validation contains 968 rows: 475 annotation-positive and 493 annotation-negative examples. These are annotation-presence measurements, not independently reviewed contextual privacy truth. The [measured report](local-sgd-study-v1-quality-20261006.md) supplies artifact identities, source tables and raw-evidence bindings. Its completed grid contains nine accepted and nine rejected updates, zero eligible candidates and no candidate endpoint inference.

| Quality measure | Semantic classifier | Full pipeline |
| --- | ---: | ---: |
| TP / TN / FP / FN | 246 / 155 / 338 / 229 | 427 / 143 / 350 / 48 |
| Recall | 51.79% | 89.89% |
| Specificity | 31.44% | 29.01% |
| Precision | 42.12% | 54.95% |
| F1 | 46.46% | 68.21% |
| Balanced accuracy | 41.61% | 59.45% |
| Service median / p95 elapsed time | 14.63 / 20.08 ms | 38.56 / 62.80 ms |

Latency is the runtime's returned service elapsed time over this run, including the first request. It excludes the browser and bridge and does not establish representative production latency. The pipeline's higher recall includes regex/NER contributions; it cannot be attributed entirely to the transformer.

A [reproducible baseline diagnostic](../evaluation/results/decision_margin_fuzzer_20261006_preflight/baseline-triggers.json) reconciles every semantic prediction with its recorded severity/category union. Of 338 annotation-negative flags, 221 have severity alone, 100 have both severity and categories, and 17 have categories alone. Among the 246 detected annotation-positive rows, those counts are 192, 43 and 11. Merely removing categories would leave the 321 severity-triggered false positives. This motivates examining the combined decision's training loss, but trigger association does not establish error cause or an auxiliary-loss benefit.

The model has 36,756 parameters, a seeded encoder, a 512-entry vocabulary, two encoder blocks and a 96-token configured context. The six classification-head tensors contain 660 trainable parameters under the head-only treatment. The last-block treatment also trains the final encoder block. Exact changed/frozen tensors are checked per artifact in each measured report. This is a compact repository-owned classifier; profile names do not constitute a quality ranking.

| Quality dimension | What the present evidence supports | What remains unestablished |
| --- | --- | --- |
| Annotation detection | Confusion counts, recall, specificity, precision, F1 and balanced accuracy for semantic and pipeline outputs | Contextual truth, complete span recovery and performance outside the sampled sources |
| Dataset dependence | Separate source supports and errors for each measured checkpoint | A conclusion that a source dataset itself is defective |
| Contextual actions | Casewise comparison on 41 quantitative provisional fixture cases; seven ambiguous cases excluded | Broad action accuracy against independently reviewed contextual labels |
| Sensitivity, visibility and categories | Explicit training targets, objective components and safety guards | Independent per-task accuracy on representative human-reviewed labels |
| Optimization | Same-batch initial/final objective, class-weight and sampling audits; local-SGD transport/clipping/state commitments | A generalization improvement inferred solely from falling training loss |
| Model integrity | Artifact/checksum/fingerprint identity, exact guarded publication and frozen parameter checks | An accuracy claim based only on successful publication |
| Confidence | Returned confidence is recorded | Calibration, reliable probabilities or calibrated uncertainty |
| Generalization | Exploratory validation and reused development measurements | Untouched final performance; protected final examples and labels remain uninspected and unscored |

The qualifying rule is at least 90% pipeline recall and measured specificity improvement against the declared fresh original. On this validation partition that requires at least 428 true positives and more than 143 true negatives. Only a frozen qualifying validation winner may receive candidate development and fixture assessment. Retention additionally requires at least 238/264 development true positives, more than the fresh reference's 69/238 true negatives, and zero newly introduced fixture harms. Improvements on one fixture case cannot cancel a newly introduced failure on another.

Small differences in reused exploratory data are descriptive. Source imbalance, grouped examples, provisional contextual targets and repeated experimentation constrain interpretation; these notes do not claim statistical superiority, seed robustness or untouched generalization. The [study index](model-quality-study-index-20261006.md) keeps completed failures and ongoing results distinct. Each study's loss scale, training inventory, model identity and measured dataset breakdown must remain attached to its results.

The paper is unchanged during this work. Results, quality assessments and comparison-dataset research are kept in Markdown files.
