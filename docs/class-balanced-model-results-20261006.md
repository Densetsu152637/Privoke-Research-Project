# Class-balanced fuzzer results and model quality

The prospectively declared 24-attempt study completed: 10 accepted and 14 rejected updates, with no eligible candidate. All 12 final-block updates were rejected; the accepted models are head-only updates. Selection froze with no winner, so no candidate development or safety-fixture inference occurred and no artifact was retained. This experiment does not meet the improvement target. The completed initial 54-attempt study remains separate failed evidence in [its results](fuzzer-model-results-20261006.md) and [measured quality report](fuzzer-model-study-v2-quality-20261006.md).

The current study starts every attempt independently from the exact live balanced model, `v0.3.0+train.2`, with 36,756 parameters. It compares original example weighting with a class-balanced objective, using heads or the last encoder block plus heads. The [fixed protocol](class-balanced-fuzzer-study-20261006.md) defines the complete grid, selection and retention gates.

The feature images reproduce all 968 original semantic and pipeline validation classifications, presence decisions and actions with zero differences. The fresh baseline measurements are:

| Partition / layer | Positive / negative rows | TP / TN / FP / FN | Recall | Specificity |
| --- | ---: | --- | ---: | ---: |
| Validation / semantic | 475 / 493 | 246 / 155 / 338 / 229 | 51.79% | 31.44% |
| Validation / pipeline | 475 / 493 | 427 / 143 / 350 / 48 | 89.89% | 29.01% |
| Development / semantic | 264 / 238 | 146 / 76 / 162 / 118 | 55.30% | 31.93% |
| Development / pipeline | 264 / 238 | 242 / 69 / 169 / 22 | 91.67% | 28.99% |

These are reused exploratory partitions. Presence labels do not establish contextual severity, visibility or privacy-action correctness. The semantic model's low recall and specificity remain visible even where the complete pipeline recovers sensitive examples. Model size and profile names do not establish quality; the encoder originates in repository-owned seeded initialization and the live model includes prior training.

The highest accepted recall is 89.89%, with specificity up to 29.41% (TP427/TN145/FP348/FN48), two additional true negatives over the fresh original model. The highest specificity is 30.83% (TP425/TN152/FP341/FN50), but recall is only 89.47%. Neither satisfies at least 90% recall plus a measured specificity improvement. These are descriptive extrema, not selected winners. Rejected RPCs do not expose precise failed candidate guard metrics, so no rejection is assigned an invented accuracy or specific failing subgate.

Each seed samples only 6, 8 or 9 sensitivity-positive training rows among 256. The balanced objective gives each contextual class half the original total weight, preserving within-class relative weights. This amplifies sparse provisional supervision without adding evidence. Ordered partition commitments bind text, groups, full contextual targets and original weights. Existing held-out guards count rows and remain unchanged; passing them does not establish the requested benchmark improvement. Training diagnostic and supervised objective losses are reported separately and are not interchangeable quality measures.

The [complete measured quality report](class-balanced-study-v1-quality-20261006.md) records every accepted attempt's semantic and pipeline confusion counts, recall, specificity, precision, F1, balanced accuracy, dataset-specific supports and errors, parameter identities/trainability, before/after held-out guards, paired prediction changes and optimization-weight audits. All 12 objective pairs use identical ordered original train/held-out inputs. Rejected updates receive no scored model-quality claim. The read-only reporter is `evaluation/report-class-balanced-fuzzer-study.py`; durable JSON, Markdown, reporter source, frozen selection and source commitments are in `evaluation/results/class_balanced_fuzzer_20261006_v1`.

Both the fresh baseline and completed candidate stages restored and independently verified all seven original model payloads and five serving image IDs. The paper files remain unchanged against their saved 47-file snapshot. The protected final partition remains uninspected and unscored. Confidence calibration, representative production latency, independent contextual label quality and untouched generalization are not established.

The next computation hypothesis is to average category BCE over labels instead of summing ten terms beside sensitivity and visibility CE, while retaining class balancing and all existing gates. Category-gradient dominance has not been measured; this is a separate prospective experiment, not an explanation established by the present results. Its preparation and validation occur in isolation, and no future result is claimed here.
