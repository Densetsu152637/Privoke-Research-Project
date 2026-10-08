# Fuzzer adaptation results and model quality

The fixed initial study completed all 54 one-cycle training requests: 23 accepted, 31 rejected, and 15 validation-eligible. Rejected candidates have no scored accuracy claim. Selection froze before assessing development or the contextual fixture. The frozen winner is efficient, head-only training, learning rate 0.003, seed 42. It failed development and contextual retention and was not retained. This completed initial experiment does not satisfy the user's improvement goal.

## Measured validation behavior

All rows below use the same 968 reused exploratory examples: 475 positive and 493 negative. TP/TN/FP/FN refer to annotation presence. Original profiles are checked-in v0.3 models; they are distinct from the previously trained live balanced model.

| Model | Layer | TP / TN / FP / FN | Recall | Specificity |
| --- | --- | --- | ---: | ---: |
| Original efficient | Semantic | 282 / 156 / 337 / 193 | 59.37% | 31.64% |
| Original efficient | Pipeline | 442 / 146 / 347 / 33 | 93.05% | 29.61% |
| Original balanced | Semantic | 283 / 133 / 360 / 192 | 59.58% | 26.98% |
| Original balanced | Pipeline | 435 / 122 / 371 / 40 | 91.58% | 24.75% |
| Original quality | Semantic | 334 / 112 / 381 / 141 | 70.32% | 22.72% |
| Original quality | Pipeline | 445 / 108 / 385 / 30 | 93.68% | 21.91% |
| Frozen efficient winner | Semantic | 280 / 158 / 335 / 195 | 58.95% | 32.05% |
| Frozen efficient winner | Pipeline | 442 / 148 / 345 / 33 | 93.05% | 30.02% |
| Quality last-block, 0.003, seed 2026 | Semantic | 217 / 206 / 287 / 258 | 45.68% | 41.78% |
| Quality last-block, 0.003, seed 2026 | Pipeline | 417 / 194 / 299 / 58 | 87.79% | 39.35% |

The winner preserves pipeline recall and returns a negative annotation-presence prediction on two additional clean-labelled rows compared with its same-profile original: a 0.41 percentage-point specificity increase. Its pipeline balanced accuracy is 61.54%. This is a small descriptive improvement; 345 of 493 clean rows still trigger detection. Its semantic layer loses two true positives while gaining two true negatives. High pipeline recall therefore does not establish high semantic model quality or contextual action correctness.

Of 27 last-block requests, 25 were rejected. The two accepted quality-profile requests improve specificity but fail the 90% pipeline recall requirement. Distinct updated parameter fingerprints show that repeated confusion counts across seeds are not evidence of identical weights or no training. Rejected RPCs do not expose the precise failed candidate gate measurements.

## Quality and provenance

Efficient, balanced and quality have 19,028, 36,756 and 54,292 parameters respectively. Their encoders originate in repository-owned seeded random initialization and their original heads in authored bootstrap supervision. Profile names and capacity are not quality rankings. Only the opt-in last-block strategy updates the final encoder block; head-only training leaves the encoder frozen.

The sampled 256-row training partitions contain only 6, 8 or 9 sensitivity-positive examples, depending on seed; the remainder are target S0. Public annotation negatives and authored contextual labels are provisional. Presence annotations do not supply independent sensitivity, visibility or privacy-action truth. These constraints limit what either the held-out training guards or benchmark scores establish.

The detailed model-quality export records every accepted candidate, precision, F1, balanced accuracy, per-source class supports and errors, training/held-out inventories, actual trainable tensors, row-based held-out guards, weighted loss definitions, paired output changes, model identities and execution amendments. An absent source class has an unavailable rate. Poor performance on a dataset is evidence of a mismatch to investigate, not proof that the dataset is defective. Confidence calibration and representative production latency have not been established.

## Decision and evidence

| Development model | Layer | TP / TN / FP / FN | Recall | Specificity |
| --- | --- | --- | ---: | ---: |
| Fresh live balanced, v0.3.0+train.2 | Semantic | 146 / 76 / 162 / 118 | 55.30% | 31.93% |
| Fresh live balanced, v0.3.0+train.2 | Pipeline | 242 / 69 / 169 / 22 | 91.67% | 28.99% |
| Frozen efficient winner | Semantic | 157 / 62 / 176 / 107 | 59.47% | 26.05% |
| Frozen efficient winner | Pipeline | 236 / 60 / 178 / 28 | 89.39% | 25.21% |

Development contains 264 positive and 238 negative rows. The winner's pipeline recall falls below 90%, and its specificity declines by 3.78 percentage points against the measured live balanced reference. Pipeline balanced accuracy falls from 60.33% to 57.30%. The fixture records no newly introduced private minimum-action failures but four new interventions on previously allowed clean controls. Either the development failure or the fixture failure independently prevents retention. Private disclosures meeting minimum action improve from 15/17 to 16/17; clean controls receiving ALLOW remain 15/24. Four clean repairs offset four newly introduced interventions in the aggregate, but cannot cancel those individual harms. A no-new-failure gate is not an absolute safety claim.

The user-confirmed target is at least 90% recall plus measured specificity improvement. Validation compares each candidate with its own original profile. Development compares only the frozen winner with freshly measured live balanced, and the fixture additionally forbids newly introduced private minimum-action failures and new interventions on previously allowed clean controls. No alternate winner is chosen using development or fixture results.

The original catalog bytes and serving image IDs are restored after each mutating stage. No default model promotion is implied by retaining a research artifact. The protected final partition is not inspected or scored. The 47 paper-file hashes remain unchanged at the latest verification.

The full [measured model-quality report](fuzzer-model-study-v2-quality-20261006.md) includes every accepted candidate and dataset stratum, development and fixture results, absolute quality limits, and immutable evidence commitments. Administrative recovery reused the completed reference development reports and one persisted fixture observation. One unpersisted fixture RPC was repeated after correcting the collector's false assumption that a successful semantic response must contain a detection. Successful empty semantic responses carry no per-case model fingerprint; the report states the collection-level provenance limits. [Execution repairs](fuzzer-model-execution-repairs-20261006.md) preserve the failed attempts separately from model outcomes.

A separate prospective computation experiment will compare original weighting with class-balanced weighting and both head-only and last-block training, starting each attempt from the exact live balanced model. It preserves the curriculum, samples, held-out weights, update guards and decision criteria. Its results must remain separate; this failed initial winner will not be replaced using its development or fixture failures.

Evidence: `evaluation/results/contextual_fuzzer_20261006_v2/state.json`, its immutable source snapshots and attempt reports; fixed protocol in [fuzzer-model-study-20261006.md](fuzzer-model-study-20261006.md); reporting method in [fuzzer-model-quality-20261006.md](fuzzer-model-quality-20261006.md). Existing dataset recalculations and primary-source comparison research remain in [dataset-review-20261006](dataset-review-20261006/README.md).
