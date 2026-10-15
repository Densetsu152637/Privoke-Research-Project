# False-positive development: 3 October 2026

This record preserves the earlier template/rule extension and its selected
checkpoint. The subsequent custom within-corpus coverage experiment and current
selection are in [public-negative results](public-negative-results.md). Its
prospectively revised selection rule does not retroactively change this record.

The user requested continued development, restarted from the original model,
before final testing. These experiments use the locked **development** partition:
502 rows, 264 positive and 238 clean. The 498-row final partition remains unscored.
Labels are retained as supplied. Rates below measure annotation-presence detection,
not independently validated contextual privacy or browser prevention.

## Controls and provenance

Every independent seed starts from the exact checked-in balanced model v0.3.0.
The baseline internal artifact checksum is
`8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c`.
Controlled training comparisons pin runtime source to `712ed72`, including the
personal-workplace correction, but excluding later financial/location changes.
The separate original-runtime image prevents rebuilding the default tag from
changing code between seed restarts. The interrupted `lr001_updates_20261003`
batch is retained but excluded because it mixed runtime source revisions.

Each cycle requests 256 source prompts. The default curriculum has one transformed
copy per prompt; fictional curricula disable transformations. All existing
publication, held-out safety, replay and gradient bounds remain enabled.
The fuzzer samples deterministic templates: there is no generation-temperature
setting. A positive scalar softmax temperature would leave sensitivity argmax
unchanged; it cannot alone remove these binary false alarms.

## Independent first-cycle attempts

Counts are **TP / TN / FP / FN**. All scored runs cover the same 502 IDs, labels
and source groups, with zero runtime errors. Rejected candidates are not scored
successes. Learning-rate changes use the existing service setting; training
implementation remains in the fuzzer/runtime, with orchestration in evaluation.

| Curriculum; learning rate; transformations | Seeds and update outcomes | Semantic counts | Pipeline counts |
| --- | --- | --- | --- |
| Original, no update | Baseline | 169 / 60 / 178 / 95 | 247 / 47 / 191 / 17 |
| Default; 0.03; one | 42, 1337, 2026 accepted | 171 / 57 / 181 / 93 for 42; 171 / 56 / 182 / 93 otherwise | 247 / 45 / 193 / 17 for 42; 247 / 44 / 194 / 17 otherwise |
| Default; 0.03; zero | 42, 1337, 2026 accepted | 171 / 57 / 181 / 93 for 42 and 1337; 171 / 56 / 182 / 93 for 2026 | 247 / 45 / 193 / 17 for 42 and 1337; 247 / 44 / 194 / 17 for 2026 |
| Default; 0.01; one | 42, 1337, 2026 accepted | TP 171, 169, 170 respectively; TN 60, FP 178, FN 264 minus TP | 247 / 47 / 191 / 17 for all |
| Default; 0.003; one | 42, 1337, 2026 accepted | 169 / 60 / 178 / 95 for all | 247 / 47 / 191 / 17 for all |
| Fictional clean-topic; 0.03; zero | Only 42 attempted; rejected before publication: pre-training exact-match rate was zero | Not scored | Not scored |
| Fictional plus bootstrap anchors; 0.03; zero | 42 and 1337 rejected for held-out regression; 2026 accepted | 158 / 67 / 171 / 106 for 2026 | 246 / 54 / 184 / 18 for 2026 |
| Fictional plus bootstrap anchors; 0.01; zero | 42, 1337, 2026 accepted | TP 166, 167, 168 respectively; TN 62, FP 176, FN 264 minus TP | 246 / 49 / 189 / 18 for 42 and 1337; 247 / 49 / 189 / 17 for 2026 |
| Fictional plus bootstrap anchors; 0.003; zero | 42, 1337, 2026 accepted | 169 / 61 / 177 / 95 for all | 247 / 48 / 190 / 17 for all |

The new curriculum contains 72 fictional clean-topic and 36 fictional private
templates, with optional 16 existing bootstrap anchors. These are provisional
training labels, not independent human annotations. No benchmark row is copied
into training. More templates do not establish better distribution coverage.

Only the anchored 0.003 candidates improve specificity without decreasing recall
in either semantic or pipeline relative to the original. Each corrects exactly
one clean prediction and changes no positive prediction. All three tie in
pipeline balanced accuracy (0.568643 using exact class denominators); the lower
seed, 42, is selected. This small development effect is not proof of generalization
or a statistically significant adaptation benefit.

## Additional-cycle stopping and selected artifact

The bounded continuation starts from the selected seed-42 first cycle, using
the same anchored curriculum, seed and learning rate. Cycle 2 is accepted by the
service but gives semantic counts **168 / 61 / 177 / 96**; pipeline remains
**247 / 48 / 190 / 17**. The semantic recall loss fails the conservative
no-regression selection rule. Cycle 3 is not attempted. Cycle 1 is restored.

Selected artifact: `evaluation/results/calibration0003_20261003/seed42-model.json`.

- Internal checksum: `494cdafa337b9c93325e8262704978e2e7b55b2011b9403716996399a85ed309`.
- Exact file SHA-256: `b2c63c6fd41879a7bff97ff5f7e432bd260b1728361337681f8dc6352ac071a8`.
- Version: v0.3.0+train.1. Version text alone does not identify a seed-specific model.
- Stopping evidence: `evaluation/results/calibration_curve_20261003/selection.json`.

## Rule changes and live integrated result

Separately tested source `cbaecf8` requires personal/structured context for money
and coarse location disclosures. Generic product prices, public budgets and
phrases such as “from the document” no longer imply a private disclosure.
Regression cases retain personal amounts, residence statements and contractions.
The revised runtime suite passes 82 tests in Docker.

With the **original model**, development rule diagnosis gives:

| Layer | TP | TN | FP | FN | Recall | Specificity |
| --- | --- | --- | --- | --- | --- | --- |
| Revised regex | 172 | 231 | 7 | 92 | 65.15% | 97.06% |
| Revised regex plus unchanged NER | 193 | 225 | 13 | 71 | 73.11% | 94.54% |
| Revised pipeline, original model | 247 | 53 | 185 | 17 | 93.56% | 22.27% |

Seven regex true positives are lost, but other layers preserve all of those
pipeline detections. Six pipeline false positives are removed. This diagnostic
reuses archived unchanged NER/semantic binary outputs; it is not a live timing run.
The old fixed-rule specificity ceiling of 87.39% is therefore historical.

The **live** revised-rule pipeline with the selected anchored 0.003 model gives
**TP 247, TN 54, FP 184, FN 17**: **93.56% recall, 22.69% specificity**, with
zero errors on all 502 rows. Compared with the frozen original, seven fewer clean
rows trigger, with unchanged positive predictions. The full pipeline still
misses the user-approved 90% specificity target by a large margin.
Evidence: `evaluation/results/selected_context_development_20261003/`, including
dataset/model/report hash manifest and returned model identity.

## Counterevidence and next investigation

The normalized offline original model matches all archived live semantic binary
predictions. A sensitivity-probability gate grid does not attain both 90% targets
with the original rule/NER union. Preserving raw case raises NER recall from
20.83% to 45.45%, but decreases specificity from 97.48% to 83.61%; that diagnostic
is not deployed. Neither a threshold-only nor casing-only change is supported as
a sufficient remedy. These bounded grids do not prove that every calibration
or model redesign must fail.

Inspect representation and training coverage next. The checked-in generator
randomly initializes the frozen encoder and fits heads on a small authored
bootstrap set; it is not a pretrained language encoder. One averaged head update
cannot be assumed to add broad semantic understanding. A broader, separately
partitioned training curriculum or a separately evaluated pretrained detector
would be a new development experiment, with recorded protocol changes and matched
controls. Retain original results, safety gates and the untouched final partition.

The read-only evidence audit verified 35 report hashes, candidate checksums and
matched IDs/labels/groups, including the selected live integrated result. This
computational audit is not supervisor review or independent contextual labeling.
The final read-only SQLite receipt snapshot contains 25 rows and passes
`integrity_check`; raw update audit records are preserved separately.

## Reproduction and evidence paths

See [evaluation runners](../../evaluation/README.md) for ordered Compose overlays,
original-source extraction, learning-rate drivers and development diagnoses.
Experiment directories are `lr001_pinned_20261003`, `lr0003_pinned_20261003`,
`calibration_updates_20261003`, `calibration_anchors_20261003`,
`calibration001_20261003`, `calibration0003_20261003`, and
`calibration_curve_20261003`, with corresponding per-seed measurement directories.
Keep failed RPC details in each denominator. Source/image identity, artifact
checksum and exact file hash have different meanings and must all be preserved.
