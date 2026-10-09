# Continual synthetic fuzzer results — 9 October 2026

The new curriculum ran through the real Docker fuzzer, runtime, model-streaming
and parameter-update services. Results were mixed: balanced gained pipeline
specificity while losing recall, efficient changed one semantic false positive
without changing pipeline detection, and quality showed no endpoint change after
one accepted update. These results do not support promoting a new default model.

## Treatment and endpoint

The prospective [protocol](../evaluation/results/continual_fuzzer_20261009/protocol.json)
prescribed 20 manual attempts for each of `privoke-efficient`, `privoke-balanced`
and `privoke-quality`, with checkpoints at 0, 5, 10 and 20. The host Python
controller used the existing gRPC interface; this repository has no FastAPI
fuzzer caller. Training RPC deadlines remained at 300 seconds; inference and
model snapshot deadlines were 120 seconds. Automatic startup
training was disabled in the isolated study; the ordinary periodic deployment
defaults remain available.

Each attempt submitted 192 new rows and 64 replay rows, learning rate 0.003,
maximum tensor delta 0.05, seed sequence 1337–1356, zero text transformations and
the same 16-row publication guard. Replay uses weight 0.35 versus new-row weight
1.0: it is 25% of rows and 10.45% of total example weight. Heads were trainable;
encoder tensors stayed frozen. Each model exposed 1,280 grammar, 1,280 offline
teacher, 1,280 evolved and 1,280 replay rows over its 20 attempts, counting
repetitions and rejected attempts. Every model visited all 672 distinct TRAIN
rows and all 64 replay anchors. Families remain separate from the guard, with
permanent assignments checked by canonical text and ID as well.

Teacher templates are authored offline by a Codex assistant, with exact runtime
model identity unavailable. Labels are `assistant_provisional`; there was no
human adjudication or live external teacher API. Fact-preserving descendants
remain correlated members of their parent families. Mining queried a fixed
128-row sample of TRAIN every five rounds and prioritized at most eight TRAIN
IDs; endpoint errors were never used to select training examples.

Evaluation used the exact development JSONL with SHA-256
`65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095`:
502 rows, 264 annotation-positive, 238 annotation-negative and 465 source groups.
All 12 checkpoints collected semantic and full-pipeline predictions with zero
runtime errors, covering 12,048 endpoint RPC observations. Repeated observations
do not increase the independent sample count. The endpoint measures binary
annotation presence, which differs from the curriculum's contextual privacy
targets. No final examples were opened, and development comparisons remain
exploratory rather than an independent confirmation of contextual-policy quality.

Serving image IDs and effective settings were frozen in the three
`operations-*.json` records and checked before every training request. All
profiles used the same serving images. Storage was isolated under
`privoke-continual-20261009-*`; no production checkpoint was replaced. Exact
source hashes, model versions, checksums, tensor fingerprints and input bytes
are retained with the evidence.

## Before and after 20 attempts

All rates below are percentages; each cell is baseline → final. The summary
also retains precision, F1, accuracy and balanced accuracy without rounding.

| Profile | Accepted / attempted | Pipeline recall | Pipeline specificity | Pipeline false positives | Pipeline false negatives |
| --- | ---: | ---: | ---: | ---: | ---: |
| Efficient | 20 / 20 | 89.39 → 89.39 | 25.21 → 25.21 | 178 → 178 | 28 → 28 |
| Balanced | 20 / 20 | 93.56 → 92.42 | 22.27 → 26.05 | 185 → 176 | 17 → 20 |
| Quality | 1 / 20 | 91.29 → 91.29 | 18.91 → 18.91 | 193 → 193 | 23 → 23 |

| Profile | Semantic recall | Semantic specificity | Semantic F1 | Semantic balanced accuracy |
| --- | ---: | ---: | ---: | ---: |
| Efficient | 59.85 → 59.85 | 25.63 → 26.05 | 52.75 → 52.84 | 42.74 → 42.95 |
| Balanced | 64.02 → 57.95 | 25.21 → 28.57 | 55.32 → 52.13 | 44.61 → 43.26 |
| Quality | 71.97 → 71.97 | 20.17 → 20.17 | 59.01 → 59.01 | 46.07 → 46.07 |

The exact pipeline TP/TN/FP/FN counts were efficient
236/60/178/28 before and after; balanced 247/53/185/17 → 244/62/176/20;
and quality 241/45/193/23 before and after. Balanced pipeline F1 changed
70.98% → 71.35%, accuracy 59.76% → 60.96%, and balanced accuracy
57.91% → 59.24%. Its semantic TP/TN/FP/FN counts changed
169/60/178/95 → 153/68/170/111. The semantic result therefore includes a
substantial recall loss, even though pipeline fusion retains more positives.

Paired percentile bootstrap intervals use 2,000 source-group resamples at seed
1337. Balanced pipeline specificity changed **+3.78 percentage points**
(95% descriptive interval **+1.63 to +6.32**), recall **−1.14 points**
(**−2.57 to 0.00**), and balanced accuracy **+1.32 points**
(**+0.06 to +2.70**). Balanced semantic recall changed **−6.06 points**
(**−8.96 to −3.38**) and specificity **+3.36 points**
(**+0.90 to +6.06**). These exploratory intervals are not adjusted for the
multiple profiles, layers, checkpoints and metrics.

Efficient removed one semantic false positive (+0.42 specificity points;
interval 0.00 to +1.31), with no changed pipeline binary predictions. Quality's
first update changed weights but none of these endpoint predictions; the other
19 attempts were rejected by the unchanged held-out quality gate. Thus quality
received one retained update, not twenty retained updates. In total, 41 of 60
attempts were accepted. All rejected attempts and their messages are preserved.

Full contextual classifications changed on 4 efficient semantic/pipeline rows,
48 balanced semantic rows and 36 balanced pipeline rows; quality had none.
These are changes in outputs, not contextual accuracy measurements: the public
endpoint does not provide sensitivity, visibility and category ground truth.

## Interpretation and limitations

The implemented cursor, replay, provenance and guard mechanisms work in the live
stack. Real head tensors changed in all three profiles, and the encoder remained
unchanged. The evidence shows a specificity/recall tradeoff for balanced and
limited endpoint change for the other profiles. An accepted update is evidence
of passing the fixed publication check; its effect on independent examples is
measured separately here.

This run does not isolate the contribution of grammar, teacher paraphrases,
evolution, replay or mining, because they were combined into one treatment.
It does not establish a benefit over the old sampler: that requires a separately
prespecified matched control arm. The fixed seeded encoder, small provisional
curriculum, conservative learning rate and annotation/contextual task mismatch
are plausible limits, not experimentally isolated causes. Further work should
first adjudicate contextual targets and specify a new matched experiment before
using another endpoint or changing training capacity. Longer training on these
same development outcomes is not justified as a search for a favorable result.

The three controller runs took 140, 160 and 149 seconds respectively, about
7 minutes 29 seconds of combined run time including endpoint measurements and
mining. Docker build and startup time is separate. Manual requests avoided the
hourly scheduler wait without lowering RPC deadlines or weakening the gate.

## Evidence and reproduction

The [independently reconciled summary](../evaluation/results/continual_fuzzer_20261009/summary.json)
contains all checkpoint metrics, paired intervals, changed tensor magnitudes and
durable allocation coverage. Profile directories retain `run-manifest.json`,
every request/response, checkpoints, exact parameter snapshots, mining evidence
and executable `published-artifact.json` exports. `state/` retains SQLite
allocations and updater publication/receipt data. JSON artifact weights are
reconciled with snapshots at the actual float32 serving precision.

```powershell
python evaluation/summarize-continual-fuzzer-study.py --study-root evaluation/results/continual_fuzzer_20261009
```

This archived-evidence audit independently recounts every checkpoint's confusion
matrix and rates, verifies archived hashes, compares float32 artifact weights,
checks frozen encoder tensors, reconciles attempts/acceptances and confirms
TRAIN/replay allocation coverage without reading any corpus or contacting a
service. It writes only the derived `summary.json`. See [evaluation instructions](../evaluation/README.md#continual-synthetic-fuzzer-study)
for a new isolated run. The study services have been stopped, and their named
volumes and exported artifacts retained. Rebuilding the final fuzzer image after
the experiment added the offline preparation resources needed by the production
image's cross-component test; serving code used in the experiment was unchanged.
