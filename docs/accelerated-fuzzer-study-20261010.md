# Accelerated normal batch fuzzer study

Research record **AS-20261010**. Implementation and protocol draft are ready for
review; no study results exist yet. The original user message timestamp is
unavailable. The exact objective is:

> Can you now simulate an accelerated Fuzzer training period so that we can see whether the changes we made had measurable impacts on the LLM layer? This will inform whether we do more iteration on improvement or we can move to discussion and wrap up the paper.

This is new prospective training from fresh checked-in Tiny model bases. The
conversational backend prompt revision is not consumed by Tiny head training, so
these measurements cannot establish its effect. Seeded sampling remains opt-in;
normal defaults remain deterministic sampling, seed zero and replay weight 0.35.
The earlier [63-cell comparison](fuzzer-curriculum-improvement-process-20261009.md)
and its immutable evidence remain separate historical measurements.

The distinct `evaluation/run-accelerated-fuzzer-study.py` supervisor exposes
`prepare`, `execute`, and `audit`, under schema `accelerated-semantic-v1`. It does
not import old trajectories, run offline Adam, promote weights or open protected
final examples. Every endpoint explicitly requests semantic only and asserts the
actual returned successful layer execution. Training uses semantic gradients.

## Prospective budget

Each profile (efficient, balanced, quality) has one shared original-curriculum /
deterministic control and three revised-curriculum / seeded realizations with
sampler seeds 42, 43, 44: twelve trajectories. All use trainer seeds 1337–1504.
The original deterministic path requires sampler seed zero, uses fixed family
ordering, and does not use a replicate seed in numerical computation. Trainer
seed randomness is confined to augmentation, which is disabled. The common
trainer sequence, fresh base/cursors, row order, weights, optimizer and guard are
held fixed. Request and project names identify receipts and storage; they are
not numerical inputs. This supports one shared control per profile. Revised seed
spread is conditional on that control; it is not three independent paired
control realizations or an estimate of control-seed variance.

Each trajectory attempts exactly 168 cycles of 32 rows: 24 TRAIN and eight
replay, with four new rows per role/class stratum and four replay per class.
The common publication guard contains 16 rows. Learning rate is 0.003, gradient
clamp 0.05, replay weight 0.35, replay fraction 0.25, with no transformations or
mining. Known rejections consume allocations and count toward attempts.

The total is 2,016 attempts and 64,512 allocated presentations (48,384 new,
16,128 replay). Per trajectory, 5,376 presentations are only 5% more than the
previous 20 × 256 schedule's 5,120. This tests repeated normal-size batches and
allocation epochs, rather than a substantial data-dose increase. Hourly waits
are compressed; 168 requests approximate a scheduled week excluding the startup
request. This does not simulate actual aging, natural prompt arrival or an
evolving production corpus. Accepted-update cache waits remain necessary.

Checkpoints 0, 24, 72 and 168 measure the same 502 annotation-presence development
rows, 64 assistant-provisional contextual rows and 48 fixtures: 29,472 endpoint
observations overall. Contextual controls and disclosures each contain 32 rows;
four hard positive mechanisms are also reported separately. Forty-one fixtures
are quantitative and seven remain descriptive. These endpoints are kept out of
training, replay, guard and mining. Annotation-presence recall/specificity are a
separate task from contextual sensitivity/visibility/category/action truth.

## Fixed decision rules

Only attempt 168 determines the iteration decision. Checkpoints 24 and 72 are
descriptive; no favorable checkpoint selection or result-dependent stopping is
permitted. Every prediction change is counted, including changes whose aggregate
effects cancel.

A revised seed is promising if its final contextual joint exact accuracy
strictly exceeds both its own baseline and the shared control's final result;
annotation recall and the disclosure subgroup's joint, sensitivity exact,
visibility exact, category-set exact and action accuracy are no lower than
either reference; and no new/worsened quantitative fixture restriction or
incorrect action occurs against either reference. Disclosure membership is
target sensitivity other than S0, rather than the guard's category-aware sensitive
definition. A profile is promising when at least two of its three revised
realizations pass and none of the three adds fixture harm against its own
baseline. A third harmful realization vetoes a promising profile outcome.

Reports separately expose specificity/contextual gains with recall, disclosure
or fixture losses as tradeoffs. The `no_specificity_or_context_joint_gain` flag
means neither of those two metrics improved; recall, disclosure components or
actions may still improve. Zero accepted publications in the final 24 attempts
is a separate continuing-rejection flag.
These are engineering iteration criteria with descriptive scenario-family
bootstrap intervals, not statistical significance claims. The separate legacy
qualification condition remains recall ≥90%, strict specificity improvement,
no contextual-joint decline and no fixture harm versus own baseline; no model is
automatically promoted even if it qualifies.

Each revised seed also has an explicit final contrast against its profile's
single shared control: annotation recall/specificity, contextual joint and all
components, the five disclosure components, casewise fixture harms and exact
prediction changes. Reports verify identical baseline predictions and model
identities, compute each arm's change and their difference, and verify that the
difference in changes equals the final contrast. Paired development intervals
resample the 465 source groups; contextual intervals resample declared scenario
families, using the existing 2,000-draw bootstrap and seed 10102026. These describe
scenario sampling conditional on the same shared control; the three contrasts
do not create three independent controls or a control-seed variance estimate.

## Evidence and execution contract

Preparation requires committed computation sources and hashes exact source,
resources, input files and five immutable serving images. Copied fuzzer/updater/
runtime source is attested inside the images. Both reviewed curricula and their
shared guard, replay and assessment bytes are validated, including exclusions
against the opaque protected-key index and pinned development rows. Static pools
may be reused after exact verification, but every trajectory starts with fresh
storage, cursors and model artifact bytes. Existing/frozen experiments are never
resumed or rewritten.

Each trajectory owns a unique Compose project and five named volumes. Compose
uses `docker-compose.yml`, `evaluation/compose.tests.yml`,
`evaluation/compose.continual-fuzzer-study.yml` and an immutable-image override.
Services run sequentially on the documented ports. Automatic requests are
disabled. An optional controller checkpoint callback collects contextual and
fixture predictions at the exact deployed identity before the next attempt.
Interrupted runs retain their exact pending protobuf request; altered live
identities, inputs, settings or checkpoint commitments abort recovery.

An opt-in `study_gate_diagnostics=v1` request field writes one atomic, prompt-free
JSON record per request into the existing fuzzer dump volume before the unchanged
guard rejects or submits its candidate. It records the protobuf request hash,
base version, canonical base/candidate parameter fingerprints, baseline/candidate
held-out recall, specificity and exact match, training exact match, candidate
safety regression, configured floor and all failed guard predicates. Diagnostic
request hashes and seeded reservation fingerprints are distinct commitments.
Retries reuse identical records; conflicting records fail closed. Prior accepted
receipt replay returns without recomputing a diagnostic. Ordinary requests do not
write these records.

Passing the guard and successful publication are separate facts. Final auditing
requires diagnostics for every accepted and rejected attempt, independently
reconstructs predicates, reconciles candidate fingerprints with accepted payloads,
and fails on missing records. The safety metric concerns target-capped severity
and policy-action regression in the synthetic guard, separately from assessment
casewise harms. Candidate fingerprints commit identities; rejected tensors and
independent recomputation of candidate metrics are not retained, a remaining
limitation. Complete snapshots verify deployed encoder immutability every round.
SQLite allocations and cursor consumption, accepted publication payloads and
durable receipts, endpoint truth/identity/layer contracts, archives and fixed
decision rules are audited independently of service return wrappers.

The manager must accept the implementation before source commit, Docker preflight,
source-overlay builds and protocol freeze. No live study starts during this
implementation milestone. Build only task-owned fuzzer/updater/runtime overlays
from inspected immutable parents; preserve normal image tags and unrelated
resources. After freeze, use the existing evaluation interpreter:

```powershell
& evaluation/.venv/Scripts/python.exe evaluation/run-accelerated-fuzzer-study.py prepare --study-id privoke-accelerated-20261010 --output evaluation/results/accelerated_fuzzer_20261010 --images evaluation/results/accelerated_fuzzer_20261010_build/images.json --current evaluation/results/curriculum_improvement_20261009_v1/curricula/current/manifest.json --revised evaluation/results/curriculum_improvement_20261009_v1/curricula/revised/manifest.json
& evaluation/.venv/Scripts/python.exe evaluation/run-accelerated-fuzzer-study.py execute --output evaluation/results/accelerated_fuzzer_20261010 --cell efficient-control
& evaluation/.venv/Scripts/python.exe evaluation/run-accelerated-fuzzer-study.py execute --output evaluation/results/accelerated_fuzzer_20261010
& evaluation/.venv/Scripts/python.exe evaluation/run-accelerated-fuzzer-study.py audit --output evaluation/results/accelerated_fuzzer_20261010
```

These are prospective commands; image inventory/build and protocol creation have
not yet occurred. The first complete prespecified trajectory supplies a runtime
benchmark and remains included. It cannot alter outcome budgets. Stop services
after each trajectory, preserve raw archives/volumes until acceptance, and clean
only verified task-owned resources afterward. Raw prompts, predictions, weights,
SQLite state and diagnostics remain in ignored local results; any later safe
publication must link its own execution source, freeze, audit and limitations.
