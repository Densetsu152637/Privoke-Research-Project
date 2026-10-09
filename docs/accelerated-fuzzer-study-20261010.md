# Accelerated normal batch fuzzer study

Research record **AS-20261010**. All twelve prospective trajectories and the
full raw audit completed on 10 October 2026 in Australia/Sydney (9 October UTC).
Training changed predictions, but none of nine revised realizations met the
prespecified promising criterion, none of three profiles passed, and none of
twelve cells qualified. The evidence supports closing this experiment and
discussing its negative results and tradeoffs in the paper. It does not establish
deployment readiness or the effect of the conversational prompt revision.
The original user message timestamp is unavailable. The exact objective is:

> Can you now simulate an accelerated Fuzzer training period so that we can see whether the changes we made had measurable impacts on the LLM layer? This will inform whether we do more iteration on improvement or we can move to discussion and wrap up the paper.

This was new prospective training from fresh checked-in Tiny model bases. The
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

## Frozen prospective budget

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

The implementation was reviewed before execution source
`f2df530353a66de657a9a1adb8699021b072e418` was committed. Preparation froze the
protocol at `2026-10-09T16:39:58.404715+00:00`, SHA256
`39cbf3f7d88ed3b0260f97b41ebe3c41bd8b0e09376bf3e1488dba600da0aef3`.
Three task-owned fuzzer/updater/runtime source overlays were built from inspected
immutable parents and their copied sources attested; streaming and telemetry
used existing immutable images. Normal image tags and unrelated resources were
preserved. These were the execution commands, using the existing interpreter and
process-local import paths:

```powershell
$env:PYTHONPATH='evaluation;shared/python;extension/client-runtime/generated'
$env:PYTHONDONTWRITEBYTECODE='1'
& evaluation/.venv/Scripts/python.exe evaluation/run-accelerated-fuzzer-study.py prepare --study-id privoke-accelerated-20261010 --output evaluation/results/accelerated_fuzzer_20261010 --images evaluation/results/accelerated_fuzzer_20261010_build/images.json --current evaluation/results/curriculum_improvement_20261009_v1/curricula/current/manifest.json --revised evaluation/results/curriculum_improvement_20261009_v1/curricula/revised/manifest.json
& evaluation/.venv/Scripts/python.exe evaluation/run-accelerated-fuzzer-study.py execute --output evaluation/results/accelerated_fuzzer_20261010 --cell efficient-control
& evaluation/.venv/Scripts/python.exe evaluation/run-accelerated-fuzzer-study.py execute --output evaluation/results/accelerated_fuzzer_20261010
& evaluation/.venv/Scripts/python.exe evaluation/run-accelerated-fuzzer-study.py audit --output evaluation/results/accelerated_fuzzer_20261010
```

The first complete prespecified trajectory remained included and took 519.225
seconds from cell start through archive capture. This includes startup,
measurements, inspections, snapshots and training requests, and excludes the
subsequent service stop; it is not isolated model compute time. Its audit was
accepted before the other eleven trajectories ran. No budget changed in response
to results. All executions and the full raw audit exited successfully, and their
launcher and Python processes were confirmed absent. Services were stopped after
each trajectory. At accepted handoff, 72 stopped task containers, 60 volumes,
twelve empty networks and three overlay images remained available for audit;
cleanup has separate acceptance. No model was promoted.

## Results and controlled package effects

All 2,016 attempted requests resolved: 1,270 accepted publications with matching
durable receipts and 746 guard rejections. Every attempt has numeric gate
diagnostics and an allocation receipt, including rejected attempts. The audit
reconciled 64,512 allocated presentations and all 29,472 semantic endpoint
observations. Each trajectory covered 736 distinct training/replay rows in 44
families, with a maximum of 21 exposures to one row. These are repeated exposures
to a fixed pool, not 64,512 independent examples.

The table reports final annotation-presence recall and clean specificity, and
contextual joint exact matches out of 64. Percentages are rounded here only; the
[aggregate evidence](evidence/accelerated-fuzzer-20261010/README.md) preserves
every numeric value without rounding, all checkpoints, all component and
subgroup metrics, paired intervals and fixture harm counts.

| Profile and realization | Accepted | Rejected | Recall % | Specificity % | Context joint / 64 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Efficient shared control | 162 | 6 | 59.09 | 27.73 | 9 |
| Efficient revised 42 | 147 | 21 | 51.52 | 32.35 | 9 |
| Efficient revised 43 | 145 | 23 | 51.89 | 32.35 | 9 |
| Efficient revised 44 | 143 | 25 | 51.89 | 32.35 | 9 |
| Balanced shared control | 168 | 0 | 41.67 | 40.34 | 17 |
| Balanced revised 42 | 165 | 3 | 47.73 | 35.29 | 14 |
| Balanced revised 43 | 167 | 1 | 47.35 | 35.29 | 14 |
| Balanced revised 44 | 166 | 2 | 47.73 | 35.29 | 14 |
| Quality shared control | 1 | 167 | 71.59 | 20.17 | 8 |
| Quality revised 42 | 2 | 166 | 71.59 | 20.17 | 8 |
| Quality revised 43 | 2 | 166 | 71.59 | 20.17 | 8 |
| Quality revised 44 | 2 | 166 | 71.59 | 20.17 | 8 |

Efficient revised package gained 4.62 percentage points in specificity against
its shared control, with 7.20–7.58 points less annotation recall and no contextual
joint gain. Its baseline recall was 59.85%, so the final revised recall loss was
7.95–8.33 points. Balanced revised package retained 5.68–6.06 points more recall
than its control, but lost 5.04 points of specificity and 4.69 points of contextual
joint accuracy against that control. Both balanced arms lost recall against their
64.02% baseline. These are package tradeoffs, not improvements across the tasks.

Quality reached a publication plateau: the control accepted one update and each
revised realization accepted two, then all four accepted zero updates in their
final 24 attempts. Final recall, specificity and contextual joint metrics matched
across the four cells. Exact prediction changes still differed: quality revised
43 and 44 each changed four development predictions against baseline, compared
with three for control and revised 42. Equal headline rates therefore do not mean
identical predictions. Across all attempts, safety regression failed in 734
diagnostics, held-out recall declined in 665, exact match declined in ten, and
specificity declined in six; these overlapping predicate counts must not be
summed as separate rejections. No attempt failed the training exact-match floor.

All disclosure subgroup category-set exact and joint accuracies remained zero
out of 32 rows at every checkpoint. Efficient revised runs also lost disclosure
sensitivity and action accuracy against both references; balanced revised runs
lost disclosure sensitivity and visibility accuracy against the shared control.
Every profile had at least one revised realization with new quantitative fixture
harm against baseline, activating the profile veto. Quality revised 43 avoided
new fixture harm against its own baseline but still failed the other required
criteria. No revised realization passed the complete engineering criterion.

The paired final package effects verify identical baseline predictions and
identities, retain both arms' changes, and show that their difference equals the
final contrast. The source-group/family bootstrap intervals remain descriptive
and conditional on one shared control per profile. They do not create independent
control replicas or demonstrate generalization. The revised package combines
curriculum wording, visibility/category exposure and allocation changes, so this
experiment cannot isolate their individual effects. Contextual targets remain
assistant-provisional and archetypes overlap. The conversational backend prompt
was not consumed by these Tiny head updates.

Repeating this schedule does not supply evidence of a promising package under
the frozen rule. The supported next step is to wrap the current experiment and
explain its measurable tradeoffs and plateau in the paper. Further implementation
work would need a distinct hypothesis and fresh evaluation; these results do not
justify promotion or a broad claim of LLM-layer readiness.

## Public evidence and reproduction

The accepted raw summary SHA256 is
`66c419b4e3f755242ee7ac42dde5df84d40e5f5ce5ab1f255a1b0d2510716fc8`;
the raw audit SHA256 is
`10c58eef05a5f9d90cd3a6419e6f080aa151f2e219bdaf3508a8a801ae00476f`.
The [publication manifest](evidence/accelerated-fuzzer-20261010/publication-hashes.json)
separately binds the aggregate public files and projection script. The unchanged
audit receipt binds the raw summary, not the public summary projection.

Explicit structural allowlists retain all numeric metrics, counts, predicates,
decisions, controlled contrasts and uncertainty. They omit example identifiers
including nested `changed_ids`, per-attempt candidate/base fingerprints and
version names, project storage names and local input paths. Copied-source names
are repository-relative. The standalone [reproduction helper](evidence/accelerated-fuzzer-20261010/reproduce.py)
hash-verifies the three raw inputs and three accepted handoff receipts before
regeneration; it performs no RPCs, fitting or raw archive mutation. Raw prompts,
predictions, weights, SQLite state, diagnostics and operational logs remain in
ignored local results. Public aggregates alone cannot repeat the complete raw
archive audit.
