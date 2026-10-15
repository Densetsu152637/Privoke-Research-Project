# Iterative semantic Tiny fuzzer training

The goal is to improve the learned contextual models through bounded fuzzer
iterations, assess whether progress has plateaued, change the training method
when justified, and begin the next iteration with a fresh manager. The exact
retained user request was:

> /goal Iteratively train the models using the fuzzer, and when improvements plateu improve the training method. Your workflow should look like this: 1. spawn manager subagent for iteration (reasonable amount of iterations, like for an hour or two) 2. get manager subagent to analyse run and whether it should just continue iterating or not (if continue go back to step 1) 3. improve the training by implementing a new feature/optimisation/improvement into the training process 4. start a fresh workflow with a new manager subagent

The workflow keeps semantic-only selection explicit and checks actual returned
execution for training, base held-out and candidate held-out phases. Each
iteration records its protocol, fixed gates, settings, identities, stopping
reason and evidence before the manager hands off a stable result. A fresh
manager starts after a method change. No model is promoted merely because an
update passes the internal publication guard.

## First block: IM01

The local retained record is
[`evaluation/results/iterative_fuzzer_20261011/block01/result.json`](../evaluation/results/iterative_fuzzer_20261011/block01/result.json).
This ignored evidence path is available in the study workspace and is not a
distributed public artifact. The accepted block used source revision
`250780ae13fd2687c7deae1b99a4c065d6d6ae64` across balanced, efficient and quality
profiles. All 384 actual fits had independently audited semantic-only execution:
193 HEAD and 191 FULL. There were 164 accepted HEAD publications, 29 rejected
HEAD candidates and 191 rejected FULL candidates. Thus every FULL candidate was
rejected, and no learned candidate qualified.

Root accepted early plateau stops rather than forcing the proposed hour-or-two
window. Summed trajectory wall time was approximately 19.47 minutes, including
RPC fitting, checkpoint inference and operational recovery; setup and review
were outside that sum. This is neither an hour of training nor a measurement of
compute time. Budgets differed between profiles, so these runs do not establish
a matched-budget causal comparison.

Every FULL candidate lost guard clean specificity/exactness, and each FULL
stage reached the `0.05` clamp. All scored non-S0 joint predictions remained
incorrect at baseline and learned endpoints. All endpoints reuse development
data with provisional labels; the guard is small and reused, and shared
semantic archetypes limit generalization claims. Accepted HEAD updates and
clean-only gains do not establish disclosure quality. No protected final was
accessed, and historical full-pipeline measurements keep their original scope.

## Next method: opt-in FULL-stage rate

`FUZZ_UNDERLYING_TRAINING_LEARNING_RATE` now optionally selects the learning rate
for `RunUnderlyingTrainingCycle` / `ComputeUnderlyingModelGradients`. It affects
embeddings, all encoder blocks **and task heads together**. It is not an
encoder-only setting. When unset, FULL falls back to
`FUZZ_TRAINING_LEARNING_RATE`; its existing default is `0.03`. HEAD and presence
keep the existing rate. Both rate settings require finite positive values.

For the proposed matched comparison, configure the fuzzer process with:

```text
FUZZ_TRAINING_LEARNING_RATE=0.03
FUZZ_UNDERLYING_TRAINING_LEARNING_RATE=0.003
FUZZ_TRAINING_MAX_GRADIENT=0.05
```

The control arm uses FULL `0.03`, with HEAD `0.03` in both arms. A custom Compose
override must explicitly put these values in the fuzzer service's `environment`;
host shell settings alone are not forwarded. Deployment defaults are unchanged.
Start from the original baselines with matched seeds and batches, preserve the
objective, tensor inventory and publication gates, and assert the selected rate
in each retained runtime request and response metadata. The runtime recomputes
gradients using the selected rate before its existing float32/clipping path;
the fuzzer never rescales already-clipped transported deltas.

The effective rate is part of the existing settings fingerprint before durable
reservation and receipt lookup for both procedural and curriculum FULL
requests. Unset and explicitly equal rates retain compatible fingerprints.
Changing the effective rate for an already reserved request identity fails
before lookup or fitting. New arms need fresh request identities; uncertain
requests must recover under their original settings. No schema migration is
needed, and previous `0.03` receipts cannot silently become `0.003` evidence.

The smaller rate is a controlled hypothesis, not a demonstrated quality gain.
This implementation was checked mechanically without new fits, model updates
or downloads. The next fresh-manager study must assess candidate admission and
actual quality separately. See [fuzzer configuration](services/fuzzer.md) and
[FULL training methods](fuzzer-underlying-training-20261010.md).


## Second block: IM02 matched FULL rates

The retained local result is
[`evaluation/results/iterative_fuzzer_20261011/block02/result.json`](../evaluation/results/iterative_fuzzer_20261011/block02/result.json),
with a compact `summary.json` beside it. These ignored records remain available
in the study workspace. Root accepted the frozen protocol before fitting;
final study acceptance remains with root. The six fixed cells started from
the immutable original balanced, efficient and quality baselines. Each arm
executed the same 100 planned batches, alternating 50 HEAD and 50 FULL stages.
HEAD used `0.03` in both arms; FULL used `0.003` or control `0.03`, with the
existing `0.05` clamp, objective and gates. Actual serialized requests, returned
rate metadata, semantic-only execution and exact 64/16/16 training/base-guard/
candidate-guard records were asserted for all 600 fits.

| Profile | HEAD accepted/rejected per arm | FULL accepted/rejected per arm | Validation joint baseline/best/final (of 64) | Selected assessment harms |
| --- | --- | --- | --- | --- |
| balanced | 48/2 | 0/50 | 10/10/7 | 0 (baseline selected) |
| efficient | 37/13 | 0/50 | 9/9/5 | 0 (baseline selected) |
| quality | 43/7 | 0/50 | 8/9/6 | 5 |

Across all cells, 256 HEAD proposals were published, 44 HEAD proposals were
rejected and all 300 FULL proposals were rejected. There were no fitting
admission or transport errors. The low/control arms had identical starting
identities, all 100 published-stage parameter fingerprints, selected parameters
and final parameters within each profile. All 50 paired FULL candidate
fingerprints differed per profile, confirming that the rate changed proposed
updates. FULL fits reaching the clamp fell from 50/50 in each control to 1/50
balanced, 2/50 efficient and 7/50 quality at `0.003` (10/150 versus 150/150
overall). This mechanical stability change produced no FULL publication or
qualified quality improvement.

Selection used the fixed validation and safety sets before assessment scoring.
Balanced and efficient retained their original baselines. Quality selected a
limited clean-only validation gain at slot 10; its five new target-capped
severity/action harms on the broader reused assessment vetoed qualification.
Assessment joint counts baseline/selected/final were 63/63/17, 39/39/25 and
43/43/45 of 320 for balanced, efficient and quality respectively. Final
assessment harms were 0, 14 and 26. Every baseline, selected and final endpoint
had zero non-S0 joint successes on validation and assessment. Quality's final
total joint increase therefore does not establish disclosure quality. No
candidate qualified, and all six fixed trajectories plateaued. Summed cell
trajectory wall time was 27.49 minutes including RPCs and checkpoint inference;
it is not a compute-time measurement or an hour of training.

Existing captured predictions also show separate category and visibility
bottlenecks. On the 32 non-S0 validation rows, final sensitivity/visibility/
exact-category-set correct counts were 18/6/0 balanced, 19/6/0 efficient and
10/6/1 quality, identical across paired arms. Positive/negative category
balances and true pre-update FULL `supervised_objective_loss` are retained in
the result; `average_loss` is a classification-distance diagnostic. Neither
diagnostic establishes held-out quality or monotonic descent.

The current bundled procedural inventory has 24 seeds: S0=11, S1=0, S2=6 and
S3=7, with positive labels for 8 of 10 formal categories and none for SEXUAL or
CHILD. Of 13 sensitive seeds, 10 use PU (UNKNOWN), and one each uses P2, P3 or
P4; none uses P0 or P1. Actual training exposures in each 6,400-row cell also
contained zero S1, SEXUAL or CHILD positives. S1 counts as sensitive under the
binary predicate. These omissions concern current fuzzer TRAIN exposure;
the earlier baseline bootstrap contains all 10 categories. Source locators
and corroboration are retained in `block02/coverage-record.json`, including
`prompt_generation/defaults.py`, `loader.py`, `generator.py`, the shared
classification predicate and `extension/client-runtime/src/LLM/prompt.py`.
The coverage omissions are confirmed, but their causal contribution to all
failures has not been isolated.

The manager recommends a separately frozen opt-in taxonomy coverage inventory
and 32-original sampler with formal category/sensitivity exposure, explicit
audience contrasts, fixed family partitions, fail-closed quota checks and
durable dataset/settings identities. Keep rates, objective, thresholds,
baselines and gates fixed for that comparison and preserve the existing
default. Root's planned source is historical prepared-v3 TRAIN material with
provisional labels and correlated rows; a guard partition from it is not
globally untouched confirmation. No next-method implementation or quality
gain is claimed by this block.

All endpoints are historically reused provisional development evidence. The
100 matched batches contain 348 distinct original and 567 distinct augmented
normalized texts; each 64-row batch has only 23–42 unique texts. Exact endpoint
exclusion does not prove semantic-family independence for procedural prompts
without source groups. There were no independent repeated schedules, protected
final access, cloud use or model promotion.

One supplemental audit assumed a multi-block tensor naming scheme and stopped
after the third completed cell. Root approved an architecture-independent
replacement that checks the exact FULL tensor inventory against the before
snapshot. The failed log, old audit and precise correction are preserved in
`block02/audit-recovery.json` and `audit-recovery.patch`. All affected audits
were rerun successfully; no fit, publication, request or volume was replayed
or reset. Six independent candidate/identity audits and 612 closed-snapshot
SQLite integrity checks passed. Training sources stayed frozen throughout;
this documentation append occurred after every trial stopped. All 30 owned
containers are stopped, with 30 volumes and six networks retained for root's
archive coverage review and later cleanup. IM01 resources were untouched.

## Next method: opt-in taxonomy coverage (TC01/TC02)

After IM02's matched rate control produced no qualifier, root accepted the
design and implementation of `taxonomy_coverage_v1`. It preserves the default
and historical contextual 256-row sampling contracts. Its hypothesis is that
explicit training exposure is useful to test; no fit or quality measurement
was performed during feature implementation.

The prepared source is exclusively
`evaluation/results/semantic_pretrained_20261010/prepared-v3/train.jsonl`,
SHA256 `ceeb394020f6c5de6e1d6d4737c7c7c6d3b6eae8122391660b9986325a3f7ece`.
Its reviewed renderer is `evaluation/privoke_eval/pretrained_context_resource.py`,
SHA256 `ee2c6310a759ea5162bd2cd8a46518f883b3bf2cf8dc825071411d9deed2d62e`.
Forty source families contain 640 previously authored TRAIN rows. The new
canonical release is retained under the ignored local evidence directory
`evaluation/results/iterative_fuzzer_20261011/taxonomy-coverage/release/taxonomy-coverage-v1.json`,
SHA256 `3b777f328a8e08140ee964facbd559c694673336b4c5655320befdd84aef66e0`.
Its companion provenance records `fit_release=false`; historical resource review
does not grant permission to fit this new study. Root must accept its new
source/data/protocol commitments before a fresh manager starts a comparison.

Within each primary category, sorted source-family IDs assign the first two to
permanent TRAIN and the other two to permanent guard, yielding twenty of each.
A seed selects one TRAIN family per category, preserving the full source
targets. Twenty actual-disclosure rows use these audience pairs:

| Primary category | Sensitive audience slots |
| --- | --- |
| HEALTH | P0, P3 |
| POLITICS | P0, P4 |
| RELIGION | P1, P3 |
| CRIMINAL | P2, P4 |
| FINANCIAL | P0, P3 |
| SEXUAL | P0, P4 |
| CHILD | P1, P3 |
| LOCATION | P2, P4 |
| IDENTITY | P2, PU |
| THIRD_PARTY | P2, PU |

Eight fiction controls from the first eight listed families use
P0/P1/P2/P3/P4/PU/P0/PU, and four mild controls from the first four use
P1/P1/PU/PU. The 32 original texts are distinct and come from ten correlated
families: S0=8, S1=4, S2=6 and S3=14, with exactly four sensitive rows per
visibility label. Each category has at least two positives. FINANCIAL has four;
THIRD_PARTY has four or six because the second eligible SEXUAL family describes
a relationship involving another person. The original TC01 first-family witness
observed four THIRD_PARTY labels and did not establish that count for both family
choices. Root approved this narrow correction: preserve both families and every
full category set, then double actual category counts after augmentation.

The alternating sixteen-row guard uses sixteen distinct permanent guard
families, eight S0/two S1/two S2/four S3, with all six sensitive visibility labels
represented. Its eight sensitive rows do not guarantee ten-category coverage.
One unchanged invariance transform produces 64 actual training rows, allowing
identity duplicates. The trainer audits the actual list immediately before the
semantic RPC: source text/targets/provenance, slots, weights, doubled exposure
and source/normalized-text isolation. HEAD and FULL both bind the snapshotted
release bytes, plan/version, resolved request, effective settings and semantic
execution contract before durable reservation and receipt lookup. Missing
durability, unknown labels, conflicting packed targets, unsupported release or
unmet quotas fail closed. Defaults and legacy fingerprints remain unchanged.

Preparation's first host attempt failed because host Python lacked `grpc`.
Automatic approval review rejected a proposed Docker preparation command that
would open assessment records to derive exclusion keys. That action was not
retried. Root accepted a distinct safer preparation using existing byte-pinned
opaque assessment and safety membership artifacts plus an explicitly authorized
64-row development-validation membership check. It never dereferences assessment
or safety record paths. Protected-final content was not opened. The new release
passed protected, endpoint and all-current-transform exclusion checks; its
provenance retains hashes and zero overlap counts without cases or labels.

The Linux dependency image
`sha256:2014ee14dfd4f7385eb9338ae877c267b6ad6bdc46c62e31d853fd4f9ae40739`
ran with read-only source, no network and temporary filesystem isolation.
The initial focused check passed seven of eight tests; one test incorrectly
compared separate classification objects by identity. Comparing packed labels
and the remaining inventory fields corrected that test. Ten focused tests then
passed. The integrated full suite, including an additional opaque-membership
test, passed all **106 tests**. The production release-only witness selected
and audited seeds 0/1/2/42/43/44/1337/2026, exposing all twenty eligible TRAIN
families across those seeds and both SEXUAL families, with zero fits, inference
or RPC calls. Logs, exact commands and hashes are retained in the taxonomy
evidence directory. These mechanical checks do not establish model quality.

Provisional targets, explicit shared framing and repeated family descendants
remain limitations. Permanent partitioning protects future mode trajectories;
its guard was historical TRAIN elsewhere and is not globally untouched. The
original IM01 seeds trace to the September `v0.3.0` fixed bootstrap, whose source
already contains all ten categories. No coverage omission is attributed to all
model history, and the causal contribution of current fuzzer omissions remains
unmeasured. A fresh comparison must fix rates/objectives/gates across arms and
preregister its budgets and selection criteria before fitting.

After the historical resource-retention statement above, root accepted CR01
cleanup: 2,989 members/153,496,230 bytes archived from 36 nonempty volumes,
nine runtime volumes confirmed empty, and 45 stopped containers/45 volumes/nine
networks removed. No images, workspace files, fits, inference or restarts were
changed by cleanup. `taxonomy-coverage/cleanup.json` records the accepted proof
digest and independent root postcheck; no iteration resources remain retained.

## IM03: accepted matched coverage block

Root accepted all six fixed IM03 cells after 600 actual fits: 300 HEAD and 300
FULL, comparing default and coverage sampling across the three model profiles.
HEAD published 143 updates and FULL one; 456 attempts failed unchanged quality
gates. Every cell plateaued and no candidate qualified for disclosure improvement;
all non-S0 disclosure joint correctness remained zero. Quality-coverage FULL
clipped coordinates in all 50 attempts, unlike the low-clamping balanced arms
examined in PC07. The evidence therefore supports a model-specific clipping
alternative, not a global absence of clipping. Accepted aggregate evidence is
`block03/result.json` (SHA256
`6b3ae4c4c6d7e994c3e2cf6f22f6ebfc8c3e83a7b1d31854cd7dc827d3f2302e`),
`block03/summary.json` (SHA256
`7b7d2227307e5eaac323259b4ebc5015b75f6a112289139435303a0edccd076f`)
and `block03/handoff.json` (SHA256
`16e252033c0f2ab427783ac3a56495065e293cbdf4f1c5726d26c9af21414d5d`).
Root independently checked 67 critical hashes with zero mismatches and confirmed
all iteration containers, volumes and networks absent. No model was promoted.

## OP01/OP02: explicit objective policy and passive TRAIN diagnostics

After the plateau, root accepted the PC07 hypothesis as a new controlled method:
activate the existing `class_balanced_contextual_v1` objective against legacy
weighting on identical coverage batches. Clean and sensitive target classes each
receive half the objective mass, preserving relative weights within each class.
Summed category BCE, one update, rates, clipping, targets and publication gates
remain fixed. Mean-category loss, decision margins and multi-step SGD are not
simultaneously enabled. This feature's effect on quality is unmeasured; historical
full-pipeline objective studies do not establish semantic-only improvement.

OP02 implements explicit artifact preparation/provenance, optional local caller
expectations and passive before/candidate TRAIN diagnostics. The independent
artifact flag `contextual_training_diagnostics_policy=train_before_candidate_v1`
requires explicit targets, both target-sensitive strata and absent optimizer
metadata before gradient computation. The flag's absence retains legacy
one-class behavior and performs no additional diagnostic evaluation. A metadata-
only flag change changes the runtime cache contract. The caller's expectations
bind into durable HEAD/FULL admission before terminal receipt lookup; actual
returned objective/diagnostic policy is checked before publication. Prepared
checksums identify preparation; subsequent stages use their actual base identity.
This assumes frozen single-writer artifacts and does not add an atomic lock
against concurrent metadata-only replacement.

Diagnostics reuse runtime-state loss and classification helpers on normalized
actual TRAIN rows and the exact existing clipped float32 transported candidate.
They report weighted task losses/total, unweighted joint/head/category-set
exactness and clean/sensitive decision rates, counts/fingerprints, successful
diagnostic semantic phases and strict raw clipping counts/maxima. They do not
measure causal per-task gradient contributions. Three existing successful
semantic training/base-guard/candidate-guard execution records remain mandatory.
Immutable raw attempt evidence survives admission failure; transport-unknown
outcomes remain unknown rather than being counted as zero work.

The combined coverage/class-balanced metadata exceeds the updater's unchanged
64-entry limit. Only the opt-in path compacts secondary sampling/weight audit
fields after verifying complete durable unprojected evidence; gate, receipt,
policy and identity fields remain explicit. Actual offline 64 TRAIN/16 guard
fixtures demonstrated 70→48 HEAD and 71→49 FULL publication entries, with a
maximum value of 1356 bytes within the unchanged 2048-byte limit. These fixture
computations are implementation checks, not a new training experiment or a
quality result. Evidence and the accepted design are retained under
`evaluation/results/iterative_fuzzer_20261011/objective-policy/`; a fresh manager
and separately accepted protocol are required before the next training block.


## FA06: fixed FULL Adam integration mechanics

The subsequent fixed experimental FULL method is versioned separately as
`full_projected_adam64_v1`, with `candidate_train_exact_eligibility_v1` selecting
candidate TRAIN exact only for authenticated actual FULL execution. The same
strict configured floor and every held-out predicate remain unchanged. It uses
64 cold CPU encoder/head Adam steps, the SUM decision-margin objective with
coefficient one, rate 0.003, beta values 0.9/0.999, epsilon 1e-8, float64 moments,
globally normalized negative directions with denominator one, and a cumulative
inward-float32 delta cap of 0.05 against an immutable base. Each direction
reconstructs the exact transported candidate; original BASE remains untouched
because zero-delta round8 transport is not identity. HEAD is explicitly dormant
and retains its prior numerical result. Startup OMP/MKL and actual Torch threads
must all be one; NumPy BASE, final TRAIN and guards are explicit CPU routes.

FA06 integration evidence is retained in
`evaluation/results/iterative_fuzzer_20261011/full-adam-method-closure/`.
Stored-gradient arithmetic reproduced 192 saved candidate fingerprints and
three final identities after selected input hashes matched the accepted FA04
manifest. It performed no encoder/head forward, loss, gradient or refit calls.
The sole new two-row FULL fit took about 5.03 seconds, completed 64 directions
and preserved the preceding synthetic deltas/metrics. Candidate TRAIN exact was
1.0, but held-out safety regression was 0.5 and remained rejected. This is neither
64-row runtime timing nor model qualification/generalization evidence.

The new FULL policy's publication copy omits its validated detailed trace while
retaining the immutable raw response. Exact outgoing weight strings move into
`full_adam_weight_audit_v1.fields`; the TC02-only exact fourteen sampling strings
move into `full_adam_taxonomy_audit_v1.fields`. Each canonical JSON summary has
`schema=1`. Consumers must unpack these named fields without converting or
rounding values, and may separately parse count-map JSON strings. Strategy,
taxonomy dataset hash, optimizer configuration, compact trace/work counts,
selected-metric/strict-threshold guard summary and bound evidence digest remain
visible. Role-quota constructors emitted 64 entries; TC02 constructor packing
is verified separately against the accepted release. Both are manufactured
success-boundary packing witnesses using mocked numerical payloads, separate
from the unchanged observed rejection. Missing/tampered evidence or summary
collisions fail closed. Default/HEAD publication keys stay unchanged.

## IM04: accepted objective-policy comparison

Root accepted all six fixed IM04 cells after 600 actual fits: 300 HEAD and 300
FULL. HEAD published 118 updates and rejected 182; FULL rejected all 300.
Every cell selected its baseline and plateaued, with zero qualifying disclosure
gain and zero non-S0 joint correctness. Within each arm, all 300 HEAD candidates
reduced TRAIN objective; 297/300 FULL candidates increased it (three exceptions
in efficient-classbalanced). Absolute weighted losses are not compared across
objective policies. All 200 quality-profile primary pre-update TRAIN exact rates
were zero; this was a TRAIN gate floor, not the primary held-out guard failure.
Candidate TRAIN exactness became positive only in two class-balanced quality
FULL attempts, with a maximum of 0.03125. Gates were unchanged.

Accepted `block04/result.json` SHA256 is
`2715ee020e9797afe572363263c32a6c1aa91d0d0f3bf4ad6dd2c01a295c3e70`;
`block04/summary.json` SHA256 is
`f635e5ef6b1b6a399270063648055fa092662958c8f583edd4f04e33f54b2142`.
Root verified the fixed source inventories with zero mismatches and accepted
612 closed SQLite checks and archive verification before removal of 30
containers, 30 volumes and six networks. Summed trajectory wall time was
1545.764 seconds (25.76 minutes), not compute time. No model was promoted.

## GC01: bounded FULL gradient consistency audit

The subsequent offline audit restored the exact balanced-legacy and
balanced-classbalanced FULL slot-0016 bases, actual TRAIN rows and retained
unclipped directions. Fifteen prespecified float32 states per case included the
base and positive/negative scales 1, 1/4, 1/16, 1/64, 1/256, 1/1024 and 1/4096.
Existing round-to-eight-decimals plus float32 candidate transport was preserved;
the unperturbed base remained exact. Both full candidates reproduced the retained
fingerprints and per-task losses. Every one of 1920 in-process AnalyzePrompt
fixture calls explicitly selected semantic only and returned one successful
semantic layer. Thirty auxiliary Torch no-grad forwards (60 microbatches) scored
the same states inside the checked fixtures. There were no new gradient fits,
live RPC calls, publication attempts or trajectory updates.

| Captured case | Base TRAIN objective | Full step | 1/4 step | 1/16 step |
| --- | ---: | ---: | ---: | ---: |
| balanced-legacy | 8.134500 | 16.163123 | 8.092196 | 7.695744 |
| balanced-classbalanced | 6.570094 | 16.496246 | 7.099641 | 6.163631 |

These are within-case curves, not cross-policy loss comparisons. Serving and
Torch task losses agreed at all 30 states within the tolerances fixed before
execution; maximum logit discrepancies were 3.82e-6 and 5.73e-6. Central
directional differences at scales 1/16 through 1/1024 agreed with the retained
negative-autograd prediction within the preset 5% relative or 0.01 absolute tolerance.
Each corresponding positive step reduced serving loss and each negative step
increased it. The 1/4096 points remain recorded but are excluded from derivative
evidence because rounding distortion exceeded the preset 1% directional-residual
limit. Their changed coordinates alone do not establish derivative agreement.

Rate overshoot is supported for these two unclipped updates; a serving/Torch
forward or direction mismatch is not supported here. This does not establish a
cause for every FULL rejection or solve the separate quality TRAIN-exact floor.
The smallest conditional next-method recommendation is a separately frozen
lower FULL rate, with 0.003/16 = 0.0001875 as an exploratory candidate from this
diagnostic, preserving the objective, one-gradient update and all existing gates.
Two cases cannot establish a globally safe rate or improved disclosure. Root
will decide after independent review whether to use that fixed-rate control or
authorize a bounded TRAIN-loss-aware backtracking feature; neither was adopted
or implemented in GC01. The raw prompt-free curves, fixed tolerances, hypothesis
ledger, source/input pins and cleanup proof are retained in
[gradient-consistency/result.md](../evaluation/results/iterative_fuzzer_20261011/gradient-consistency/result.md).


## BS01 bounded TRAIN backtracking feature

After accepting GC01's two-case overshoot diagnosis and independent PC12 review,
the manager selected a separately reviewed optional bounded backtracking method
as the next hypothesis. GC01's fixed-lower-rate recommendation remains its
historical recommendation; no method was implemented in that investigation.
BS01 adds `full_train_backtracking_v1` for FULL only, with immutable preparation
and caller admission, one original gradient and at most five candidates at
requested-rate scales 1, 1/4, 1/16, 1/64 and 1/256. Each trial starts from the
original raw direction before clipping and existing rounded/float32 transport.
The first finite TRAIN-objective decrease strictly above 0.00002 that changes an
encoder coordinate is selected, without guard-guided selection or fallback.
The selected delta, effective rate and exact candidate identities must agree
through runtime diagnostics, client admission and publication. Exhausting all
five produces a durable known one-fit rejection with no guard claim or update.

The legacy/default and HEAD algorithms, objective mathematics, samplers and all
publication gates remain unchanged. Raw request/header/response persistence
precedes local admission, with separate verdicts and unknown transport outcomes;
committed retries use the historical receipt without another fit. Gradient fits
and extra TRAIN semantic forwards are counted separately. The quality TRAIN-exact
floor remains unresolved. Tiny offline semantic-only fixtures check mechanics,
serialization, durability and wire quotas; they do not establish a quality gain
or a globally suitable rate. No training trajectory or model promotion is part
of BS01. The design, check logs, scoped patch/source identities, limitations and
cleanup are retained in
[train-backtracking/result.md](../evaluation/results/iterative_fuzzer_20261011/train-backtracking/result.md).


## QC01 TRAIN-only direction diagnostic and SM01 objective

QC01 was accepted after independent reconstruction of three frozen QUALITY TRAIN
batches (slots 2, 50 and 100; seeds 3043, 3091 and 3141). One fresh FULL gradient
per batch and five prescribed rates produced 15 candidates. The original base,
raw gradient and first three transported candidates/losses reproduced the retained
IM05 records. None of the 15 candidates combined meaningful loss descent, preserved
TRAIN clean/sensitive decision counts and positive joint exactness. All nine
loss-descending candidates lost sensitive recall; sensitive joint exactness was
zero for all 15. The third-rate aggregate exact gains were clean-only, while the
last two rates had zero aggregate joint exactness. These three correlated TRAIN
fixtures reject same-direction constrained selection for those batches, rather
than establish a global impossibility or category-loss dominance. No historical
guard was read or evaluated. QC01 retained three diagnostic fits, six backward
microbatches and 1,152 checked semantic row calls separately from IM05's fits.
See [quality-train-curves/result.md](../evaluation/results/iterative_fuzzer_20261011/quality-train-curves/result.md).

SM01 implements a separately admitted
`class_balanced_contextual_sum_category_decision_margin_v1` objective for HEAD and
FULL: existing class-balanced sensitivity CE, visibility CE and summed category
BCE plus a coefficient-1 union decision-margin BCE. The union uses non-S0-minus-S0
severity logits and category logits offset by the artifact threshold logit. It is
a threshold-aligned surrogate with deterministic maximum ties, preserving the
existing decoder and the separate mean-category margin mode. Objective-specific
schema-2 evidence retains all four components and their total. The original
header bytes bind durable identity before reservation/receipt lookup, and raw
responses precede local admission. Existing defaults, optimizer absence, rates,
clipping, sampler, labels, guard gates and base TRAIN exact-match floor remain
unchanged. In particular, a zero base TRAIN exact-match floor still blocks QUALITY
publication independently of the new direction. Mechanical checks and the small
TRAIN-only QC02 pilot are separately recorded in
[sum-margin-objective/result.md](../evaluation/results/iterative_fuzzer_20261011/sum-margin-objective/result.md);
they confer no disclosure-quality or production qualification.

QC02 falsified the prespecified QUALITY hypothesis on these three fixtures:
0/15 candidates were feasible, sensitive joint exactness remained 0/48 at every
rate in every case, and all nine own-objective loss descents lost sensitive recall.
At the third rate, aggregate joint exactness was 21/192 versus the immutable old
control's 10/192, entirely from clean rows; sensitive recall was 32/144 versus
112/144 at base and 61/144 for the old third-rate control. These clean-only gains
are not disclosure gains. Loss descent is compared against each objective's own
baseline, without comparing absolute losses across different objectives.

The first pilot invocation halted after one saved gradient, two backward
microbatches and 64 successful checked semantic base calls because the probe's
independent scorer used a normalized-target method on a protobuf target. The
manager authorized one recovery: correct that scorer, verify and reuse the exact
saved direction without recomputation, repeat 64 base calls, then complete the
original candidates and remaining two batches. The original plan was three fits,
six backwards and 1,152 row calls; the authorized recovery added 64 calls, yielding
three actual diagnostic fits, six backward microbatches and 1,216 successful
semantic row calls across both invocations. Failed evidence remains retained. No
guard, assessment, safety or validation payload was evaluated, and no trajectory,
live RPC, publication or automatic training continuation occurred. The feature's
42 passing focused mechanical checks do not reverse this negative pilot outcome
or remove the independent base TRAIN floor.

## BC01: ordinary-benign TRAIN coverage preparation

Source inspection established that legacy taxonomy S0 controls are all fiction.
That coverage gap supports testing an opt-in ordinary-benign pool; it does not
establish the cause of development degradation, convergence or a benefit from
this intervention. `taxonomy_benign_coverage_v1` generates the legacy batch
first, then replaces HEALTH/P0, POLITICS/P1, RELIGION/P2 and CRIMINAL/P3 fiction
slots using an independent deterministic RNG. Four fiction rows remain. The
32 originals/64 presentations, sensitivity quotas 8/4/6/14, sensitive/category
exposure, raw unit weights and exact ordered 16-row guard remain fixed.

The pool and label rationales were frozen before membership feedback and admitted
by a fresh independent label review. Under
`evaluation/results/iterative_fuzzer_20261011/train-benign-coverage/`, SHA-256 pins
are pool `7c6ed6f6d751d2568141f715abd7ee8235fec937d9d1c0f6c0e29d0f2b9b99d7`,
rationales `cceed14fa0962b310798392756d5e7bd1e2af090c02defe646366f787d046f88`,
review `c1cc9b1674ec44540681ff40810317ef02f97a522d154bd454a8b4369e3dc4b2`,
fresh exclusion proof `77392a02fe414419ff909a639d42fbe2ee2fdec6b08ba52be6868ba43089d61a`
and initial r0 manifest `7d9b12f01607eceaf8aa77bfc325cd4031eff2eb6ba46402cca430bf61bca10f`.
Independent implementation review found that an altered in-memory legacy row
could retain its dataset hash and reach the mocked direct-trainer runtime
boundary. The corrected r1 manifest
`c817db3579b93f88ac2028d1f226884e3882ec9405b3bd2a868bdd5fa0a38ec9` additionally
binds independently extracted legacy content commitment
`04db8a469aa5c430f9333829da015f01b4377eb5268c58c1451c63b0a51dcced`.
It covers all 640 ordered rows' exact text, full/packed targets, raw weights and
complete metadata, plus partitions and exclusion metadata. Generation, audits
and direct training reject changes even when the caller retains the dataset hash
or attempts to construct a new manifest. The r0 artifacts/image and pre-fix mock
reproduction remain historical evidence; pool, rationales, label review and
exclusion proof bytes are unchanged. Corrected records are under `r1/`.
All 96 approved variant slots were checked against unchanged existing opaque
exclusion commitments and authorized frozen development membership; all legacy
source/guard variants were checked for collisions. No protected payloads were
opened or endpoint keys regenerated. Both preparation artifacts keep
`fit_release: false`.

The 32 unique groups belong to one authored collection, not 32 independent
collection sources. Each visibility has eight English tasks with explicit
audience cues; repeated visibility terms and topics that are not crossed across
audiences remain limitations. No benchmark predictions informed authoring.

Six focused behavioral tests and the integrated 131-test fuzzer suite pass at
the corrected revision. An actual source/service/protobuf/publication constructor
witness used a manufactured saved response with zero/full tensor fixtures:
85 incoming metadata entries became 58 outgoing entries, maximum 1405 bytes,
with exact string restoration except the intentionally removed validated trace.
The unchanged retained updater and runtime consumers accepted their respective
bounded artifact contracts. This is contract evidence, not a real numerical fit,
active artifact-aware publication, model quality or performance measurement.
The snapshot-comparison failure, two missing test-fixture recoveries and a
packed-only guard commitment correction remain in the evidence logs. The r1
actual-source witness rejects eight same-hash mutations before any mock runtime
call. One r1 retained-consumer mount failure and its environment-only recovery
are preserved; the corrected updater and runtime checks pass.

A separately released real numerical canary and frozen finite-schedule proof
are required before training. The five-seed source witness does not release a
future study schedule, and no numerical readiness or generalization is claimed.

## AR01: fixed gold-target TRAIN anchor rehearsal preparation

The accepted PC43 table is retained in
`evaluation/results/iterative_fuzzer_20261011/train-anchor-rehearsal/accepted-contract.md`.
The opt-in `taxonomy_anchor_rehearsal_v1` bank fixes sixteen anchors and sixteen
complements across all twenty permanent TRAIN families. It preserves aggregate
8/4/6/14 sensitivity quotas, full source category sets, unit raw weights and one
legacy seeded invariance transform per original. Each half has four clean and
twelve sensitive originals. The source release and provenance remain immutable;
a separate canonical manifest binds exact row/group membership, target/text
commitments, weights, inherited expansion/guard contracts and historical opaque
exclusion commitments. All dataset/bank/manifest pins are required before durable
reservation or receipt lookup. Only authenticated FULL Adam can execute it.

Immutable complete sampling evidence precedes compute; ordered 64-row protobuf
commitments and lossless bounded publication summaries are checked. Same-parent
identity expansions remain allowed; actual unique expanded inputs are counted.
Missing pins, altered manifests, forbidden partitions, source changes, collisions,
HEAD/default mixtures, curriculum and extra golden replay fail closed. The
same-seed v1 guard, optimizer math, strict candidate TRAIN floor, heldout gates,
baseline-inclusive development selection and explicit successful semantic-only
execution assertions are unchanged. No historical measurement is relabeled.

AR01 is preparation and nonmodel verification only (`fit_release=false`). Fixed
family and audience composition changes coverage as well as persistence, so it
does not establish forgetting or isolate its temporal cause. Before any future
fit, the manager must prove actual v2 expanded outputs are a subset of the pinned
TC02 source-row/legacy-transform superset already validated against opaque
exclusions and development validation64. Preserve its endpoint commitments and
verify source/target/transform identity; old seed-specific hashes cannot identify
new batches, and validation968 is unrelated. No endpoint payload access or
regenerated endpoint keys are needed. The manager must freeze
finite common warm-up, identical paired arm states, update slots, physical-fit
budget and semantic assertions. The unchanged-v1 control and new feature score
the same sixteen anchor originals for joint and visibility retention from a shared
attained state, separately reporting four clean/twelve sensitive denominators.
Failure to reduce retention loss rejects the mechanism; accuracy never attained
is inconclusive. Development outcomes cannot tune warm-up or a coefficient.
Passing retention still requires unchanged development qualification and creates
no assessment/generalization claim. No experiment or numerical release occurs
in this implementation assignment.

## SR01: ORIGINAL TRAIN sensitivity retention implementation

The root SR01 design and pilot-outline records specify two prospective policies:
`full_projected_adam64_original_train_gate_v1` and
`full_projected_adam64_original_train_hinge_v1`. Both preserve BC01's main 64,
CURRENT-relative ordered guard 16, unit wire weights, source-row content binding and
FULL Adam settings. The second adds coefficient one times a separately
normalized unweighted mean ORIGINAL-minus-CURRENT decoder-aligned binary-margin
hinge; the first has no auxiliary gradient work. Both require every eligible
TRAIN row to retain sensitivity, severity and rounded-confidence action capped
at the lesser of gold and ORIGINAL. A positive union margin alone is insufficient.

The positively admitted bank contains 200 rows in twenty groups, with immutable
content SHA `c9b0b64133e6474487c1d3fe2ac9410c720b19a1f1571469dc8c3483f4e4a41a`.
Reference eligibility requires gold non-S0, ORIGINAL decoded sensitive, margin
and sensitivity top-two gap each greater than `1e-6`, and all twenty groups per
profile. The root label acceptance precedes outputs. An independently configured
trusted manifest SHA authenticates immutable bank, ORIGINAL artifact and
references before service reservation, receipt recovery, direct trainer or
runtime model access. Request self-pins alone do not authenticate predictions.
Schema4 and new policy/objective IDs coexist with old exact combinations.

The actual in-process reference route sends `[4]`, asserts sole returned semantic
execution and ORIGINAL identity, and captures logits from that prediction once.
Scoped bindings are explicitly passed through the threadpool closure and reset
on every exit. No historical RPC or additional teacher pass is introduced.
Parity uses an already-required CURRENT auxiliary Torch call only when CURRENT's
fingerprint equals ORIGINAL. This legitimately remains CURRENT work.

The subsequent SR01-F32 repair corrected a pure representation mismatch: raw
JSON decimal teacher fingerprints differed from genuine float32 protobuf CURRENT
fingerprints in all three profiles. SR01 identity and teacher snapshots now share
the existing float32 conversion, while immutable raw artifact SHA/checksum and
global fingerprint policy remain unchanged. Actual protobuf roundtrips prove the
old mismatch and repaired agreement; seven shared and nine fake/analytic runtime
checks passed. A stubbed driver proves the unchanged exact parity branch is
reachable, without measuring parity or adding a teacher forward. Evidence is
retained separately in `train-sensitive-retention-f32-repair/`; original package
and held pilot records remain historical. No historical measurement changes,
genuine teacher outputs, numerical release or model benefit follows this repair.

The later SR01 CURRENT-config repair addresses a transport-format failure after
an accepted update: the updater writes indented artifact JSON, and the parameter
server returns its config whitespace unchanged. The retention preflight had
compared that string with compact ORIGINAL config JSON. It now strictly parses
CURRENT string JSON objects, rejects duplicate keys, malformed/nonobject input
and nested nonfinite values, and compares canonical JSON while preserving keys,
types and values. No defaults or coercion are introduced; main64/guard16 and all
training gates remain unchanged. The sealed compact 362-byte and pretty 580-byte
configs have identical canonical content. Five focused source-contract tests
exercise the exact helper and full preflight function with inert dependencies,
including both policy IDs and rejection before model arithmetic; these are not
runtime image/import compatibility or numerical checks. Pilot04 remains HALTED
after eleven attempts: ten whole audits (two accepted, eight rejected), one
unknown and seven undispatched. The unknown is not replayed or reclassified.
Evidence is retained in `train-sensitive-retention-config-repair/`; the repaired
numerical route remains unvalidated, with no model-benefit claim or numerical
release from this repair.

Successful runtime work is separately accounted: declared semantic execution
rows are main 64/baseguard 16/candidateguard 16, while actual NumPy work is
main 128 plus legacy guard 48, plus two auxiliary passes of K eligible rows. The
third guard pass uses prefit CURRENT reference parameters. Main Torch work is
64 steps times64 rows; hinge adds64K rows in64 ceil(K/32) microbatches. Gate-only
adds no auxiliary backward work. One scalar capability backward is separate.
These overlapping wire/backend units must not be added together. Partial work is
recorded as observed lower bounds with unknown completion explicit. At eighteen
prospective fits the NumPy ceilings are main 2,304/guard 864/auxiliary 7,200, separate
from declared semantic 1,728 rows and separately budgeted ORIGINAL 600
reference-generation forwards.

Evidence is retained under
`evaluation/results/iterative_fuzzer_20261011/train-sensitive-retention/`.
Focused checks passed: six shared contracts, seven analytic/fake runtime checks,
four new fuzzer behaviors and the new Go validator. The integrated fuzzer suite
passed 135 tests after the publisher dispatch repair. Actual manufactured
service/trainer constructor paths for both policies emitted 61 bounded entries,
maximum 1,405 UTF8 bytes per value, restored exact strings, bound raw traces and
preserved ordered guard wire bytes. Retained updater handlers validated artifacts,
published isolated zero-delta fixtures, replayed identical receipts and rejected
conflicts; retained runtime checks verified schema4 and active artifact binding.
All model calls, actual teacher forwards and live RPC counts are zero.

Failures remain preserved: fixture build/formatting/Go noexec recoveries,
constructor fixture/reservation failures, the root-confirmed PUB1 publisher
dispatch omission and its one authorized repaired verification, and the updater
generated-import-path recovery. Production/test/preparation sources are frozen in
`production-freeze.json`; offline final fuzzer/runtime/updater/model images are
retained for root review. The production model image was built without launching
services. Documentation and affected paper methods describe implementation only.

Manufactured references, losses, work counters and full-tensor zero-delta records
are contract fixtures, not accepted ORIGINAL predictions, measured gradients,
encoder-changing updates or numerical readiness. The actual reference phase,
TRAIN pilot and model benefit remain unreleased. Root acceptance and independent
review precede a separately bounded 600-forward/18-fit protocol; endpoint gates
remain unchanged, and no convergence or generalization claim follows this work.

### ADVICE-ROI1: advisory token-efficiency review (2026-10-12)

Question (exact user prompt): "how do you think we could get better model improvement relative to the tokens spent?" Scope: advice only; the training goal remains paused. No new training, service operation, cleanup, implementation or endpoint access was performed. This record is advisory and changes no paper result.

Inputs: primary checkout `feat/dev-testing`, base `250780ae13fd2687c7deae1b99a4c065d6d6ae64`, existing dirty changes preserved; completed session evidence in blocks01–05 and08–10, TRAIN diagnostics in block06/07, cached-head-probe, cached-margin-probe and full-adam-probe. Root's accepted checkpoint reports 3,609 product trajectory fits, 1,214 accepted and 2,395 rejected, with zero qualified learned models. This advisory review did not independently recount the later blocks. Pilot04's eleven attempts are separate (two accepted/eight rejected/one unknown); pilot05 never started. Detailed token attribution is unavailable, so no fraction of tokens is attributed to avoidable work.

Method: one bounded review of retained session evidence and two opened primary sources, accessed 2026-10-12: Martin Zinkevich's Google *Rules of Machine Learning* (`zinkevichRulesML`, rules4–5 and the overview) and Google Research's *Deep Learning Tuning Playbook* (`googleResearchTuningPlaybook`, incremental tuning, narrow experiment goals and experiment tracking). Prior block08 and TRAIN diagnostics agree that loss descent/publication acceptance can coexist with worse recall or absent development qualification. The FULL64 Adam pilot's TRAIN utility3/3 is a narrow positive, while its later product trajectory still selected original baselines; this prevents treating a TRAIN mechanism pass as generalization.

Ranked recommendations (inferences, not measured improvements):

1. Use one deterministic finite experiment runner for training, scoring, accounting, stop conditions and a compact machine-readable summary. Let the agent design the question and interpret exceptions/results rather than narrate individual fits. Retain raw evidence automatically without repeatedly loading it into model context.
2. Before a larger block, require an actual runtime acceptance/update/next-fit consumer witness: first update accepted and loaded, second fit starts from the expected identity, then terminal recovery reconciles it. Mock-only and isolated validators cannot establish that sequence. Unknown outcomes halt and reconcile, without blind replay.
3. Test one narrow hypothesis on a small fixed TRAIN-only semantic panel before production integration or hundreds of fits. Require explicit layer4 and actual sole semantic execution. Freeze budgets and falsifiers; use matched original starts and batches. Keep unchanged development gates and reserve them for qualification. Small comparisons are screening evidence, not proof of global superiority; interacting optimizer settings remain a fairness caveat.
4. Analyze already retained per-head errors, label/audience coverage and decoded decision flips. Test whether the existing model can learn a tiny diagnostic TRAIN set; if loss drops while joint accuracy/recall fail, diagnose objective/decoder/data alignment before adding another retention or optimizer feature. New labels require review and family-separated splits. Do not tune on assessment.
5. Use one root by default, an optional bounded critic at consequential gates, short task/result records and exception-only checkpoints. Set finite agent-token and training-compute budgets separately; instrument actual tokens per accepted decision and qualified development gain before asserting ROI improvements.

Sources support reliable infrastructure, simple incremental changes, narrow questions and retained experiment evidence; the proposed runner, exact preflight sequence and agent budgets are project-specific recommendations. No evidence guarantees a particular new objective, architecture, distillation method or rehearsal feature will improve quality. Next owner: root decides whether to adopt a future workflow; this review authorizes no resumed training.
# Frozen-window implementation follow-up

The opt-in window/checkpoint policy implements an eight-block, eight-epoch TRAIN schedule and separately normalized componentwise ORIGINAL retention. Frozen source manifests, schema-5 admission and actual semantic-only execution evidence bind the full fuzzer/runtime/publication/updater path. BASE plus steps8…64 are selected using TRAIN only; the single selected nonBASE candidate receives the unchanged guard and configured strict TRAIN exact floor. BASE/failure outcomes retain their version without publication, with durable known-outcome replay. Original teacher-file and component-manifest pins are independently configured; v2 task-query teachers require matching complete CURRENT configuration. This is an implementation change. No real-data fit, teacher-reference generation, new study score or model promotion follows from it. Historical union-margin and full-pipeline measurements remain historical.

