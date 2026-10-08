# Prospective contextual fuzzer model study — 6 October 2026

This protocol asks whether actual training through PriVoke's fuzzer improves the
full contextual pipeline. The treatment changes repository-owned randomly
initialized models; it does not use external pretrained weights. Efficient,
balanced and quality are evaluated because capacity alone does not establish
quality. Before execution, root and independent review must resolve material
implementation and protocol findings and freeze this document's canonical UTF-8
LF SHA-256 with the controller, curriculum, source and immutable image IDs.
There are no measured results from this experiment yet.

## Data and interpretation

Preparation derives the pinned 2,443-row public-negative curriculum, byte hash
`61b0d5c5f06fe0d948092f86044eb21c64a08c5f6d4f60ec6ecfb1466d42ecda`.
Exclude every existing validation group, ID and normalized text. Expected
exclusions are 271 rows in 190 groups, including 40 exact IDs. The remainder is
2,172 rows: 2,129 public annotation negatives and 43 disclosed bootstrap replay
examples. Public S0/PU labels remain provisional policy training targets: lack
of annotated PII does not establish contextual harmlessness.

Add exactly 128 novel authored contrastive examples in 16 whole families, four
wording variants for each clean/disclosure member. Synthetic values serve
explicitly asserted contextual roles; their targets are hand-authored assistant
provisional labels. All siblings share `metadata.group_id`, including both sides
of a contrast. These labels are not professor-confirmed human truth. Total
curriculum: 2,300 rows / 1,683 groups, S0 2,203, S2 36, S3 61. The public source is
PIIMB upstream `test` at revision `4a13e9ffe6fd0d275efbde8afd4d8d8f1ffc2133`;
repartitioning makes this custom within-corpus development.

Use the pinned opaque 1,000-row development/final selection index, without
opening any final examples or labels. Strictly validate complete contextual
targets, provenance, disjoint validation groups, and exact/normalized fixture
text exclusions. No PII span source is converted into severity, visibility,
category or action truth. The 48-case contextual fixture is never training data.
Authored families have no shared identifier with its 12 families. The preserved
LF fixture bytes hash to
`d6c7d5d87235cd6b0f9d24eac43b30c3ace9f0bf4f421ef5d5d812de79827a17`.

Validation is the existing 968 rows, 475 annotated-positive/493 negative; development
is the existing 502 rows, 264 positive/238 negative. Both have been used by prior
studies and remain **reused exploratory evidence**, not untouched generalization.
The earlier selected model overlaps validation; each new treatment instead starts
from its checked-in original v0.3.0 profile and uses the filtered curriculum.
Final remains uninspected and unscored. No joint 90%/90% result is promised.

## Fixed paired attempts

Run the Cartesian product of profiles efficient/balanced/quality, strategies
head-only/last-block, rates 0.003/0.01/0.03 and seeds 42/1337/2026: 54 independent
single-cycle attempts. Each begins from the exact frozen original profile. The
last-block arm uses the reviewed `contextual_last_block_sgd_v1` opt-in helper:
only the final encoder block's nine tensors plus six contextual heads train;
the embedding and earlier layers remain frozen. This is bounded partial encoder
training, not full-encoder pretraining. The existing per-tensor 4,096-value and
total update limits remain unchanged. A strategy flag changes export commitments
but not initial inference weights; parity must be verified by the runtime checks.

Each request samples 256 prompts, reserves 16 distinct held-out groups (both
classes), uses learning rate as listed, maximum tensor delta 0.05 and zero text
transformations. Preserve strict positive training exact-match, every existing
held-out exact-match/class/severity/action gate, float32 publication checks,
replay namespace and durable update receipts. Startup training stays zero. The
sampler draws uniformly from rows; this is highly imbalanced. Capture actual
seed-selected training/heldout class and role counts, opaque group IDs and text
sequence commitments before each call. These counts explain coverage; they do
not change sampling, class weights or outcomes after inspection.

Run serially. A staged command can execute the next 1–54 fixed attempts; this
only bounds work per command and cannot alter the grid or selection denominator.
Within this initial fixed comparison, no extra cycles, seeds, rates or
candidate-driven curriculum edits are allowed. The user's subsequent instruction
authorizes fresh experiments involving changes to model computation if results
plateau below the qualifying standards. Such experiments receive separate
prospective protocols and immutable inputs; they do not rewrite this grid or
discard its failed outcomes.
Capture elapsed times and actual service resource configuration; use the first
attempt to estimate remaining duration, without dropping unfavorable arms.
Rejected RPCs remain attempted candidates, not successful scores. A timed-out,
unavailable or otherwise unknown administrative outcome stops the study; never
blindly retry its request or advance to the next candidate. Quiesce the dedicated
fuzzer/updater before any catalog restoration. If quiescence cannot be proved,
stop catalog writes and require root recovery using preserved receipts.

## Selection and provisional contextual retention

Measure original validation baselines and each accepted candidate through matched
semantic and full-pipeline RPC runs. Require zero errors, all IDs/truth/groups,
raw confusion reconciliation, and exact returned artifact/model/fingerprint
identity. Candidate eligibility requires full-pipeline TP at least 428/475
(recall >=90%) and TN strictly above the same-profile original validation
baseline.

The fixed study sets evaluator bootstrap iterations to zero: selection uses
verified per-case raw counts, and makes no significance claim. Ordinary
`run-ablations.py` invocations retain their 2,000-resample default. Report IDs
must match the evaluator's `local-jsonl:` namespace with unchanged group IDs.
Rank by TN, TP, fewer cycles, lower learning rate, lower seed, smaller
profile, then head-only as final deterministic tie preference. The last tie is
predeclared and never resolved using development or fixtures. Preserve semantic
regressions separately when other layers rescue pipeline detections.

Freeze the winner and all 54 outcomes before candidate development access. If
none qualifies, retain original live state and report the failed search. Evaluate
only the frozen winner once on development and the unchanged contextual fixture;
do not select an alternative after seeing either. Retention requires development
recall >=90%, strictly higher specificity than the **freshly measured original
live balanced checkpoint**, and zero newly introduced contextual failures per
case. On each private disclosure, a failure occurs when live balanced met its
required WARN/BLOCK but the candidate falls below that minimum. On each clean
control, previously ALLOW becoming WARN/BLOCK is a new intervention. Aggregate
improvement cannot cancel a newly harmed case. The seven ambiguous cases are
excluded; 24 controls and 17 disclosures contribute quantitative checks. Some
controls retain S1/categories, so use `required_sensitive` and action requirements,
never annotation-presence or `Classification.is_sensitive()` as fixture truth.
Report existing live failures, all action downgrades and per-case outputs.

Report by originating PIIMB source stratum with supports and null absent-class
rates, for semantic and pipeline validation/development. These are exploratory
source subsets, not complete upstream benchmarks or causal capacity comparisons.
No inferential significance, independently established policy safety, final
generalization, installation or deployment claim follows from a passing fixture.

## Execution and restoration

Root alone builds images and operates live services. The controller never builds
images. Use new task tags, supply runtime/streamer/updater image options at the
baseline stage, and resolve every image to its immutable ID before changes.
The opt-in runtime uses `requirements-fuzzer-training.txt`: the same pinned CPU
Torch wheel as the earlier training mechanics, with typing_extensions 4.16.0
to satisfy the existing runtime's anyio dependency. The image must pass pip check.
Source-overlay parent images and all imported source paths are recorded; this
research build does not change the normal runtime Dockerfile. The study fixes
OMP, MKL and OpenBLAS thread counts to one and records effective resources.
Capture all live E/B/Q artifact **exact bytes**, identities and existing serving
image IDs. Preserve live balanced train.N, rather than assuming its version or
substituting checked-in original bytes. Dedicated study updater/fuzzer services
share only the model catalog, use a fresh named receipt volume, and mount the
curriculum read-only. A scoped permissions job owns only that fresh receipt mount.

Every mutating stage stops study publishers, restores all original E/B/Q bytes
atomically, recreates original services using captured immutable image IDs plus
the original ordered base overlays, verifies exact bytes/images, and preserves
receipts. Research retention archives a selected artifact; it does not promote
the default catalog. Failed attempts and accepted-but-unscored artifacts remain
under their fresh attempt directories. Never reuse partial attempt/run IDs or
overwrite old evidence.

From the integrated checkout, using its Python 3.11 study environment:

```powershell
$StudyPython = 'evaluation/.venv-fuzzer-study/Scripts/python.exe'
$SourceResults = 'D:/Git Repositories/Privoke-Research-Project/evaluation/results'
& $StudyPython evaluation/prepare-contextual-fuzzer-study.py --source-results $SourceResults --output evaluation/results/ctxfuzz-prepared --inspect-only
& $StudyPython evaluation/prepare-contextual-fuzzer-study.py --source-results $SourceResults --output evaluation/results/ctxfuzz-prepared
& $StudyPython evaluation/run-contextual-fuzzer-study.py plan --output evaluation/results/ctxfuzz-study --prepared evaluation/results/ctxfuzz-prepared --source-results $SourceResults
& $StudyPython evaluation/run-contextual-fuzzer-study.py initialize --output evaluation/results/ctxfuzz-study --prepared evaluation/results/ctxfuzz-prepared --source-results $SourceResults
# Root supplies exact new image references, reviewed before this mutating stage:
# baseline --runtime-image <task CPU runtime> --streamer-image <task streamer> --updater-image <task updater>
& $StudyPython evaluation/run-contextual-fuzzer-study.py baseline --output evaluation/results/ctxfuzz-study
& $StudyPython evaluation/run-contextual-fuzzer-study.py candidates --output evaluation/results/ctxfuzz-study --limit 1
# Continue fixed next candidates with --limit 1 or a larger bounded stage, until 54 terminal attempts.
& $StudyPython evaluation/run-contextual-fuzzer-study.py freeze --output evaluation/results/ctxfuzz-study
& $StudyPython evaluation/run-contextual-fuzzer-study.py finalize --output evaluation/results/ctxfuzz-study
```

Preserve any existing serving overlays with `--base-override` at plan/initialize;
the controller stores their order. All output names must be fresh. Plan and
initialize do not connect to Docker or mutate models. Inspect-only preparation
does not write files. Do not execute the baseline command before root confirms
the reviewed CPU runtime and strict streamer/updater image references. Passing
mechanics tests are not evidence that those live image/model paths have passed.
