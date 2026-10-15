# Experimental pretrained v3 stack and study

Status: three resource pilots are accepted and the 18-cell V3-R1 protocol is
frozen at 256 steps. All 18 main fits are complete and independently accepted.
All 21 raw snapshots, paired analysis, three fixed FULL seed-42 research exports
and cleanup are accepted. The final planned study closed on 13 October 2026
(Sydney); its stable ID and earlier source-access dates remain unchanged.
Results are reused DEVELOPMENT evidence, with limited absolute joint agreement
and action harms. No protected-final score or model promotion is established.

## V3-R1 execution and recovery record (2026-10-12)

Stable study ID: `pretrained_v3_20261012`, plan revision `V3-R1`.
The human authorized approximately doubling pretrained tiers, training both the
heads and entire encoder with the fuzzer, and running the study now. The exact
original prompt and accepted clarifications are recorded verbatim below.

Completed: three byte-exact pretrained ORIGINALs with zero heads, independent
official provenance, host Python 3.11/Torch CPU preparation and three accepted
resource pilots (efficient HEADS, efficient FULL, quality FULL). Resource evidence
selected the common 256-step budget; the 18-cell protocol is frozen and all main
fits, all 21 endpoint sets, paired analysis and fixed exports are complete.
Mechanical/resource and guard publication outcomes remain separate from the
development quality measurements reported below.

Accepted identities:

- Protocol SHA-256: `06f272f2a2b305fddebc17899b82d1e208a14398fdbdc6b34de0726b7931e273`.
- Server image: `sha256:4a5624eda0c0cd7dfb3da2366e3d18e720eda4a82797bf4e92320fa0987e9bd1`.
- Pilot resource summary SHA-256: `0d8be24ee1d8830df0167471492893aafc92363712c1e318ae213c03d1ce3abc`.

The original user goal, verbatim (without the `/goal` command prefix):

> Now that this study is completed, use the other chat's context and create a new set of v3 models, each tier being 2x parameters as the previous. However, do not initialise the models with random weights, see if you can find one that has already gone linguistic training as a base model, and then we will train it (the model and the encoder) with the fuzzer. Coordinate this yourself as a long-horizon task and as the final study that we will do.

Accepted clarifications: "Approximately 2× with intact pretrained weights";
"Prepare models and run the final study now". Prior TW01 closed as an early
negative partial study. V3 is the final planned research study; its endpoints
remain reused DEVELOPMENT evidence, not protected-final evaluation.

The original execution sequence (all four steps are now complete):

1. Finish shared stage/commit admission, ordered source sidecars, host controller
   and scorer; run synthetic host mechanics and import checks; root review.
2. Build the server image and run exactly three two-step pilots: efficient HEADS,
   efficient FULL, quality FULL. Choose one common 64/256/512-step budget using
   resource evidence only.
3. Freeze and execute exactly 18 cells: three tiers, HEADS/FULL, seeds 42/43/44.
   Each paired seed uses the same 512 TRAIN occurrences (eight batches of 32
   originals plus one invariant transform each), 16 guard rows, and ORIGINAL.
4. Audit every terminal candidate, including guard rejection; score all 18 raw
   candidates and three ORIGINAL controls, derive effective publication outcomes
   separately, and export the predetermined FULL seed 42 per tier with guard
   status. No best-seed selection or release promotion.

The original phase-1 implementation writer stopped before Docker lifecycle, fitting RPCs, and endpoint
scoring. Protected-final payload access and model promotion remain unauthorized.
Reused context320/context64 are primary DEVELOPMENT evidence; binary development
and hazard fixtures are separate secondary evidence. Implementation methods and verified references were documented before results
were available; paper results and conclusions are now updated from accepted
final evidence. Older study changes remain separately owned. Preserve
failed attempts and immutable evidence on interruption.

## Completed fits and scoring amendment checkpoint

All 18 terminal cells completed 256 optimizer steps each: 4,608 steps and 294,912
TRAIN exposures in total. Aggregate physical fit time was 1,020.4155697559981 s;
the longest cell took 142.130528833 s and maximum reported CUDA allocation was
419,415,552 bytes. Ten guards applied publication and eight rejected it; all raw
terminal candidates remain retained for endpoint scoring. These are execution
and publication counts, not quality conclusions. Fit completion is pinned by
`study/fit-completion.json`, SHA-256
`5b8dc294c06367113c2de7e66ab0f96bbc9374a7ddf67e3aaae640be6017fe30`.
Failed main-start attempts remain under `evaluation/results/pretrained_v3_20261012/main/`.

Scoring attempts 01 and 02 failed on pre-case 60-second runtime Health readiness
windows, after two and then five complete snapshot sets. One prewarm recovery
preceded the second attempt. No incomplete scoring reservations existed at the
amendment checkpoint. The 4,670 prior requested cases (4,635 eligible) had no
errors; 14,036 prior evidence files and all 18 terminal artifacts are pinned and
preserved byte-for-byte. Failure records remain under
`evaluation/results/pretrained_v3_20261012/scoring/`.

An explicit post-fit operational/audit amendment at implementation commit
`6b491e8380a66f8a19c82bd3d29903e98929c7e3` changes exactly five host paths. Its
scope is a 180-second scoring readiness window and normalization of nullable
hazard visibility hints (`None` to protobuf empty string) for audit comparison.
TRAIN, stimulus generation, scoring metrics, model selection and export choices
are unchanged. At this historical amendment checkpoint, attempt 03 was ongoing;
it subsequently completed with known exit code zero. Observed runtime
readiness around 77 seconds after container start supports the longer window as
a mitigation, without establishing the cause of the earlier failures.

The explicit amendment file is
`models/experiments/pretrained_v3_20261012/study/amendments/postfit-scoring-audit-01.json`,
SHA-256 `fc22e6d4c3d34d31903b051550a3f87e9ea5a8332a8e495141cefb940259e9c7`.
It retains original 165-file source closure
`c540b0ab4efcad07235a54b6694d23a42015c8ccc186267fb647ea84c2802c38`
and records amended closure
`899b9ae53f0917fc36a1a6e79a63060e09ebd419d1e9ca27675952b89e67acec`.
The 144-file server closure, image, original protocol and completed fits are
unchanged. Original frozen source captures are retained, not rewritten. Strict
training/default validation intentionally rejects the changed host source;
only score/analyze/export accept this explicit audited amendment. Seventeen
focused host tests passed in 13.024 s. Subsequent analysis/export acceptance is
recorded below; no checkpoint or budget was selected from endpoint quality.

## Family and initialization

The opt-in `privoke_pretrained_bert_v3` family preserves every native Google BERT
encoder and pooler tensor. These are complete pretrained models, substantially
larger than the historical Tiny family; the approximately doubling ladder is
within v3, not twice the Tiny parameter counts.

| ID | Official pretrained repository | Encoder + pooler | New zero affine heads | Complete v3 |
| --- | --- | ---: | ---: | ---: |
| `privoke-v3-efficient` | `google/bert_uncased_L-4_H-128_A-2` | 4,782,464 | 2,580 | 4,785,044 |
| `privoke-v3-balanced` | `google/bert_uncased_L-2_H-256_A-4` | 9,591,040 | 5,140 | 9,596,180 |
| `privoke-v3-quality` | `google/bert_uncased_L-12_H-256_A-4` | 17,488,640 | 5,140 | 17,493,780 |

Exact revisions and independently pinned upstream weight/config/vocabulary hashes
live in `privoke_model.v3_contract`. Source manifests and raw official files are
retained under `models/experiments/pretrained_v3_20261012/upstream/<tier>/`.
`evaluation/prepare-pretrained-v3.py` loads weights with `weights_only=True` on CPU,
excludes only the nine documented `cls.*` MLM/NSP entries, constructs the native
architecture on meta with initialization disabled, and requires strict learned-key
loading. It preserves encoder/pooler tensor values exactly and creates three
affine task heads with explicit `torch.zeros`. It checks unchanged RNG state;
missing keys, random fallback or overwritten ORIGINALs fail.

The three actual preparations produced complete counts shown above, exact
encoder/pooler byte equality, and zero task heads. Immutable manifests, full
safetensors and preparation proofs live in `initials/<tier>/`. This establishes
initialization, not model quality.

The native uncased WordPiece vocabulary and 512-token total limit are retained.
Physical batches pad dynamically. Overlength input fails without truncation.
Detector normalization runs once in the adapter. Dropout is disabled for this
deterministic experiment while autograd remains enabled. New zero heads produce
deterministic initial ties: sensitivity S0, visibility P0, and category probabilities
0.5, admitted by the fixed `>=0.5` category threshold. Production confidence uses
the maximum sensitivity/category probability, so its initial value is 0.5.

## Isolated services and binary publication

`evaluation/compose.pretrained-v3-study.yml` launches only experimental Python
checkpoint, runtime and fuzzer servers. Existing Go/Tiny limits, defaults and
frozen MiniLM contracts remain separate. No browser/native streaming integration
or release-channel promotion is claimed.

The runtime implements existing `AnalyzePrompt` messages and requires exactly
`layers=[4]` plus an explicit v3 model ID. It returns actual semantic execution
and complete snapshot/backbone/tokenizer identity, including clean results. The
single-finding decoder reuses production classification packing/action policy,
confidence moderation, clean response and masking helpers. Admission/inference
errors remain visible and block under the existing conservative failure behavior.

The dedicated `privoke.experimental.v3` protocol carries opaque checkpoint SHA
references and bounded ordered binary chunks. Its independent cap is 80 MiB per
blob, 1 MiB per chunk and 256 KiB per canonical manifest. Full finite float32
safetensors, exact tensor inventories and fixed source provenance are admitted
before a candidate can be published. No caller-selected filesystem paths travel
over this protocol.

Physical fitting happens in the runtime server. It fetches the base over the
checkpoint service, creates an isolated candidate, differentiates, serializes and
reloads the candidate, proves guard inference parity, then uploads evidence and
checkpoint bytes. The fuzzer validates dispatched TRAIN/guard wire commitments,
actual scope/work/model identities and candidate references before requesting
publication. The checkpoint server is the sole current-pointer writer.

A durable SQLite transaction atomically changes the current manifest and records
the terminal CAS receipt. Exact replay returns the same receipt; changed-content
ID reuse fails; stale bases reject. A lost response triggers a status query. An
unknown outcome stops the cell without a replacement fit or implicit rebase.
Staged candidates never change serving state. Rejected terminal candidates remain
the predeclared scientific endpoint alongside the published artifact, avoiding
selection bias from reporting only guard-approved candidates.

## TRAIN source, objective and study budget

The fuzzer reuses the maintained taxonomy/ordinary-benign source snapshots and
invariance transforms, with their exact admitted byte hashes. Permanent declared
TRAIN/guard groups and normalized texts must be disjoint. Each seed generates
one ordered stream independently of arm or model. Paired head/full cells start
from identical ORIGINAL bytes and see the same frozen stream and guard.
These are existing assistant-provisional TRAIN labels, not independent gold.

The objective is the sum of sensitivity cross entropy, visibility cross entropy,
and category BCE averaged across ten categories. Each component is accumulated
over microbatches then divided by the common 64-example macro denominator.
AdamW uses head LR 0.001 in both arms, encoder/pooler LR 0.00002 only in FULL,
zero weight decay, betas (0.9, 0.999), epsilon 1e-8 and global clipping at1.0.
Microbatches contain4 rows. HEADS freezes the complete encoder/pooler; FULL
trains all encoder/pooler/head parameters, including word embeddings. The first
zero-head step may have zero encoder gradient; later nonzero embedding, first
block, last block, pooler and head changes must be observed.

The two-step pilot uses 64 TRAIN rows and 16 guard rows. The completed 18-cell study
compares 3 tiers x HEADS/FULL x seeds 42/43/44. Its frozen common window
has 512 rows (8 x 64) and one fixed 16-row guard. Main work budgets 64/256/512 steps
correspond to 4096/16384/32768 repeated exposures. The final 256-step budget was
accepted from efficient HEADS/FULL and representative quality FULL resource
pilots. There was no development-driven checkpoint selection or tuning.

Publication requires at least one additional guard case with exact
sensitivity/category-set/visibility and production action correctness. Neither
per-row under-restriction nor over-restriction distance to the guard target may
increase. Guard rejection preserves the candidate for the paired endpoint study.
Allowed-action sets in development fixtures must be evaluated as sets, not
silently reduced to an arbitrary rank. The existing TRAIN guard has explicit
single targets.

All raw tests, preparation clients, controller and dataset loops run on host
Python. Docker runs only servers. The host environment is
`evaluation/.venv-v3-study` (Python3.11, CPU Torch2.11.0); the GPU server uses
Torch2.11.0+cu128 and verifies sm_120 kernel/device/autograd readiness before
model access. The workstation reports RTX5080/16,303 MiB VRAM; readiness and
pilot measurements established usability for the admitted workload.

## Commands and evidence

Generate host bindings and run scoped host mechanics:

```powershell
evaluation/.venv-v3-study/Scripts/python.exe evaluation/setup-host.py
evaluation/.venv-v3-study/Scripts/python.exe -m unittest discover -s evaluation/tests -p "test_pretrained_v3*.py"
```

`evaluation/run-pretrained-v3-study.py` provides the phases below. Actual completed
work is established by the pinned receipts and audits, not by command examples.

- `init-cell --cell <directory> --tier <tier> --scope <scope> --seed 42 --steps 2`
  admitted only the three predeclared pilot coordinates. Their completed immutable
  cells are retained; do not initialize or fit them again.
- `bind-cell --cell <directory> --image-id sha256:<exact-ID>` freezes current
  server source bytes (including dirty helper dependencies), all installed host
  package versions, and the actual ordered schedule before startup. An existing
  binding is immutable and may only be reused byte-for-byte.
- `start`, `health`, `cycle`, and `stop` use the cell directory. Startup checks
  the server byte closure against the host, inspects each running container's
  exact image ID, and records readiness and the full container configuration.
  `cycle` rechecks live source, policy and image before durably reserving the
  single fit. The physical optimizer runs only inside the runtime server.
- `reconcile --cell <directory>` queries publication/fit status, fetches terminal
  artifacts and checks one TRAIN inference. It never calls a fitting or commit
  RPC. A reserved fit with unknown publication stops the study without refitting.
  Evolving unknown publication and fit statuses are retained by content hash under
  `status-observations/{publication,fit}/`, preserving every distinct observation.
- `freeze-plan --plan <fresh-directory> --pilot-cells <three-directories>
  --image-id sha256:<exact-ID> --max-total-seconds <resource-budget>
  --vram-capacity-bytes <observed-capacity>` validates the three pilot work
  records, then chooses the largest of 64/256/512 steps fitting the supplied
  resource limit. The estimate uses measured per-step time, the slowest pilot
  for unmeasured arms, a 50% allowance, and peak allocation below 90% of capacity.
  Guard/endpoint quality does not participate. This writes all 18 cell bindings,
  shared per-seed schedules, source byte snapshots and the immutable protocol.
  The parent fixed `--max-total-seconds 14400` prospectively before endpoint
  results; each projected cell must also remain below 7200 seconds. No fitting
  budget is admitted if those limits or the 90% measured-VRAM gate fail.
- `validate-plan` and `run-plan` take `--plan <directory>` under the original
  strict source closure. Score/analyze/export use the explicit amendment below
  after the accepted host-only change. Matrix execution stops on an unknown cell. Completed
  cells are audited and skipped; a reserved incomplete cell requires explicit
  reconciliation before the matrix can continue.

The actual post-fit scoring/analysis/export commands use the host interpreter
and retain the original study directory. All three phases completed under the
explicit amendment. These reproduction commands do not authorize overwriting
retained immutable evidence or repeating fits:

```powershell
evaluation/.venv-v3-study/Scripts/python.exe evaluation/run-pretrained-v3-study.py score-plan --plan models/experiments/pretrained_v3_20261012/study --audit-amendment models/experiments/pretrained_v3_20261012/study/amendments/postfit-scoring-audit-01.json
evaluation/.venv-v3-study/Scripts/python.exe evaluation/run-pretrained-v3-study.py analyze-plan --plan models/experiments/pretrained_v3_20261012/study --audit-amendment models/experiments/pretrained_v3_20261012/study/amendments/postfit-scoring-audit-01.json
evaluation/.venv-v3-study/Scripts/python.exe evaluation/run-pretrained-v3-study.py export --plan models/experiments/pretrained_v3_20261012/study --audit-amendment models/experiments/pretrained_v3_20261012/study/amendments/postfit-scoring-audit-01.json
```

`score-plan` first requires all 18 audited terminal cells. It scores all raw
terminal candidates plus three ORIGINAL controls using explicit `layers=[4]`,
with exact model/manifest/blob/backbone/tokenizer identity and actual execution
checks on every response. Immutable request, response or transport error, and
case records remain under `endpoints/<model>/<fixture>/rows/`. All requested
eligible cases remain in denominators; error BLOCK responses earn no correctness.
Allowed actions are sets. Primary context320/context64 and secondary binary/hazard
results remain separate. Analysis recomputes row counts from retained response
bytes, reports paired FULL-minus-HEADS and candidate-minus-ORIGINAL by seed and
across all three seeds, and derives effective publication outcomes separately.

`export` writes the predetermined FULL seed 42 candidate for each tier to the
ignored `models/experiments/pretrained_v3_20261012/final-models/<tier>/`, with
manifest, vocabulary, configuration, training evidence and explicit guard and
publication status. This is a retained research artifact, without release
promotion. All other cells and failed attempts remain retained.

Compose uses the dedicated project `privoke-v3-study`. The controller stops its
three services after each main/scoring cell and preserves their state directories.
The parent owns final container/network cleanup and any retained image; no
volumes or unrelated containers are removed. On interruption, inspect existing
cell reservations, status databases and artifacts before restarting a server;
missing agent handles alone do not establish that processes stopped.

Evidence lives under `models/experiments/pretrained_v3_20261012/{initials,pilot,cells}`
and `evaluation/results/pretrained_v3_20261012/`. Keep ORIGINALs, effective
snapshots, independently pinned source data and failed-attempt records. Retained
server processes/resources and cleanup owners must be recorded at handoff.
No protected final data are authorized. Historical Tiny metrics and reused
development endpoints require separate labels; three seeds do not establish
statistical confirmation or independent generalization.

## Accepted development results and interpretation

All 21 snapshots completed: 19,614 requested cases, 19,467 eligible cases and
zero errors. Each snapshot requested 320 + 64 + 502 + 48 cases; the hazard
fixture excludes seven ambiguous cases, leaving 41 eligible. Actual semantic
execution and checkpoint/backbone/tokenizer identity were checked on every
response, including clean responses. Scoring attempt 03 completed with exit zero.
The final independent review checked all 58,948 current evidence files against
audited bytes/provenance and all 19,614 raw records, including ambiguous cases.

Every ORIGINAL has intact pretrained encoder/pooler weights and zero task heads.
Its observed output is S0, P0, all ten categories and WARN. Thus binary detection
is positive on every binary502 row despite S0: 264/264 annotated positives and
0/238 annotation-negative specificity. All three ORIGINALs score zero contextual
joint correctness. Improvement against this untrained task-head baseline is
weak evidence of useful privacy classification and does not isolate pretraining.

### Raw terminal primary counts

Joint requires complete packed sensitivity/visibility/category correctness and
allowed production action correctness. Counts below are raw terminal candidates,
including guard rejection. Each seed sees the same reused cases; seed repetitions
do not create independent prompts. ORIGINAL rows are one control per tier.

| Snapshot | context320 joint | context64 joint | Guard publication | Effective snapshot |
| --- | --- | --- | --- | --- |
| efficient-heads-42 | 9/320 | 6/64 | rejected | original-efficient |
| efficient-heads-43 | 13/320 | 5/64 | rejected | original-efficient |
| efficient-heads-44 | 14/320 | 8/64 | rejected | original-efficient |
| efficient-full_encoder-42 | 42/320 | 8/64 | applied | efficient-full_encoder-42 |
| efficient-full_encoder-43 | 44/320 | 5/64 | applied | efficient-full_encoder-43 |
| efficient-full_encoder-44 | 39/320 | 9/64 | applied | efficient-full_encoder-44 |
| original-efficient | 0/320 | 0/64 | control | original-efficient |
| balanced-heads-42 | 34/320 | 9/64 | rejected | original-balanced |
| balanced-heads-43 | 32/320 | 8/64 | rejected | original-balanced |
| balanced-heads-44 | 32/320 | 8/64 | rejected | original-balanced |
| balanced-full_encoder-42 | 51/320 | 8/64 | applied | balanced-full_encoder-42 |
| balanced-full_encoder-43 | 48/320 | 11/64 | applied | balanced-full_encoder-43 |
| balanced-full_encoder-44 | 47/320 | 12/64 | rejected | original-balanced |
| original-balanced | 0/320 | 0/64 | control | original-balanced |
| quality-heads-42 | 34/320 | 7/64 | applied | quality-heads-42 |
| quality-heads-43 | 27/320 | 5/64 | applied | quality-heads-43 |
| quality-heads-44 | 28/320 | 6/64 | applied | quality-heads-44 |
| quality-full_encoder-42 | 66/320 | 7/64 | rejected | original-quality |
| quality-full_encoder-43 | 59/320 | 10/64 | applied | quality-full_encoder-43 |
| quality-full_encoder-44 | 65/320 | 7/64 | applied | quality-full_encoder-44 |
| original-quality | 0/320 | 0/64 | control | original-quality |

The largest raw context320 joint count is 66/320 (20.625%); the largest
context64 count is 12/64 (18.75%). These different fixtures remain separate.

### Primary component counts

Every cell below is correct/eligible. Action agreement alone is not joint
classification correctness or an absence of casewise harms.

| Snapshot | Fixture | Sensitivity | Visibility | Category set | Action | Sensitive recall | Clean specificity |
| --- | --- | --- | --- | --- | --- | --- | --- |
| balanced-full_encoder-42 | context320 | 161/320 | 142/320 | 160/320 | 177/320 | 10/160 | 159/160 |
| balanced-full_encoder-42 | context64 | 57/64 | 21/64 | 33/64 | 55/64 | 31/32 | 30/32 |
| balanced-full_encoder-43 | context320 | 159/320 | 139/320 | 160/320 | 176/320 | 10/160 | 158/160 |
| balanced-full_encoder-43 | context64 | 57/64 | 19/64 | 35/64 | 55/64 | 31/32 | 29/32 |
| balanced-full_encoder-44 | context320 | 161/320 | 133/320 | 160/320 | 177/320 | 10/160 | 159/160 |
| balanced-full_encoder-44 | context64 | 56/64 | 22/64 | 34/64 | 53/64 | 30/32 | 30/32 |
| balanced-heads-42 | context320 | 141/320 | 89/320 | 160/320 | 167/320 | 50/160 | 141/160 |
| balanced-heads-42 | context64 | 52/64 | 13/64 | 31/64 | 47/64 | 29/32 | 27/32 |
| balanced-heads-43 | context320 | 142/320 | 95/320 | 160/320 | 167/320 | 57/160 | 138/160 |
| balanced-heads-43 | context64 | 51/64 | 16/64 | 32/64 | 48/64 | 31/32 | 27/32 |
| balanced-heads-44 | context320 | 145/320 | 88/320 | 160/320 | 159/320 | 38/160 | 142/160 |
| balanced-heads-44 | context64 | 50/64 | 14/64 | 32/64 | 43/64 | 29/32 | 26/32 |
| efficient-full_encoder-42 | context320 | 161/320 | 135/320 | 161/320 | 180/320 | 75/160 | 144/160 |
| efficient-full_encoder-42 | context64 | 54/64 | 16/64 | 34/64 | 52/64 | 31/32 | 26/32 |
| efficient-full_encoder-43 | context320 | 150/320 | 142/320 | 161/320 | 167/320 | 83/160 | 132/160 |
| efficient-full_encoder-43 | context64 | 54/64 | 15/64 | 33/64 | 54/64 | 31/32 | 26/32 |
| efficient-full_encoder-44 | context320 | 156/320 | 122/320 | 160/320 | 173/320 | 62/160 | 144/160 |
| efficient-full_encoder-44 | context64 | 55/64 | 16/64 | 35/64 | 55/64 | 30/32 | 29/32 |
| efficient-heads-42 | context320 | 106/320 | 74/320 | 159/320 | 169/320 | 122/160 | 80/160 |
| efficient-heads-42 | context64 | 47/64 | 13/64 | 32/64 | 50/64 | 32/32 | 21/32 |
| efficient-heads-43 | context320 | 103/320 | 84/320 | 159/320 | 162/320 | 124/160 | 74/160 |
| efficient-heads-43 | context64 | 47/64 | 12/64 | 32/64 | 51/64 | 32/32 | 21/32 |
| efficient-heads-44 | context320 | 116/320 | 84/320 | 159/320 | 169/320 | 124/160 | 81/160 |
| efficient-heads-44 | context64 | 50/64 | 16/64 | 32/64 | 52/64 | 32/32 | 23/32 |
| original-balanced | context320 | 160/320 | 41/320 | 0/320 | 119/320 | 160/160 | 0/160 |
| original-balanced | context64 | 32/64 | 13/64 | 0/64 | 7/64 | 32/32 | 0/32 |
| original-efficient | context320 | 160/320 | 41/320 | 0/320 | 119/320 | 160/160 | 0/160 |
| original-efficient | context64 | 32/64 | 13/64 | 0/64 | 7/64 | 32/32 | 0/32 |
| original-quality | context320 | 160/320 | 41/320 | 0/320 | 119/320 | 160/160 | 0/160 |
| original-quality | context64 | 32/64 | 13/64 | 0/64 | 7/64 | 32/32 | 0/32 |
| quality-full_encoder-42 | context320 | 162/320 | 154/320 | 160/320 | 178/320 | 10/160 | 160/160 |
| quality-full_encoder-42 | context64 | 56/64 | 23/64 | 34/64 | 56/64 | 26/32 | 30/32 |
| quality-full_encoder-43 | context320 | 156/320 | 145/320 | 160/320 | 172/320 | 18/160 | 155/160 |
| quality-full_encoder-43 | context64 | 52/64 | 23/64 | 35/64 | 52/64 | 25/32 | 30/32 |
| quality-full_encoder-44 | context320 | 158/320 | 151/320 | 160/320 | 175/320 | 21/160 | 157/160 |
| quality-full_encoder-44 | context64 | 57/64 | 24/64 | 36/64 | 57/64 | 29/32 | 30/32 |
| quality-heads-42 | context320 | 144/320 | 66/320 | 160/320 | 172/320 | 70/160 | 130/160 |
| quality-heads-42 | context64 | 54/64 | 20/64 | 35/64 | 48/64 | 31/32 | 27/32 |
| quality-heads-43 | context320 | 168/320 | 66/320 | 160/320 | 190/320 | 100/160 | 125/160 |
| quality-heads-43 | context64 | 53/64 | 24/64 | 34/64 | 49/64 | 32/32 | 25/32 |
| quality-heads-44 | context320 | 158/320 | 69/320 | 159/320 | 175/320 | 56/160 | 135/160 |
| quality-heads-44 | context64 | 51/64 | 26/64 | 34/64 | 48/64 | 31/32 | 24/32 |

### Paired changes and action harms

All differences compare matched eligible cases. Each net is improved minus
regressed correctness; zero net can conceal changes in both directions. Under
and over counts mark casewise increases in distance to the allowed-action set
relative to the reference. They are separate directional counts, not a unique
harmful-case union. No confidence intervals or significance claims are inferred.

#### FULL minus matched HEADS by seed

| Candidate | Joint320 net; improved/regressed | Joint64 net; improved/regressed | 320 under/over | 64 under/over | Hazard under/over | Binary502 net | Hazard action net; improved/regressed |
| --- | --- | --- | --- | --- | --- | --- | --- |
| balanced-full_encoder-42 | +17; 30/13 | -1; 5/6 | 29/2 | 3/0 | 3/1 | -41 | +2; 6/4 |
| balanced-full_encoder-43 | +16; 27/11 | +3; 8/5 | 31/1 | 2/1 | 2/2 | +8 | 0; 4/4 |
| balanced-full_encoder-44 | +15; 30/15 | +4; 9/5 | 15/6 | 3/1 | 2/1 | -14 | +1; 4/3 |
| efficient-full_encoder-42 | +33; 38/5 | +2; 7/5 | 34/27 | 6/4 | 2/1 | -28 | +4; 6/2 |
| efficient-full_encoder-43 | +31; 36/5 | 0; 5/5 | 23/43 | 3/5 | 4/1 | -33 | -1; 3/4 |
| efficient-full_encoder-44 | +25; 34/9 | +1; 8/7 | 35/29 | 6/1 | 4/1 | -38 | -1; 2/3 |
| quality-full_encoder-42 | +32; 43/11 | 0; 5/5 | 39/3 | 2/1 | 0/1 | +5 | +4; 5/1 |
| quality-full_encoder-43 | +32; 42/10 | +5; 10/5 | 40/13 | 6/1 | 0/1 | +11 | +3; 4/1 |
| quality-full_encoder-44 | +37; 49/12 | +1; 7/6 | 19/12 | 1/1 | 1/1 | +14 | +2; 3/1 |

#### Raw candidate minus its ORIGINAL by seed

| Candidate | Joint320 net; improved/regressed | Joint64 net; improved/regressed | 320 under/over | 64 under/over | Hazard under/over | Binary502 net | Hazard action net; improved/regressed |
| --- | --- | --- | --- | --- | --- | --- | --- |
| balanced-full_encoder-42 | +51; 51/0 | +8; 8/0 | 135/7 | 3/1 | 5/3 | +8 | +18; 23/5 |
| balanced-full_encoder-43 | +48; 48/0 | +11; 11/0 | 133/8 | 1/2 | 5/4 | +36 | +17; 22/5 |
| balanced-full_encoder-44 | +47; 47/0 | +12; 12/0 | 134/6 | 3/2 | 5/3 | +27 | +18; 23/5 |
| balanced-heads-42 | +34; 34/0 | +9; 9/0 | 107/33 | 5/2 | 5/2 | +49 | +16; 20/4 |
| balanced-heads-43 | +32; 32/0 | +8; 8/0 | 104/35 | 4/2 | 5/2 | +28 | +17; 21/4 |
| balanced-heads-44 | +32; 32/0 | +8; 8/0 | 122/19 | 8/1 | 4/2 | +41 | +17; 20/3 |
| efficient-full_encoder-42 | +42; 42/0 | +8; 8/0 | 69/67 | 2/3 | 2/3 | -16 | +20; 22/2 |
| efficient-full_encoder-43 | +44; 44/0 | +5; 5/0 | 61/84 | 1/4 | 5/5 | -17 | +16; 19/3 |
| efficient-full_encoder-44 | +39; 39/0 | +9; 9/0 | 83/58 | 3/1 | 5/5 | -15 | +16; 19/3 |
| efficient-heads-42 | +9; 9/0 | +6; 6/0 | 42/61 | 2/5 | 1/4 | +12 | +16; 16/0 |
| efficient-heads-43 | +13; 13/0 | +5; 5/0 | 45/56 | 2/3 | 1/4 | +16 | +17; 17/0 |
| efficient-heads-44 | +14; 14/0 | +8; 8/0 | 54/48 | 3/2 | 1/4 | +23 | +17; 17/0 |
| quality-full_encoder-42 | +66; 66/0 | +7; 7/0 | 133/8 | 6/2 | 2/2 | +8 | +22; 23/1 |
| quality-full_encoder-43 | +59; 59/0 | +10; 10/0 | 126/20 | 7/2 | 2/1 | +31 | +22; 22/0 |
| quality-full_encoder-44 | +65; 65/0 | +7; 7/0 | 122/19 | 4/2 | 1/1 | +25 | +22; 22/0 |
| quality-heads-42 | +34; 34/0 | +7; 7/0 | 97/29 | 5/3 | 3/4 | +3 | +18; 19/1 |
| quality-heads-43 | +27; 27/0 | +5; 5/0 | 93/17 | 3/4 | 3/3 | +20 | +19; 20/1 |
| quality-heads-44 | +28; 28/0 | +6; 6/0 | 113/14 | 4/4 | 2/3 | +11 | +20; 21/1 |

#### Across-seed descriptive contrasts

Denominators are 960 for context320, 192 for context64, 1,506 for binary502
and 123 for hazard action. These are three repeated sets of the same cases,
not independent samples of those sizes. Full component-level improvement and
regression counts remain in the accepted `study/analysis.json`.

| Contrast | Tier/arm | Joint320 net | Joint64 net | Binary502 net | Hazard action net | 320 under/over | 64 under/over | Hazard under/over |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| FULL-HEADS | balanced-full_encoder | +48 | +6 | -47 | +3 | 75/9 | 8/2 | 7/4 |
| FULL-HEADS | efficient-full_encoder | +89 | +3 | -99 | +2 | 92/99 | 15/10 | 10/3 |
| FULL-HEADS | quality-full_encoder | +101 | +6 | +30 | +9 | 98/28 | 9/3 | 1/3 |
| Candidate-ORIGINAL | balanced-full_encoder | +146 | +31 | +71 | +53 | 402/21 | 7/5 | 15/10 |
| Candidate-ORIGINAL | balanced-heads | +98 | +25 | +118 | +50 | 333/87 | 17/5 | 14/6 |
| Candidate-ORIGINAL | efficient-full_encoder | +125 | +22 | -48 | +52 | 213/209 | 6/8 | 12/13 |
| Candidate-ORIGINAL | efficient-heads | +36 | +19 | +51 | +50 | 141/165 | 7/10 | 3/12 |
| Candidate-ORIGINAL | quality-full_encoder | +190 | +24 | +64 | +66 | 381/47 | 17/6 | 5/4 |
| Candidate-ORIGINAL | quality-heads | +89 | +18 | +34 | +57 | 303/60 | 12/11 | 8/10 |

FULL exceeds matched HEADS context320 joint counts in all nine paired tier/seed comparisons, but
regresses individual joint cases in every comparison. Context64 net changes
include one negative and two ties. Binary502 FULL-minus-HEADS totals are -99,
-47 and +30 correct occurrences for efficient, balanced and quality respectively;
hazard action totals are +2, +3 and +9. These dependent contrasts and action harms
support a tradeoff description, not uniform benefit or monotonic capacity gains.

### Separate secondary counts

Binary502 has 264 annotated positives and 238 negatives. Hazard action uses
allowed action sets on 41 eligible cases out of 48 requested. Binary annotations
do not establish contextual sensitivity/visibility/action truth; hazard targets
are assistant-provisional. No primary and secondary denominators are pooled.

| Snapshot | Binary correct | Annotated-positive recall | Annotation-negative specificity | Hazard action |
| --- | --- | --- | --- | --- |
| balanced-full_encoder-42 | 272/502 | 91/264 | 181/238 | 33/41 |
| balanced-full_encoder-43 | 300/502 | 159/264 | 141/238 | 32/41 |
| balanced-full_encoder-44 | 291/502 | 126/264 | 165/238 | 33/41 |
| balanced-heads-42 | 313/502 | 194/264 | 119/238 | 31/41 |
| balanced-heads-43 | 292/502 | 219/264 | 73/238 | 32/41 |
| balanced-heads-44 | 305/502 | 223/264 | 82/238 | 32/41 |
| efficient-full_encoder-42 | 248/502 | 113/264 | 135/238 | 35/41 |
| efficient-full_encoder-43 | 247/502 | 138/264 | 109/238 | 31/41 |
| efficient-full_encoder-44 | 249/502 | 120/264 | 129/238 | 31/41 |
| efficient-heads-42 | 276/502 | 208/264 | 68/238 | 31/41 |
| efficient-heads-43 | 280/502 | 229/264 | 51/238 | 32/41 |
| efficient-heads-44 | 287/502 | 227/264 | 60/238 | 32/41 |
| original-balanced | 264/502 | 264/264 | 0/238 | 15/41 |
| original-efficient | 264/502 | 264/264 | 0/238 | 15/41 |
| original-quality | 264/502 | 264/264 | 0/238 | 15/41 |
| quality-full_encoder-42 | 272/502 | 113/264 | 159/238 | 37/41 |
| quality-full_encoder-43 | 295/502 | 157/264 | 138/238 | 37/41 |
| quality-full_encoder-44 | 289/502 | 150/264 | 139/238 | 37/41 |
| quality-heads-42 | 267/502 | 176/264 | 91/238 | 33/41 |
| quality-heads-43 | 284/502 | 203/264 | 81/238 | 34/41 |
| quality-heads-44 | 275/502 | 187/264 | 88/238 | 35/41 |

### Effective guarded outcomes and resource costs

Ten applied cells use their raw candidate predictions; eight rejected cells use
the unchanged ORIGINAL predictions. Reporting only applied cells would omit
predeclared scientific endpoints. The first table gives the exact mapping.

| Cell | Effective source | Joint320 | Joint64 | Binary correct | Hazard action |
| --- | --- | --- | --- | --- | --- |
| balanced-full_encoder-42 | balanced-full_encoder-42 | 51/320 | 8/64 | 272/502 | 33/41 |
| balanced-full_encoder-43 | balanced-full_encoder-43 | 48/320 | 11/64 | 300/502 | 32/41 |
| balanced-full_encoder-44 | original-balanced | 0/320 | 0/64 | 264/502 | 15/41 |
| balanced-heads-42 | original-balanced | 0/320 | 0/64 | 264/502 | 15/41 |
| balanced-heads-43 | original-balanced | 0/320 | 0/64 | 264/502 | 15/41 |
| balanced-heads-44 | original-balanced | 0/320 | 0/64 | 264/502 | 15/41 |
| efficient-full_encoder-42 | efficient-full_encoder-42 | 42/320 | 8/64 | 248/502 | 35/41 |
| efficient-full_encoder-43 | efficient-full_encoder-43 | 44/320 | 5/64 | 247/502 | 31/41 |
| efficient-full_encoder-44 | efficient-full_encoder-44 | 39/320 | 9/64 | 249/502 | 31/41 |
| efficient-heads-42 | original-efficient | 0/320 | 0/64 | 264/502 | 15/41 |
| efficient-heads-43 | original-efficient | 0/320 | 0/64 | 264/502 | 15/41 |
| efficient-heads-44 | original-efficient | 0/320 | 0/64 | 264/502 | 15/41 |
| quality-full_encoder-42 | original-quality | 0/320 | 0/64 | 264/502 | 15/41 |
| quality-full_encoder-43 | quality-full_encoder-43 | 59/320 | 10/64 | 295/502 | 37/41 |
| quality-full_encoder-44 | quality-full_encoder-44 | 65/320 | 7/64 | 289/502 | 37/41 |
| quality-heads-42 | quality-heads-42 | 34/320 | 7/64 | 267/502 | 33/41 |
| quality-heads-43 | quality-heads-43 | 27/320 | 5/64 | 284/502 | 34/41 |
| quality-heads-44 | quality-heads-44 | 28/320 | 6/64 | 275/502 | 35/41 |

Physical fit costs exclude scoring, startup, export and total elapsed study
time. CUDA peak is reported allocated tensor memory, not total process/driver
VRAM. Every cell completed 256 steps and 16,384 repeated TRAIN exposures.

| Cell | Fit seconds | Reported CUDA peak bytes |
| --- | --- | --- |
| balanced-full_encoder-42 | 35.558738 | 293053952 |
| balanced-full_encoder-43 | 40.500049 | 293053952 |
| balanced-full_encoder-44 | 35.215249 | 293053952 |
| balanced-heads-42 | 21.967830 | 161722880 |
| balanced-heads-43 | 21.485838 | 161722880 |
| balanced-heads-44 | 22.718616 | 161722880 |
| efficient-full_encoder-42 | 52.674191 | 180103680 |
| efficient-full_encoder-43 | 54.044822 | 180103680 |
| efficient-full_encoder-44 | 60.430969 | 180103680 |
| efficient-heads-42 | 34.365250 | 114695168 |
| efficient-heads-43 | 28.469863 | 114695168 |
| efficient-heads-44 | 28.578818 | 114695168 |
| quality-full_encoder-42 | 139.082761 | 419415552 |
| quality-full_encoder-43 | 142.130529 | 419415552 |
| quality-full_encoder-44 | 129.696933 | 419415552 |
| quality-heads-42 | 59.165093 | 193313280 |
| quality-heads-43 | 56.817476 | 193313280 |
| quality-heads-44 | 57.512545 | 193313280 |

### Limits and study closure

Targets are assistant-provisional, both primary fixtures and secondary fixtures
are reused DEVELOPMENT data, and all seeds reuse case identities. Counts and
paired contrasts are descriptive; they establish neither independent
population generalization nor contextual privacy safety. Zero heads make the
ORIGINAL a weak task baseline. Tier packages differ in depth/width/capacity;
there is no matched random-encoder arm, so the experiment does not isolate a
causal pretraining or capacity effect. Guard acceptance is a small TRAIN guard
publication decision, not a development-safety certificate. Absolute joint
accuracy remains low, and net improvements conceal regressions and harms.
No protected-final data were scored and no artifact was promoted. This closes
the final planned experimental study; no additional study is promised here.

## Fixed exports, final evidence and cleanup

All three predetermined FULL seed-42 research exports completed without best-seed
selection. Each contains manifest, safetensors, training evidence, native config
and vocabulary under `models/experiments/pretrained_v3_20261012/final-models/<tier>/`.
Independent review verified all 15 copied file hashes. Quality FULL42 failed its
guard and is retained as a rejected raw candidate; its effective served snapshot
remained ORIGINAL. Efficient and balanced FULL42 were applied. These local
research exports do not change the default release channel or establish browser
integration, deployment readiness or promotion.

| Tier | Candidate manifest SHA-256 | Guard/publication |
| --- | --- | --- |
| efficient | `3e60f251144c975dbf947d06bc25e0e35ae56006fae3c8d08af1f6add444bc0b` | applied |
| balanced | `bb1627fa5cdde65dc4d313e0525f1ee4d2f59c697fe0d1a9bdbd56e57f91de1f` | applied |
| quality | `812f24d35c99f2f6b77e692d3dfd2cb7f95bc3cbab8ad8df401bfca6dace1a1d` | rejected |

Final evidence identities (all under the stable October 12 study ID):

| Record | SHA-256 |
| --- | --- |
| `models/experiments/pretrained_v3_20261012/study/analysis.json` | `ad7726cd21cb377c793f91c40394a5cffe5ff05e47634632797f8a1bb1c3ee2b` |
| `models/experiments/pretrained_v3_20261012/study/postfit-analysis-provenance.json` | `ca48c245b9018e95f09ef7051438e3a20be0c7eb2d542698fbcfe7d82d2fb939` |
| `evaluation/results/pretrained_v3_20261012/scoring/independent-audit/final-analysis-review.json` | `882571402b20f70e354b72eba7e4f94abddc3f0e97df634f762d108c30a93034` |
| `models/experiments/pretrained_v3_20261012/study/exports.json` | `b56518a13bd40301fd99a1bad0924c22e6468e3f2066d9411528118f021f2932` |
| `evaluation/results/pretrained_v3_20261012/finalization/independent-export-review.json` | `bf787ee1e9bcea0d3164f31e4b0a62b34b3264315d307c71f1f43e1313b4ceae` |
| `evaluation/results/pretrained_v3_20261012/finalization/export-cleanup-review.json` | `7c4d3355308bac4055614f4ce3a39f2138efb967063e42eb69e70829054057c7` |

Cleanup receipt time is `2026-10-12T13:33:16.0977655Z` (13 October in Sydney,
UTC+11). Project-scoped `docker compose ... down` exited zero without volume/image
removal or global pruning: zero `privoke-v3-study` containers/networks remained,
ports 50171-50173 were released, and no live study command remained. The exact
image `sha256:4a5624eda0c0cd7dfb3da2366e3d18e720eda4a82797bf4e92320fa0987e9bd1`
is retained for reproduction/serving; root owns cleanup when the user no longer
needs it. Host environment, source captures, upstream assets, ORIGINALs, all 18
cells, all 21 endpoint sets and failed attempts remain retained. No task worktree
was created; the shared primary checkout and unrelated dirty work were preserved.

## Verified primary source keys

Selected host/server Torch is 2.11.0 CPU / 2.11.0+cu128. Transformers is installed
at 4.57.6; the consulted BERT API documentation is 4.57.1. Torch 2.12/cu130 was
a considered alternative only. Sources were opened before metadata extraction;
no unavailable author/date fields were invented. Pinned cards were retrieved
through their equivalent raw revision URLs after browser rendering failed.

| Claim | `paper/ref.bib` key | Primary URL |
| --- | --- | --- |
| Efficient upstream card/license | `googleBertL4H128A2` | [Source](https://huggingface.co/google/bert_uncased_L-4_H-128_A-2/blob/c29bee83fc7f003ac8c5e6e135529da4ecddb7c3/README.md) |
| Balanced upstream card/license | `googleBertL2H256A4` | [Source](https://huggingface.co/google/bert_uncased_L-2_H-256_A-4/blob/4e937a8675e5afd9a4836735c186ec01695bc3ea/README.md) |
| Quality upstream card/license | `googleBertL12H256A4` | [Source](https://huggingface.co/google/bert_uncased_L-12_H-256_A-4/blob/2ab9a0f41435a4d23d4cbc11cc3e7c922545f13d/README.md) |
| Selected CPU/cu128 distribution commands | `pytorchPreviousVersions` | [Source](https://pytorch.org/get-started/previous-versions/) |
| Blackwell/cu128 release support; not host readiness | `pytorch27Blackwell` | [Source](https://pytorch.org/blog/pytorch-2-7/) |
| Restricted loading; not complete protection against denial of service/memory corruption | `pytorch211Serialization` | [Source](https://docs.pytorch.org/docs/2.11/notes/serialization.html) |
| BertModel API; configuration alone does not load weights | `huggingfaceTransformers4571Bert` | [Source](https://huggingface.co/docs/transformers/v4.57.1/en/model_doc/bert) |
| Alternative wheel availability only, including 2.11 cp311 Windows | `pytorchCu130TorchIndex` | [Source](https://download.pytorch.org/whl/cu130/torch/) |
| Alternative 2.12 cu128 retirement/cu130 driver requirements | `pytorch212Release` | [Source](https://pytorch.org/blog/pytorch-2-12-release-blog/) |

Card declarations do not establish project parameter counts or quality. Counts
and byte-preserving initialization use local preparation/inventory evidence.
The 2.12 article requires drivers 580.65.06 Linux / 580.88 Windows for its
recommended CUDA 13.0+ route; it does not establish host compliance.
