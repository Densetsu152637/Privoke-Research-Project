# Experimental pretrained v3 stack and study

Status: implementation mechanics and immutable ORIGINAL preparation are being
validated. No completed study, quality improvement, protected-final score or model
promotion is established by this document.

## V3-R1 execution and recovery record (2026-10-12)

Stable study ID: `pretrained_v3_20261012`, plan revision `V3-R1`.
The human authorized approximately doubling pretrained tiers, training both the
heads and entire encoder with the fuzzer, and running the study now. The exact
original prompt remains in the parent task conversation; this paragraph records
the accepted scope rather than claiming to reproduce that prompt verbatim.

Completed: three byte-exact pretrained ORIGINALs with zero heads, independent
official provenance, and host Python 3.11/Torch CPU environment. At recovery,
only an efficient HEADS pilot binding exists; no physical fitting has occurred.
Partial source changes are being integrated and have not yet passed root review.
Previous synthetic mechanics establish no model-quality outcome.

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

The phase-1 writer stops before Docker lifecycle, fitting RPCs, and endpoint
scoring. Protected-final payload access and model promotion remain unauthorized.
Reused context320/context64 are primary DEVELOPMENT evidence; binary development
and hazard fixtures are separate secondary evidence. Paper/bibliography updates
are deferred to the parent after real results because those files contain older
study changes. Preserve failed attempts and immutable evidence on interruption.

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

The two-step pilot uses64 TRAIN rows and16 guard rows. A subsequent18-cell study
would compare3 tiers × HEADS/FULL × seeds42/43/44. Its prospective common window
has512 rows (8×64) and one fixed16-row guard. Main work budgets64/256/512 steps
correspond to4096/16384/32768 repeated exposures. The final work budget requires
resource-only acceptance after efficient HEADS/FULL and representative quality
FULL pilots. There is no development-driven checkpoint selection or tuning.

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
pilot measurements must establish actual usability.

## Commands and evidence

Generate host bindings and run scoped host mechanics:

```powershell
evaluation/.venv-v3-study/Scripts/python.exe evaluation/setup-host.py
evaluation/.venv-v3-study/Scripts/python.exe -m unittest discover -s evaluation/tests -p test_pretrained_v3.py
```

The host controller provides `init-cell`, `start`, `health`, `cycle`, and `stop`.
It starts/admit-checks servers sequentially through loopback, dispatches one
fuzzer cycle, retains terminal checkpoint/evidence/receipt, then performs one
serialized-candidate semantic request on a TRAIN row. It does not automatically
run the full matrix or score endpoint datasets.

Evidence lives under `models/experiments/pretrained_v3_20261012/{initials,pilot,cells}`
and `evaluation/results/pretrained_v3_20261012/`. Keep ORIGINALs, effective
snapshots, independently pinned source data and failed-attempt records. Retained
server processes/resources and cleanup owners must be recorded at handoff.
No protected final data are authorized. Historical Tiny metrics and reused
development endpoints require separate labels; three seeds do not establish
statistical confirmation or independent generalization.
