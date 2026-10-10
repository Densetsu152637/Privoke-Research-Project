# Audited accelerated fuzzer study evidence

All twelve fresh semantic-only trajectories completed their fixed 168 attempts.
The accepted audit reconciled 2,016 requests, 1,270 publications/receipts, 746
rejections, 64,512 allocated presentations and 29,472 endpoint observations.
None of nine revised realizations or three profiles met the frozen promising
criterion; none of twelve cells qualified. The [study record](../../accelerated-fuzzer-study-20261010.md)
explains the specificity/recall tradeoffs, quality publication plateau and limits.

Execution source is `f2df530353a66de657a9a1adb8699021b072e418`; protocol SHA256 is
`39cbf3f7d88ed3b0260f97b41ebe3c41bd8b0e09376bf3e1488dba600da0aef3`.
These commitments predate this publication. Training used Tiny semantic heads,
not the revised conversational prompt. Seeded allocation was explicitly enabled
for the revised cells; normal deterministic defaults did not change. One shared
deterministic control per profile supports three conditional revised-seed
contrasts, not three independent control replicas.

| Artifact | Content |
| --- | --- |
| [Summary](summary.json) | All twelve cells and checkpoints, numeric guard metrics/predicates, publication and exposure counts, contextual components/subgroups, fixture harm counts, qualification, nine controlled contrasts and descriptive paired intervals |
| [Protocol projection](protocol.json) | Frozen objective, matrix, budget, decisions, source/input/image hashes and copied-source attestations with repository-relative names |
| [Original audit receipt](audit.json) | Unchanged accepted raw audit bytes, twelve archive hashes and original summary/protocol commitments |
| [Provenance](provenance.json) | Raw and handoff input hashes, exact totals, execution source, process cessation, retained resource counts and scoped runtime spans |
| [Publication hashes](publication-hashes.json) | Public file and script hashes, raw-to-public mappings and explicit omissions |
| [Reproduction helper](reproduce.py) | Standard-library, hash-bound aggregate projection with explicit field allowlists and fail-closed schema validation; no RPCs or fitting |

The raw audit's `summary_sha256` binds the original local summary
`66c419b4e3f755242ee7ac42dde5df84d40e5f5ce5ab1f255a1b0d2510716fc8`.
It does not bind the separately hashed public projection. All numeric metrics,
counts, predicates, decisions, controlled contrasts and intervals are retained
without rounding. Per-example identifiers, including `changed_ids` inside
controlled contrasts, are omitted everywhere. Per-attempt base versions and
base/candidate parameter fingerprints, project storage names and local input
paths are also omitted. No text, per-example predictions, tensors, SQLite data,
payloads, environments, secrets or operational logs are distributed here.
Candidate fingerprints remain in the raw evidence; rejected tensors and
independent candidate metric recomputation were not retained.

The helper verifies the accepted raw inputs and handoff receipts before writing
and rechecks their hashes afterward. Scoped Git attributes preserve JSON bytes
and LF script endings. From the repository root, with the complete ignored local
evidence available, regenerate to a separate directory:

```powershell
& evaluation/.venv/Scripts/python.exe docs/evidence/accelerated-fuzzer-20261010/reproduce.py evaluation/results/accelerated_fuzzer_20261010 evaluation/results/accelerated_fuzzer_20261010_build evaluation/results/accelerated_fuzzer_20261010_publication-check
```

The regenerated four JSON artifacts and publication manifest must match the
published bytes and hashes. Focused publication tests run without the ignored
raw datasets:

```powershell
& evaluation/.venv/Scripts/python.exe -m unittest discover -s evaluation/tests -p test_accelerated_fuzzer_publication.py -v
```

Public aggregates alone cannot rerun the full archive audit. That requires all
local raw archives and the frozen execution revision with its dependencies; a
later documentation revision must not be substituted for the frozen computation
source. At accepted handoff, all execution/audit processes had ceased, 72 owned
containers were stopped, 60 volumes and twelve empty networks were retained,
and three task overlay images remained available. Resource cleanup is a separate
subsequent step; these original receipts do not claim it is complete.

## Completed resource cleanup

The later [cleanup receipt](cleanup.json) records removal of 72 owned stopped
containers, 60 volumes, twelve empty networks and three task overlay images, plus
four unused task build intermediates removed automatically by Docker. All 147
explicit deletion commands succeeded. The initial post-checker exited 2 because
its comparison omitted the four intermediate images from task ownership;
retained uncached build steps and deletion output resolved that discrepancy.
The original checker receipt remains intact, and the separate reconciliation
passed without additional deletion.

All 27 unrelated containers, 135 volumes, eleven networks and fourteen image
records were preserved, including all five normal/shared parent images. All
twelve raw archives, frozen inputs/sources and original public evidence were
reverified unchanged. Cleanup completed at
`2026-10-10T02:37:06.594742+00:00`; the separate receipt SHA256 is
`d1ef45166a9e2da35640bb3e61b1b11ce5201d63e5a232520c5a2ed2c14fa378`.
Its reconciliation and proof hashes bind the local operational evidence without
publishing identifiers or local paths. The five original JSON files and
`reproduce.py` retain their original hashes; this later receipt is separately
hashed and is not an output of that original reproduction helper.
