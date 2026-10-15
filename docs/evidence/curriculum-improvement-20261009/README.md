# Audited curriculum comparison evidence

This directory publishes selected safe aggregates for the [process and results
record](../../fuzzer-curriculum-improvement-process-20261009.md). The semantic-only
v2 matrix completed 63 cells, including 15 imported semantic views and 48 fresh
cells. Execution source is `7c0322d6872e7b99ed88d1bc5bd67f2d0b9623a4`;
execution protocol SHA256 is
`f631c6078c439f9f7ff616e29f9c3d09ad36e22f079d2cdeed16a7fb459fc602`.
These commitments predate this documentation publication. The semantic criterion
changed after 15 cells were observed; the amended results are exploratory.

| Artifact | Content |
| --- | --- |
| [Summary](summary.json) | All 63 seed-level outcomes, 21 profile/arm/mode groups and 24 contrasts; component metrics, fixture harms, exposure, qualification and descriptive bootstrap intervals |
| [Protocol projection](protocol.json) | Frozen budgets, matrix, source/input/image hashes, amendment and semantic-only criterion |
| [Raw audit receipt](audit.json) | Unchanged accepted local audit; 63 archive hashes and their original execution protocol commitments |
| [Provenance](provenance.json) | Exact raw input hashes, copied-source attestations, scoped training equivalence, accepted counts, process cessation, operational recovery and retained-resource status |
| [Contextual subgroups](contextual-subgroups.json) | Uniform post-observation S0-control/nonS0-disclosure breakdown for all 18 offline cells and nine paired comparisons; no primary or qualification changes |
| [Rejections](rejection-breakdown.json) | All 45 live cells, exact structured reasons, attempts, accepted publications and consumed allocations |
| [Publication hashes](publication-hashes.json) | Actual published-file hashes and explicit raw-to-published mappings |
| [Reproduction script](reproduce.py) | Hash-verifies selected accepted local inputs and regenerates the safe publication without RPCs or fitting |

`audit.json.summary_sha256` binds the **raw local** summary
`b191e660f3e792a53047282c352e57089ff1f1bf05698a1c3c0d40b0c72867c2`.
It does not bind the separately hashed published projection. Only duplicated or
local path/provenance material is separated or omitted: every published cell,
group and contrast metric is unchanged. Subgroup endpoint path/hash inventories
remain local. The audit and rejection files retain their original bytes.
Scoped Git attributes preserve these JSON bytes and the reproduction script's LF
line endings. The publication manifest also binds the script's SHA256.

From the repository root, with the complete ignored local evidence available:
publication regeneration was validated with the existing
`evaluation/.venv/Scripts/python.exe` interpreter (Python 3.13.2).

```powershell
& evaluation/.venv/Scripts/python.exe docs/evidence/curriculum-improvement-20261009/reproduce.py evaluation/results/curriculum_improvement_20261009_v2 evaluation/results/curriculum_improvement_20261009_publication-check
```

Compare the regenerated JSON hashes with `publication-hashes.json`. Original raw
prompts, predictions, SQLite state, weights, optimizer states and operations stay
in the ignored v1/v2 results; they are not distributed here. Public aggregates
alone cannot rerun the raw archive audit. After obtaining the complete local raw
archives, run the existing audit with the execution revision's interpreter and
dependencies; the later documentation revision must not be mistaken for that
frozen execution source.

All 900 live attempts resolved: 615 accepted publications/receipts and 285
held-out rejections. Offline fitting contributed 360 separate Adam steps. All
63 candidates fail qualification; none was promoted. Specificity and contextual
control gains coexist with recall loss and casewise harms. Contextual labels are
assistant-provisional, semantic archetypes overlap, and curriculum wording,
visibility and category exposure change together. Deterministic replicas are
not independent; paired source-group/family intervals describe scenario sampling
variation rather than three-seed confidence. Offline optimization differs from
live training. Rejected candidate tensors and numeric gate components were not
independently retained. The process record explains these limits and the
separate, unverified backend chat accuracy.

At accepted experimental handoff, all 378 containers were stopped, 315 named
volumes and 15 empty networks were retained, and 48 verified empty task networks
had been retired to recover Docker address-pool exhaustion. The corrected
inventory preserves the original empty-filter error as superseded evidence.
Later resource cleanup has its own acceptance and provenance; this snapshot
does not claim cleanup is complete.

## Completed resource cleanup

After acceptance of the raw study audit, EX-8 removed all 378 owned stopped
containers, 315 named volumes, 15 remaining empty networks and five unused
task images, with exact identity/consumer checks and absence proofs. All 27
unrelated containers, 135 unrelated volumes, 11 unrelated networks, shared/parent
image rows and the running buildx container were preserved. All 63 raw archives
and accepted raw hashes were reverified unchanged after removal.

The separate [cleanup receipt](cleanup.json) has SHA256
`86e9afa0616e110a99cbe0d91d2cdbdbe3a4cbb7b573d94c74defa2ece3781f7`. Its detailed command/identity proofs remain
in ignored local results. This later receipt leaves the original six generated
aggregate artifacts and their publication hash map unchanged.
