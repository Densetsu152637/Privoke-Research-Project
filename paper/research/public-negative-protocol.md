# Prospective public-negative development protocol

Recorded 3 October 2026 before generating or scoring candidates for this study.
The preceding turn made progress: pinned learning-rate/curriculum comparisons,
revised rules, checked selected predictions, committed records and a verified local
artifact package. It did not achieve sufficient results or complete the paper.

## Question and practical criterion

Can broader clean-text training reduce annotation-presence false positives while
preserving at least the user-approved 90% full-pipeline sensitive recall? Current
selected pipeline: TP247/TN54/FP184/FN17 on502 development rows. The encoder remains
frozen; this study changes training coverage and learning rate, not architecture.

This new study uses a **prospective full-pipeline tradeoff criterion**: select the
highest clean specificity subject to recall >=90% and specificity >=the current
selected checkpoint (54/238). Ties prefer higher recall, then fewer cycles, lower
learning rate and lower seed. Semantic regressions must be reported separately;
they do not disappear when other layers preserve pipeline coverage. This differs
from the previous extension's stricter no-regression-in-both-layers criterion.
Do not retroactively reselect or relabel previous experiments under the new rule.
The change addresses the user's practical aggregate targets, not a favorable final
test result. Final498 remains unavailable to model selection and is not scored.

## Data and label limits

Use the same pinned PIIMB revision as the locked split. Scan eligible English
rows with the existing annotation parser, deduplication and conflict exclusion.
Exclude every locked development/final group ID, row ID and normalized text key
(the shared training key also removes case/compatibility/whitespace differences).
Exclude normalized conflicts among remaining candidates. Uniformly select2,400
clean rows with seed4102026; refuse an undersized pool. Retain source/ID/group
provenance and per-source counts. Add all43 existing bootstrap training examples,
with their original labels and individual groups. No public positive row needs an
invented privacy severity or visibility label in this negative-coverage study.

Benchmark-negative rows are assigned S0/PU/no categories for this experimental
annotation-presence training objective. Absence of an annotated span does **not**
prove absence of contextual private disclosure. Labels are provisional policy
training targets, not independently validated privacy/action ground truth. Original
bootstrap examples are replay, not independent evaluation. Escaping braces must
preserve each literal public sentence through the existing template renderer.

PIIMB exposes an upstream split named `test`. Repartitioning unused source
documents into training makes this a custom within-corpus development study, not
an untouched official benchmark-test score. State that prominently if used in the
paper. Other source documents can share templates/content; group and normalized
text checks do not establish semantic or pretraining independence. Dataset card:
[PIIMB](https://huggingface.co/datasets/piimb/pii-masking-benchmark), inspected
3 October2026. Audit its CC BY-NC4.0 and upstream-source restrictions before any
raw-data redistribution; this work remains local.

## Internal guard and bounded execution

When curriculum entries have `metadata.group_id`, reserve held-out examples from
distinct groups, retain their provenance, and exclude every reserved group from
training. Existing text-key disjointness remains mandatory. Entries without group
metadata keep the prior text-disjoint behavior, preserving existing comparisons.
Unit tests must cover sibling exclusion, reproducibility and exhausted grouped
datasets failing closed. Test invocation remains in evaluation; generation and
training implementation remain in the fuzzer/runtime.

Pre-execution source inspection also found that gradient/held-out execution used
raw input while serving uses canonical detector normalization. Align both training
and held-out inputs with `normalize_text`, including Unicode compatibility,
obfuscated email separators and spaced digits, before this study. A regression
test must prove identical gradients/metrics for raw versus equivalent canonical
inputs and unchanged caller inputs. Serving inference itself is unchanged. This
training-path correction is prospective; older update results retain their original
source and are not pooled as an otherwise-identical learning-rate comparison.

First measure a live original-model baseline with revised rules on the same502
development rows. Start each candidate from exact v0.3.0 and fixed serving source.
Run one256-prompt cycle for seeds42,1337,2026 at rates0.03,0.1,0.3, with
transformations disabled. Keep max-gradient0.05, automatic updater training off,
the16-example internal held-out guard and every publication/replay/severity gate.
The larger rates test whether averaged steps were too small; clipping still bounds
the candidate. Do not interpret requested rate as actual unclipped update size.
Archive every rejection, accepted response, artifact and matched semantic/pipeline
measurement. An RPC rejection is an attempted candidate, not a scored success.

If a candidate improves specificity by at least five percentage points over the
current selected checkpoint while satisfying pipeline recall>=90%, continue only
the selected seed/rate for at most two more cycles. Stop at an internal rejection,
failure of the prospective recall floor, or lack of specificity improvement.
Otherwise stop this study after the nine independent attempts. Restore the best
eligible measured checkpoint; restore the prior selected checkpoint after errors
or if no candidate is eligible. Do not weaken gates to make the study succeed.

## Evidence and interpretation

Record dataset/source/artifact/report hashes, service image identities, exact
configuration, source-group exclusion counts, errors and TP/TN/FP/FN. Compare
pipeline and semantic outputs on matched IDs with paired source-cluster intervals.
Development selection across these candidates requires descriptive uncertainty
and disclosure of the search; it does not establish confirmatory significance.
Final testing, figure integration, installed-extension enforcement, client costs,
artifact reproduction and professor confirmation remain completion requirements.
