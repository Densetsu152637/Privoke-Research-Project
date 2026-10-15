# Results, model quality and dataset comparisons

These notes keep recalculated results, model quality and comparison research separate from the paper. For the six historical 6 October grids below, the qualifying target was at least 90% pipeline recall plus a measured specificity improvement against the declared fresh reference. A candidate also had to introduce no new casewise failures in the provisional contextual fixture's 41 quantitative cases; seven ambiguous cases were excluded. Acceptance of a training update does not establish that target. These historical combined-detector results are not LLM-only evidence.

| Study | Completed attempts | Outcome | Results and measured quality |
| --- | ---: | --- | --- |
| Initial contextual fuzzer grid | 54 | Frozen winner failed development and fixture retention; no retained model | [Results](fuzzer-model-results-20261006.md), [quality](fuzzer-model-study-v2-quality-20261006.md) |
| Class-balanced objective | 24 | 10 accepted, 14 rejected, zero eligible; no candidate endpoint inference | [Results](class-balanced-model-results-20261006.md), [quality](class-balanced-study-v1-quality-20261006.md) |
| Mean-category objective | 12 | Five accepted, seven rejected, zero eligible; no candidate endpoint inference | [Results](mean-category-model-results-20261006.md), [quality](mean-category-study-v1-quality-20261006.md) |
| Role-quota sampling | 12 | Six accepted, six rejected, zero eligible; no candidate endpoint inference | [Results](role-quota-model-results-20261006.md), [quality](role-quota-study-v1-quality-20261006.md), [protocol](role-quota-fuzzer-study-20261006.md) |
| Local SGD | 18 | Nine accepted, nine rejected, zero eligible; no candidate endpoint inference | [Results](local-sgd-model-results-20261006.md), [quality](local-sgd-study-v1-quality-20261006.md), [protocol](local-sgd-fuzzer-study-20261006.md) |
| Decision-margin auxiliary objective | 6 | Six accepted, zero eligible; no candidate endpoint inference | [Results](decision-margin-model-results-20261006.md), [quality](decision-margin-study-v1-quality-20261006.md), [protocol](decision-margin-fuzzer-study-20261006.md) |

The later [semantic-only curriculum and representation comparison](fuzzer-curriculum-improvement-process-20261009.md)
is a separate 63-cell study: 45 live cells resolved 900 attempts as 615 publications
and 285 guard rejections; 18 offline cells completed 360 Adam steps. None qualified
or was promoted. Its primary and gate use semantic-only outcomes, including
contextual joint agreement and casewise action harms. The criterion changed after
15 observed efficient cells, whose isolated semantic views were imported; the
remaining 48 cells were prospective. Specificity and S0-control gains coexist
with development annotation-presence recall losses. Offline balanced/quality joint
gains arise entirely from controls; nonS0 joint correctness stays 0/32 at baseline
and every offline endpoint. Authored disclosure sensitivity does not uniformly
worsen. Offline/live optimization and budgets differ. See the [safe aggregate
evidence](evidence/curriculum-improvement-20261009/README.md) for all seeds,
components, harms and descriptive intervals. These cells do not alter the
historical six-grid total of 126 attempts.

The separate [accelerated normal-batch semantic study](accelerated-fuzzer-study-20261010.md) completed twelve fresh trajectories of 168 attempts: 2,016 attempts, 1,270 publications and 746 guard rejections, with 64,512 allocated presentations and 29,472 semantic endpoint observations. None of nine revised realizations met its frozen promising criterion, none of three profiles passed, and none of twelve cells qualified. Efficient traded recall for specificity against its shared control; balanced retained more recall than its control while losing specificity and contextual joint agreement; quality reached a publication plateau. Disclosure category-set exact and joint correctness remained 0/32 at every checkpoint. See the [audited aggregate evidence](evidence/accelerated-fuzzer-20261010/README.md) for all arms, checkpoints, component outcomes, fixture harms and descriptive paired contrasts conditional on one control per profile. This fixed-pool package comparison supports closing the experiment as a negative/tradeoff result, without deployment readiness, conversational-prompt attribution or real-week aging claims. It changes neither historical attempt total nor prior study interpretation.

The class-balanced and mean-category studies use the same exact live balanced model as their independent base. Its fresh semantic validation recall/specificity is 51.79%/31.44%, compared with 89.89%/29.01% for the full pipeline. On reused development, those rates are 55.30%/31.93% and 91.67%/28.99%, respectively. Pipeline recovery therefore must not conceal weak semantic-model quality. Profile names and parameter counts are not quality rankings.

The measured reports retain model identities, parameter counts and trainability, semantic and pipeline confusion counts, recall, specificity, precision, F1 and balanced accuracy, originating-dataset supports, paired prediction changes, training coverage, held-out guards and objective audits. The [model quality assessment](model-quality-assessment-20261006.md) explains the measured baseline and the evidence still missing for contextual actions, calibration and generalization. The [training-signal diagnosis](fuzzer-training-signal-diagnosis-20261006.md) records the next untested hypothesis. Losses describe optimization; metrics describe measured behavior. Mean-category task losses are separately labelled from the legacy classification-distance diagnostic and differently scaled historical losses. Rejected updates receive no invented accuracy.

[Dataset-centred recalculation](dataset-review-20261006/results-by-dataset.md) covers the preserved earlier configurations. [Complete stratified tables](dataset-review-20261006/all-stratified-results.md) retain their source-level results. Each newer study's measured quality report supplies its own dataset breakdown and model identities; results from different checkpoints must not be silently pooled. [Comparison datasets from other papers](dataset-review-20261006/comparison-datasets.md) and [the evidence record](dataset-review-20261006/evidence-and-reproduction.md) document prospective comparison choices and constraints.

Poor performance on a sampled source does not establish a defective dataset. Annotation-presence labels do not establish contextual severity, visibility, appropriate action or complete span recovery. Training targets are provisional, the encoder originates in seeded initialization, and these experiments reuse exploratory validation/development partitions. Calibration, representative production latency, untouched generalization and statistical superiority remain unestablished. The protected final examples and labels remain uninspected and unscored. Historical studies restored original serving models/images; the later isolated matrix's resources were retired after audit, preserving raw evidence and shared resources. No research artifact is promoted by these notes. The historical six-grid reports left the paper unchanged during their original work.
