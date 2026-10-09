# Synthetic prompt generation for continual fuzzer training

PriVoke should expand its reviewed contextual scenarios first, use a separate
teacher model to diversify their wording, and then mine constrained hard cases
from permitted training pools. These methods can expose missing coverage while
keeping supervision traceable. More generated rows or accepted updates do not
establish improved detection. The six contextual grids completed on 6 October
produced 126 attempts without a retained qualifying model under their study
criteria. A separate six-hour study completed on 9 October and measured repeated
training against a binary annotation-presence endpoint; its mixed profile
results do not establish contextual quality or support model promotion. See the
[six-hour study report](long-fuzzer-results-20261009.md).
[Current study outcomes](model-quality-study-index-20261006.md) and
[training-signal diagnosis](fuzzer-training-signal-diagnosis-20261006.md).

This recommendation concerns contextual privacy classification, including
sensitivity, visibility, categories and required actions. Binary annotation
presence is a separate objective. The comparison below uses primary research
and the implementation at base revision `4b5508b1b9e1b6dbaa85778d8119b31c727ae56c`,
with the automatic-requester changes described below. Research date: 9 October
2026. No detector-quality result is implied by the scheduler change. The later
[audited curriculum comparison](fuzzer-curriculum-improvement-process-20261009.md)
completed 63 cells and tested a revised contextual package, persistent seeded
allocation, replay weighting and a separate offline representation comparison.
It measured gains and losses but retained no qualifying candidate. Teacher-model
paraphrases and reviewed failure-guided mining remain prospective and were not
tested in that matrix. Its targets remain assistant-provisional. The historical
combined-detector studies retain their original scope; current and future LLM
comparisons use explicit semantic-only requests and validate returned execution,
following the user's later instruction and the repository policy.

## Automatic training behavior

Normal service and production, development and Compute Engine Compose defaults
now request 32 training prompts after startup, then another cycle 3,600 seconds
after completion or exhausted retries. New cycles use new request IDs and
increment the seed; retries preserve both. Count `0` disables the requester;
interval `0` selects one startup cycle. Existing explicit settings take
precedence. The sequence restarts at the configured seed on process restart and
does not guarantee novel texts. Candidate quality gates, durable receipts and
the runtime training boundary remain in place.
[Requester](../services/param-update-service/app/fuzzer_requests.py) and
[configuration](README.Parameter-update-service.md#fuzzer-requests).

Controlled experiments must include `evaluation/compose.tests.yml` and their
study-specific overlays, or explicitly disable the original updater too.
Some study overlays disable only their additional study updater. Background
training would change the reference model and confound a matched comparison.
Existing running containers need rebuilding/recreation for the new code and
configuration to take effect. Accepted updates change persistent model files;
the development stack writes into its bind-mounted `models` directory.

## Methods and evidence

The integration column proposes applications to PriVoke. The cited studies
establish methods or results in their own tasks, not a privacy-detector gain.

| Method | Primary evidence | Proposed integration | Main limitation |
| --- | --- | --- | --- |
| Structured grammar and contextual contrast pairs | CheckList, ACL July 2020, sections 2.2–2.3, uses capability matrices, templates, lexicons, invariance and directional tests. [Paper](https://aclanthology.org/2020.acl-main.442.pdf) | Extend scenario facts beyond slot vocabulary. Pair fictional/public/consented examples with private disclosures, changing one decisive fact at a time. | Behavioral testing does not establish a training benefit. Contextual targets require an independently reviewed rubric. |
| Teacher-generated examples and paraphrases | Self-Instruct, ACL July 2023, section 2.2, generates instances and filters invalid/similar items before tuning pretrained GPT-3. [Paper](https://aclanthology.org/2023.acl-long.754.pdf) | Generate realistic chat, email and document forms offline from reviewed scenario facts, then approve JSONL for the existing loader. | Its instruction-following results cannot transfer directly to PriVoke. The authors' 200-instance audit found every field valid in only 54%; generated supervision needs review. |
| Diversity and controlled complexity evolution | WizardLM / Evol-Instruct, first preprint April 2023, revised v3, 27 May 2025, section 3.2, evolves instruction breadth and depth. [Paper](https://arxiv.org/html/2304.12244v3) | Expand domains and formats; add negation, references, third-party information and mixed public/private material in controlled steps. | More complex text can change the label or put decisive facts beyond the model's context window. Evidence concerns pretrained generative models. |
| Failure-guided mutation and hard negatives | TextAttack, EMNLP October 2020, separates goal, constraints, transformation and search. [Paper](https://aclanthology.org/2020.emnlp-demos.16/) | Mine false positives and misses from reviewed TRAIN families; search constrained variants through existing prompt probes, then retain independently validated targets. | An evasion is not proof of a correct label. Optimizing only difficult or unnatural failures can distort the input distribution. |

Unchecked recursive replacement is a poor default. Shumailov et al. report
degradation in recursively generated training regimes, including language-model
experiments. Gerstgrasser et al. provide counterevidence: accumulating original
and successive synthetic data avoided collapse in their tested settings. Together
these support preserving a reviewed reference corpus and testing retention;
neither establishes an optimal replay fraction or proves that PriVoke will
collapse or improve. [Nature, July 2024, with 2025 correction](https://www.nature.com/articles/s41586-024-07566-y)
and [Gerstgrasser et al., April 2024, version 2](https://arxiv.org/abs/2404.01413v2).

## Current constraints that change the recommendation

The default generator fills fixed templates with vocabulary choices and includes
fixed bootstrap calibration phrases. Each cycle separates its held-outs by
normalized text and, where supplied, source group. Different seeds can assign a
past held-out example to later training; current-cycle disjointness is not a
permanent independent evaluation split. Calibration also overlaps bootstrap
supervision. Every new scenario family therefore needs a permanent split before
its descendants are generated. [Generation](../services/privoke-fuzzer/src/prompt_generation/generator.py),
[defaults](../services/privoke-fuzzer/src/prompt_generation/defaults.py).

The trainer preserves targets through transformations, while available
transformations include redacting names and email. Removing the only identifier
can change the appropriate category, sensitivity or presence target. This is a
label-preservation risk inferred from the code, not a measured cause of prior
failures. Use verified invariant transformations; directional changes need new
labels. [Trainer](../services/privoke-fuzzer/src/training/trainer.py),
[transforms](../services/privoke-fuzzer/src/training/transforms.py),
[existing curriculum guidance](../evaluation/README.md#learning-rate-and-false-positive-development).

The historical 2,300-row contextual curriculum contains 2,129 public
annotation-negatives, 43 bootstrap examples and 128 authored contextual rows.
Absent annotations do not establish contextual S0/PU truth. The existing
`ComputeSemanticGradients` contract requires contextual targets;
`ComputePresenceGradients` trains a separate binary head. Keep weak presence
supervision on that separate path unless a new versioned objective explicitly
masks all contextual losses for weak rows.
[Training-signal diagnosis](fuzzer-training-signal-diagnosis-20261006.md).

The default contextual update freezes the seeded encoder and trains the heads.
The balanced profile has only 95 content tokens after serving normalization, so
long synthetic documents can hide decisive facts. Better generation cannot
guarantee that a frozen representation learns a missing relationship. Test a
matched trainable-representation arm as a competing explanation for a plateau.
[Semantic classifier](README.Semantic-classifiers.md),
[diagnosis](fuzzer-training-signal-diagnosis-20261006.md),
[paper limitations](../paper/main.tex).

## Proposed integration sequence

1. **Build a reviewed scenario grammar.** Represent subject relationship,
   identifiability, disclosure status, consent, domain, category, format and
   language as explicit facts. Authors and independent reviewers assign
   contextual targets using the same rubric. Generate public/private and
   real/fictional contrast pairs; preserve ambiguous cases for adjudication.
   A public mention of a condition and a disclosure of a relative's diagnosis
   must not acquire identical targets merely because both contain health words.

2. **Prepare approved curricula outside the serving loop.** An offline generator
   should record parent/family IDs, scenario facts, generator version, random
   seed, teacher model/prompt revision, label-rubric version and review status.
   Validate facts, label schema, normalization, protected overlap and token
   visibility. Deduplicate exact text and screen near duplicates without
   assuming a similarity score proves independent meaning. Teacher agreement
   can prioritize review; it cannot establish truth. Only approved rows enter
   an immutable, hashed JSONL curriculum.

3. **Use the existing fuzzer boundary.** Approved contextual rows can already
   use `text` or `template`, `packed_classification` or a classification object,
   and `metadata.group_id` through `FUZZ_PROMPT_DATASET_PATH`. Include parent,
   generator and rubric identifiers in string metadata. Extend
   `prompt_generation/generator.py` with a versioned coverage/quota policy
   rather than adding external generation to `train_parameter_batch`.
   Keep `ComputeSemanticGradients`, the fuzzer publication checks and updater
   receipts as the training/publication boundary. Teacher calls should happen
   during preparation, with explicit model access and cost limits, rather than
   on every scheduler tick.

4. **Add persistent curriculum and retention state.** Declare a reviewed replay
   buffer covering clean controls, sensitive disclosures and rare categories.
   The accepted curriculum path now persists its manifest-bound allocations and
   cursors, supports explicit stable seeded-family allocation, and supplies fixed
   guard/replay splits. The ordinary requester can pass the configured sampler
   policy/seed; legacy deterministic behavior remains the default. This is distinct
   from the trainer's separate golden-example input. The completed matrix varied
   replay weight at a fixed 25% replay allocation; it did not select an optimal
   replay ratio. Freeze any future ratio and retain a fixed family-disjoint gate
   rather than rotating evaluation examples into training. See the
   [implemented controls and exposure audit](fuzzer-curriculum-improvement-process-20261009.md).

5. **Introduce reviewed hard-case search.** Probe only permitted TRAIN families
   through `AnalyzePrompt` with explicit semantic-only layer selection and
   validation that exactly the semantic layer executed. Prioritize
   clean false positives and missed private disclosures, then mutate with
   explicit semantic constraints and bounded search depth. Keep some broad
   exploration to avoid a failure-only curriculum. Send disagreements to review;
   do not make the detector's own prediction its label. Never mine protected
   final data or select/relabel examples from recurring publication-gate errors.

6. **Measure gains before changing the generation policy.** Automatic normal
   training stays separate from a frozen experiment. Use independent family
   splits, exact model/rule snapshots and equal budgets. Promote a policy only
   after the agreed detector-quality criteria and retention checks pass.

All descendants of a scenario, document or teacher parent must remain in their
parent's assigned split. Use only permitted opaque exclusion indexes for the
protected union; do not read final examples to construct, label or tune a
curriculum. The legacy public-negative preparation entry point reads protected
partitions and must not be reused for this work.
[Preparation restriction](fuzzer-training-signal-diagnosis-20261006.md).

## Experiment to test improvement over time

Use four matched arms: reviewed templates; templates plus teacher paraphrases;
the same with controlled breadth/depth evolution; and the same with constrained
failure-guided mining. These are future arms, distinct from the completed
curriculum/sampler/replay/representation matrix. Freeze the exact base, semantic serving
normalization, learning rate, trainable tensors, replay fraction, publication
guards and per-arm generation/training budgets. Compare independent single
cycles and a declared multicycle sequence. A practical initial design is five
independent seed sequences of ten cycles, with 256 source rows per cycle and
the same replay fraction and fixed guard in every arm. Those counts are a
proposed resource allowance, not a powered sample-size calculation or the
normal deployment's 32-row setting. Count effective training rows after
transformations and teacher/search cost too.

Separate accepted/rejected updates from qualified models. Report semantic-only
recall/specificity, contextual target correctness, required-action
failures, newly introduced clean interventions, retained-anchor performance,
unique families and coverage cells, per-domain results, and cost/latency per
cycle. Include unchanged and deteriorating outcomes. Pair comparisons by source
family and show uncertainty; repeated seeds and RPCs are not independent prompts.

The current amended LLM criterion requires at least 90% semantic recall, strict
semantic specificity improvement against the declared fresh reference, no decline
in semantic joint sensitivity/visibility/category-set exact agreement, and no new
or worsened casewise action harm in the 41 quantitative provisional contextual
fixture cases. It replaced the historical pipeline criterion after 15 cells had
been observed; preserve that disclosure and predeclare any future study criterion.
It is not a safety certification. Reused development results remain
exploratory. Select without accessing protected final, then freeze the model and
analysis before an authorized final evaluation. Product pipeline or detector
ablation testing requires a separately authorized scope and separate results.
[Quality criteria](model-quality-study-index-20261006.md).

The completed matched head-only/full-representation comparison found higher
specificity and S0-control exactness for balanced and quality full training,
alongside lower development recall and casewise harms. It retained no qualifying
candidate. Future teacher/mining experiments should use this bounded evidence to
design independent controls and reviewed targets before increasing volume;
periodic training alone does not establish better classification.
