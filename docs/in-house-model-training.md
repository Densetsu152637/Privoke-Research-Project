# In-house model training status

This page preserves the historical model/training baseline at source revision
`16095e62d2b2f286977e87126a1c17ff468dc8e1` and records an earlier synthetic
mechanics verification at source revision
`b48159cdbab5e5966b4efdd2aacf1cfcf8f6525e` (4 October 2026). The prospective
in-house training plan remains a draft. PriVoke's transformer work uses randomly
initialized repository-owned weights; it does not use external pretrained
weights, hosted model weights, or external language-model APIs as a training
source.

## Current transformer artifacts

`models/generate_baseline.py::initial_parameters` creates token and position
embeddings, attention, and feed-forward tensors from seeded NumPy randomness.
Its `TRAINABLE` set contains only the six sensitivity, visibility, and category
head tensors. `bootstrap_heads` updates those heads on the script's small
synthetic phrase curriculum; encoder tensors remain fixed at their random
initialization. This is head-only bootstrap fine-tuning, not end-to-end encoder
training or language-model pretraining.

The generator's three named source configurations are:

| Profile | Model ID | Vocabulary | Hidden | Intermediate | Context tokens | Encoder layers | Attention heads |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Efficient | `privoke-efficient` | 512 | 24 | 48 | 64 | 1 | 2 |
| Balanced | `privoke-balanced` | 512 | 32 | 64 | 96 | 2 | 4 |
| Quality | `privoke-quality` | 768 | 32 | 64 | 128 | 3 | 4 |

These are configured artifact dimensions, not evidence that a larger profile
performs better. Profile names and parameter counts do not establish accuracy,
contextual quality, or generalization.

The streamed semantic runtime executes the compact classifier locally. Its
current runtime update path computes classification-head deltas; the fuzzer
receives bounded parameter updates rather than model weights. In
`compute_semantic_gradients`, an example with `target=None` uses the model's own
prediction as a target, so that example is not independently labeled supervised
ground truth. Do not describe this path as encoder training.

The separate sparse `annotation_presence` profiles are word/character TF-IDF
features with a logistic head. Their offline fitting and online head updates do
not train the transformer encoder. Their strict boolean labels say only whether
the source example is annotated as containing PII; they do not supply contextual
sensitivity, visibility, category, or ALLOW/WARN/BLOCK truth.
Their measured fit and fixed update-attempt outcomes are reported separately in
[sparse presence profile results](presence-model-improvements.md); the related
[model-refactor protocol](../paper/research/model-refactor-protocol.md) covers
that sparse presence study, not scratch transformer training.

`LocalClassifier` and `OpenClassifier` are optional inference backends. They are
separate from the repository-owned streamed transformer and are not part of the
in-house training path described here.

## Current implementation and verification

The offline CPU trainers are implemented in
[`in_house_transformer_training.py`](../evaluation/privoke_eval/in_house_transformer_training.py)
and
[`in_house_presence_training.py`](../evaluation/privoke_eval/in_house_presence_training.py).
The combined contextual and binary CPU mechanics suite passed 22 synthetic tests
with PyTorch `2.10.0+cpu` and NumPy `1.26.4`, covering forward/backward
behavior, finite gradients, profile handling, export, and rollback. A separate
export test covers six profile/mode combinations (three profiles by head-only
or full-encoder mode) and exercises artifact and parameter-stream codecs against
the runtime wrapper using synthetic inputs. This is not a live Go RPC or
full-pipeline parity test. These mechanics checks do not fit research data or
measure accuracy.

The pure eight-arm analysis and selection contract, live-validation structural
verifier, paired component-bootstrap analysis, and protected-data blind-review
bindings are implemented and synthetically tested. The integrated Linux
evaluator ran 464 cases at source revision `7029a937b2e10c9c1315762610224e0e24a08a58`:
462 passed and two intentional platform-branch cases were skipped in 148.475
seconds. Earlier 393-case counts are historical. A dedicated train-only image
built from source revision `6289fba704ec2d93570dc6987f0c584928ac7e0b` was
separately verified to import code whose recorded source hashes match the
integrated checkout at `7029a937b2e10c9c1315762610224e0e24a08a58`; the image was
not rebuilt from that revision. It ran as UID/GID `65534:65534` and mounted no
host data, model weights, or source tree. Its fitter suite ran 20 synthetic
cases: 19 passed and one unsupported
platform branch was skipped. Preparation and raw-evidence collector suites
passed 26 and 25 synthetic cases, respectively. These counts validate bounded
implementation mechanics, not labels, model quality, or a research fit.

The corrected AdvPIIBench preparation I/O source passed its focused independent
review and Linux synthetic checks. This supersedes the earlier blocked I/O
revision; it does not mean actual review packages or labels exist. A private
fixture protection artifact was built and its protection metadata verified.
The 104,728-row structural scan is complete; the subsequent full review-package
preparation, twelve-input/protection freeze, actual review packages, provisional
labels, allocation, and training partitions remain pending. Passing synthetic
tests do not establish clean-data eligibility or model performance.

These mechanics do not change the served transformer updater. The online update
path still updates the six classifier-head tensors and enforces the existing
per-gradient-tensor limit. The offline full-encoder path is separate from the
binary `annotation_presence` classifier and does not make that classifier a
contextual model. See the still-draft
[prospective study plan](in-house-transformer-study-plan.md) and the
[training module](../evaluation/privoke_eval/in_house_transformer_training.py).

## Prospective end-to-end training direction

The proposed in-house mechanics direction is a separate offline CPU training
path for the repository's randomly initialized transformer. In this context,
*end-to-end* means optimizing the encoder and task head together on an explicitly
labeled supervised objective. It does not mean that PriVoke has a generative
language model, that it performs self-supervised language-model pretraining, or
that it uses externally pretrained weights. The existing sparse-presence
protocol does not authorize this transformer fit; a real training experiment
requires its own prospectively reviewed protocol.

The differentiable trainer, isolated training image, and mechanics tests have
since been added and mechanically tested, but no research-data fit or resulting
accuracy measurement exists. Work remains separate from the existing head-only
fuzzer updates and sparse-presence study. Before any fit is treated as evidence,
the design requires:

- independent train/validation/test groups and explicitly reviewed labels for
  the chosen task; no reuse of development or locked final rows for fitting;
- a differentiable forward pass outside the serving method's inference mode,
  independent trainable Torch parameters, finite-loss/gradient checks, and
  round-trip parity with the runtime's serialized inference;
- a training-only CPU Torch environment with pinned dependencies; ordinary
  serving dependencies should remain separate from that training dependency;
- frozen tokenization, model configuration, seed, stopping limits, thresholds,
  selection rule, and artifact format, with complete provenance and failed-run
  records.

The current draft proposes comparing a head-only random-encoder arm with an
end-to-end random-encoder arm under the same tokenizer, initialization, and
prospectively reviewed grouped data. It is not an accepted protocol, a result, or
permission to score data before the separate data and protocol gates pass.
Research-data fit, resource use, and performance remain unmeasured for this path.

## Labels, publication limits, and claims

Binary annotation-presence labels cannot train or validate contextual severity,
visibility, category, masking, or action behavior. Do not map an `ABSENT` result
to a clean or safe prompt, or report presence metrics as contextual-pipeline
improvement. The current project development result remains 90.53% recall and
29.41% specificity, below the 90% specificity target; locked final data remain
unscored. A new representation does not resolve that gap without the required
full-pipeline evidence.

The online update service permits at most 4,096 values in one gradient tensor.
For example, the balanced token embedding has shape `[512, 32]` (16,384 values)
and exceeds that per-tensor bound. The current update mapper has no reviewed
atomic chunk-assembly contract for a full-encoder update. Keep end-to-end fitting
offline; do not split an embedding update into independent published deltas or
raise transport limits without a separately reviewed, versioned contract.

**Current wording:** “The generated PriVoke transformer uses a seeded random
encoder and head-only synthetic bootstrap; it is not initialized from external
pretrained weights.”

**Use only after implementation and experiment gates pass:** “We trained the
randomly initialized PriVoke encoder and task head end-to-end on [approved task
and grouped training data], selected [checkpoint] on the frozen validation
partition using [predeclared rule], and report the untouched test results in
[archived run manifest].” Replace every bracket with verified run evidence; do
not use this sentence for the existing head-only or sparse-presence results.
