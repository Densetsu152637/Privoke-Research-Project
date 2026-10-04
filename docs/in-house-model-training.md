# In-house model training status

This page distinguishes the models and training paths present in source revision
`16095e62d2b2f286977e87126a1c17ff468dc8e1` from an accepted in-house training
design that is still being implemented. PriVoke's transformer work uses randomly
initialized repository-owned weights. It does not download or use external
pretrained weights, hosted model weights, or external language-model APIs as a
training source.

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
[sparse presence profile results](presence-model-improvements.md).

`LocalClassifier` and `OpenClassifier` are optional inference backends. They are
separate from the repository-owned streamed transformer and are not part of the
in-house training path described here.

## Accepted end-to-end training direction

The accepted [model-refactor protocol](../paper/research/model-refactor-protocol.md)
proposes a separate offline CPU training path for the repository's randomly
initialized transformer. In this context, *end-to-end* means optimizing the
encoder and task head together on an explicitly labeled supervised objective. It
does not mean that PriVoke has a generative language model, that it performs
self-supervised language-model pretraining, or that it uses externally pretrained
weights.

At the source revision identified above, the differentiable trainer, its
training-only dependency/image, end-to-end mechanics tests, and a resulting fit
are not present. Work on that implementation is separate from the existing
head-only fuzzer updates and sparse-presence study. The design requires, before
any fit is treated as evidence:

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

The proposed first experiment compares a head-only random-encoder arm with an
end-to-end random-encoder arm under the same tokenizer, initialization, and
approved grouped data. It is a proposal, not a result or permission to score a
dataset before the separate data and protocol gates pass. Training feasibility,
resource use, and performance remain unmeasured for this path.

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
