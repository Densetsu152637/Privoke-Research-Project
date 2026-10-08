# Manuscript architecture update — 8 October 2026

## Scope and revision

The author requested that `paper/main.tex` match the current architecture and that weak sections be changed or expanded without shortening the introduction. The starting point was the author's already modified working-tree manuscript, not the version at Git HEAD. The reference manuscript and unconsolidated Results placeholder were preserved.

Base checkout: `feat/dev-testing`, HEAD `48e059a6c6d396b13942068a3d6a18730e8d484f`. Updated manuscript SHA-256: `eea9eff0e092ea6978df9959e96134e7d01cb408f8a361c759dcfa3f512fa3e2`.

## Questions and evidence ledger

| Question | Manuscript treatment | Decisive evidence and boundary |
| --- | --- | --- |
| What is the central contribution? | Abstract, Introduction and research gap emphasize guarded cloud training, publication and redistribution to local classifiers. Improvement remains an empirical question. | [Prior critical review](../../docs/paper-critical-review-20261008.md), [contribution](contribution.md), and [Casper v1](https://arxiv.org/html/2408.07004v1). Layered local inspection has precedent; this is not an exhaustive novelty search. |
| Where does training occur? | Architecture separates workstation inference, server-runtime gradient computation, fuzzer orchestration and updater publication. | [Fuzzer service](../../docs/README.Fuzzer-service.md), [updater](../../docs/README.Parameter-update-service.md), runtime `LLM/privoke/training.py`, fuzzer `training/trainer.py`, and shared `privoke_model/contextual_training.py`. Default head updates, opt-in last-block updates and offline full-encoder mechanics remain distinct. |
| How do clients receive revisions? | Snapshot identity, validated tensor streaming and request-triggered cache refresh are explicit. | [Model streaming](../../docs/README.Model-streaming-service.md), runtime `LLM/privoke/streamed_model.py`, and `LLM/privoke/parameter_stream.py`. Publication does not establish instantaneous fleet-wide refresh. |
| What does enforcement protect? | PII policy and new threat model distinguish original-body ALLOW/WARN forwarding, BLOCK cancellation, masking evidence, outage behavior and unsupported paths. | Runtime `classification/classification_policy.py`, `pipeline.py`, browser `page-interceptor.js`, and [browser documentation](../../docs/README.Browser-extension.md). This edit is a source audit, not an observed deployment test. |
| What does telemetry protect? | Five-field nominal event-tuple LDP proof, composition budget, assumptions and excluded observables replace broad privacy claims. | [Telemetry scope review](telemetry-scope-review.md), runtime `telemetry/privacy.py` and `telemetry/event_emitter.py`. Finite-sampler certification and aggregate utility remain unverified. |
| How is adaptation evaluated? | New methodology separates annotation presence, contextual labels, policy actions and transmission, including contamination controls, matched comparisons and study-specific uncertainty. | [Methods draft](../../docs/research-methodology-draft.md), [initial fuzzer specification](../../docs/fuzzer-model-study-20261006.md), [study report](../../docs/fuzzer-model-results-20261006.md), [cascade report](../../docs/contextual-cascade-results.md), and [protocol](protocol.md). Reports were used to describe methods and limitations; no numerical performance results were consolidated into the manuscript. |
| Are literature comparisons fair? | Local filtering precedent is credited; unsupported collective DP attribution to Casper, HaS and ProSan was removed. | Primary texts opened: [Casper](https://arxiv.org/html/2408.07004v1), [HaS](https://arxiv.org/html/2309.03057v1), [ProSan](https://arxiv.org/html/2406.14318v1). The preserved introduction's older citations were not exhaustively re-audited. |

## Validation and review acceptance

- All original top-level sections and five contribution bullets remain. The first two Introduction paragraphs are unchanged. Introduction whitespace-token count, including TeX, increased from 708 to 955; this is not a rendered prose word count.
- Results is unchanged. `paper/reference.tex` retains SHA-256 `d52ae53efda6d55c922c73c15df9a31b4aa54b0e17638d6ecbf036a928d86db4`.
- Source checks passed for balanced braces/environments, unique labels, resolved internal references and existing bibliography keys. `git diff --check` passed after trailing-whitespace cleanup. These checks do not establish compilation or visual layout.
- Two independent critic assignments reviewed manuscript hash `b1a54f1cc59ed524727aa2331c72723271fa30b9ac142002a6c8b2f59ab243e9`. The architecture/evidence critic reported no consequential findings. The framing critic identified one sanitizer/DP attribution defect and advised sharpening the contribution wording. Root accepted both reviews and verified the narrow repairs at manuscript lines 45, 62 and 97; the remainder of the reviewed manuscript is unchanged.
- Built-in LaTeX compilation was attempted on 8 October 2026. Preview preparation failed before compilation with `windows sandbox: helper_unknown_error: setup refresh had errors`. No rendered PDF or compilation success is claimed.
- No experiments were rerun, final prompts or labels were accessed, application code was changed, or commits were created. Final scoring, human contextual adjudication, representative installed-browser measurements and PDF verification remain separate work.

This revision includes AI-assisted manuscript editing. Authors should verify the text and track disclosure under the eventual venue policy. Worker token usage and cumulative session token telemetry were unavailable through the host interface.
