# Critical review of the PriVoke reference manuscript

Reviewed 8 October 2026 for the authors and research supervisor. The manuscript assessed is `paper/reference.tex`, at repository revision `48e059a6c6d396b13942068a3d6a18730e8d484f`. Supporting experimental evidence comes from the repository documents, particularly the 6 October model studies. This review follows the repository research workflow.

**The reference manuscript needs major revision even when the unfinished results section is excluded.** It explains a worthwhile problem and a plausible system, but currently reads as a proposal and service overview rather than a sufficiently specified research paper. The most consequential weaknesses are an unclear contribution beyond Casper, a missing methods section, and claims that exceed the implemented mechanisms or the quantities evaluated. The repository's protocols and evidence reports are substantially more rigorous than the manuscript.

The expected-results section at manuscript lines 169–194 is excluded from assessment. Missing numerical tables, illustrative result figures and a result-dependent conclusion receive no penalty. Existing development findings are used to check whether the introduction and design claims are defensible, not to demand that those findings already appear in the paper. Threat assumptions, label definitions, experimental methods and limitations can be specified before results are consolidated and remain within scope. No manuscript changes are applied by this review.

## Assessment of the nonresults sections

| Dimension | Assessment | Reason |
| --- | --- | --- |
| Problem and motivation | Clear, but too broad | Accidental prompt disclosure is well motivated. Some incident examples involve assets outside the proposed interception boundary. |
| Contribution and novelty | Major revision | Endpoint filtering and the three detector layers substantially overlap prior work; the distinctive empirical question is insufficiently stated. |
| Related work | Major revision | The review lists techniques but relies on broad assertions about static systems and adaptation. It needs direct comparisons of tasks, mechanisms and evidence. |
| Design and implementation | Major revision | Service responsibilities are understandable, but masking, model training and streaming descriptions disagree with the documented implementation. |
| Methodological specification | Missing from the reference manuscript | Data, labels, splits, baselines, selection, training and uncertainty are not defined in a methods section, despite substantial material already existing in the repository. |
| Threat and privacy guarantees | Major revision | The trusted boundary, supported request paths, action semantics and exact telemetry privacy unit are insufficiently specified. |
| Writing and organization | Readable early draft | The prose communicates intent, but repeats motivation and broad benefits where a precise argument and mechanisms are needed. |

The useful foundations should be retained: pre-transmission intervention addresses a concrete disclosure opportunity; the client/server separation is understandable; sensitivity, visibility and category are sensible dimensions to distinguish; and the repository preserves negative findings rather than hiding them. Artifact identities, matched examples, source grouping, update guards and protected final evaluation are substantive research strengths in the supporting documents. They need to become visible methods in the paper.

## Research questions and evidence ledger

The review asks whether a reader can identify a distinct contribution, reproduce the evaluated treatment, understand the protection boundary, and distinguish observations from hypotheses. The ledger separates high-confidence documentary discrepancies from unresolved empirical explanations.

| ID | Question and assessment | Manuscript locator | Supporting or opposing evidence | Confidence and unresolved boundary |
| --- | --- | --- | --- | --- |
| E1 | Is the contribution distinct? Architectural overlap is substantial. | Lines 64–70, 111–131 | Casper v1 §§5.1–5.3; `paper/research/contribution.md:3–14` | High for overlap; novelty across the entire literature remains unresolved. |
| E2 | Does telemetry drive learning? The documented paths are separate. | Lines 125, 131, 158 | `docs/services/fuzzer.md:25–42`; `paper/research/telemetry-scope-review.md:60` | High for the documented implementation; a future feedback mechanism would require specification and evaluation. |
| E3 | Is contextual privacy the measured target? Large-sample evidence primarily measures annotation presence. | Lines 45, 68, 137 | `docs/research-methodology-draft.md:37–42`; `docs/contextual-cascade-results.md:74–78` | High; representative independently reviewed contextual truth is unresolved. |
| E4 | Is the study reproducible from the manuscript? Methods are missing and model identity is vague. | Lines 137, 150–166 | `docs/research-methodology-draft.md:19–25,50–103`; `docs/model-quality-assessment-20261006.md:23` | High for reporting omissions; this does not invalidate all documented experiments. |
| E5 | Do tested updates support continuous improvement? The evidence is mixed or negative. | Lines 70, 119, 125, 131 | `docs/model-quality-study-index-20261006.md:7–20`; `docs/fuzzer-model-results-20261006.md:22–43` | High for the tested grids; no conclusion that all adaptation methods fail. |
| E6 | What is prevented before transmission? BLOCK cancels supported requests; WARN forwards original content. | Lines 45, 60, 66, 146 | `docs/runtime/browser-extension.md:28,198`; `extension/src/page-interceptor.js:23–35` | High for source/document agreement; full deployment coverage remains unestablished. |
| E7 | What does telemetry protect? A nominal event-tuple mechanism has a narrower scope than de-identification. | Lines 99–103, 158 | `paper/research/telemetry-scope-review.md:19–43`; `shared/proto/privoke/v1/telemetry.proto:43–47` | High for the stated mechanism and exclusions; exact finite-sampler certification and monitoring utility remain unresolved. |
| E8 | Are the literature and motivation claims appropriately bounded? Several generalizations require narrowing. | Lines 58, 113, 123, 129 | Declared boundary in `paper/research/contribution.md:18–45`; Casper v1; InferDPT v8 | High for the scope mismatch; no exhaustive literature or incident audit is claimed. |

## Findings requiring substantive revision

### Establish a contribution beyond the layered architecture

The contributions at lines 64–68 emphasize endpoint framing, local browser protection and rules/NER/semantic detection. Casper already describes local browser inspection with those three kinds of detector. A citation acknowledging Casper does not explain what new question PriVoke answers. The claim at lines 111–131 that existing systems lack adaptive mechanisms is stronger than the reviewed sources establish; Casper also permits customized rules. Distinguish user customization from learned updates rather than treating every prior pipeline as immutable. These comparisons concern the pinned [Casper preprint, sections 5.1–5.3](https://arxiv.org/html/2408.07004v1), not a matched performance reproduction or an audit of its published version.

The strongest candidate argument is a controlled study of whether bounded synthetic updates improve a local detector, and how layer aggregation changes that benefit or its harms. Risk/action policy and locally randomized monitoring can support that argument, but their implementation alone does not establish novelty. Reduce the five capability-oriented contribution bullets to two or three specific research contributions, each connected to a question and a corresponding analysis.

### Separate monitoring from the learning mechanism

Lines 125 and 131 imply that private telemetry and adaptive refinement together continuously improve detection. The documented fuzzer trains from generated or prepared labeled examples. Telemetry contains randomized marginal summaries of the detector's own outputs; it does not contain prompt features or corrected labels, and its model-release mapping removes training suffixes. The scope review explicitly states that telemetry is not connected to examples, gradients or federated learning. See the [fuzzer guide](services/fuzzer.md), lines 25–42, and [telemetry scope review](../paper/research/telemetry-scope-review.md), lines 9 and 60.

This is a missing mechanism, independent of result consolidation. Prediction counts alone cannot identify which predictions were wrong. Describe aggregate monitoring and synthetic updates as separate functions. If a telemetry-guided learning contribution is intended later, specify the estimable signal, correctness source, selection rule, privacy boundary and a comparison with the same update budget without that signal.

### Define what contextual privacy means and what each experiment measures

The abstract and categorization paragraph promise context-dependent sensitive-disclosure detection. The primary binary evaluation instead measures whether an entity was annotated, with a positive prediction defined by sensitivity or category output regardless of ALLOW/WARN/BLOCK. Public names and dates can be annotated; missing annotations do not independently establish that a whole prompt is harmless. These are legitimate annotation-presence experiments, but they cannot validate contextual sensitivity, visibility, action correctness or prevented transmission. See the [methods draft](research-methodology-draft.md), lines 37–42.

The contextual fixture is useful for illustrative cases and regression checks, but its 41 quantitatively evaluated cases have assistant-provisional labels, with seven ambiguous cases excluded. Independent human adjudication remains pending. Existing required-BLOCK failures can remain even when no additional failure is introduced. See [contextual cascade results](contextual-cascade-results.md), lines 74–78. A relative no-regression guard is not an absolute protection certificate.

Define sensitivity levels, visibility evidence, category assignment and policy separately. Explain how unknown visibility is handled and how confidence changes actions; do not imply that model confidence is calibrated. The visibility list at line 137 also omits implemented `P4` ([shared contract](../shared/python/privoke_contracts/classification.py), lines 22–28). Add contrasting examples such as public biography versus private disclosure, and generic health discussion versus linked private health information. Contextual ground truth requires a separate rubric and independent review, already proposed in the [labeling rubric](../paper/research/contextual-labeling-rubric.md).

### Put the actual experimental methods into the paper

The reference manuscript moves from a one-paragraph taxonomy to service descriptions, then to expected results. It has no substantive account of research questions, data provenance, label construction, grouping, held-out partitions, candidate selection, baselines, update treatment or uncertainty. This omission is a problem even if every result table is intentionally deferred.

The [methods draft](research-methodology-draft.md) and [protocol](../paper/research/protocol.md) already supply much of this information: the protected final partition, matched layer comparisons, a precisely configured Presidio baseline, grouped paired analyses and model identities. Incorporate that material after checking the chronology against the later studies. The older methods draft alone cannot describe all subsequent treatments.

Retain three crucial distinctions. Repeatedly consulted validation/development data are exploratory, even when each later study freezes its own choices. Known training/validation overlap belongs to the affected historical control, not automatically to every filtered study. Within-corpus training from an upstream split named `test` requires a custom-study description rather than an untouched official benchmark-test claim. Repeated RPCs, threshold candidates and training seeds are not additional independent prompts. The cascade report also says its promised paired intervals remain uncomputed; do not silently generalize interval coverage from other experiments.

Separate a comparison with the current deployed checkpoint from the causal effect of training the same profile. The initial efficient winner's development comparison against live balanced is a replacement decision, not an isolated estimate of the update effect. Include existing simple learned text controls as well as layer ablations and the configured Presidio comparison when assessing the semantic component's value. The [sparse text control](../paper/research/text-control-results.md), lines 7–17, is relevant counterevidence to assuming that transformer complexity is necessary, but its exploratory binary results do not establish contextual or deployment superiority.

### Describe the evaluated classifier and updates accurately

Line 150 calls the semantic component the PriVoke LLM without explaining what it is. The documented balanced model is a compact transformer classifier with 36,756 parameters, a 512-entry vocabulary and a 96-token context. Its original encoder is randomly initialized and frozen, with heads bootstrapped on 43 authored examples. Head-only treatments train 660 parameters; later last-block treatments are distinct. See the [model assessment](model-quality-assessment-20261006.md), line 23, and [methods draft](research-methodology-draft.md), lines 19–25. Readers must not be left to assume pretrained language understanding or generative LLM training.

Lines 154 and 166 also misplace training responsibilities. The [fuzzer guide](services/fuzzer.md), lines 25–42, assigns fetching, model execution and gradient computation to the runtime; the fuzzer orchestrates labeled batches and submits bounded updates. The streaming API is gRPC, not the secure WebSocket transport asserted at line 162 ([streaming guide](services/model-streaming.md), lines 41–59). Rewrite the path around who sees text, who holds weights, who computes the candidate and what publication guards establish.

Describe the executed training conditions rather than the broad capability of the infrastructure. The recent 54-attempt protocol uses zero text transformations, and its sampled batches have only 6–9 sensitivity-positive cases among 256. The negative-focused curriculum contains no public annotation-positive training rows. Those choices can address a narrower false-positive question but do not by themselves test paraphrase or adversarial robustness. Representation quality, truncation, provisional labels, training exposure and small updates remain competing explanations for a plateau; the [training-signal diagnosis](fuzzer-training-signal-diagnosis-20261006.md), lines 5–24, explicitly avoids claiming a proven cause.

### Frame adaptive improvement as the question under test

Lines 70, 119, 125 and 131 make the adaptive architecture sound like an established route to improving detection. The six recent grids contain 126 attempts without a retained qualifying model. Earlier experiments include small gains and recall/specificity tradeoffs. This counterevidence should change the paper's framing without being treated as a reason to suppress an honest negative study. See the [study index](model-quality-study-index-20261006.md) and [fuzzer results](fuzzer-model-results-20261006.md).

One documented validation checkpoint illustrates why semantic and pipeline evidence must remain separate: semantic recall/specificity are 51.79%/31.44%, whereas pipeline values are 89.89%/29.01% on the same 968 rows. Those numbers concern annotation presence, not true privacy risk or user-visible intervention rates. They show that higher pipeline recall cannot simply be attributed to semantic reasoning. They are not pooled with other checkpoints and do not establish final performance. See [model quality assessment](model-quality-assessment-20261006.md), lines 7–19.

Use wording such as “we investigate whether controlled updates improve detection.” A functioning update RPC, falling loss and a passed internal guard establish different properties from generalization. Failed configurations bound conclusions about the tested treatment, not about all possible adaptive detectors. A useful paper can explain when updates fail, provided the controls and alternative explanations support that explanation.

### Specify the threat boundary and actual enforcement semantics

Lines 60 and 66 claim warning, masking or blocking. The extension's documented behavior is that ALLOW and WARN forward the original request; BLOCK cancels a supported request. Returned masked text is not automatically substituted into website traffic. This is a material difference between request gating and sanitization ([browser guide](runtime/browser-extension.md), lines 28 and 198; [page interceptor](../extension/src/page-interceptor.js), lines 23–35).

Add an explicit threat model covering the trusted workstation, extension, runtime and model publisher; supported endpoint/body/transport shapes; unsupported paths; bypass toggles; unavailable analysis; and partial-layer fallback. The [candidate contribution](../paper/research/contribution.md), lines 18–45, already supplies these boundaries. Parameter streaming to local inference and an optional hosted inference backend have different disclosure boundaries and must be distinguished.

Keep accidental submission of sensitive content as the direct motivation. The incident chain at line 58 also invokes billing exposure and exfiltration of historical provider conversations. Those assets may never pass through the outgoing-prompt filter. Their relevance is downstream context, not evidence that this defense prevents the same attack. Actual transmission prevention needs browser capture evidence; detector metrics cannot substitute for it. “Lightweight” and preserved usability should remain design objectives unless the corresponding cost and user/task outcomes are measured. Runtime service elapsed time excludes browser and bridge overhead.

### State the precise telemetry guarantee

The generic DP equation at lines 99–103 does not define the privacy unit, neighboring inputs, parameters or actual mechanism. Line 158 calls the metrics non-private and says DP de-identifies users. Risk/category/action metadata can itself be sensitive; omitting direct identifiers does not imply anonymity.

The documented mechanism applies independent generalized randomized response to five categorical fields, with event epsilon 1 by default, split equally across fields, and nominal daily accounting capped at epsilon 8 per installation. The defensible mathematical claim concerns a nominal event tuple at a fixed reporting opportunity under public configuration, trusted execution and ideal sampling assumptions. It does not protect report presence, exact counts, arrival timing or network metadata; it is not user-level privacy or private model training. Persistent ledger and clock assumptions matter, and exact finite-sampler privacy loss has not been certified. See the [telemetry scope review](../paper/research/telemetry-scope-review.md), especially lines 19–43 and 62–66. The schema explicitly exposes exact accepted counts ([telemetry protobuf](../shared/proto/privoke/v1/telemetry.proto), lines 43–47).

Describe the randomized fields, composition argument and exclusions. Useful monitoring accuracy is a separate empirical question: marginal inversion can have substantial variance and clipping can introduce bias. Keeping telemetry as a supporting mechanism allows a narrower paper without inventing a monitoring-utility or learning result.

## Smaller writing and citation corrections

The introduction repeats the privacy motivation across general adoption, incidents and the proposed system, while the background repeats parts of that material. Shorten these passages and use the space for the closest-work comparison and methods. Prefer specific design choices over unsupported “lightweight,” “robust,” “continuous” or usability language.

At line 123, replace the general claim that applying DP to prompt contents is impractical with a scoped explanation of PriVoke's own design choice. [InferDPT v8](https://arxiv.org/html/2310.12214v8), sections IV–VII, studies prompt perturbation and local extraction for closed-box generation. Its existence challenges a categorical dismissal; it does not establish suitability for PriVoke or validate its reported privacy/utility claims in this review.

Use “Chrome/Chromium extension” or “WebExtension” rather than “google extension”; standardize TypeScript, Python, protobuf and ChatGPT spelling. Resolve the submission-date placeholder when preparing a submission version. A generic IEEE class does not establish compliance with an unspecified venue. These are smaller issues than the research argument. A result-dependent conclusion can wait; limitations concerning constructs, trusted components, provisional labels and exploratory reuse can be written now.

## Recommended revision order

1. **Freeze the argument.** State the precise question about controlled updates and aggregation; credit architectural precedent and separate monitoring from learning.
2. **Reconcile design with implementation.** Correct action semantics, classifier initialization/trainability, service responsibilities, transport and local-versus-hosted boundaries.
3. **Write methods before integrating numbers.** Describe each study's task, labels, provenance, groups, base model, treatment, selection, controls, uncertainty and exclusions. Preserve exploratory and diagnostic status.
4. **Add threat assumptions and limitations.** Specify what is blocked, what is forwarded, what is bypassed and what telemetry protects. Distinguish relative guards from absolute correctness.
5. **Consolidate findings only after those decisions.** Retain null and harmful updates, attach results to exact configurations, and let the conclusion answer the narrowed question. Independent human contextual review is needed for validated contextual-action claims; otherwise retain illustrative cases and annotation-presence scope.

A suitable framing to develop is: “PriVoke evaluates the contribution and limits of controlled synthetic updates in a locally executed prompt-inspection system, separating entity-presence detection, contextual policy decisions and request enforcement.” This is a candidate argument, not a finding of superiority or an assurance of publication acceptance.

## Verification and review limits

The source reviewed has SHA-256 `d52ae53efda6d55c922c73c15df9a31b4aa54b0e17638d6ecbf036a928d86db4`. Two independent research critiques covered experimental evidence and novelty/mechanism validity; their consequential findings were checked against manuscript passages, repository documents and selected implementation paths. All 33 distinct citation keys in the reference source resolve to bibliography entries; this is a structural check, not verification that every citation supports its sentence.

Decisive arithmetic was independently recomputed: `246/475 = 51.79%`, `155/493 = 31.44%`, `427/475 = 89.89%`, `143/493 = 29.01%`, and `54+24+12+12+18+6 = 126`. Development reports remain attached to their own checkpoint and task. No final examples or labels were inspected or scored, experiments were not rerun, and raw prediction archives were not comprehensively re-audited. Casper v1 and InferDPT v8 primary full texts were opened; published-version verification and an exhaustive bibliography review remain outside this scoped assessment. This source review does not establish successful LaTeX compilation or final PDF layout quality, and it does not replace the supervisor's scientific judgment.
