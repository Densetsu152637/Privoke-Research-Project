# PriVoke research and paper completion plan

Prepared 3 October 2026. Repository review checkpoint: `f03aa1b58cf2052afd822edffc9aac6c28ef101d`, branch `feat/dev-testing`.

Execution updates are in [the current integration record](../evaluation/PROGRESS.md)
and [the evidence ledger](../paper/research/claims.md). The user clarified that test
invocation belongs in evaluation while test cases and fuzzer training remain with
their components. Development targets are >=90% sensitive recall and >=90% clean
specificity; final testing must be reported honestly and must not drive tuning.
Agent review is provisional pending professor [git4san](https://github.com/git4san)
confirmation. The initial architecture table below records the original discovery
checkpoint; current fail-closed page-hook behavior is documented in the evidence ledger.

**Revised deadline: paper ready on 19 October 2026 (Australia/Sydney).** This replaces the original eight-week schedule. Starting on 3 October leaves 16 elapsed days, or 17 calendar dates inclusive: two full weeks and a short third week. Target a complete review draft on 14 October, freeze results on 13 October, and finish the checked paper/artifact on 18 October so 19 October is reserved for delivery and essential corrections. The cutoff time on 19 October is unspecified, so do not rely on that day for core work.

## Publication assessment

**PriVoke has a plausible path to a publishable applied privacy/security paper, but the current manuscript is not ready for submission.** Finishing the prose alone will not establish publishability. The decisive work is to demonstrate a contribution beyond existing prompt-privacy systems, measure it fairly, and show that the browser actually enforces the stated protection. Acceptance cannot be predicted from a plan or implementation.

IEEE is an organization with many venues and tracks, rather than one publication standard. A focused applied conference or relevant workshop is a reasonable initial target if the experiments below support a useful result. IEEE Symposium on Security and Privacy (S&P) and IEEE European Symposium on Security and Privacy (EuroS&P) are ambitious targets: both solicit novel security/privacy contributions. A functioning extension and a three-layer detector are insufficient by themselves. This is a research-paper assessment, not a guarantee of acceptance or an assertion that a workshop has a lower evidence standard. [S&P call](https://sp2027.ieee-security.org/cfpapers.html), [EuroS&P call](https://eurosp2027.ieee-security.org/cfp.html).

The most immediate novelty challenge is **Casper**. Its original abstract already describes an entirely client-side browser extension combining rules, NER, and a local semantic topic identifier. PriVoke must therefore establish what controlled updates, its risk/action policy, or its measured deployment behavior add. Do not claim that the layered architecture or client-side protection is new. The original Casper paper reports synthetic-prompt evaluation; its published related version and available artifacts should be read before choosing the final comparison. [Casper original paper](https://arxiv.org/abs/2408.07004).

Recommended primary question: **Can controlled template-driven updates improve held-out prompt-privacy detection, especially under unseen prompt transformations, without unacceptable increases in false alarms or client latency?** Treat this as a falsifiable hypothesis. A null or negative result should change the paper's contribution, not be hidden.

## What is established and what remains unknown

| Item | Evidence inspected | Status and implication |
| --- | --- | --- |
| Draft manuscript | [`paper/main.tex`](../paper/main.tex), especially Results, Limitations and Conclusion | Contains explicitly hypothetical accuracy/speed figures and acknowledges missing longitudinal evaluation. Replace with observed results before submission. |
| Evaluation method | [Evaluation guide](README.Evaluation.md) | Existing evaluator measures prompt-level binary detection through the Compose runtime. It does not measure action correctness, exact spans, masking, or browser leakage prevention. |
| Dataset coverage | Evaluation guide and `evaluation/privoke_eval/` inventory | PIIMB supports a binary comparison; AI4Privacy, Nemotron, Gretel and Meddies are supporting positive-only recall tests. Synthetic data support controlled tests but do not establish real-world generalization. |
| Regex experiments | [Regex report](README.Regex-evaluation-results.md) | Historical summary reports speed comparisons and a 13.6% false-positive rate on injected review text. Raw reports were not available in the inspected `evaluation/results` listing; the injected dataset named in the report was absent from the tracked inventory. Treat these values as documented historical claims pending artifact recovery or rerun. |
| Semantic updates | [Semantic guide](README.Semantic-classifiers.md), [Fuzzer guide](README.Fuzzer-service.md), [Model artifacts](README.Model-artifacts.md) | Documentation describes a compact transformer with frozen encoder and trainable heads. Demonstrating transport/update execution is separate from demonstrating learned generalization. |
| Browser enforcement | [Extension guide](README.Browser-extension.md) | Guide says WARN forwards original content, BLOCK cancels, and runtime/bridge failure fails open. The Compose evaluator bypasses this browser path. Verify actual code and behavior before asserting guarantees. |
| Private telemetry | [Telemetry guide](README.Telemetry-service.md) | Documents conditional event-level LDP, composition and an installation-local daily ledger. Event presence, exact report counts and transport metadata are outside the guarantee. Statistical usefulness remains to be measured. |

This was a planning review of the manuscript and documentation, with limited source inspection. No detector benchmarks, browser experiments, manuscript compilation, or independent expert review were performed for this plan. Documentation is evidence of intended behavior, not proof that the implementation meets it.

Resolve known inconsistencies early: the paper omits `P4` in its visibility list; its Limitations description of the semantic representation differs from the newer transformer guide; the paper and extension guide disagree about default semantic enablement; and sections of the project guide contradict newer update/telemetry descriptions. Some root README links still point to `documents/`. Read the relevant source, tests and protobuf definitions, record the observed behavior, then reconcile descriptions. Do not choose whichever description supports a stronger claim.

## Research questions and claim boundaries

| ID | Question | Evidence needed | Claim limit |
| --- | --- | --- | --- |
| RQ1 | What does each detector layer contribute? | Matched full-pipeline and isolated-layer runs; public and independently labeled contextual prompts | Binary prompt detection is separate from category, span, sensitivity and action correctness. |
| RQ2 | Do controlled updates improve unseen cases? | Frozen baseline versus updated versions on disjoint families/documents; multiple independent training seeds; clean-set regression checks | Template memorization or improvement only on update examples is not adaptation to real users. |
| RQ3 | Does enforcement prevent transmission as specified? | Browser request capture with fake sensitive markers, endpoint matrix and outage tests | WARN forwarding is not prevented disclosure. Coverage applies only to tested paths and supported formats. |
| RQ4 | What is the client cost? | Warm/cold latency distributions, memory, model download and update costs on specified hardware | Runtime `elapsed_ms` excludes browser/bridge overhead; do not label it end-to-end latency. |
| RQ5 | Is telemetry private within its stated scope and useful? | Mechanism/composition argument, ledger tests, aggregate-error simulations | Event-level LDP is not user-level DP, anonymous transport, private training, or hidden event presence. |

For the October deadline, prioritize RQ1–RQ4 within a narrow, explicitly tested scope. RQ5 is a supporting mechanism/scope review; defer a full telemetry-utility study and make no measured monitoring-utility claim without results. Do not present telemetry as a learning signal: current documentation separates telemetry from training. Federated learning, masking, pruning and automatic speed improvement remain future work.

## Deadline scope and three-week calendar

The target is a complete, internally reviewed paper with recoverable evidence by 19 October, not a promise that the results will justify acceptance at a particular venue. Reduce breadth before reducing validity. Existing code and evaluation infrastructure must be usable quickly; this schedule cannot absorb a major architecture rewrite.

### Minimum evidence package

- One locked English binary public benchmark (PIIMB), with explicit sample-size/precision rationale and raw predictions. Start with the documented 500-prompt pilot; decide the final size before tuning or final test inspection.
- Matched regex, NER, semantic, regex+NER and full-pipeline measurements, plus at least one independent relevant baseline. Do not describe a different configuration of PriVoke as independent prior work.
- Frozen versus updated semantic-only and full-pipeline comparisons on disjoint data, clean-input regression checks, and three independent training seeds if feasible. If that is not feasible, label the update evidence exploratory and remove broad adaptation claims.
- A bounded contextual/action set independently labeled by two available team members with a rubric and adjudication. It need not cover every category. If this cannot be completed, retain PII-presence claims and remove claims of validated contextual/action quality.
- One specified workstation/browser configuration and explicitly selected request paths, with request capture for ALLOW/WARN/BLOCK and outage behavior; warm/cold end-to-end latency and resource measurements. Broader browser/provider support remains unvalidated.
- A privacy-scope review, measured figures/tables, methods/limitations, an exact artifact manifest, and independent supervisor/domain review.

One supporting positive-only dataset may be added after the core package is complete. All four supporting datasets, extra regex rule combinations, a full Casper reimplementation, extensive cross-device tests, large-scale annotation, user recruitment, model pruning, masking, federated learning and new deployment features are deferred. Read Casper and explain overlap regardless of whether its code can be benchmarked. If a matched comparison is unavailable, disclose that limitation and narrow comparative claims.

### Calendar and completion gates

Assign named owners on 3 October. These roles may be held by the same person; overlapping tasks assume available team capacity. With one researcher, cut optional scope immediately and reserve review time with the supervisor now. Writing runs alongside experiments, but final tests wait until the protocol and model/rule choices are locked.

| Dates (Sydney) | Work and accountable role | Output / decision gate |
| --- | --- | --- |
| **Week 1: 3–4 October** | Research lead + implementation owner: audit claims/defaults, closest work, threat model, infrastructure smoke check; agree venue/template or internal-review format | Contribution, scope and protocol v1; identify any critical blocker by 4 October |
| **5–6 October** | Evaluation/annotation owners: pilot on development data, independent contextual labels, deduplication/splits, baseline adapter; writing lead drafts design/methods | Lock final data, primary metrics, practical tolerances and tuning choices on 6 October |
| **7–9 October** | Evaluation owner: core baseline/ablation runs; model owner: controlled updates; writing lead completes related work and methods | Recoverable predictions and versioned artifacts; first evidence review on 9 October |
| **Week 2: 10–11 October** | Model/evaluation owners: complete paired held-out comparisons, seeds and regressions; systems owner: bounded browser capture and timing | Resolve whether updates support the primary contribution; retain null results |
| **12–13 October** | Evaluation/systems owners: necessary reruns, intervals, error analysis, privacy-scope review; writing lead creates measured tables/figures | Freeze experimental results and manifests on 13 October; cut unsupported claims |
| **14 October** | Writing lead integrates full paper; coauthors check claims/citations | Complete review draft and artifact delivered to independent reviewer |
| **15–16 October** | Supervisor/domain reviewer + authors: focused critique, reproduce a key result, revise conclusions and limitations | Resolve material objections; freeze contribution scope on 16 October |
| **Week 3: 17–18 October** | Writing/artifact owners: final prose, citations, disclosures, author approval, compilation/render inspection, reproduction and format checks | Checked PDF, source and artifact ready by end of 18 October |
| **19 October** | Research lead: delivery and essential correction buffer | Ready paper package; record any unresolved blocker explicitly |

### Contingency decisions

- **4 October — infrastructure:** if the current experiment path is still unusable, stop optional additions and allocate 5 October to repair. If it remains blocked on 6 October, deliver the strongest reproducible narrower study possible and explicitly flag that the planned empirical paper may miss the readiness target. Do not substitute expected trends for results.
- **6 October — protocol:** if contextual annotation or baseline adaptation is incomplete, reduce their scope before final test runs. Record what the remaining evidence can establish; do not claim contextual superiority without appropriate labels/comparisons.
- **9 October — preliminary evidence:** inspect development/pilot findings to allocate work. The locked final test is for planned evaluation, not model/rule tuning. Investigate unexpected failures with development examples; disclose any protocol change.
- **11 October — contribution:** if updates do not improve held-out performance, report that result and pivot the narrative to a useful comparative finding or bounded prototype evaluation. Do not start a new model architecture to chase a favorable score. A narrower paper may fit a different venue/track.
- **13 October — freeze:** cancel optional runs. After this date, run only checks needed to repair invalid evidence or resolve a material review objection. Preserve raw results and regenerate affected figures; recheck affected conclusions.
- **16 October — review:** if a central claim remains unsupported, remove it. If the remaining contribution is too weak for the intended venue, prepare an honest complete internal-review paper by the deadline and state that external submission readiness is unresolved.

Do not cut split integrity, attribution, error reporting, essential enforcement evidence for prevention claims, or honest uncertainty to meet the date. The deadline constrains paper scope, not the truth of its claims.

## Phased execution plan

The phases below are execution detail for the dated calendar above, not additional weeks. Apply the minimum package and deferred-scope decisions to each phase. Assign a named owner to each deliverable; one person may hold several roles. Keep one writer per artifact.

### Phase 1 — Freeze scope and audit claims (3–4 October)

Research lead and implementation owner:

1. Write a one-page contribution statement and threat model: sensitive disclosure to a hosted LLM, trusted workstation components, trusted/untrusted model/update services, supported requests, and excluded adversaries. Separate accidental disclosure from adversarial evasion.
2. Trace every contribution in the manuscript to code, tests, or an experiment. Resolve the documentation conflicts above. Identify what makes the semantic encoder useful, how baseline weights were produced, and exactly what is frozen/trained.
3. Build a related-work matrix covering Casper, the draft's PromptShield/HaS/ProSan references, modern PII detectors, and update/robustness methods. Verify the exact identity of each paper and distinguish privacy protection from similarly named prompt-injection defenses. Read full primary papers and search current literature; record search terms, date, inclusion criteria and limitations.
4. Decide the main contribution and what to remove. Do not make blanket claims that previous systems are static or lack adaptation without a scoped literature search.

Deliverables: `paper/research/claims.md`, `paper/research/related-work.md`, `paper/research/protocol.md` (proposed new files). Gate: a concrete, potentially useful difference from the closest prior system, with a test that could disprove it. If none survives, plan an honest comparative/replication study rather than an unsupported novel-system claim.

### Phase 2 — Fix the evaluation protocol and ground truth (5–6 October)

Evaluation owner and annotation lead:

1. Predefine primary outcomes, allowed tuning, practical improvement and false-alarm/latency tolerances before seeing final test results. Choose tolerances for the intended use case; there is no universal publication score threshold.
2. Use PIIMB for binary public benchmarking. An optional positive-only supporting dataset measures recall only; report it separately. Defer the full four-dataset supporting suite. Preserve pinned revisions, licenses, exclusions, sample IDs, selection digests and source-document grouping. Disclose Meddies' training-split use if selected and any model-training overlap.
3. Add a contextual prompt set with clean hard negatives: public biography, fictional characters, quoted text, general medical advice, private personal disclosure, third-party information, and credentials. Define sensitivity, visibility, category and action labels separately. Visibility often cannot be inferred from text; specify supplied context and allow unknown/ambiguous labels.
4. Have two annotators label independently using a written rubric, adjudicate disagreements, and report agreement plus disagreement types. Decide institutional ethics requirements before recruiting people or collecting genuine prompts; use fictional/synthetic identifiers where possible. Human annotation does not by itself make generated text representative of users.
5. Split by source document, template family and transformation lineage, not merely random rows. Deduplicate across training, development, final test and external benchmarks. Lock the final test before model/rule tuning; record potential upstream contamination that cannot be ruled out.
6. Start with a pilot to estimate variability and annotation burden. A 500-prompt run is a useful initial experiment, not a proof of sufficient sample size. Size the final sample for the predefined effect/interval precision and category strata; rare categories may need oversampling and separate reporting.

Gate: frozen protocol, trustworthy labels, disjoint splits and reproducible selections. Changes after test inspection must be disclosed and evaluated on a fresh holdout.

### Phase 3 — Establish baselines and ablations (7–9 October; essential reruns by 13 October)

Evaluation owner:

- Compare custom regex, NER alone, semantic alone, regex+NER, and the full pipeline. Defer expanded external-rule combinations and scheduling comparisons unless essential to the selected contribution. Record intentionally skipped layers and failures separately.
- Include at least one independently configured relevant baseline, such as Presidio or a credible pretrained local semantic detector, with a documented task match. A second baseline or existing runnable Casper artifact is optional after core evidence is complete; do not undertake a full reimplementation for this deadline. Published accuracy numbers on another dataset are not a matched baseline.
- Adapt outputs to the same ground-truth task without tuning on the final test. Match input context, preprocessing, data, hardware and resource accounting, or disclose differences.
- Report TP/TN/FP/FN, recall, specificity, balanced accuracy, F1/F2 and uncertainty for binary sets. Precision depends on prevalence; balanced-sample precision is not a deployment estimate. Do not average heterogeneous dataset scores.
- Report action confusion separately on the action-labeled set. Record actual final API outputs; the strongest-action selector can drop weaker evidence, so isolated-layer quality may not equal pipeline quality. Category-grouped prompt recall is not exact category accuracy.

Gate: recoverable raw predictions, complete run manifests and valid comparisons. Existing `paper_result_valid` only checks runtime success; it does not certify labels, leakage, novelty or statistical validity. Runs with failures require diagnosis and a clean rerun for primary results, while retaining failure evidence.

### Phase 4 — Test update generalization and robustness (7–11 October; results frozen 13 October)

Model/update owner:

1. Preserve the original artifact and evaluate version zero. Run controlled update cycles; archive each exact version, checksum, update data/seed, head deltas, training settings and audit records. Disable unrelated/background updates during experiments. Do not assume `latest` selects an immutable historical version.
2. Compare frozen full pipeline versus updated full pipeline, and frozen versus updated semantic-only models, on the same locked examples at predefined checkpoints. Include ordinary-example updates versus transformed-example updates to isolate the benefit of fuzzing.
3. Plan three independent training seeds within the available compute budget. If uncertainty prevents a useful conclusion, report it rather than extending experiments indefinitely. Repeated evaluation of the same examples is not additional independent data. Compare paired predictions, using source/family-aware bootstrap intervals for differences; predefine treatment of multiple comparisons.
4. Hold out transformation families: spacing/Unicode, paraphrases, indirect disclosure, mixed contexts, long prompts/truncation, and identifier formatting. Verify that transformations preserve the intended labels. Distinguish realistic accidental disclosures from adversarial attack results.
5. Measure clean false alarms, per-category regressions, forgetting, runtime cost and failed/stale updates. Test publication of the expected artifact version to the next client request; a successful update RPC alone is insufficient.

Gate: reproducible evidence of useful held-out improvement with bounded regressions, or an explicit null/negative result and revised contribution. Do not promise monotonic learning curves or claim federated/private training from bounded deltas alone.

### Phase 5 — Validate bounded client enforcement, performance and privacy scope (10–13 October)

Browser/systems owner and privacy reviewer:

- Build a supported browser/endpoint/body-format matrix. Use controlled request-capture fixtures with fake markers to distinguish ALLOW, WARN and BLOCK. Record whether the protected request actually contains the marker. Test fetch/XHR, resubmission, oversized/malformed bodies, runtime/bridge outages, partial-layer failure and unsupported transports. Validate documented fail-open behavior; if retained, narrow the firewall guarantee accordingly.
- Measure warm and cold end-to-end p50/p95/p99 decision latency separately from runtime-only elapsed time. Record hardware, OS, browser/runtime versions, CPU/GPU backend, prompt-length distribution, warmup, concurrency, memory, model download size and cache behavior. Timing repeats describe performance variability, not extra independent detection evidence.
- Verify local prompt processing and inspect outgoing streaming, telemetry and update payloads/logs in controlled tests. Hosted semantic backends have a different disclosure boundary and must not be described as fully local.
- Review generalized randomized response mathematically: fixed domains, five-field budget composition, repeated-event composition, trusted emitter and persistent ledger assumptions. Test restarts, exhaustion, errors and clock behavior. Standard LDP mechanisms are supporting engineering unless there is a separate novel analysis.
- Defer the full telemetry-utility simulation. Explain that clipping, low report volume and the default eight-report daily cap can limit usefulness and introduce selection/censoring; aggregates of emitted reports need not represent all prompt events. State that exact sample counts and network metadata are outside the privacy guarantee. Do not claim measured deployment-monitoring utility.

Gate: measured enforcement within explicit coverage, quantified client costs, and privacy claims matched to mechanism and deployment assumptions. Remove unsupported usability claims; a user study is optional unless human behavior or adoption is a central contribution.

### Phase 6 — Write the empirical paper and package artifacts (5–14 October; final checks 17–18 October)

Writing lead, with section owners supplying evidence:

| Section | Required revision |
| --- | --- |
| Abstract/introduction | One clear question, specific contributions, actual measured findings and scope. Shorten incident narrative; audit factual anecdotes and use primary references. |
| Related work | Explain closest overlap and substantive difference; avoid presenting integration alone as novelty. |
| Threat model/design | Trust boundaries, WARN forwarding, measured failure/timeout behavior, local versus hosted semantic modes, actual model architecture and update limitations. |
| Methodology | Labels, splits, contamination controls, baselines, ablations, hardware, versions, statistical protocol and ethics. |
| Results | Replace both hypothetical figures with scripts derived from archived observations. Include uncertainty, failure cases and negative findings. Keep hypotheses out of measured-result claims. |
| Discussion/limitations | Explain why gains occur, where they fail, generalization limits, benchmark mismatch and telemetry limits. |
| Conclusion | Answer the research questions with supported findings; separate future extensions. |

Draft methods and design while experiments run; finalize abstract and conclusion after results stabilize. Update `paper/scripts/fig1.py` and `fig2.py` only when their data sources and purposes are defined. Maintain a machine-readable run manifest and a mapping from every result/table/figure to raw reports and generation commands. Archive ignored result files deliberately rather than relying on local `evaluation/results` contents surviving.

Package an exact source revision, dependency/runtime versions, dataset retrieval instructions and licenses, models/checksums, raw predictions, aggregate reports, figure scripts and a small reproduction example. Specify compute/cost requirements and restrictions. Provide an anonymized artifact where required. S&P explicitly encourages reproducible artifacts; artifacts complement rather than replace research evidence. [Artifact call](https://www.ieee-security.org/TC/SP2027/cfartifacts.html).

### Phase 7 — Independent review and readiness decision (15–16 October; delivery 19 October)

Ask a supervisor/domain reviewer who did not produce the main results to review a stable paper and artifact for: novelty relative to Casper, leakage between splits, baseline fairness, detection-versus-enforcement claims, uncertainty and privacy scope. Resolve objections with evidence; record unresolved issues. This independent review remains pending and is not replaced by this planning assessment.

Choose the venue after the main result is known:

- **Applied privacy/security conference or focused workshop:** appropriate to investigate for a bounded system/evaluation contribution. Verify the exact current call, scope, archival status, format, review model and recent accepted papers before selecting it.
- **IEEE S&P / EuroS&P:** consider when the evidence supports a distinctive, broadly useful security/privacy insight beyond integrating familiar components. A robust comparative finding may be valuable even without a new algorithm, but must explain what the community learns.
- **Short/demo track:** consider if the strongest outcome is a working prototype with limited empirical insight, where the venue explicitly offers that track. It is a different deliverable from a full research paper.
- **SoK:** not a shortcut for unfinished experiments; it requires a substantial evidence-based systematization contribution.

As checked on 3 October 2026, EuroS&P 2027 lists abstract registration on **25 November 2026** and submission on **2 December 2026**, both AoE. Those are external venue dates; **19 October is the user's paper-readiness deadline** and governs this plan. Venue opportunity does not relax that date or justify unsupported claims. Its supplied A4 template, anonymous review, 13-page body limit and open-science expectations differ from simply using generic IEEEtran. Recheck the call before preparing a submission. [Official call](https://eurosp2027.ieee-security.org/cfp.html).

The current named-author manuscript and identifying GitHub link need a venue-specific anonymous submission version where required. Verify author approval, conflicts, overlap/simultaneous-submission rules, ethics/data statements, AI-use policy, template and artifact requirements. Agree the venue and submission with all authors; this plan does not authorize submitting or contacting organizers.

## Completion checklist and evidence ledger

- [ ] Contribution and nearest-prior-work comparison survive supervisor review.
- [ ] Architecture/defaults/documentation contradictions are resolved against source and observed behavior.
- [ ] Labels, splits, protocol and practical success criteria were fixed before final testing.
- [ ] Baselines, ablations and update experiments are reproducible; error runs and negative findings are retained.
- [ ] Browser transmission outcomes support the exact enforcement claim.
- [ ] Latency/resource and telemetry privacy conclusions have measured or mathematical support; unmeasured telemetry-utility claims are removed.
- [ ] Every numerical paper claim maps to an archived run; no illustrative trend is presented as a result.
- [ ] Ethics, licenses, contamination, data availability and claim limitations are explicit.
- [ ] Independent review objections are resolved or disclosed.
- [ ] Final PDF compiles and is visually checked for figures, references and venue compliance; artifact reproduction succeeds from documented setup.

Maintain the claim ledger in `paper/research/claims.md` with: claim ID; proposed wording; source path/URL and locator; artifact/version; observation versus inference; assumptions; counterevidence; uncertainty; owner; status; next resolving check. Record exact experimental results rather than success adjectives. The paths above are proposed deliverables, not files already created by this plan.

First action: complete Phase 1 and freeze the contribution/protocol before scaling experiments. If the primary adaptation question fails, retain the data and choose a defensible comparative finding or narrower paper scope. The research is complete when the selected claims are adequately supported, not when every proposed extension has been built.
