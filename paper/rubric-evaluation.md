# PriVoke final-paper rubric evaluation: current revision

**Review ID:** RUBRIC-20261017-ITERATION-02. **Reviewed:** 17 October 2026 (Australia/Sydney). **Status:** current-artifact assessment after the second feedback iteration and a newly rebuilt PDF. Four editorial recommendations have now been implemented and reassessed; two remain. No experiments were performed.

The current paper is a coherent, self-contained engineering study with candid negative results. It fits ten complete pages and now makes the contribution of each research question explicit against the relevant prior-work strand. The discussion draws bounded engineering implications from the ablation's gains and harms, rejected updates and telemetry errors. These changes improve the argument without creating stronger empirical evidence. A clearly hypothetical policy traversal now links labels to request behavior, and a compact ablation table exposes agreement alongside both restriction errors. The remaining editorial opportunities are precise artifact availability and a connected account of bias mitigation and residual uncertainty.

This review replaces the obsolete assessment of the sixteen-page manuscript. That assessment and its recommendations remain recoverable in Git history; they are not current findings. In particular, no appendix or supplement is permitted, and excluded studies must not be restored as a way to satisfy an older recommendation. No numerical mark or highest-band outcome is guaranteed.

## 1. Reviewed inputs, freshness and scope

Iteration 2 started on `docs/paper` at input Git HEAD `d1778e349cf5004f55de03cb15c2193be67c144e`, with tracked files clean and the unchanged user-supplied [template.tex](template.tex) untracked. This assessment binds the iteration-2 working artifacts below, not the unchanged files at that input commit. The template remains user-owned. The assessment authority is the visible **FYP B Final Paper Marking Rubric** in [Final_Paper_Rubric.pdf](Final_Paper_Rubric.pdf). The paper inputs are [main.tex](main.tex), [main.pdf](main.pdf), the mandatory [rewrite scope](REWRITE_SCOPE.md), and the accepted **NOAPPX17** revision in the [revision record](research/rubric-rewrite-20261017.md#noappx17-self-contained-paper-with-a-reduced-evidence-set).

| Input | Current SHA-256 |
| --- | --- |
| `paper/Final_Paper_Rubric.pdf` | `4a9ae5ef53481929244d18d2844b0e208f5efd2f7219ced23a9c42608bf2f2a3` |
| `paper/main.tex` | `cd199b7dc129ac03957696d14c6a1f84280a6a91e37bbeedbea095a00e3b665a` |
| `paper/main.pdf` | `3ce5612fba9fd51f0c6a476d5804934d6a3752002a03075edebc48406e934d1c` |
| `paper/template.tex` | `e4ea281c35acf1028e726f0777f2b75817478824a6b6fa723bd8b85ae8d9c056` |
| `paper/REWRITE_SCOPE.md` | `44f70e3752aaabfb3ac480fe92742f9e6dd7b94ea0bd5ecb82339fdbbc02b040` |

The paper retains the supplied template's default IEEEtran journal mode, journal author/affiliation format, 184-word single-paragraph abstract, alphabetized keywords, drop-cap opening, IEEEtran bibliography and documented customizations. Iteration 2 added a hypothetical traversal in III-B and a three-row ablation table in V-A, replacing dense comparison prose without changing the study. The rebuilt PDF has complete ten-page visual coverage: all pass6 pages were inspected, then the only changed pass7 page (7) was inspected again; the other nine final renders are byte-identical to those inspected. The delivered PDF matches the final build. The [iteration record](research/rubric-iterations-20261017.md) binds the current source, PDF and checks. All six pre-existing tables, both equations, the overview, prior labels, citation-key sequences and RQs are preserved. The seventh table promotes twelve existing outcome counts and seven layer-ID digits, not new measurements. The earlier [template alignment record](research/template-alignment-20261017.md) remains historical evidence of those formatting decisions.

### Current contents and permitted evidence

The PDF contains one overview figure, seven tables, two displayed equations and twenty references. Physical pages locate the material as follows; sections can share a page:

| Pages | Material |
| --- | --- |
| 1–2 | Abstract, Introduction, three RQs and Related Work |
| 2–5 | System Design, complete policy mapping, overview and telemetry equations |
| 5–6 | Evaluation Method and Table I |
| 6–7 | RQ1, product Table II, ablation Table III and final confusion Table IV |
| 7–8 | RQ2, matched continuation Table V and guard outcomes |
| 8–9 | RQ3, browser cost Table VI (p. 8) and telemetry utility Table VII (p. 9) |
| 9–10 | Discussion, Conclusion, AI Assistance and references |

Only these seven evidence units may be covered in a rewrite:

1. RQ1: full-product contextual comparison of all three historical/updated tiers on 1,560 provisional cases.
2. RQ1: targeted balanced full/no-rules/no-NER contrasts.
3. RQ1: frozen 498-row annotation-presence endpoint, all six semantic-only arms.
4. RQ1: thirty-three installed receiver probes.
5. RQ2: matched HEADS/FULL continuation across three seeds, with its sixteen-case guard.
6. RQ3: 360 rules/NER browser decisions across twelve profiles.
7. RQ3: finite telemetry privacy, estimator error and ledger/selection behavior as one mechanism.

The scope document governs the precise inclusions, exclusions and authorization conditions. Historical Presidio/AdvPIIBench comparisons, extra adaptation branches, reconstruction and client-event tests, incompatible cost catalogues, and omitted ablation configurations are not recommended additions. Qualitative related-work synthesis remains appropriate. No protected raw data, inference, fitting, scoring, resampling or new external-source research was undertaken here.

**Assessment confidence:** high for current contents, page count, scope and resolved presentation issues; moderate for band judgments and the relative value of editorial changes. The supplied template has now been read and its applicable manuscript conventions checked. Marker discretion and the institution-specific AI declaration format remain unverified; the template does not supply that declaration form. This is uncertainty, not evidence of noncompliance. Existing literature provenance is reused; this review does not certify an exhaustive new search of the current field.

## 2. Rubric interpretation and revised band assessment

The four category weights are **30%, 50%, 10% and 10%**, totaling 100%. The supplied rubric uses **0, N, P, C, D and HD**, without numerical band cutoffs, subcriterion weights, a mixed-subcriterion aggregation rule or a specified overall penalty. C exceeds all acceptable criteria and meets some HD criteria; D exceeds all acceptable criteria and meets most HD criteria. Accordingly, no defensible numerical total can be calculated from the supplied rubric alone.

The current judgments below reflect the completed iteration. The completed improvements strengthen relevant criteria, but are insufficient by themselves to justify an automatic band increase:

| Category | Revised judgment | Current basis and remaining reservation |
| --- | --- | --- |
| Background, context, literature review/state of the field — **30%** | **D is defensible; HD not established by this review.** | The motivation is relevant, all three RQs are justified, and local intervention, regression-aware revision and randomized reporting each have scholarly grounding. Contextual integrity, Yan et al., RAPPOR and the DP foundation are now present. Critical comparisons distinguish targets and mechanisms. The Introduction and final Related Work paragraph now connect concrete outputs to RQ1/RQ2/RQ3 and local sanitization, negative-flip analysis and RAPPOR. This strengthens critical synthesis and bounded originality; comprehensive literature coverage is still not independently certified here. |
| Scientific and Engineering content — **50%** | **D is plausible, with several HD features.** | Complete scoped methods, informative failures, paired harms, uncertainty and explicit RQ answers support a strong engineering account. Negative outcomes are interpreted honestly. Discussion VIII-A/C/D now explains the decisions implied by detector-removal harms, guard rejection and reporting error. Reproducibility/availability and a clearer bias–mitigation–residual account remain the principal methodological editorial opportunities. Provisional truth, small guard/weak base and limited overhead/utility evidence restrict stronger claims; they do not automatically prevent high marks for rigorous design and informative findings. |
| Structure, figures and tables — **10%** | **D–HD on observed organisation, visual quality and supplied-template alignment.** | Ten pages including references, no appendix/dependency, coherent order and readable, directly referenced visuals remove the earlier length/integration diagnosis. Table III now makes the three approved ablation contrasts directly comparable without duplicating their full counts in prose. Its normal table text and captions fit legibly, with uncertainty and losses retained nearby. The supplied journal-class, title/author, abstract, keyword, reference and visual conventions have now been applied while preserving the requested custom features. Alignment removes that former uncertainty; it does not alone establish an unconditional category HD. |
| Clarity and written expression — **10%** | **D is defensible; HD is plausible after final editorial/institutional checks.** | Developed explanatory prose, defined metrics and scope distinctions, consistent references and a truthful AI statement are present. The hypothetical traversal clarifies policy application and Table III reduces the ablation paragraph's numerical load. Other paired sequences in RQ1/RQ2 still require attentive reading. No major grammar or rendering defect was observed, but this is not a guarantee of zero typographical errors or compliance with an unavailable declaration form. |

The paper is now substantially stronger than the submission assessed in the original review. Its route to a better assessment is primarily clearer synthesis and more accessible evidence, not manufactured positive outcomes or more study coverage. An overall HD or a numeric aggregate is not established by these category judgments.

### Coverage of every assessed dimension

| Rubric dimension | Current evidence | Remaining highest-band opportunity or check |
| --- | --- | --- |
| Background relevance and depth | Introduction explains legitimate prompt use, disclosure and intervention; Design states trust/transport boundaries and illustrates the policy. | The former traversal recommendation is addressed in III-B: assumed labels lead to WARN/original transmission, while an earlier BLOCK prevents semantic execution. It is explicitly non-empirical. |
| Literature coverage | Section II covers local sanitization, negative flips and reporting; foundational contextual-integrity/DP sources support the concepts. | Retain the now-explicit synthesis and relevant coverage; do not add references merely to increase count. |
| Critical literature analysis | Different request contracts, recovery functions, reporting mechanisms and outcome denominators are distinguished; the closing paragraph maps each strand to its RQ and contribution. | This editorial recommendation is addressed. Maintain the distinction between evaluated integration and established primitives; no superiority inference from incompatible measures. |
| Research question | Three unchanged questions now have explicit contribution statements in the Introduction; Table I maps evidence and Section II connects prior work. | Preserve this mapping and the exact questions; no additional RQ is needed. |
| Abstract, Introduction and Conclusion | All three are present, coherent and qualified; abstract includes denominators and decisive negative results. | End the conclusion with the decision-making value of the findings, while retaining its limits. |
| Methodology | Policy, execution scope, target definitions, model differences, training recipe, exclusions, uncertainty and measurement windows are in the main paper. | Add concise artifact/configuration availability information; do not imply a missing entire protocol. |
| Data and Results | Tables II–VII and accompanying text retain all approved arms, paired gains/harms and failed guards; uncertainty is described where applicable. | Table III now displays the targeted ablation tradeoff; adjacent prose preserves 139 gains, eighteen losses, net 121 and separate family/expression intervals. Maintain those qualifications rather than treating aggregate gain as sufficient protection. |
| Discussion | Section VIII links to contextual integrity, sanitization, Yan et al. and RAPPOR, and now gives bounded design implications. | Explicit implications are addressed; pairing mitigations with residual bias remains worthwhile. |
| Innovation and originality | Integration and findings are explicitly distinguished from established detection, regression and randomization primitives; each RQ supplies a different output. | Preserve the bounded claim. Greater clarity does not establish first-ever novelty or superiority. |
| Organisation | Abstract-to-conclusion flow, RQ-specific results and coherent main-text methods. | Use substitutions rather than accumulating extra sections within the ten-page limit. |
| Figures and tables | One legible overview; seven numbered, captioned, referenced tables; equations and units are readable. | The new ablation table is readable and removes repeated comparison counts from prose. Preserve its three contrasts and normal typography; further visual additions are not automatically improvements. |
| Formatting requirements | Ten complete US Letter pages in the supplied default IEEEtran journal typography; no appendix. | Supplied-template alignment and retained customizations are documented and visually checked. Preserve these settings in future revisions; optional fictional examples are not required content. |
| Clarity and precision | Policy labels, joint metrics, execution boundaries, content privacy and cost units are defined; the worked traversal distinguishes assumed labels from observations. | Preserve that distinction and avoid presenting the example as a new case or user-consent claim. Dense remaining paired prose can be proofread without deleting harms. |
| Grammar and syntax | Connected academic explanation and no conspicuous errors preventing understanding. | A final proofread after any revision; avoid claiming exhaustive typo-free certification. |
| Referencing and AI acknowledgement | Twenty references; foundational claims cited; AI Assistance names GPT-6 Astra and provisional labels without claiming human adjudication. | Confirm institutional declaration/style requirements and maintain version-qualified source claims. No missing-AI-statement finding remains. |

## 3. Resolved since the original review

| Former issue | Current status |
| --- | --- |
| Sixteen physical pages and appendix-dependent interpretation | **Resolved:** ten complete pages including references; essential definitions and retained protocols are in the main paper. No appendix/supplement workaround is allowed. |
| No complete explicit AI-writing acknowledgement | **Resolved at the content level:** the paper states provisional-label support, drafting, GPT-6 Astra review/rewriting and author responsibility. Exact institutional form remains unverified. |
| Thin prior-work grounding for retention and telemetry | **Substantially resolved:** Section II now discusses Yan et al. and RAPPOR; contextual integrity and DP foundations are also cited. |
| Missing policy legend/edge rules and ambiguous confidence | **Resolved:** all sensitivity/audience/category labels, action exceptions and low-confidence mapping appear; confidence is explicitly uncalibrated. |
| Multiple unexplained meanings of joint correctness and execution scope | **Resolved:** label-joint versus label-and-action joint, product versus sole-semantic execution, guard versus assessment, and prediction versus receiver outcomes are separated. |
| Remote or unreferenced retained visuals and weak method self-containment | **Resolved for the retained set:** seven tables and the overview are integrated; required methods and both equations are present. |
| Historical experiment catalogues obscuring RQ answers | **Resolved by approved selection:** seven meaningful units remain, with their failures and scope limits. Removed studies are not restoration targets. |
| Generic contribution language (former Priority 5) | **Addressed in iteration 1:** Introduction links each RQ to a concrete output; Section II explicitly relates those outputs to local sanitization, negative-flip analysis and RAPPOR. Integration and empirical understanding are distinguished from invented primitives or superiority. |
| Implications ending mainly in limitations (former Priority 1) | **Addressed in iteration 1:** VIII-A uses 139 corrected restrictions/eighteen lost correct actions to motivate reviewing both costs; VIII-C makes the configured guard a veto despite aggregate gain; VIII-D separates privacy, estimation and admission justification. Provisional targets, small guard, no publication and absent monitoring validation remain explicit. |
| Abstract policy without a worked traversal (former Priority 2) | **Addressed in iteration 2:** III-B, p. 3, applies assumed S2/HEALTH/confidence 0.7 to WARN and unchanged-body transmission; an earlier BLOCK prevents semantic execution. The paragraph expressly disclaims observed prediction, independent labelling or an extra test. |
| Dense targeted ablation comparison (former Priority 3) | **Addressed in iteration 2:** Table III, p. 7, preserves full/no-rules/no-NER action and joint agreement plus under/over-restriction. V-A, pp. 6–7, retains gains, losses, net gain, both paired intervals and the fixture-specific no-NER caveat. |

## 4. Two remaining improvements within the locked scope

These are improvements to a functioning paper, not two missing mandatory components. Original priority identifiers are retained for traceability; Priorities 1, 2, 3 and 5 have moved to the resolved table above. **Editorial** uses existing manuscript facts; **provenance extraction** means reading existing non-protected records, not executing or rescoring a study. Each proposed addition should replace repetition or dense presentation so that the complete PDF stays within ten pages. Suggested wording below is illustrative and has not been inserted into the manuscript.

### Priority 4 — State reproducibility and artifact availability precisely

**Location:** Section IV and a short closing methods/availability paragraph. **Rubric benefit:** methodology (50%).

The current methods provide meaningful recipes, but package lineage and a generic repository footnote do not clearly identify the reproducible artifact boundary. Add a concise statement of the evaluated source/package revisions and essential runtime configuration where these affect interpretation, using existing manifests. Distinguish tracked aggregates that support the reported tables from pinned source/model/data assets needed to rerun inference, and identify availability restrictions honestly.

**Basis:** provenance extraction from existing records, not the excluded reconstruction experiment or a fresh reproduction claim. Keep essential methods in the paper; a repository URL is optional provenance, not a substitute for them. **Acceptance:** another researcher knows which configuration the retained result describes, what is available and what remains unavailable. Do not promise Git-only reproduction, redistribute assets, or run studies under this recommendation.

### Priority 6 — Pair bias, mitigation and residual uncertainty

**Location:** Section VIII-B/D, pp. 9–10. **Rubric benefit:** critical discussion and bias/error treatment (50%).

Limitations and safeguards are present but distributed across Methods and Discussion. A compact replacement table or tightly structured paragraph could connect them explicitly:

| Threat | Mitigation already described | Residual uncertainty that must remain |
| --- | --- | --- |
| Provisional contextual targets and reuse | Separate frozen annotation-presence endpoint | Different target; no independent contextual adjudication. |
| Related cases and source groups | Paired cluster sensitivity analyses and declared exclusions | Unknown template/pretraining dependence; no population guarantee. |
| Package confounding in RQ1 | Separate fixed-base matched continuation in RQ2 | Does not retroactively isolate the RQ1 package effect; zero-head base and small guard remain weak. |
| Browser resource attribution | Defined request/window boundaries and actual execution records | No unprotected baseline, semantic cost or per-role attribution. |

**Basis:** existing methods, not a claim that every threat was eliminated. **Acceptance:** each mitigation is real, its scope is correct and its residual effect on the conclusion is explicit. Replace repeated qualifications rather than adding a second limitations catalogue.

## 5. Section-by-section disposition

| Current section | Retain | Focused action and completion check |
| --- | --- | --- |
| Title/author block/Abstract/keywords, p. 1 | Local supported-path framing, distinct service roles, 1,560/498/33 denominators, poor specificity and rejected updates. | No mandatory expansion. Ensure any later abstract edit still matches the seven-unit evidence and avoids “low overhead”, general safety or user-benefit claims. Preserve the applied journal author/affiliation format, 150–250-word standalone abstract and alphabetic keywords. |
| I. Introduction, pp. 1–2 | Historical explanatory style, legitimate-use motivation, exact three RQs and their rationale. | Contribution-to-RQ mapping is now explicit. Preserve its developed explanation and bounded originality; no further rewrite is required merely to restate this recommendation. |
| II. Related Work, p. 2 | Three strands, contextual integrity, negative flips, RAPPOR, local sanitization/recovery distinctions and target incompatibility. | The closing synthesis now explicitly connects the three RQs to the reviewed strands. Preserve it and the incompatible-target warning; a larger reference count or omitted leaderboard is not needed. |
| III-A. Scope and Trust, pp. 2–3 | Trusted client/publisher boundary, supported fetch/XHR, hosted-inference distinction and coverage exclusions. | Keep deployment assumptions explicit; no additional diagram is necessary to repair an observed defect. |
| III-B. Inspection and Enforcement, p. 3 | Complete labels/policy/confidence mapping, strongest-action cascade, failure/fallback and unchanged WARN forwarding. | Priority 2 is addressed by the clearly hypothetical traversal. Preserve its labels-to-policy-to-transmission distinction and explicit non-empirical status. |
| III-C. Guarded Updates, pp. 3–4 | Exact-base checks, staged publication, replay and client refresh design. | Keep design capability distinct from the retained experiment's hypothetical acceptance; do not restore removed publication-success claims. |
| III-D. Telemetry, pp. 4–5 | Five domains, ideal and finite equations, entropy assumptions, accounting/content boundary. | Definitions are already complete for interpretation. Preserve nominal-bound failure and avoid treating the ledger as user-level/participation privacy. |
| IV. Methods, pp. 5–6 | Seven units, metric and target distinctions, frozen versus reused data, training recipe, exclusions, cluster methods and measurement windows. | Priority 4 adds precise provenance/availability, not an expanded study inventory. |
| V. RQ1, pp. 6–7 | All tiers and final arms, paired gains/losses, low final specificity, ablation harms and receiver/fallback outcomes. | Priority 3 is addressed by Table III and its paired gain/harm prose. Keep the product and final comparisons' different targets/execution scopes and avoid a causal distribution-shift claim. |
| VI. RQ2, pp. 7–8 | All seeds, all terminal candidates, head/full comparisons, guard outcomes and no publication. | Existing Table V is useful. If reformatting dense prose, preserve the different harm comparators and do not sum directional harms as disjoint cases. |
| VII. RQ3, pp. 8–9 | Six latency cells, whole-container boundary, finite privacy excess, both utility examples and ledger/selection outcomes. | Existing Tables VI–VII address the original missing presentations, and VIII-D now draws the reporting implication. Preserve those boundaries; no extra utility/cost experiment or post-hoc success threshold is implied. |
| VIII. Discussion, pp. 9–10 | Literature links, provisional truth, source imbalance, guard/base limitations and lack of human/deployment benefit. | Priority 1 is addressed through bounded engineering consequences. Priority 6 remains: connect existing mitigations to residual bias without duplicating this discussion. Preserve deliberately excluded transport and utility boundaries. |
| IX. Conclusion, p. 10 | Direct qualified synthesis and informative failed outcomes. | Optionally finish with the engineering decision the lifecycle makes inspectable; do not add a new measurement or promise. |
| AI Assistance and references, p. 10 | Explicit known AI roles, no invented human adjudication, version-qualified citations. | No missing declaration diagnosis. Check any institution-specific form/style when supplied; retain actual authorship/funding facts only. |
| Appendices/supplements | None. | No addition permitted. Historical files/records do not create an exception or a place to move essential methods. |

## 6. Evidence limits that prose cannot remove

The following constrain stronger claims, not the legitimacy of reporting the existing engineering work. The rubric explicitly values honest, informative failures and originality in design or findings; it does not require all experiments to succeed.

| Stronger claim not established | Current reason | Status of additional evidence |
| --- | --- | --- |
| Independently accurate contextual privacy decisions | Labels/policy are provisional; annotation presence is a distinct target. | Independent contextual adjudication would require separately authorized work and any necessary scope amendment. It is not an automatic extra study recommendation. |
| Useful adaptation without sacrificing protected behavior | All matched FULL candidates fail the guard; HEADS has one failing seed; the base/guard/assessment are limited. | A stronger base/retention evaluation and any deployment validation require their own authorization; no editorial wording can convert rejected candidates into served gains. |
| Incremental or semantic-pipeline overhead | Cost covers rules/NER decisions and whole-container infrastructure without an unprotected baseline. | Matched baseline and semantic measurements are outside the currently authorized rewrite. Preserve the existing measured scope. |
| Useful representative monitoring or participation protection | Estimator error, incoherent marginals and admission selection remain; the bound covers event content conditionally. | Application criteria, estimator changes or deployment studies need new authorization. Do not choose a threshold after seeing results to label them successful. |
| Human benefit or general provider/platform coverage | Synthetic receiver evidence is bounded; task completion, comprehension and broader coverage were not measured. | Human/provider/platform studies would expand evidence scope and are not required additions under this review. |

No new measurement automatically belongs in the paper merely because it becomes available. Any change to the seven-unit set requires direct user instruction under REWRITE_SCOPE.md; authorization to run an experiment and authorization to expand manuscript coverage are distinct.

## 7. Completion checks for a future revision

1. Every paragraph and result remains attributable to the approved seven units or appropriate qualitative literature/design explanation; no excluded study or appendix dependency returns.
2. Each optional addition either clarifies an implication, applies a definition, exposes a tradeoff or improves provenance. Remove repetition to pay for its space.
3. All retained tiers, seeds and contrasts remain; adverse findings, denominators and uncertainty are preserved. Do not equate full-pipeline with semantic-only results or candidate eligibility with publication.
4. Complete main PDF stays at most ten pages including references, without typography reduction. Preserve the supplied journal-class conventions and documented customizations; do not revert to conference mode simply to save space.
5. Rebuild after rendering-relevant changes, resolve references/citations, inspect every final page and verify source/PDF freshness. Current visual acceptance cannot approve a changed future PDF.
6. Preserve truthful AI acknowledgement and source-version distinctions. Institutional format remains a check, not an invented failure or invented author verification.

**Review outcome:** current submission-level length and acknowledgement defects are resolved; the main remaining opportunities are synthesis, accessibility and precise provenance. The prioritized changes can use existing evidence within the locked scope. The empirical limitations remain real and should remain visible. Iterations 1–2 addressed contribution mapping, bounded design implications, the policy traversal and ablation presentation. The current artifact passes the documented ten-page and visual checks. Two editorial opportunities remain; no automatic HD or numerical uplift follows from completing these recommendations. Bibliography data, rewrite scope and underlying research evidence are unchanged.
