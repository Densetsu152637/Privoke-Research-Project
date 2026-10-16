# PriVoke final-paper rubric evaluation: current revision

**Review ID:** RUBRIC-20261017-ITERATION-03. **Reviewed:** 17 October 2026 (Australia/Sydney). **Status:** current-artifact assessment after the third feedback iteration and a newly rebuilt PDF. All six initial editorial recommendations have now been implemented and reassessed; this does not resolve the scientific limitations. No experiments were performed.

The current paper is a coherent, self-contained engineering study with candid negative results. It fits ten complete pages and now makes the contribution of each research question explicit against the relevant prior-work strand. The discussion draws bounded engineering implications from the ablation's gains and harms, rejected updates and telemetry errors. These changes improve the argument without creating stronger empirical evidence. A clearly hypothetical policy traversal now links labels to request behavior, and a compact ablation table exposes agreement alongside both restriction errors. The methods now distinguish tracked recipes/aggregates from historical source closure and locally pinned assets, and the discussion connects actual safeguards to their residual uncertainty. This completes the six selected editorial improvements without claiming independent contextual truth, exact public reproducibility or deployment benefit.

This review replaces the obsolete assessment of the sixteen-page manuscript. That assessment and its recommendations remain recoverable in Git history; they are not current findings. In particular, no appendix or supplement is permitted, and excluded studies must not be restored as a way to satisfy an older recommendation. No numerical mark or highest-band outcome is guaranteed.

## 1. Reviewed inputs, freshness and scope

Iteration 3 started on `docs/paper` at input Git HEAD `d085e97b8ef881a6b4f356734649950b583fa613`, with tracked files clean and the unchanged user-supplied [template.tex](template.tex) untracked. This assessment binds the iteration-3 working artifacts below, not the unchanged files at that input commit. The template remains user-owned. The assessment authority is the visible **FYP B Final Paper Marking Rubric** in [Final_Paper_Rubric.pdf](Final_Paper_Rubric.pdf). The paper inputs are [main.tex](main.tex), [main.pdf](main.pdf), the mandatory [rewrite scope](REWRITE_SCOPE.md), and the accepted **NOAPPX17** revision in the [revision record](research/rubric-rewrite-20261017.md#noappx17-self-contained-paper-with-a-reduced-evidence-set).

| Input | Current SHA-256 |
| --- | --- |
| `paper/Final_Paper_Rubric.pdf` | `4a9ae5ef53481929244d18d2844b0e208f5efd2f7219ced23a9c42608bf2f2a3` |
| `paper/main.tex` | `0442c8b03e243ee095cf560f53897d3d3b1c3c924e0b19094ac56de83b078acf` |
| `paper/main.pdf` | `f795578809c633414b1734b2338f979347df9530e2dfd2a956f2ccd92477caf0` |
| `paper/template.tex` | `e4ea281c35acf1028e726f0777f2b75817478824a6b6fa723bd8b85ae8d9c056` |
| `paper/REWRITE_SCOPE.md` | `44f70e3752aaabfb3ac480fe92742f9e6dd7b94ea0bd5ecb82339fdbbc02b040` |

The paper retains the supplied template's default IEEEtran journal mode, journal author/affiliation format, 184-word single-paragraph abstract, alphabetized keywords, drop-cap opening, IEEEtran bibliography and documented customizations. Iteration 3 adds the historical matched-fit environment in IV-B (p. 5), an artifact-availability statement in IV-C (p. 6), and replaces repeated Discussion qualifications with mitigation–residual explanations in VIII-B/C/D (pp. 9–10). All ten final pass7 pages were rendered and inspected anew; the delivered PDF is byte-identical to that build. Root independently inspected changed pages 5, 6, 9 and 10 and accepted their layout and the complete source diff. The [iteration record](research/rubric-iterations-20261017.md) binds the current source, PDF and checks. All seven complete table environments, both equations, the overview, labels, citation-key sequences and RQs are unchanged from iteration 2; Results and Conclusion onward are also unchanged. No numerical outcome or inference was added. The earlier [template alignment record](research/template-alignment-20261017.md) remains historical evidence of those formatting decisions.

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
| Scientific and Engineering content — **50%** | **D is plausible, with several HD features.** | Complete scoped methods, informative failures, paired harms, uncertainty and explicit RQ answers support a strong engineering account. Negative outcomes are interpreted honestly. Discussion VIII-A/C/D now explains the decisions implied by detector-removal harms, guard rejection and reporting error. The methods now state the historical fit environment and artifact boundary, while VIII-B/C/D pairs freezing, exclusions/clustering, matching and measurement boundaries with their actual residual limits. These improve methodological transparency; exact reproduction and public availability of all pinned assets are not established. Provisional truth, small guard/weak base and limited overhead/utility evidence restrict stronger claims; they do not automatically prevent high marks for rigorous design and informative findings. |
| Structure, figures and tables — **10%** | **D–HD on observed organisation, visual quality and supplied-template alignment.** | Ten pages including references, no appendix/dependency, coherent order and readable, directly referenced visuals remove the earlier length/integration diagnosis. Table III now makes the three approved ablation contrasts directly comparable without duplicating their full counts in prose. Its normal table text and captions fit legibly, with uncertainty and losses retained nearby. The supplied journal-class, title/author, abstract, keyword, reference and visual conventions have now been applied while preserving the requested custom features. Alignment removes that former uncertainty; it does not alone establish an unconditional category HD. |
| Clarity and written expression — **10%** | **D is defensible; HD is plausible after final editorial/institutional checks.** | Developed explanatory prose, defined metrics and scope distinctions, consistent references and a truthful AI statement are present. The hypothetical traversal clarifies policy application and Table III reduces the ablation paragraph's numerical load. Other paired sequences in RQ1/RQ2 still require attentive reading. No major grammar or rendering defect was observed, but this is not a guarantee of zero typographical errors or compliance with an unavailable declaration form. |

The paper is now substantially stronger than the submission assessed in the original review. The six selected changes improve synthesis, accessibility and methodological transparency. No further material editorial defect was identified in this bounded reassessment; that does not certify exhaustive literature coverage or perfect prose. An overall HD or a numeric aggregate is not established by these category judgments.

### Coverage of every assessed dimension

| Rubric dimension | Current evidence | Remaining highest-band opportunity or check |
| --- | --- | --- |
| Background relevance and depth | Introduction explains legitimate prompt use, disclosure and intervention; Design states trust/transport boundaries and illustrates the policy. | The former traversal recommendation is addressed in III-B: assumed labels lead to WARN/original transmission, while an earlier BLOCK prevents semantic execution. It is explicitly non-empirical. |
| Literature coverage | Section II covers local sanitization, negative flips and reporting; foundational contextual-integrity/DP sources support the concepts. | Retain the now-explicit synthesis and relevant coverage; do not add references merely to increase count. |
| Critical literature analysis | Different request contracts, recovery functions, reporting mechanisms and outcome denominators are distinguished; the closing paragraph maps each strand to its RQ and contribution. | This editorial recommendation is addressed. Maintain the distinction between evaluated integration and established primitives; no superiority inference from incompatible measures. |
| Research question | Three unchanged questions now have explicit contribution statements in the Introduction; Table I maps evidence and Section II connects prior work. | Preserve this mapping and the exact questions; no additional RQ is needed. |
| Abstract, Introduction and Conclusion | All three are present, coherent and qualified; abstract includes denominators and decisive negative results. | The conclusion already links a versioned decision lifecycle to bounded findings; preserve that synthesis rather than adding another closing claim. |
| Methodology | Policy, execution scope, target definitions, model differences, training recipe, exclusions, uncertainty and measurement windows are in the main paper. | Addressed in IV-B/C: historical fit versions and tracked-versus-local availability are explicit. Exact rerunning and public distribution of all pinned assets remain unverified. |
| Data and Results | Tables II–VII and accompanying text retain all approved arms, paired gains/harms and failed guards; uncertainty is described where applicable. | Table III now displays the targeted ablation tradeoff; adjacent prose preserves 139 gains, eighteen losses, net 121 and separate family/expression intervals. Maintain those qualifications rather than treating aggregate gain as sufficient protection. |
| Discussion | Section VIII links to contextual integrity, sanitization, Yan et al. and RAPPOR, and now gives bounded design implications. | Addressed in VIII-B/C/D: each safeguard is paired with what it cannot establish. Maintain the target, dependence, confounding and measurement distinctions. |
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
| Imprecise artifact/configuration availability (former Priority 4) | **Addressed in iteration 3:** IV-B, p. 5, gives the historical matched-fit environment; IV-C, p. 6, names tracked recipes and dated aggregate/provenance records, differentiates study closures and identifies local ignored checkpoints/raw artifacts. Historical uncommitted dependencies prevent a clean-checkout-only reproduction claim; public asset distribution is not established. |
| Dispersed safeguards and residual biases (former Priority 6) | **Addressed in iteration 3:** VIII-B/C/D, pp. 9–10, connects endpoint freezing to target limitations, exclusions/clustering to unresolved dependence, matched continuation to remaining package confounding, and request/window records to whole-container cost limits. Telemetry accounting is also distinguished from estimation and selection. |

## 4. Status after the six editorial improvements

All six initial recommendations are now addressed using the approved studies and existing non-protected evidence. **No new mandatory editorial addition is identified by this bounded review.** Retain the improvements rather than repeatedly rewriting them to continue the loop or increase a projected grade. Routine proofreading and checking any subsequently supplied institutional AI declaration remain appropriate; neither indicates an observed current failure.

For **Priority 4**, the availability paragraph and historical environment state which configurations the evidence describes and where recipes, fingerprints and receipts are recorded. The paper explicitly rejects the inference that cloning Git suffices for exact reruns. It does not claim that ignored models/data are publicly obtainable or that anyone independently reproduced the measurements. Those practical limitations remain despite the fulfilled editorial recommendation. Essential retained protocols stay in the main paper; repository references do not replace them.

For **Priority 6**, the revised discussion makes the mitigation–residual relationship explicit. A frozen semantic endpoint limits post-selection there, but does not independently validate contextual authorization. Declared exclusions and cluster sensitivity analyses address known grouping without certifying template or pretraining independence. Matching RQ2 does not retroactively isolate RQ1's package effect. Defined measurement windows do not create an unprotected baseline or isolate semantic cost. These are justified safeguards with bounded interpretation, not assertions that bias has been removed.

The remaining assessment uncertainty principally concerns the strength and breadth of the evidence and marker judgment. Section 6 separates stronger empirical claims the paper cannot make from editorial completeness. None of those limits instructs the author to add an excluded study, invent a successful result or use an appendix. Further measurements or changes to the seven-unit set require direct authorization.

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
| IV. Methods, pp. 5–6 | Seven units, metric and target distinctions, frozen versus reused data, training recipe, exclusions, cluster methods and measurement windows. | Priority 4 is addressed by the historical fit environment and explicit availability boundary. Preserve the distinction between tracked records and ignored assets; exact public reproduction is not certified. |
| V. RQ1, pp. 6–7 | All tiers and final arms, paired gains/losses, low final specificity, ablation harms and receiver/fallback outcomes. | Priority 3 is addressed by Table III and its paired gain/harm prose. Keep the product and final comparisons' different targets/execution scopes and avoid a causal distribution-shift claim. |
| VI. RQ2, pp. 7–8 | All seeds, all terminal candidates, head/full comparisons, guard outcomes and no publication. | Existing Table V is useful. If reformatting dense prose, preserve the different harm comparators and do not sum directional harms as disjoint cases. |
| VII. RQ3, pp. 8–9 | Six latency cells, whole-container boundary, finite privacy excess, both utility examples and ledger/selection outcomes. | Existing Tables VI–VII address the original missing presentations, and VIII-D now draws the reporting implication. Preserve those boundaries; no extra utility/cost experiment or post-hoc success threshold is implied. |
| VIII. Discussion, pp. 9–10 | Literature links, provisional truth, source imbalance, guard/base limitations and lack of human/deployment benefit. | Priorities 1 and 6 are addressed through bounded engineering consequences and explicit mitigation–residual pairs. Preserve the unvalidated contextual target, source dependence, package confounding, small guard and measurement/utility boundaries. |
| IX. Conclusion, p. 10 | Direct qualified synthesis and informative failed outcomes. | The current lifecycle synthesis is adequate for these findings; no additional closing claim is needed. Preserve the negative results and bounded interpretation. |
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

**Review outcome:** submission-level length and acknowledgement defects are resolved, and all six selected editorial recommendations have been addressed across iterations 1–3. The current artifact remains ten complete pages and passes the documented visual, reference and preservation checks. Scientific limitations remain real and visible; editorial completion does not establish independent contextual truth, useful deployment, comprehensive literature coverage or exact public reproducibility. No automatic HD or numerical uplift follows. No further material editorial defect was found in this bounded reassessment, so additional rewriting should require a concrete reason rather than quota consumption. Bibliography data, rewrite scope and underlying research evidence are unchanged.
