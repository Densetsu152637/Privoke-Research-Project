# PriVoke final-paper rubric evaluation and revision plan

**Review ID:** RUBRIC-20261016. **Reviewed:** 16 October 2026. **Status:** assessment and proposed changes; the manuscript has not been changed and no experiments have been run for this review.

The current paper has a credible systems contribution, substantial engineering evidence, and unusually careful reporting of unsuccessful experiments. Its highest-mark opportunity is to make that contribution easier to judge, strengthen the literature-to-question argument, and present the decisive evidence in a compliant, self-contained submission. The immediate submission risks are **16 physical pages against a rubric that explicitly lists exceeding 10 pages as an N-band defect**, and **no complete, explicit acknowledgement of AI use in the paper**. The largest scientific limitation is the absence of independently adjudicated contextual privacy targets. More prose cannot supply those targets, but the rubric does not require every experiment to succeed or every limitation to disappear.

## 1. Scope, inputs and confidence in this assessment

The assessment uses the supplied [Final Paper Rubric](Final_Paper_Rubric.pdf), all of [the manuscript source](main.tex), and every rendered page of [the current PDF](main.pdf). The rubric's visible heading is **FYP B Final Paper Marking Rubric**. Its embedded PDF title refers to an older FYP A interview; the visible four-page marking table, not that stale metadata, is the assessment authority here.

The reviewed repository revision is `d82f39bae0809f5415278475b530c812198f91f7`, branch `docs/paper`. These SHA-256 bindings make the assessment reproducible:

| Input | SHA-256 |
| --- | --- |
| `paper/Final_Paper_Rubric.pdf` | `4a9ae5ef53481929244d18d2844b0e208f5efd2f7219ced23a9c42608bf2f2a3` |
| `paper/main.tex` | `d22feab98758443857071090ad73aa319c43196e6144d5ce17967ebab7c538c6` |
| `paper/main.pdf` | `d9ee4bd5ba74b28853c3cf7fffdf5a715f71c5e5f218800d178e08de4fd26027` |

The source and PDF hashes match the latest top-level artifact bindings in [the revision record](research/professor-rq-revision-20261016.json). PDF creation metadata is 16 October 2026, 03:44:32 AEDT. The source and rendered content agree on the revised abstract, three questions, section sequence, tables and conclusion. This supports treating them as the same current manuscript; this review did not rebuild the PDF. Older page counts and hashes retained inside the append-only [revision history](research/professor-rq-revision-20261016.md) describe earlier versions and must not substitute for the current artifact.

The actual layout is:

| Physical pages | Content |
| --- | --- |
| 1-9 | Title, abstract, Sections I-IX, ending with Conclusion |
| 10-15 | Appendices A-I and delayed result figures/tables |
| 16 | References, 24 numbered entries |

I read selected existing, prompt-free research records to check whether proposed additions already have support. These are historical evidence records, not independently rerun experiments: [claims ledger](research/claims.md), [controlled studies](research/controlled-studies-20261014.md), [installed-client evidence](research/installed-client-evidence-20261014.md), [telemetry evidence](research/telemetry-evidence-20261014.md), [literature review](research/literature-baseline-review-20261015.md), [contextual labeling rubric](research/contextual-labeling-rubric.md), and the current revision records. No raw protected-final examples, model weights, training, detector calls, study scoring, or new external literature search were used. Literature recommendations below identify what to investigate and cite; they do not claim that an unperformed search has established novelty.

**Confidence:** high for rubric wording, page count, visible presentation, source-level omissions and the reported evidence boundaries; moderate for predicted marking bands, because marker discretion and the official template/instructions beyond this rubric are unavailable. This is a reasoned assessment, not a promised grade.

## 2. What the rubric actually rewards

The rubric has four weighted categories, totaling 100%. Its columns are **0, N, P, C, D and HD**. It does **not** specify numerical boundaries for those bands, point allocations to subcriteria, how to combine mixed subcriteria, or an automatic overall-paper penalty for a formatting breach. C means exceeding all acceptable criteria and meeting some HD criteria; D means exceeding all acceptable criteria and meeting most HD criteria. The P column supplies the acceptable descriptions. A 0 applies when the category is absent or insufficient to assess.

Consequently, there is no defensible rubric-derived numerical mark or total to calculate. Treating HD as a particular percentage, assigning invented subweights, or converting the page-limit defect into a specified overall deduction would add rules that the PDF does not contain. The estimates below use the actual bands. If the course supplies numerical conversion rules, a total can then be calculated as `0.30 × background score + 0.50 × scientific score + 0.10 × structure score + 0.10 × expression score` on a common scale.

| Category and weight | All assessed dimensions | HD requirement, condensed faithfully | Current judgment and evidence |
| --- | --- | --- | --- |
| **Background, context, literature review/state of the field: 30%**; rubric p. 1 | Relevance/depth; literature coverage; critical analysis; research question | Comprehensive relevant context; concise current and seminal literature, with appropriate grey literature; understanding of engineering concepts; critical identification of gaps/inconsistencies; a clearly defined question justified by the review. | **C-D, leaning C.** Sections I-II establish local prompt disclosure and critically distinguish Casper, HaS, ProSan and Presidio. The guarded-update and randomized-telemetry contributions have much thinner prior-work grounding. The three questions are explicit, but the paper needs a sharper chain from each documented gap to the corresponding question. |
| **Scientific and Engineering content: 50%**; rubric p. 2 | Abstract/introduction/conclusion; methodology; data/results; discussion; innovation/originality | Clear summary and framing; appropriate, concise, sufficiently complete design/prototyping/testing methods; supporting visuals; comprehensive honest analysis with statistics where applicable; informative failures; discussion linked to earlier literature, bias, limitations and significance; original approach, design or findings. | **D is plausible; C-D under a stricter self-contained-methods reading.** The mechanisms and negative findings are substantial. All three questions receive explicit answers. The central weaknesses are provisional contextual targets, an extremely small retention guard/weak base, absent incremental semantic-cost measurement, and too much interpretive detail delegated to appendices. Honesty about these limits is a strength, not a reason to demand positive results. |
| **Structure, figures and tables: 10%**; rubric p. 3 | Organisation; figure/table quality and integration; formatting | Coherent flow using Abstract, Introduction and Conclusion; professional, explained, correctly cross-referenced visuals; strict use of the provided template. | **N-band formatting risk as supplied.** The PDF is 16 pages. The N descriptor explicitly includes “Exceeds 10 pages.” Organisation alone is closer to D, and many visuals are good, but the rubric does not say how a marker aggregates that with noncompliance. Template identity is unverified. Four visuals lack direct textual callouts and a table floats out of numerical order. |
| **Clarity and written expression: 10%**; rubric p. 4 | Clarity/precision; grammar/syntax; referencing, including AI acknowledgement | Precise, concise, accessible technical writing; defined terms; excellent grammar and no typographical errors; correct consistent citations; correctly acknowledged AI use in the project or paper. | **C-D for prose, with a material N-band acknowledgement risk.** Language is generally accurate, but study abbreviations, multiple meanings of joint correctness, and slash-packed numbers tax the reader. Methods disclose assistant-supported targets; the paper does not explicitly cover AI-assisted writing/project work. The revision record describes an Astra whole-manuscript rewrite. Whether course acknowledgement rules are satisfied cannot be assumed. |

**Overall assessment:** a potentially strong D-level scientific paper inside a currently risky submission package. An overall HD judgment is not yet supported. Fixing page compliance and acknowledgement removes avoidable risks; it does not itself establish HD-level literature synthesis, originality or empirical support.

### Subcriterion-specific route to the highest band

| Rubric dimension | Highest-band gap to close | Completion evidence |
| --- | --- | --- |
| Background relevance/depth | Explain the engineering problem of contextual disclosure, intervention and safe revision, including the intended user/task setting. | A reader can identify whose information is protected, against what disclosure, through which supported path. |
| Current/seminal coverage | Cover the foundations and closest work for **all three** contribution strands, not just local sanitization. | A small, verified set of primary sources supports contextual decisions, update/retention design and local randomized reporting; every source earns its space. |
| Critical literature analysis | Turn descriptions into gap/choice/consequence comparisons. | Each claimed gap names the reviewed evidence and its scope; “not described in this version” is not inflated into “does not exist.” |
| Question justification | Explain why each question follows from a gap and what the available measurement can answer. | One concise gap-to-RQ map, consistent with the method/result map. |
| Abstract/introduction/conclusion | Prioritize one systems story and a few decisive findings. | All three passages agree on contribution, measured scope and unresolved benefit. |
| Methodology | Put the necessary target definitions, model comparison, split status, guard and measurement boundary in the main text. | An engineer can interpret every headline result without an appendix or repository audit. |
| Data/results | Give interpretable effect sizes, denominators, paired harms and appropriate existing uncertainty beside the principal finding. | All numeric claims trace to a named evidence unit; repeated calls are not presented as new cases. |
| Discussion | Explain what the findings change in engineering decisions and how they relate to cited work. | A short implication for each RQ plus explicit bias mitigation and remaining limitation. |
| Innovation/originality | Identify a bounded original integration or finding and establish it against relevant prior art. | A contribution table connects prior limitation, PriVoke design difference, measured evidence and boundary. |
| Organisation | Compress to a compliant argument, rather than a catalogue of experimental history. | Complete paper within the confirmed limit; coherent section transitions; essential evidence retained. |
| Figures/tables | Integrate the visuals and prioritize those that carry the argument. | Every retained figure/table has a direct callout, readable labels, a takeaway, correct order and explicit metric/scope. |
| Template adherence | Confirm that IEEEtran conference is the actual supplied template; obey its layout. | Comparison with the official course template and compliant compiled output. |
| Clear, precise language | Standardize vocabulary and separate metric meanings. | Consistent definitions of sensitivity, visibility/audience, policy agreement, label-joint and action-joint correctness. |
| Grammar/syntax | Final full-paper copyedit after structural changes. | No typographical errors, ambiguous slashes, undefined acronyms or broken references in rendered pages. |
| Referencing/AI | Support technical foundations and source-version distinctions; give a truthful, complete AI statement. | Verified claim-to-source mapping, clean bibliography and acknowledgement meeting course requirements. |

## 3. Immediate submission decisions

### 3.1 Resolve the page limit conservatively

The current main narrative fits in nine pages, but that is not enough to establish compliance. The supplied rubric does not exempt references or appendices. Counting all pages gives 16; excluding only references still gives 15. Only an independently confirmed rule excluding appendices **and** references would make the nine-page interpretation sufficient. The earlier editorial acceptance of a main-text limit is not evidence that the new rubric permits that interpretation.

**Recommended action:** prepare a maximum-ten-page complete submission, including references, unless the course explicitly permits exclusions. Retain detailed methods and negative evidence in a separately permitted supplement/repository record. Do not hide essential definitions or adverse findings there. Confirm whether supplements are accepted and assessed; the main paper must still stand alone if they are not read.

An initial all-inclusive space budget is below. It is a planning aid, not a reason to shrink the template's typography or omit a necessary result.

| Material | Target page equivalents |
| --- | ---: |
| Title, abstract, introduction | 1.20 |
| Related work and bounded contribution | 0.90 |
| System design, overview and two compact flows | 1.40 |
| Evaluation method | 1.15 |
| RQ1 results | 1.40 |
| RQ2 results | 0.75 |
| RQ3 results | 0.75 |
| Discussion, limitations and conclusion | 1.10 |
| AI acknowledgement and references | 1.35 |
| **Total** | **10.00** |

The current nine-page main narrative plus one-page references is already near that total. Recover room for necessary methods/literature additions by removing repeated caveats, duplicate result presentations and low-priority chronology. Keep the main architecture and supporting flows; make them compact, legible panels if needed. Do not achieve the limit by reducing prescribed font sizes or margins.

### 3.2 Complete the AI-use statement

Source lines 165 and 305 describe assistant-provisional labels. That acknowledges one use, but the manuscript has no explicit statement describing AI assistance with writing, code or analysis where applicable. The [revision history](research/professor-rq-revision-20261016.md) records AI-assisted rewriting, so writing assistance is a concrete issue here.

Add the course-required declaration in its required location. Verify the actual tools/models, activities and human checking before writing it. Cover dataset/label assistance and manuscript drafting/revision; include software or analysis assistance only to the extent actually used. State what the authors independently checked and take responsibility for. Do not imply that AI-generated targets were independently human-adjudicated. A repository log, a tool citation, or an acknowledgement of labels alone should not be assumed to satisfy the paper-writing requirement. This is a correctable disclosure gap, not a finding of misconduct.

## 4. Section-by-section change and addition instructions

The locators below refer to the reviewed source/hash, not to line numbers after editing. **Editorial** means using existing material or improving explanation. **Evidence extraction** means selecting already recorded, allowed aggregate evidence; it is not permission to rerun a study. **New evidence** means an additional study, analysis or implementation step requiring a separate plan and appropriate authorization.

### Title, author block, abstract and keywords

**Current location:** source lines 29-52; PDF p. 1. **Rubric links:** scientific framing, clarity, structure.

**Keep:** the implemented local-inspection/action/update/telemetry scope and the candid negative conclusion. The abstract currently has a clear problem, system and evaluation sequence.

**Change/add:**

1. **Editorial:** decide whether “semantic privacy firewall” remains the most accurate short description of a layered product with conditional fallback. The title can stay if the abstract immediately states the supported-request boundary. A contribution-oriented alternative could emphasize *guarded detector updates*; changing the title is optional, not a rubric requirement.
2. **Editorial:** compress the abstract's service mechanics. Allocate one sentence each to problem, distinctive design, evaluation design, decisive outcomes, and significance. Do not add a list of every study acronym.
3. **Evidence extraction:** replace the vague “probes confirmed” with the bounded fact that 33 declared installed-browser correctness probes matched the expected request disposition. Retain the separate semantic-only specificity range of 13.36-21.76% and the finding that all three matched full-model candidates failed retention despite aggregate improvement. These are different scopes and must stay clearly labeled.
4. **Editorial:** explain why the negative findings matter: aggregate classification gains were insufficient to establish protected disclosure or justify publication. “Auditable lifecycle” should identify the observable artifact/action/guard linkage, rather than sound like a general assurance claim.
5. **Editorial:** preserve “useful adaptation and user benefit remain unestablished.” Do not use “safe,” “effective privacy protection,” “real-time,” or “low overhead” without the corresponding evidence.

**Acceptance:** a reader can state the system, original contribution, study boundaries and principal finding after the abstract alone. Every quantitative abstract claim appears with its denominator/scope in the body. The author block and footnotes comply with the official template.

### I. Introduction

**Current location:** lines 54-70; PDF pp. 1-2. **Rubric links:** relevance, justified questions, originality, accessible framing.

**Keep:** the distinction between detecting information, deciding an action, preventing transmission and preserving protection during updates. Retain the professor's three questions verbatim unless a later authorized revision changes them.

**Change/add:**

1. **Editorial:** introduce one short, explicitly illustrative scenario showing why presence is not authorization: similar information may be acceptable in one audience/task context and inappropriate in another. Use an invented benign example, not a protected-final example. Make clear that the scenario motivates the problem; it is not empirical evidence.
2. **Editorial:** state the intended setting and success criterion more concretely: inadvertent disclosure on supported outgoing web requests, under trusted client/publisher assumptions. Separate that from a claim to stop a malicious page or compromised endpoint.
3. **Editorial/literature work:** add a compact contribution paragraph or three-item list: (a) implemented request enforcement with inspectable execution, (b) version-bound guarded revision evaluated using gains and harms, and (c) separately accounted telemetry with measured privacy/utility limits. Link each to RQ1, RQ2 or RQ3 and identify what is actually novel after the literature review is strengthened.
4. **Editorial:** distinguish a research question from a success claim. RQ1 can receive a qualified answer; RQ2 can receive “not established”; neither should be silently weakened after seeing results.
5. **Editorial:** shorten the roadmap and duplicated descriptions already explained in Design. Use the recovered space for the gap-to-contribution argument.

**Acceptance:** the introduction explains why the work is needed, what prior systems already provide, what this project adds, and how each question tests that addition. The general engineering reader need not know repository protocol names.

### II. Related Work and Contribution

**Current location:** lines 72-80; PDF p. 2; related detail in Appendix D, pp. 12 and 15. **Rubric links:** the full 30% background category and originality/discussion in the 50% scientific category.

This is the highest-value intellectual revision. The current comparisons are careful and useful, but coverage is concentrated on local sanitization. The paper's strongest claimed distinction is guarded revision, while telemetry has a formal privacy argument; these strands need their own scholarly context.

**Change/add:**

1. **Literature work:** organize a concise synthesis around three needs: contextual/local prompt intervention; regression-aware detector revision and model delivery; locally randomized reporting and its utility/implementation limits. Locate and read relevant primary sources, including seminal foundations where appropriate. Reuse verified sources already in the bibliography when they support the exact claim. A long general federated-learning survey is not useful coverage for a system that explicitly does not implement federated learning.
2. **Editorial/evidence extraction:** move a shortened functional comparison from Appendix D into the main section. Suggested columns: protection target, outgoing-content action, user acknowledgement/recovery, update validation described, telemetry scope described, evaluation target. Use “not described in the reviewed version” for unavailable features. Do not infer absence from missing text or an abstract-only source.
3. **Editorial:** add the missing argumentative link after each theme: prior evidence establishes X, leaves Y unresolved within the reviewed scope, and PriVoke tests Z. For RQ2, distinguish existing software publication primitives from the contribution of combining and measuring them for privacy-detector retention. Do not present compare-and-swap, replay protection or classifier fine-tuning individually as newly invented techniques.
4. **Editorial:** preserve the excellent warning that Casper/HaS/ProSan report different targets and denominators. Reduce the space devoted to unmatched headline percentages unless a number is needed to explain an evaluation difference. The comparison should establish a design/evidence gap, not imply a leaderboard.
5. **Literature work:** add primary support for the randomized-response mechanism, privacy composition and any claims about implementation-level numerical privacy. The current rendered bibliography does not provide an evident foundational citation for Equation (1). Define the privacy model in Design, rather than asking an engineering reader to infer it from a formula.
6. **Editorial:** write a final bounded novelty statement distinguishing **design integration**, **empirical findings**, and **unproven benefits**. The strongest existing findings include the gap between aggregate gains and retention, the effect of early rule decisions, and the divergence between a conditional reporting bound and usable estimates.

**Acceptance:** each contribution has a defensible closest-work comparison and each RQ follows from that comparison. The review contains critical synthesis, appropriate current and foundational sources, and version-qualified claims. No new source is cited from a search snippet alone.

### III. System Design and Privacy Boundary

**Current location:** lines 82-142; PDF pp. 2-4. **Rubric links:** engineering methodology, conceptual understanding, figures, originality.

**III-A, Scope and Trust.** Keep the trusted workstation/publisher boundary and explicit transport exclusions. Add a small requirements-to-mechanism mapping: supported outgoing text remains local until a release action; BLOCK cancels before send; a revision must match its declared base; randomized reports remain separate from training. Label which are implemented contracts and which are tested invariants. Clarify whether any requirement is aspirational. Cite the relevant system tests/evidence artifact through a compact reproducibility pointer rather than adding a log catalogue.

**III-B, Local Inspection and Request Enforcement.** Keep the regex-first early stop and failure/fallback distinction. Bring a compact sensitivity/audience/category/action legend from Appendix A into the main text. Define “audience” versus the implementation's “visibility” once and use consistently. Explain that a returned confidence value is a heuristic head score, not a validated probability of privacy correctness. Include one illustrative traversal showing why a later semantic result cannot undo an early rule BLOCK. Preserve WARN's immediate unchanged-body forwarding and the fact that masked spans are not substituted into traffic.

**III-C, Guarded Detector Updates.** Keep the distinction between well-formed artifacts, retention checks, publication and client refresh. Put the core acceptance rule in a compact algorithm or equation: candidate tied to base, artifact validation, declared retention predicate, exact-base atomic publication or rejection. Explain that publication occurs separately for head/underlying-model stages. State whether each reported experiment actually published, merely computed a hypothetical effective artifact, or only tested the transport mechanism. A guard pass must remain a claim about declared cases/criteria.

**III-D, Separate Randomized Telemetry.** Define local differential privacy in words, the protected unit as an event tuple at a fixed reporting opportunity, the compared input/output distributions, and the role of epsilon. State the independent randomness/common-configuration assumptions before deriving composition. Keep the distinction between the ideal mechanism and audited finite implementation. Move the long numerical kernel derivation to permitted supplementary material, but keep the nominal-bound failure and the reporting-presence/metadata exclusions in the main paper. Explain what aggregate question telemetry is intended to answer; that is necessary to interpret its measured utility.

**Figures 1-3:** retain their data/control distinctions. A three-panel design overview may save space, but labels must remain readable at normal print size. Check that all arrows and caption statements match the actual mechanisms, particularly the unchanged original-body release path, separate training examples and no telemetry-to-training edge. Current pixels are generally legible; the task is compression and integration, not a wholesale graphic redesign.

**Acceptance:** the reader can trace one supported request, one rejected/accepted revision, and one telemetry event, including failures and trust assumptions. The description does not equate local inference with complete privacy or a guard with universal safety.

### IV. Evaluation Method

**Current location:** lines 143-183; PDF pp. 4-6. **Rubric links:** methodology, bias/error handling, statistically appropriate reporting.

**IV-A, Questions and Evidence Units:** expand Table I selectively into a true study map. For each decisive experiment, include target, sample unit/count, development/final status, actual detector scope, comparison and metric. Separate 1,560 reused contextual cases, 498 once-only annotation-presence rows, 2,000 category-reference rows, 1,080 continuation-assessment cases, 16 guard cases, 33 receiver probes, and 360 timing decisions in 12 profiles. This prevents a reader combining incompatible evidence. State that the 1,080 cases are reused provisional assessment material, not a new independent test population.

Add a compact metric definition block. Use distinct names such as **label-joint agreement** and **label-and-action joint agreement**. This is particularly important because the semantic-only matched-continuation study includes action in its joint metric, while another semantic-only result excludes it. Define allowed-action agreement, under/over-restriction, binary projection and the relevant denominator. Table III can remain TP/TN/FP/FN if the corresponding rates are explained directly beside it.

Describe the labeling process and existing checks honestly. State who/what proposed the labels, whether any independent annotation occurred, and what the [labeling rubric](research/contextual-labeling-rubric.md) specifies. **Do not turn the existence of a labeling rubric into evidence of human agreement.** Independent adjudication is new evidence, addressed in Section 6 below.

**IV-B, Comparison and Retention Protocols:** include a compact V1/V3 configuration summary in the main method: encoder/pretraining status, tier capacity, input limit, decision thresholds and training lineage at the level needed to interpret confounding. Keep full recipes/seeds/source hashes in the evidence package. For the matched continuation study, retain byte-identical initial weights, three seeds, 4,096 exposures/64 steps, trainable parameters and changed clipping scope. Explain why the zero-head base and 16-case guard limit the inference. State the mismatch between a single derived guard action and allowed-action sets in assessment.

Add a short statistical-analysis paragraph before Results: paired comparisons, resampling unit, number of draws, seed, percentile construction, and descriptive rather than population coverage. Place existing uncertainty with the main claim it qualifies. Do not use thousands of calls or three repeats as independent sample size, and do not turn three shared-data seeds into a general significance claim. If a desired interval is not already recorded for that exact metric, label its production as a separately planned analysis; do not invent it or borrow a different endpoint's interval.

**IV-C, Enforcement, Cost and Telemetry Protocols:** give the browser/OS/configuration and historical model scope; summarize expected receiver outcomes and late-send checks. Put the cost boundary beside the experiment description: rules/NER only, page decision endpoint, two profiles per cell, container-wide CPU/charged memory, no unprotected baseline. State telemetry simulation truth distributions, 180 cells, 10,000 repetitions per cell, conditional estimand and accounting tests briefly. These details already exist in the appendices/records and can be selected without new execution.

**Acceptance:** every headline result has a defined target, denominator, comparison, execution scope and uncertainty interpretation in the main paper. Methods distinguish provisional labels, untouched final evidence at its original release, reused development evidence and synthetic systems probes.

### V. RQ1: Detection and Enforcement

**Current location:** lines 185-245; PDF pp. 6-7. **Rubric links:** honest comprehensive results, interpretation, scientific significance.

**V-A, Contextual Policy Agreement:** retain the six-package comparison and paired gains/harms. Replace packed historical/updated cells with clear grouped columns or a concise plot if space permits; use count/denominator and percentage consistently. The current Table II and Figure 4 largely duplicate the same comparison. Choose one main representation and put the detailed companion in the permitted supplement.

Promote the controlled ablation into a small table or paired-gain/loss graphic: balanced full-product action agreement 1,409/1,560 versus 1,530/1,560 without regex; 139 corrected restrictions but 18 lost correct actions; under-restriction 12 to 30. The [existing record](research/controlled-studies-20261014.md) already reports descriptive paired action-rate ranges by family and audience expression. If included, label the separate grouping assumptions and use the intervals for that contrast only. No new experiment is needed to explain this result. The engineering insight is the tradeoff imposed by the cascade, not that rules should generally be disabled.

**V-B, What Transfers Beyond the Authored Cases?:** separate the three target types visibly. Keep Table III and the poor final specificity prominent. Place the same-artifact comparison with authored semantic specificity directly next to it, explicitly stating that texts and targets changed. Keep the 2,000-row category result distinct, including its different any-finding projection. Condense Presidio details to the point needed for interpretation; the same-text reference is not a matched reproduction of the competing end-to-end systems. Report failed calls and skips, but move repetitive “zero errors” operational detail to concise table notes.

**V-C, Does a Decision Control Transmission?:** add a compact contract table giving expected versus observed send behavior for ALLOW, WARN, BLOCK and analysis/stream failures, drawn from the completed 33-probe evidence. Explain the eighteenth/fifteenth split only as observed unchanged sends versus zero-send cases, not 33 prevented disclosures. Preserve the difference between a runtime decision, a browser handoff and receiver-observed traffic. Failed earlier captures remain separately recorded.

**New evidence, only if retaining stronger effectiveness claims:** independently adjudicated contextual evaluation and authorized task utility are required. A new matched external end-to-end comparator could strengthen a superiority claim, but superiority is not needed for the present bounded contribution. Do not add a rushed unfair baseline to create the appearance of breadth.

**Acceptance:** the answer to RQ1 distinguishes provisional policy agreement, source-label agreement and verified request disposition. The section explains the most consequential failure modes and their engineering implications, not just the highest score.

### VI. RQ2: Updates and Previously Protected Behavior

**Current location:** lines 246-276; PDF pp. 7-8. **Rubric links:** innovation, informative negative results, experimental rigor.

**VI-A, Mechanism Versus Useful Adaptation:** keep the distinction and shorten the list of earlier experimental branches to a sentence plus a supplementary evidence pointer. State the mechanism evidence precisely: which artifact/update/client-refresh properties were demonstrated, under which setting. Avoid describing the unmatched historical-to-updated package comparison as an isolated test of automatic adaptation.

**VI-B, Matched Continuation and Guard Decisions:** revise Table IV so each row or grouped entry clearly identifies head-only/full-model treatment, aggregate improvement, assessment losses, guard outcome and hypothetical retained artifact. A reader should see that all three full-model candidates fail and that none was published. Keep the head-only passes/failure and shared weak base visible. State explicitly that the small guard does not bound harms in the 1,080-case assessment.

Use the paired losses to explain why average gains are an insufficient publication criterion. Do not sum under-enforcement and over-enforcement counts into an invented disjoint total. Distinguish harm relative to head-only treatment from the guard's harm relative to its declared base. Reuse exact existing intervals only where available and pertinent; three seeds do not establish a population-level guarantee.

**New evidence:** to claim useful adaptation without sacrificing previously protected behavior, use a meaningful trained common base, independently reviewed retention cases, declared casewise harm tolerances and a new protected assessment. A practical update study also needs publication and verified client refresh of an eligible candidate, with candidate/effective-artifact distinction. This is a stronger claim than the current experiment supplies. If that work is infeasible, the negative result remains a valid contribution: the guard rejected specific harmful changes, and useful safe adaptation remains unestablished.

**Acceptance:** an examiner can reconstruct why each candidate would be accepted/rejected and what would actually be served. The key conclusion remains the finding about aggregate gains versus retained protection, not a promise of universal safety.

### VII. RQ3: Systems and Privacy Overhead

**Current location:** lines 278-294; PDF p. 8. **Rubric links:** appropriate measurement, analysis, interpretation, limitations.

**VII-A, Measured Systems Cost:** put the measurement boundary in the first sentence and in a small table: rules/NER decision latency, whole-container CPU, sampled charged memory, included/excluded components, and missing baseline. Retain 27.9-35.0 ms as observed cell medians, not “semantic inference latency” or incremental overhead. Use “observed maximum” instead of visually emphasizing p99 based on only 60 measurements/two profile clusters per cell. Do not compare host RPC timing to browser decision latency as if they were the same quantity. Existing descriptive product cost can be summarized in a sentence or moved out of the main submission.

**New evidence:** if RQ3 is to claim incremental system overhead, measure matched unprotected and protected configurations on the same hardware/workload with randomized or counterbalanced ordering, cold/warm conditions, multiple independent session windows and explicit process/resource boundaries. For the LLM-layer cost question, explicitly select and assert semantic-only execution. Any separately authorized product end-to-end experiment should report its detector selection and actual skips separately. Measure semantics rather than inferring its cost from rules/NER timings.

**VII-B, Privacy Cost and Telemetry Utility:** present three separate answers: conditional content privacy, estimation error, and contribution/availability selection. Keep the finite nominal-bound failure, but distinguish its tiny magnitude from the much larger practical estimator error. Explain the first-category truth of seven, bias +22.84 and RMSE 42.32 in count units so a general reader can judge their scale. A small table using existing low/high contributor counts can show that absolute error and relative error need not move together.

State the intended monitoring decision and a justified error tolerance before claiming utility. Defining such a criterion is prospective work; do not choose a threshold after viewing the current cells to declare success. A proposed sampler correction or coherent histogram estimator would need separate implementation and validation, not a wording change. Preserve the distinction between fixed-contributor simulation and real deployment usefulness, and between content privacy and participation/network metadata.

**Acceptance:** RQ3 answers what was actually measured and explains what additional measurement would be needed to answer “overhead” or “useful telemetry” more broadly. Nominal versus finite epsilon, time versus CPU-seconds, and charged memory versus process RSS remain unambiguous.

### VIII. Discussion and Limitations

**Current location:** lines 296-319; PDF pp. 8-9. **Rubric links:** insightful discussion, literature connection, bias/error mitigation, future directions.

The current limitations are unusually complete. Keep their honesty, but reduce repeated statements and devote more space to what the results teach.

**VIII-A, What the System Evidence Supports:** organize around three design implications: (1) classification, policy and transmission need separate assurance; (2) retained behavior must be checked casewise before a version is published; (3) a content privacy bound does not establish useful monitoring. For each, cite the decisive result and connect it to a specific cited prior-work design or evaluation target. The current comparison to sanitization/recovery is a useful start; extend the scholarly connection to updates and telemetry after the literature work.

**VIII-B, Ground Truth and Generalization:** consolidate a threat-to-validity table if it saves space: threat, mitigation already performed, residual effect on the claim, next resolving study. Include provisional labels, reuse, source imbalance, grouping/dependence, unknown upstream exposure, native-package confounding and target mismatch. Do not equate lexical/group exclusions with certified template independence. Keep the explicit prohibition on reusing opened final data for tuning as if it were still untouched.

**VIII-C, Retention, Availability and Practical Utility:** distinguish deliberate scope exclusions from missing evidence required by a claim. Unsupported workers/attachments can remain scope exclusions if the paper does not claim their coverage. Independent contextual labels and incremental semantic-cost evidence are actual missing support for stronger accuracy/overhead claims. Explain the availability cost of blocking unavailable analysis and the semantic-coverage cost of fallback. User comprehension/task completion remain unmeasured. The post-capture diagnostic-event implementation and its 53 synthetic tests are peripheral: move detailed contracts to supporting material and retain only the fact that diagnostics are not user-benefit evidence.

**VIII-D, Measurement and Reproduction Boundaries:** reduce repeated capsule details to a precise artifact-availability statement. Name what another researcher can reproduce from tracked aggregates, what requires local ignored assets, and what is not publicly reproducible. Add a short, ordered future-work plan driven by the claims, not a catalogue: contextual truth/generalization first, meaningful-base retention next, semantic baseline-relative cost and task utility after that.

**Acceptance:** each main limitation has a stated effect on the conclusion, each claimed mitigation really occurred, and each future study resolves a named uncertainty. The discussion adds interpretation beyond paraphrasing the result tables.

### IX. Conclusion

**Current location:** lines 321-323; PDF p. 9. **Rubric links:** clear findings and significance.

Keep the concise and qualified conclusion. Tighten it around three outcomes: implemented auditable enforcement/update mechanisms; empirical evidence that aggregate improvements did not establish retained protection or broad contextual accuracy; and measured limits of overhead attribution and telemetry utility. End with what the contribution enables an engineer to inspect or decide. Do not end only with a list of missing work, and do not introduce a new result, citation-dependent novelty claim or promised future benefit. Quantities are optional here if already prominent elsewhere.

**Acceptance:** the conclusion answers the three original questions, matches the abstract, and gives one clear statement of significance without exaggerating the evidence.

### References and acknowledgements

**Current location:** bibliography command at lines 557-558; PDF p. 16. **Rubric links:** literature coverage, correct referencing and AI disclosure.

1. Verify the official referencing/template style before assuming `IEEEtran` plus `ieeetr` is accepted. It looks like a coherent IEEE-style manuscript, but the supplied course template was not provided for comparison.
2. Audit each claim-to-citation link. For example, the introductory sentence about provider-side handling should be supported by sources that actually establish that handling, rather than a broad privacy/economics reference whose relevance is unexplained. This is a source-checking task, not a finding that every current citation is incorrect.
3. Preserve distinctions between Casper v1 and its proceedings/abstract record, HaS's supplied version and dates, ProSan's supplied version and later publication, and PromptShield publication/abstract sources. The [existing literature record](research/literature-baseline-review-20261015.md) already documents several of these boundaries.
4. Add verified foundational/closest-work citations where the expanded literature and Equation (1) need them. Do not increase reference count with irrelevant surveys or claim to have inspected inaccessible full text.
5. Shorten repository-audit prose inside bibliography entries where the citation style allows; move interpretation into the paper or supplement. Keep enough version/revision information for reproducibility. Check author/title capitalization, venue/year, DOI/URL and access-date consistency against the source.
6. Add the truthful AI-use declaration described above and any required author-contribution/funding statement. Do not invent a funding source, individual contribution or human verification process.

**Acceptance:** every citation resolves; every cited source supports the attached claim; version distinctions are preserved; the paper itself correctly acknowledges actual AI assistance under the course rules.

### Appendices A-I and supporting artifacts

Appendices are currently six pages of the same PDF. Their value is real, but their present placement creates the page-limit problem. Under the conservative all-inclusive limit, extract the minimum necessary definitions into the main text and move the remaining detail only to a permitted supplement/repository artifact. Preserve the complete evidence; do not discard failed outcomes to reduce length.

| Current appendix and locator | Main-text content to retain/promote | Supporting-material treatment |
| --- | --- | --- |
| **A. Exact Policy Representation**, lines 327-331; p. 10 | Sensitivity/audience/category definitions, action mapping and confidence caveat. | Full label list and edge-case policy truth table; use the same terminology as main Methods. |
| **B. Detailed Comparison Protocols and Terminology**, lines 333-373; pp. 10-11 | Distinct joint metrics, study scopes, main configuration differences, paired uncertainty method, guard/assessment mismatch. | Full lineage terminology, optimizer/hardware versions, closure details, source hashes, all seven ablation layer configurations and external-reference protocol. Organize by study, not by execution chronology. |
| **C. Retained Update and Reference Detail**, lines 375-400; pp. 11-14 with delayed figures | Paired harms, core ablation finding, important negative adaptation outcome, appropriate uncertainty beside the relevant claim. | Preserve historical failures and complete counts; do not pool incompatible attempts. Select one main comparison plot instead of duplicating Table II. |
| **D. Related-System Interaction Detail**, lines 402-445; pp. 12 and 15 | Compact function/gap matrix supporting the novelty argument. | Version-qualified external metric table if still useful; no cross-study ranking. Add explicit callouts for retained Tables V and VI. |
| **E. Selected Training Lineage**, lines 447-470; pp. 12-13 | Enough package capacity/window/pretraining/training information to interpret V1/V3 confounding. | Full selected ancestry, optimizer recipes, stopping/selection and parameter-count table. Distinguish selected from attempted training dose and unknown upstream pretraining. |
| **F. Installed-Browser Cost Protocol**, lines 474-483; pp. 13-14 | Hardware/platform, requested layers, window boundaries, two profiles per cell, instrumentation and absent baseline. | Detailed startup/collector/cleanup protocol and failed-capture provenance. |
| **G. Descriptive Product Cost**, lines 487-506; p. 14 | At most one bounded comparison statement if it supports the main question. | Full median/p95/RSS table with backend/order/cascade caveats; do not compare its scope directly to browser timing. |
| **H. Installed-Browser Cost Outcomes**, lines 510-530; p. 14 | Main scoped latency/resource summary and session/sample units. | Complete transport/action table and sampling-gap/startup details; call a cell maximum a maximum. |
| **I. Telemetry and Local Reconstruction Details**, lines 534-554; p. 15 | Event unit/assumptions, finite nominal-bound failure, representative estimator error and exact reproduction limitation. | Kernel derivation, full simulation/accounting results and local capsule recipe as separate subsections/artifacts. Separate mathematical privacy evidence from software reconstruction. |

**Acceptance:** the submitted paper stays within the confirmed limit and remains interpretable without supporting files. Every supplement is clearly named/versioned and linked according to submission rules; no unsupported claim becomes true merely because a detailed protocol is available elsewhere.

## 5. Specific visual and structural corrections

All 16 pages were inspected as rendered PNGs, not judged solely from extracted text. No obvious clipping or collision prevented reading the inspected pages at review scale. This is not a fresh compilation/font audit.

| Observed issue | Location/evidence | Required correction |
| --- | --- | --- |
| The submission exceeds the rubric's stated limit. | 16 physical PDF pages; rubric p. 3 N descriptor. | Resolve counting rules and produce a compliant complete artifact. |
| Major result figures are remote from the result narrative. | Figures 4 and 5 on pp. 13-14; RQ1 on pp. 6-7. | Move the chosen essential result visual into RQ1 or provide a direct supplementary callout; remove redundant main-paper representations. |
| Four floats have labels but no direct textual `\ref` callout. | `fig:pipeline_v1_v3`, `fig:pipeline_presidio_reference`, `tab:related_functions`, `tab:related_results` each have zero direct references in source. | For every retained visual, add a sentence naming it and explaining its takeaway. Referencing the whole appendix does not fully integrate the individual visual. |
| A table appears out of numerical order and far from its section. | Table V on p. 12; Tables VII-IX on pp. 13-14; Table VI finally appears on p. 15. | Reduce/reposition the large table and review float order after compiling. Avoid forcing every float with `[H]` as a blanket fix. |
| Slash-packed data slows interpretation. | Tables II-IV and VIII, pp. 6-7 and 14. | Use clear historical/updated or head/full column headings and consistent units/denominators; preserve exact counts. |
| Some tabular labels are cramped. | Transport/action cells in Table IX, p. 14; long population text in Table VI, p. 15. | Add readable column spacing, shorten cells and move detailed caveats to notes without reducing prescribed font size. |
| Multiple meanings of “joint” are easy to miss. | Main Methods/Results and Appendix B. | Give each metric an explicit name and use that name in every heading/caption. |
| Template adherence is not demonstrated by appearance alone. | `\documentclass[conference]{IEEEtran}`, source line 1. | Compare against the actual provided template, including author block, references, margins and any required statements. |

## 6. What needs new evidence, and what can be fixed now

The highest band rewards good engineering research and informative failures. It does **not** require replacing every negative result with a positive one. The priority is to support the paper's chosen claims. A carefully bounded systems paper can improve substantially through writing and evidence selection alone; stronger generalization, adaptation, utility or overhead claims require additional work.

| Priority | Action | Work type | Required output/acceptance | Claim unlocked or clarified |
| --- | --- | --- | --- | --- |
| **P0** | Resolve page count, official template, AI declaration and float/citation defects. | Editorial/compliance verification | Compliant rendered submission, truthful acknowledgement, all callouts resolved. | Removes explicit rubric risks. |
| **P1** | Strengthen literature-to-contribution/RQ reasoning across enforcement, updates and telemetry. | Targeted source research and writing | Verified critical comparison and bounded novelty statement. | Supports background HD and defensible originality. |
| **P1** | Make study units/metrics and main result interpretation self-contained; consolidate duplicate detail. | Editorial and existing aggregate extraction | Main study map, unambiguous joint metrics, interpretable results and stated uncertainty. | Supports scientific rigor and clarity without new runs. |
| **P2** | Obtain independent contextual privacy/action annotations. | New evidence; human input/appropriate governance | Frozen annotation guide, independently assigned labels, disagreement/adjudication report, agreement statistics and separately frozen evaluation plan. Annotators should not infer labels from model outputs. | Tests contextual policy validity instead of merely assistant-label agreement. |
| **P2** | Evaluate generalization on a new protected successor with meaningful source/policy variation. | New evidence; separate authorization | Prospective frozen data/model/scoring protocol, disjoint development/guard/final roles, explicit leakage/group checks, semantic execution assertions and all outcomes retained. | Supports a bounded out-of-development contextual accuracy claim. |
| **P2** | Test retention from a meaningful trained common base and representative guard. | New evidence | Matched exposures/resources, independent retention targets, prespecified harms/tolerances, candidate/effective outcomes, rejected attempts retained; publication evidence only if actually performed. | Tests useful revision without conflating weak-base learning with safe adaptation. |
| **P2** | Measure baseline-relative semantic cost. | New evidence | Matched unprotected/protected sessions, explicit semantic-only cost arm, per-scope attribution, independent session units and uncertainty. | Supports an incremental overhead answer for the semantic layer. |
| **P3** | Evaluate authorized task completion and intervention burden. | New evidence; human/task study as appropriate | Independent expected actions/tasks, comparator, success/time/reformulation/comprehension measures and false-block burden; approved human-study process where required. | Supports practical user benefit, which receiver probes cannot establish. |
| **P3** | Establish a telemetry monitoring task and improve/test the mechanism or estimator if needed. | Prospective design plus new validation | Predeclared usefulness tolerance; coherent estimation analysis; exact implemented privacy bound for any revised sampler; selection assumptions stated. | Supports useful monitoring or a corrected bound, rather than simulation consistency alone. |
| **P3, claim-dependent** | Broaden installed-provider/platform coverage or create a matched external system comparison. | New authorized product study | Pinned compatible settings, common task/labels/actions, explicit unsupported functions, receiver evidence and failures. | Supports only the tested compatibility/comparative claim; not necessary to keep the current narrow systems claim. |

**Execution boundaries for any later work:** this review authorizes none of these studies. LLM-layer training/evaluation/testing must explicitly request the semantic layer and assert actual returned execution; an empty layer list runs the complete pipeline and is invalid for that purpose. Regex, NER and full-pipeline work belong only to a separately requested product end-to-end study or detector ablation, with separate results. Raw Python tests/evaluation/scoring belong in the maintained host Python environment, not a test-driver container. The already opened final endpoint must not be reused as an untouched selection set. Reusable weights, independent originals, provenance and failed attempts must be retained under the project rules.

## 7. Suggested revision sequence and stopping conditions

1. **Freeze the submission contract.** Confirm page counting, template, supplement rules and AI acknowledgement wording/location. Use the conservative all-inclusive ten-page plan until an exemption is established.
2. **Write the contribution and gap map first.** Define what the completed evidence supports and retain the three questions. This governs what stays in the main text.
3. **Revise Related Work and the main study map.** Add verified, necessary literature; promote metric/target definitions and comparison boundaries from the appendices.
4. **Choose the decisive visual for each question.** RQ1 needs detection/action tradeoffs and bounded receiver behavior; RQ2 needs paired gain/harm/guard outcome; RQ3 needs explicitly scoped cost and privacy/utility evidence. Avoid multiple plots that merely repeat a table.
5. **Rewrite Results and Discussion around findings and implications.** Keep failures and limits; reduce repeated defensive caveats by putting each qualification at its most consequential claim.
6. **Decide whether stronger claims warrant new evidence.** If studies cannot be done, retain the narrower conclusion. Do not write proposed work as completed work or guarantee HD after a prose revision.
7. **Compile, inspect and audit the final submission.** Update artifact hashes and evidence pointers after the manuscript is stable. Stop when the rubric checks below pass; do not add experimental branches merely to increase volume.

## 8. Final acceptance checklist

### Rubric and story

- [ ] The complete PDF obeys the confirmed page-count rule; all exclusions have an authoritative basis.
- [ ] The supplied template and mandatory Abstract, Introduction and Conclusion are used correctly.
- [ ] Every contribution is grounded in a critical literature comparison; each RQ follows from an identified gap.
- [ ] The abstract, introduction, results answers and conclusion agree on what was implemented, measured and not established.
- [ ] The discussion connects results to cited prior work and explains design implications, bias mitigation and residual limitations.

### Scientific interpretation

- [ ] Each headline result identifies its target, population/sample unit, denominator, model/version, detector scope and reuse/final status.
- [ ] Label-joint and label-and-action joint metrics are distinguishable; the matched semantic-only action-inclusive metric is explicit.
- [ ] Contextual policy agreement, annotation presence, official category agreement and observed transmission are never pooled into “privacy accuracy.”
- [ ] Paired gains and harms accompany aggregate improvements; rejected candidates and hypothetical effective artifacts are not presented as published improvements.
- [ ] Uncertainty uses the correct paired/group structure and is labeled descriptive where appropriate; repetitions/calls are not independent cases.
- [ ] WARN forwarding, early rule BLOCK, fallback, unsupported traffic and trust assumptions remain visible.
- [ ] Browser latency is not relabeled semantic latency; container cost is not relabeled incremental overhead.
- [ ] Ideal and finite telemetry guarantees, content and participation scope, and simulation versus deployment utility remain distinct.
- [ ] No new human-label, generalization, calibrated-confidence, safe-adaptation, superiority or user-benefit claim appears without new supporting evidence.

### Presentation and integrity

- [ ] Every figure/table has a direct callout, a purpose, readable units/labels and a correct caption; float order is coherent.
- [ ] All citation keys/references resolve and support the exact attached claims; source versions and dates are accurate.
- [ ] Actual AI use in labels, project work and manuscript writing is truthfully acknowledged as required.
- [ ] All rendered pages have been inspected at normal reading scale for crowded columns, clipped content, tiny labels, unresolved references and misleading visual comparisons.
- [ ] The final PDF and source are hash-bound to the same reviewed revision; retained old records are not mistaken for current acceptance.
- [ ] Supporting artifacts distinguish public tracked aggregates from local-only assets and make no unsupported clean-install/reproduction promise.

## 9. Review record and limitations

**Assigned review prompt retained for provenance:** “Evaluate the current paper according to the newly inserted paper/Final_Paper_Rubric.pdf and produce a detailed Markdown next to the paper specifying changes/additions for every section to achieve the highest rubric marks.” The delegated scope required cohesive review of the full rubric, source and rendered PDF, criterion/weight/band coverage, evidence-linked reasons, section-by-section changes, priorities and acceptance checks, while forbidding manuscript changes and experiments. This document is the persistent question map, evidence ledger and result for that bounded review; it is discoverable beside the paper.

The review questions were: (1) what does this exact rubric require, (2) where does the current submission meet or miss it, (3) what changes improve each section, and (4) which claims need new evidence rather than editing? Sections 1-2 bind the evidence and criteria; Sections 3-5 answer the submission/section questions; Sections 6-8 define the work distinction and acceptance conditions.

Checks performed: full LaTeX read; text extraction of all four rubric pages and all sixteen paper pages with `pypdf`; all-page raster rendering with Poppler and visual inspection; artifact SHA-256 comparison against the latest revision JSON; source search for sections, AI acknowledgement and direct figure/table references; narrow comparison with existing aggregate evidence records. No training, service startup, inference, protected-final access or study scoring occurred. The full bibliography's external sources were not independently re-opened in this review, the course's official template and numerical grade conversion rules were unavailable, and the scientific results were assessed as reported rather than rerun. Those limits remain explicit rather than being treated as passes.
