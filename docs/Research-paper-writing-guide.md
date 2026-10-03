# PriVoke research paper: methodology, writing and submission guide

Reviewed 3 October 2026. Use alongside the [research completion plan](Research-completion-plan.md), [evaluation guide](README.Evaluation.md) and current [`paper/main.tex`](../paper/main.tex). This guide recommends how to make the paper credible and easy to review; it cannot guarantee acceptance. It does not report new experimental results.

A [methodology draft](research-methodology-draft.md) records the implemented
evaluation design, development amendments and pending evidence. Review its
statuses against the final frozen experiment before incorporating it into the
manuscript.

## Does the methodology need to change?

**Yes: strengthen the empirical evaluation and align claims with what is measured. The layered architecture does not need to be replaced merely to publish with IEEE.** Retain the implementation if it answers a worthwhile question. Change the experimental design wherever it cannot establish the proposed contribution.

There is no single IEEE-mandated methodology for all papers. Separate three issues:

| Issue | What it means | What PriVoke should do |
| --- | --- | --- |
| Publication policy | Originality, attribution, accurate reporting, authorship and applicable research ethics | Follow IEEE policy and the selected venue's additional rules. |
| Venue compliance | Template, anonymity, length, submission fields and artifact policies | Use the exact current call, not a generic IEEE template. |
| Scientific strength | Whether the evidence supports a novel, useful conclusion | Adopt the experiment recommendations below and obtain independent domain review. These are recommendations, not universal IEEE mandates. |

IEEE's conference policies cover publication integrity and AI-generated content. S&P and EuroS&P solicit novel security/privacy contributions, but their calls do not prescribe one universal dataset, sample size or minimum accuracy. [IEEE submission policies](https://conferences.ieeeauthorcenter.ieee.org/author-ethics/guidelines-and-policies/submission-policies/), [S&P 2027 call](https://sp2027.ieee-security.org/cfpapers.html), [EuroS&P 2027 call](https://eurosp2027.ieee-security.org/cfp.html).

### Required changes to support the intended PriVoke claims

Here, “required” means necessary to substantiate the stated claim, not an IEEE-wide rule.

| Current evidence or approach | Necessary improvement | Reason |
| --- | --- | --- |
| Hypothetical accuracy/speed trends | Replace with measured findings or remove the performance claim | Expected results cannot establish effectiveness. |
| Full-pipeline binary scores | Add matched baselines and layer ablations | Establish whether the semantic layer or updates add value beyond rules/NER. |
| Template-driven updates | Separate update/development/test sets by family, document and transformation lineage; compare frozen and updated versions | Distinguish generalization from memorizing generated examples. |
| PII-presence datasets | Add independently annotated contextual/action cases for contextual-risk claims | An entity annotation is not a privacy policy or a correct ALLOW/WARN/BLOCK label. |
| Runtime API scoring | Add browser request-capture tests | Detection does not prove prevention of transmission. |
| Average runtime | Measure distributions, cold/warm behavior and end-to-end overhead | A mean runtime-only value does not establish interactive client cost. |
| Multiple runs without an independence model | Pair comparisons on the same examples; report variation across training seeds and group related examples | Repeated measurements are not additional independent prompts. |
| Description of private telemetry | Specify the privacy unit, assumptions, composition and exclusions; measure aggregate usefulness if claimed | A formal mechanism does not automatically establish useful monitoring or user-level protection. |

Retain PIIMB as the main public binary benchmark and the four positive-only datasets as separate recall studies. Do not manufacture trusted negative labels from missing annotations. Synthetic prompts remain useful controlled tests; describe their construction and limits. More synthetic rows alone do not resolve external validity.

Predefine the main outcome, tuning budget, sample-size rationale and acceptable regressions. Report effect sizes and uncertainty, not only whether a result is statistically significant. Use a source/family-aware paired comparison where examples are related. A confidence interval for a difference directly addresses improvement; comparing overlap of two separate intervals does not answer that question reliably. Report planned primary analyses and identify exploratory analyses. Preserve failed runs and explain exclusions.

The project-specific priority is a testable difference from Casper, which already describes a client-side rules/NER/local-semantic pipeline. A controlled-update contribution is plausible, but its usefulness remains a hypothesis until held-out evidence supports it. [Casper](https://arxiv.org/abs/2408.07004).

## Build the manuscript around one argument

Use this reasoning chain: **problem → gap in existing work → research question → design choice → experiment → finding → implication and boundary**. Each contribution must have a corresponding result or analysis. Model streaming and microservices are useful implementation details; their existence alone does not establish a research contribution.

Recommended structure:

1. **Abstract:** problem, specific approach/difference, evaluation scope, main measured result and its implication. Write last. Use actual values only after validating the reports.
2. **Introduction:** define the disclosure problem, explain the closest existing solution and the remaining question, then state two or three concrete contributions. Avoid a long catalogue of incidents or an unsupported claim that all prior systems are static.
3. **Background and related work:** include only concepts necessary for the argument. Compare systems by detection task, local/cloud boundary, enforcement behavior, adaptation and evaluation. Credit overlap explicitly.
4. **Threat model and scope:** identify assets, adversary, trusted components, supported inputs, deployment assumptions and excluded cases. Distinguish accidental disclosure, deliberate evasion and compromised-client attacks.
5. **Design and implementation:** explain consequential choices and tradeoffs. Describe actual model initialization/training, frozen parameters, action selection, update publication, outage behavior and telemetry boundary. Omit deployment instructions that belong in documentation.
6. **Methodology:** research questions, data provenance/labels, annotation rubric, splits, contamination controls, baselines, tuning, versions/hardware, metrics, uncertainty, exclusions and ethical treatment.
7. **Results:** one subsection per question. Lead with the finding, show evidence, then interpret within scope. Include null findings, regressions and representative failures.
8. **Discussion and limitations:** explain mechanisms and competing explanations; address construct, internal, external and statistical validity. Separate observed behavior from proposed extensions.
9. **Ethics and artifact/data availability:** place these where the venue requires. Give concrete mitigation and access/reproduction information.
10. **Conclusion:** answer the original question with supported findings. Introduce no new numerical claims.

This ordering is a recommendation, not a compulsory IEEE section sequence. Do not bury decisive evidence in appendices that reviewers are not expected to read.

## Wording rules and examples

Write plainly and specifically. “We evaluate” and “we measure” are appropriate; first person is not inherently unscientific. Define terms once, use consistent labels, and prefer concrete verbs over promotional adjectives. Choose one spelling convention throughout unless the venue specifies otherwise.

| Avoid | Prefer, when supported | Why |
| --- | --- | --- |
| “PriVoke guarantees user privacy.” | “PriVoke cancels requests classified as BLOCK on the tested supported paths.” | States the implemented protection without implying universal coverage. |
| “Our novel three-layer detector…” | “We combine rules, NER and a local semantic classifier, and evaluate controlled head updates.” | Credits an established architecture while identifying the proposed contribution. |
| “PriVoke continuously learns from users.” | “The classifier is updated using labeled examples supplied by the fuzzer.” | Current documentation does not connect user telemetry to training. |
| “The system prevents all sensitive disclosures.” | “WARN forwards the original request; BLOCK cancels it. Outage behavior is reported separately.” | Detection, warning and prevention differ. Verify behavior against code and experiments. |
| “Accuracy improves over time.” | “At the predefined checkpoint, the updated model changed held-out recall by [difference] percentage points, with [interval].” | Requires measured comparisons and exposes uncertainty. |
| “The detector is fast and lightweight.” | “On [hardware], warm end-to-end p95 latency was [value] ms and peak resident memory was [value] MB.” | Makes the claim testable. |
| “No personal information leaves the device.” | “In streamed mode, classification runs locally; report presence and transport metadata are outside the telemetry guarantee.” | Avoids confusing payload minimization with anonymous communication. |
| “DP makes telemetry anonymous.” | “The randomized tuple satisfies event-level [epsilon]-LDP under the stated trusted-emitter assumptions.” | Names the actual privacy unit and assumptions. |
| “The fuzzer performs adversarial learning.” | “The fuzzer samples labeled templates and applies [specified transformations].” | Use stronger terminology only after defining and evaluating the attack/training model. |
| “Results prove real-world effectiveness.” | “Results support effectiveness on the evaluated English datasets; deployment generalization remains unmeasured.” | A benchmark is not a representative deployment study. |

Bracketed fields are placeholders, not findings. Remove every placeholder before submission. Do not weaken a supported result with vague language: use “measured” for observations, “suggests” for qualified interpretation, “we hypothesize” for untested mechanisms, and “we plan” only for future work.

### Paragraph templates

**Method:** “To test [question], we compared [systems] on [locked data]. We selected [samples/groups] using [procedure] and fixed [tuning decisions] using development data. We measured [outcomes] and estimated uncertainty using [method and grouping]. The final test set was not used for model or rule selection.” Use the final sentence only if true.

**Result:** “On [dataset], [system] achieved [outcome with interval]. Its paired difference from [baseline] was [effect and interval]. [Secondary outcome] changed by [effect], indicating [bounded interpretation]. This comparison applies to [scope].”

**Limitation:** “The test set contains [limitation], which may [direction/mechanism of bias]. We therefore do not infer [unsupported broader conclusion]. [Additional experiment] would be needed to resolve this uncertainty.”

**Contribution:** “We evaluate whether [specific method] improves [task] under [condition], using [comparison and evidence].” After results exist, state the actual finding rather than promising improvement.

## Report numbers, figures and citations precisely

- State the evaluated denominator, class distribution, successful coverage and error count. Report recall/specificity together for binary experiments; positive-only recall cannot establish clean-input performance.
- Label the measurement unit: prompt, span, category, action or transmitted request. Do not label category-grouped prompt recall as exact category accuracy.
- Distinguish percentage points from relative percentages. An illustrative change from 80% to 84% is four percentage points, or a 5% relative increase; this example is not a PriVoke result.
- Name the interval method, confidence level, grouping and bootstrap iterations where applicable. Give hardware/software/model versions and sample-selection details sufficient for reproduction.
- Captions should state dataset/split, configuration, sample size, metric/unit and meaning of error bars. Label axes and baselines; avoid plots whose scales exaggerate a small difference. Ensure figures remain legible in the final column width and grayscale.
- Generate tables and plots from archived results. Replace the manuscript's illustrative trend figures before making empirical claims. Record the source report and generation script for each figure.
- Cite primary evidence near the supported claim. Verify every bibliography entry against the source; an AI-proposed citation or search snippet is not verification. Distinguish a paper's reported result from a reproduced result.
- Keep literature comparisons fair: different datasets, label definitions or hardware prevent a direct numerical ranking. Quote or paraphrase with attribution; reuse figures only under appropriate permissions/licenses.

## Official requirements versus good practice

Requirements vary by venue and year. The following official-source checkpoints were verified on 3 October 2026; recheck before submission.

| Source | Relevant requirement | Practical action |
| --- | --- | --- |
| [IEEE conference submission policies](https://conferences.ieeeauthorcenter.ieee.org/author-ethics/guidelines-and-policies/submission-policies/) | Addresses originality, research ethics and disclosure of AI-generated content | Audit attribution and applicable ethics review; track generated content incorporated into the article. |
| [EuroS&P 2027 call](https://eurosp2027.ieee-security.org/cfp.html) | Supplied A4 template; 13-page body limit; anonymous submission; open-science and harm considerations | Create a compliant anonymous version with reproducibility information and explicit scope/harms. |
| [S&P 2027 call](https://sp2027.ieee-security.org/cfpapers.html) | US Letter `conference,compsoc` format; anonymity; ethics and generative-AI submission fields | Read the full current call and prepare its required submission metadata. |

Generic `\documentclass[conference]{IEEEtran}` in the present manuscript does not establish compliance with either specific venue. Keep readable layout; do not squeeze margins or fonts to fit. Resolve references, missing figures and compilation warnings, then visually inspect the final PDF.

AI-use rules also differ. IEEE's general policy requires disclosure of generated content and identification of its use; editing/grammar assistance is generally treated differently. EuroS&P specifies acknowledgments disclosures, while S&P additionally requires a submission field covering AI use/study and rationale. Check the selected venue even for editorial assistance. If text from this guide or other AI outputs is incorporated into the paper, track what was used and have authors verify it. Do not invent the tool/model version. See the official policies above for the exact requirements and anonymous-review handling.

Keep AI-generated dataset construction separate from manuscript assistance in the methods/disclosure record. Record generator prompts, model identifiers/dates/settings, filtering and annotation procedures where relevant. Authors remain responsible for factual accuracy, original analysis and citations. Do not treat fluent wording as evidence.

## Revision workflow and acceptance-oriented checklist

Write methods and design first, then results and discussion, and finalize the introduction/abstract last. Keep a claim-to-evidence ledger as specified in the completion plan. Review the paper in separate passes: contribution, experiment validity, claim accuracy, clarity, and venue compliance.

Before declaring the paper ready:

- [ ] A reader can identify one main question and the difference from the closest work.
- [ ] Each contribution has locatable evidence; no unmeasured improvement is implied.
- [ ] Baselines, splits, tuning and statistics permit fair comparisons and reproduction.
- [ ] Results separate detection, action decisions and actual transmission outcomes.
- [ ] Privacy claims state their unit, assumptions, composition and exclusions.
- [ ] Negative findings and major alternative explanations are addressed.
- [ ] A domain reviewer independent of the main experiments has challenged the paper and unresolved objections are recorded.
- [ ] All claims, references, figures and numbers were checked against sources/artifacts.
- [ ] Ethics, AI use, licenses and availability statements match actual practice.
- [ ] The exact venue template, anonymity, limits, submission fields and overlap rules are satisfied.
- [ ] All authors approve the final paper and venue; the final PDF and artifact have been checked.

These steps improve scientific credibility and reduce avoidable rejection risks. They do not turn an ordinary integration into a novel contribution, establish an acceptance probability, or require favorable experimental results. An honest, well-supported negative finding is preferable to a stronger claim the data cannot sustain.
