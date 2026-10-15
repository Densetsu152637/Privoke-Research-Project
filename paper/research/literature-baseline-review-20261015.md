# Uploaded literature baseline review — 15 October 2026

Record ID: LBR-20261015. Status: accepted source findings consolidated for manuscript review; recommendations remain prospective.

## Goal, exact prompt and questions

> I have now given you some sources inside the papers folder, which contains the 3 main papers that our research extends from, and some other background ones that contain background principles used in the paper. I want you to go through the 3 main ones, and use them as context and as a good baseline and literature source whilst reviewing our paper.

The supplied main papers resolve to `paper/sources/main/` in this checkout.
The review asks: what do these versions implement, what do their reported metrics mean, where does PriVoke overlap, and which manuscript claims or future comparisons need refinement?
It compares the three main papers with the manuscript and decisive browser forwarding paths; background papers are outside this audit.
It establishes a literature baseline, not a reproduced experimental baseline or whole-paper readiness decision.

## Inputs, versions and method

Repository: `D:/Git Repositories/Privoke-Research-Project`; branch `feat/dev-testing`; input HEAD `e2b3d5c97c3b9b1c7d300f78c987de8dce3d117e`.
Manuscript: [`../main.tex`](../main.tex), SHA-256 `09bfbcd21bc416aa70bf407ad5a7e47aca7c1283284574f2a1c825ebbd8a3763`.
Working bibliography: [`../ref.bib`](../ref.bib), SHA-256 `84769bf62dbf21c15edcdc213d31a0bcea4ed08d593c1a77d3a789313cfd986e`; this pre-existing dirty file was read without modification.
Line locators below refer to that manuscript snapshot, not a future revision.
Three independent readers reviewed the full supplied papers using extracted text (`pypdf`) and rendered decisive pages (`pdftoppm`).
The coordinating reviewer inspected decisive PDF pixels and implementation paths; this record consolidates those accepted findings without another research cycle.
No external research, source-paper reruns, new experiments, services, manuscript edits or PDF outputs were performed for this record.
Source locators use PDF page numbers, including the title page.
Confidence is high for direct source, metric-proxy and inspected-code findings; the fair protocol and editorial suggestions are recommendations, not measured conclusions.

| Source / local file | Supplied version and binding | Citation key |
| --- | --- | --- |
| [Casper](../sources/main/Casper.pdf) | 13 pages; 998,357 bytes; arXiv:2408.07004v1, 13 August 2024 (p. 1). SHA-256 `6f95e9780c4993e4bc193c7944f5198dd7f11801b92b887533251854d003eaf2`. | `CasperPreprintV12024` |
| [Hide and Seek](../sources/main/Hide%20and%20Seek.pdf) | 7 pages; 925,336 bytes; arXiv:2309.03057v1, 6 September 2023. SHA-256 `7cfe9422abef27916f945966a838214156c0ab6449dd6af6d0ba4c3b828cc5ef`. | `HaS2024` (compatible existing key; year 2023) |
| [ProSan](../sources/main/ProSan.pdf) | 16 pages; 1,478,323 bytes; arXiv:2406.14318v1, 20 June 2024. SHA-256 `9abde35d9df491d659dcedcae897f4c8bb3586228d6f636094decc0cc8e57d91`. | `ProSan2024` |

The companion [review bibliography](literature-baseline-sources-20261015.bib) keeps Casper v1 distinct from `Casper2024`, which currently denotes the 2025 proceedings entry.
HaS's title page displays 7 September 2024, conflicting with its arXiv v1 identifier/date and PDF creation metadata from 2023; retain this discrepancy rather than infer a new publication.
The supplied Casper preprint does not resolve the previously unavailable published full text. ProSan observations also apply to the supplied preprint, not its later journal version.

## Functional comparison

| Dimension | Casper v1 | HaS v1 | ProSan v1 | PriVoke snapshot |
| --- | --- | --- | --- | --- |
| Local protection | Browser regex, local NER and WebGPU topic model; Llama 3 8B evaluated (pp. 5–8). | Locally deployed trained Hide/Seek, with cloud target generation (pp. 2–4). | Third-party generator trains a local distilled sanitizer (pp. 8–10). | Local detector plus guarded server training, artifact publication and client refresh (`main.tex`:63,75,83). |
| Outgoing content | Identifier substitution; topic warnings and user controls. | Generative BLOOMZ or spaCy label anonymization. | Selective word substitution using task importance and privacy proxy. | ALLOW/WARN forward the original body; BLOCK cancels it (`main.tex`:61,116). |
| Response / interaction | Identifier restoration; Ctrl+Enter analysis, Ctrl+Shift restoration, topic-warning acknowledgement (p. 9). | Local recovery of response entities. | Downstream generation from sanitized prompt. | Notice and posted decision; no awaited WARN acknowledgement in inspected content-script path. |
| Main target | Entity/topic detection and sanitization workflow. | Reversible entity hiding and attacker recovery resistance. | Privacy-item hiding balanced against automatic task utility. | Presence, contextual labels, actions and guarded revision effects, with distinct endpoints. |

Casper permits custom rules/topics and swapping pretrained models (pp. 5–8); it is not adequately described as generic static or untrainable protection.
HaS's trained local models and ProSan's training/distillation establish prior art for training plus local protection; generic locality is insufficient novelty.
HaS covers fourteen entity types, not contextual authorization. ProSan's task necessity also does not establish whether disclosure is authorized.
PriVoke's current request-action interface is materially different from prompt rewriting and response recovery.

## Metric evidence and comparability limits

| Evidence ID | Reported result and population | Meaning / restriction |
| --- | --- | --- |
| C1 | Casper pp. 9–10: two GPT-4-Turbo-generated workloads of 2,000 prompts each (4,000 total). NER: 1,000 positive / 1,000 negative; Table 3 recall 98.5%, specificity 86.7%. | 92.6% accuracy can be derived from the equal classes and rounded rates; identify it as derived, not an independently observed count. |
| C2 | Casper Tables 4–5: topic workload includes 500 medical, 500 legal and 1,000 nonsensitive prompts; recall/specificity medical 96.6%/95.8%, legal 83.2%/94.2%. | Exact negative support per table is unclear. Abstract 89.9% “accuracy” is the average of the two topic recalls, not an overall detector accuracy. |
| C3 | Casper p. 11: about 0.2 s NER plus 2.15 s topic for 15 tokens, under 2.5 s total; under 22.5 s for 1,000 tokens. | NER and topic use different Mac hardware. About 20% CPU / 6.15 GB describes Chrome Helper GPU process scope, not PriVoke's container accounting. No matched speed claim follows. |
| H1 | HaS p. 5: 19,703-example TRAIN+TEST corpus, 80/20 split; separate 30,000 attack-training examples; 1,490 BBC utility examples. | Exact integer test support is unspecified. Attacks use 1.7B models (pp. 4–5); do not infer weaker or universal attack resistance. |
| H2 | HaS p. 6 Table 1: label-based black-box protection 0.4070; white-box Seek 0.3999. | Score is one minus `difflib` whole-text similarity of original and recovered text; similarity function/aggregation details are unclear. It is not 40.7% entity protection, attack failure rate or accuracy. |
| H3 | HaS pp. 5–6 Tables 2–3: classification precision/recall/F1 and translation ROUGE/BLEU/METEOR, including DeepL. | Automatic downstream utility, not a usability study; no measured latency or RAM result. |
| P1 | ProSan pp. 9–10: MedQA 10,200; SAMSum 16,369; CodeAlpaca 18,000; 1,000 test prompts per dataset, remaining examples used for training pairs. | Task-irrelevant private information is inserted. Pooled private-item support is not established; do not infer 12,000 items. |
| P2 | ProSan p. 10 Eq. 11 / p. 11 Table 3: generator diamond 96.0%, distilled local star 99.8% privacy hiding rate (PHR). | PHR counts changed private items; occupation/race/orientation require WordNet similarity below 0.9. It is not prompt-level privacy, detection, or adversarial recovery resistance. |
| P3 | ProSan p. 11 Table 4, local star QA: .521/.434/.573 to .476/.413/.527 for GPT-3.5/Spark/LLaMA. | Drops are 4.5/2.1/4.6 percentage points. ROUGE-L and CodeBLEU are automatic utility proxies, not user studies or executed-code correctness. |
| P4 | ProSan p. 12 Table 5, SAMSum: local star precision .653, recall .989, F1 .787 for privacy identification. | Added transcriber names are private; interlocutor names are useful. This is counterevidence to an unqualified utility-preservation claim: oversanitization remains. |
| P5 | ProSan p. 12: generator two RTX 3090 GPUs / 30 GB / 6.52 s; local model 2 GB / 2.03 s on i9 laptop. | Not a mobile result or matched PriVoke hardware comparison. |

Casper's 2025 published abstract reports 4,500 synthetic plus 2,000 real-world prompts and 92.6%; those are a separate version and must not be merged with v1's workload.
The Casper preprint does not establish downstream task utility or restoration accuracy through a dedicated study.
HaS's attacker intercepts obscured prompts and may query Hide for pairs; the black-box random-weight description versus stated BLOOMZ base leaves a capacity/initialization ambiguity (pp. 4–5).
HaS discusses nonentity contextual leakage and tasks requiring the hidden entities (pp. 5–6). Its “privacy budget” is task-performance loss, not differential-privacy epsilon.
ProSan assumes a semihonest provider and task-irrelevant private content (pp. 3–4).
Its gradient word importance and self-information/surprisal are proxies (pp. 4–6); RoBERTa/WordNet substitutions target selected low-importance POS words (pp. 7–8).
ProSan's random-selection ablations harm utility/privacy; embedding proxy checks do not establish attacker resistance (pp. 12–13).
Neither unlike metrics nor unlike hardware supports a shared privacy, accuracy or speed ranking.

## Prioritized manuscript recommendations

1. **Refine the contribution, retaining its present caution** (`main.tex`:63,65,75,83).
   Center guarded, version-bound classifier updates, admission/publication/client refresh, and casewise gains and harms.
   Avoid first-local-inspection, generic training/locality or uniformly-static-prior-work claims; the current text already rejects the latter and recognizes Casper.
2. **Qualify the motivation** (`main.tex`:59).
   Acknowledge existing pre-disclosure controls when describing dependence on user caution/provider policy; the remaining gap concerns evidenced coverage and update/enforcement behavior.
3. **Make version and metric boundaries explicit** (`main.tex`:85–98).
   Keep Casper's published abstract row separate from a new v1 citation; annotate HaS's attack capacity and unclear exact test support, and ProSan's local-star item-level PHR proxy.
   The existing no-ranking and no-local-reproduction caveats are strengths; preserve them.
4. **Expose the functional boundary** (`main.tex`:61,83,114–118,375,394).
   A compact matrix should distinguish original versus modified outgoing body, awaited user acknowledgement, BLOCK, recovery and actual receiver exposure.
   Accepted code evidence: `extension/src/page-interceptor.js`:24–35 (`fetch`),250–259 (XHR) forward original content unless BLOCK; `extension/src/content-script.js`:27–33 displays a notice and posts the decision without awaiting acknowledgement.
   WARN therefore does not itself demonstrate prevented disclosure or informed consent; the manuscript already states original forwarding and needs consistent interpretation, not an invented implementation defect.
5. **Name the utility gap** (`main.tex`:385,394).
   Measure authorized task completion, unnecessary blocks/warnings and reformulation cost before claiming practical utility; ProSan's task-essential/dispensable distinction is useful but cannot replace authorization labels.
6. **Retain the experimental boundary** (`main.tex`:375,379,392).
   The Presidio recognizer reference is not a matched Casper/HaS/ProSan system baseline. These sources do not invalidate current experiments or validate PriVoke's provisional truth and poor final specificity.

A credible contribution is the implemented and measured guarded revision lifecycle, paired retention/regression evidence, and observed supported-request enforcement under explicit limits.
Its value depends on demonstrated casewise outcomes; local deployment or aggregate gains alone do not establish preserved protection.
Optional editorial improvements are a short central research-question statement, a shorter abstract and clearer core-evidence/appendix division; these are not mandatory technical defects.

## Fair future comparison protocol — proposed, not run

Use this protocol only if the paper seeks comparative system claims; a rerun is not required merely to complete this literature review.
Independently adjudicate paired actual disclosures and benign mentions, with task-essential versus dispensable content and authorized audience recorded separately.
Freeze source/template exclusions and labels before fitting; preserve unresolved/unknown cases rather than silently relabel them as clean.
Run each system's supported function and record actual secrets reaching a controlled receiver, authorized task completion and user/intervention cost.
Retain all blocked tasks in the task-success denominator; distinguish prevention, rewriting, warning, restoration and unsupported outputs (NA).
Match hardware, prompt/workload scope, model versions and executed detector layers for cost comparisons; report incompatible measurements separately.
PriVoke semantic-only studies must explicitly select the semantic layer and assert sole-layer execution; product ablations require separately declared pipeline scope.
The current source review supplies no new benchmark results, superiority finding, deployment usability evidence or full-paper readiness claim.

## Strengths, unresolved limits and retention

The manuscript already distinguishes presence from contextual disclosure/actions, original forwarding from sanitization, and enabling updates from useful adaptation.
Its explicit no-ranking caveats, acknowledged casewise harms, label limits and proposed receiver/utility work align with the uploaded literature and should be retained.
Independent contextual truth, final-endpoint specificity, practical utility and broader installed-provider coverage remain unresolved; these three sources cannot settle them.
Published Casper full text, later ProSan journal content, background-paper foundations and exact undocumented supports/aggregation remain outside verified scope.
The manuscript and primary bibliography are unchanged. Uploaded source PDFs remain local/untracked; only this record, its companion bibliography and the related-work checkpoint are intended deliverables.
