# Comparison datasets from other papers

Research checkpoint: 6 October 2026 (Australia/Sydney). These are candidates and discussion evidence, not new PriVoke measurements. Papers and official metadata were read; candidate dataset rows were not downloaded. Access and license findings are limited to the inspected sources.

## Recommendation

Start with **SPY** for distinguishing author-linked PII from unrelated entity mentions, and **TAB** for contextual anonymization and protection–utility tradeoffs. Use **PrivacyLens** to explain the gap between a PII-presence score and contextually appropriate disclosure. Consider **PrivaCI-Bench** for a future flow-decision study after confirming data acquisition. These address different questions and should remain separate experiments.

For discussion of the closest architecture, include **Casper's synthetic prompt evaluation**, with its denominators made explicit. For clinical external validity, **i2b2/n2c2 2014** is a stronger domain contrast to synthetic clinical data, but requires approved access. **CI-Bench** and personalized **PrivacyBench** are useful methodological comparators; artifact/access gaps make them less ready for immediate use.

The current saved API scores a whole sentence as containing annotated PII. None of these candidates automatically supplies PriVoke's sensitivity, visibility and ALLOW/WARN/BLOCK truth. An adapter must preserve the source task or define a separately audited target before scoring.

## Candidate overview

| Candidate / paper | Best discussion or experiment | Main obstacle | Priority |
| --- | --- | --- | --- |
| SPY, NAACL SRW 2025 | Author-linked versus unrelated entity mentions | Entity labels do not certify clean whole prompts; no published split | High: specificity diagnosis |
| TAB, Computational Linguistics 2022 | Contextual masking and re-identification risk | Requires span/coreference-aware evaluation | High: context and protection–utility |
| PrivacyLens, NeurIPS 2024 Datasets and Benchmarks | Inappropriate information disclosure by agents | Existing probes lack a balanced permitted-flow control | High: contextual discussion |
| PrivaCI-Bench, ACL 2025 | Permitted/prohibited/unrelated information flows | Confirm data release and source-specific permissions | High after acquisition audit |
| Casper, 2024 preprint | Closest rules + NER + local topic-detection architecture | Original dataset release not verified; generated topic labels differ | High for discussion; conditional for measurement |
| i2b2/n2c2 2014, organizer paper 2015 | Authentic clinical language versus synthetic clinical data | Individual data-use agreement; metadata verified, paper full text unavailable | Conditional external validity |
| CI-Bench, 2024 preprint | Norm identification and appropriate communication | Artifact and data license not verified | Medium: design reference |
| Personalized PrivacyBench, 2025 preprint | Multi-turn leakage and over-secrecy | Requires memory/recipient/history; artifact licensing unclear | Medium: scope discussion |

## Verified source notes

### SPY: contextual relevance of entity mentions

[The NAACL SRW paper](https://aclanthology.org/2025.naacl-srw.23.pdf), §§3 and 5.2–5.3, reports 4,197 synthetic legal questions and 4,491 medical consultations generated with Llama-3-70B and Faker. Seven entity kinds distinguish author-linked PII from unrelated entities of the same type. The paper reports token-classification precision/recall/F1 and no train/test split. The [official code](https://github.com/LogicZMaksimka/SPY_Dataset) and [dataset card](https://huggingface.co/datasets/mks-logic/SPY/blob/main/README.md) describe placeholders and seeded Faker generation; the card declares CC-BY-4.0. Custom-loader compatibility and actual data acquisition were not tested.

Use it to test whether identity context changes detection. Preserve entity labels, fix generation seeds, and group template variants together. A non-PII entity mention is not proof that the rest of its document is clean. No row-level independence from protected PriVoke inputs has yet been established. Publication: 2025, pp. 236–246, [DOI](https://doi.org/10.18653/v1/2025.naacl-srw.23).

### TAB: protection and utility with context

[TAB's paper](https://arxiv.org/pdf/2202.00443), §4.3/Table 1 and §§6–7, describes 1,268 real English ECHR cases, split 1,014/127/127 into train/dev/test. Annotations include semantic class, direct/quasi identifiers, masking decisions, confidential attributes and coreference, with multiple annotations retained. Its metrics include recall requiring all entity mentions to be masked and information-weighted token precision. The [official v1.0 repository](https://github.com/NorskRegnesentral/text-anonymization-benchmark) supplies standoff JSON and a MIT release license. Publication: Computational Linguistics 2022, [DOI](https://doi.org/10.1162/coli_a_00458).

This supports discussion of how an apparently benign public entity can become identifying through context. To measure TAB's original task, PriVoke would need evaluated masking spans rather than its current sentence-level score. Audit case identities and person links before splitting. Public availability does not certify harmless disclosure.

### PrivacyLens: contextual disclosure failures

[The paper](https://arxiv.org/pdf/2409.00138), §§3–4 and Appendix G, describes 493 seeds, corresponding vignettes and agent trajectories, plus 1,479 QA probes. Appendix G.2 says all expected probe answers are “No”: they do not constitute balanced clean-versus-sensitive truth. The agent task measures leakage/helpfulness; the datasheet says the data are not intended for training. [Official code](https://github.com/SALT-NLP/PrivacyLens) identifies NeurIPS 2024 Datasets and Benchmarks, MIT code and CC-BY-4.0 data; the [card](https://huggingface.co/datasets/SALT-NLP/PrivacyLens/blob/main/README.md) describes the English release. Norm sources and generated trajectories are not a population sample.

Use this to discuss information-flow decisions and agent leakage. A standalone negative-probe experiment cannot establish PriVoke specificity: add separately validated permitted-flow controls for that question. Group descendants by seed and original source. The repository's ConfAIde/CultureBank extension is a separate provenance family; ConfAIde-derived examples are not independent confirmation of ConfAIde.

### PrivaCI-Bench: flow decisions and compliance

[The ACL 2025 paper](https://arxiv.org/html/2502.17041v2), §3.4, reports 6,351 compliance samples and 147,840 generated MCQs; Appendix A/Table 6 instead totals 6,417 compliance samples. Neither total is an independent-scenario count. Labels are permitted/prohibited/unrelated. HIPAA evaluation reuses GoldCoin, and its knowledge base reuses PrivacyChecklist. The stated HIPAA total is 214, while listed components sum to 211. Preserve both count discrepancies until artifact verification. The [official repository](https://github.com/HKUST-KnowComp/PrivaCI-Bench) has MIT code and expects local cached data, but a complete data-download location was not established. Appendix B gives source-specific terms; the code license does not license every underlying dataset. Publication: pp. 10544–10559, [DOI](https://doi.org/10.18653/v1/2025.acl-long.518).

Promising for a future flow-decision comparison. Legal compliance labels are not automatic PriVoke action labels. Audit reused source families and permissions before acquisition or evaluation. Judgment accuracy/F1 and context MCQ scores cannot be ranked against current PII-presence recall.

### Casper: closest architectural evaluation

[Casper v1](https://arxiv.org/html/2408.07004v1), 13 August 2024, §§7.2–7.3/Tables 3–5, uses GPT-4-Turbo-generated prompts: 1,000 with named entities plus 1,000 without; a separate topic test has 500 medical, 500 legal and 1,000 other prompts. Labels follow generation instructions. Table 3 reports 98.5% positive detection and 86.7% negative detection. Although the abstract calls 98.5% “accuracy,” the table's denominator makes it recall-like; implied accuracy on its balanced sample is **92.6%**: `(98.5 + 86.7)/2`. The abstract's topic figure 89.9% equals `(96.6 + 83.2)/2`, a mean of medical/legal positive detection rates. No original downloadable corpus was verified in this review.

Use this to discuss matched architecture and synthetic-label limitations, without changing the reference manuscript or ranking systems. General medical/legal topics can be positive under this task without personal disclosure. A useful follow-up requires the original released corpus and common labels, or a clearly named reproduction with new generation and independent annotation. Historical published scores are not a PriVoke rerun.

### i2b2/n2c2 2014: restricted clinical evidence

The [official n2c2 index](https://n2c2.dbmi.hms.harvard.edu/data-sets), 2014 de-identification entry, lists 1,304 longitudinal clinical notes for 296 diabetic patients from Partners HealthCare, with approved-user access under an individual data-use agreement. Do not redistribute the corpus or upload it to GitHub. The linked organizer paper is Stubbs, Kotfila and Uzuner (2015), [DOI](https://doi.org/10.1016/j.jbi.2015.06.007). Full-text retrieval was blocked, so this entry relies on official metadata and does not claim source-verified paper scores. The [project portal](https://portal.dbmi.hms.harvard.edu/projects/n2c2-2014/) was also not successfully accessed. The index says the 2016 N-GRID psychiatric notes are unavailable outside the original challenge.

This could test clinical-language transfer beyond synthetic Meddies, subject to access approval and a verified annotation schema. Split/group by patient, not note. It would still be a de-identification task rather than a contextual prompt-action benchmark.

### CI-Bench: contextual norms, acquisition unresolved

[CI-Bench v1](https://arxiv.org/html/2409.13903v1), 20 September 2024 preprint, Dataset/Table 1 and Experiments, describes 44,100 cases spanning dialogue/email and eight domains, with negative:positive ratio 7.4:1. Its four tasks address context understanding, norm identification, appropriateness and response generation. Cases are synthetic descendants of structured scenarios. Multiple-choice/AUC and leakage/utility outcomes differ from PriVoke's detection unit. The paper discusses subjective norms and cultural bias. No official downloadable artifact was located in this bounded review; the paper's CC-BY-NC-SA license does not establish a data license, and release languages remain unverified.

Use it as a design reference until artifact access and permissions are established. Group scenario permutations and derived questions. Its example count is not the number of independent documents. Class imbalance also makes ordinary accuracy alone a weak privacy diagnostic.

### Personalized PrivacyBench: conversational leakage

[PrivacyBench v1](https://arxiv.org/html/2512.24848v1), 31 December 2025 preprint, §§3–5/Table 1, describes four synthetic communities, 48 users and 31,972 documents. It measures leakage, over-secrecy, inappropriate retrieval and persona consistency in personalized conversations. Secrets recur across documents/recipients. The [paper-linked artifact repository](https://github.com/sri-ja/privacy-bench-dataset) is public, but its reviewed README did not establish an explicit data license or complete acquisition procedure. The paper license cannot substitute for artifact terms. This is distinct from TonicAI's similarly named synthetic workplace Privacy-Bench.

Useful for explaining recipient- and history-dependent privacy. The current prompt detector has no corresponding memory/retrieval/output context, so immediate numerical comparison would be misleading. Group by community, user and linked secret; document count is not an independent privacy-case count. Verify artifact completeness and permissions before use.

## Existing sources and dependence

The [PIIMB card](https://huggingface.co/datasets/piimb/pii-masking-benchmark), Tasks and Metrics, identifies AI4Privacy/OpenPII, Nemotron, Gretel, Privy and MAPA source families. Its AI4Privacy English and multilingual tasks share one upstream dataset. Character-level masking scores on that leaderboard use a different denominator from our sentence-presence results. Current card contents are metadata evidence, not a new audit of the pinned experiment revision.

Nemotron and Meddies already have positive-only source-heldout results in [the recalculation](results-by-dataset.md); they are not new untested comparison datasets. Different Hugging Face IDs, derived BIOES/mixed releases, or a train/test rename do not establish independent provenance. The existing [dataset expansion review](../../paper/research/dataset-expansion-sources.md) and [external data analysis](../PII-dataset-analysis.md) remain historical records and were not edited.

AdvPIIBench remains a possible adversarial/hard-negative diagnostic in the existing [prospective protocol](../../paper/research/clean-augmentation-protocol.md). That record describes a USENIX Security 2026 poster and forthcoming full paper; it is not included here as a verified published paper. Its narrow native labels and structural row counts do not establish PriVoke whole-prompt clean truth or performance.

## Proposed fair comparison procedure

1. Choose the question first. Keep annotated presence, entity relevance, contextual disclosure, adversarial robustness, masking utility and action correctness as separately named targets.
2. Before acquiring rows, record the actual artifact revision, data-specific terms, source families, annotation taxonomy, declared split, stable IDs and group definition. Resolve blocked acquisition and ambiguous licenses. Public metadata access alone is not dataset readiness.
3. Exclude protected original training/validation/development/final, bootstrap and later external expansion identities, normalized text keys and source groups through the existing opaque protected-index workflow. Do not open the locked final data to build a shortcut index.
4. Preserve original document, patient, template, seed, scenario and linked-secret groups. Use connected components where the same person, secret or source links examples. Do not treat generated variants as independent observations.
5. For any prompt-level conversion, audit the entire prompt under a declared taxonomy while blinded to detector output. Source-specific empty annotations or unrelated entities do not certify broad-target clean examples. For contextual tasks, document sender, recipient, purpose, consent and disclosure policy, with independent annotation and disagreement resolution.
6. Freeze models, rules, preprocessing, thresholds, exclusions and reporting before a fresh grouped test. Train/calibrate only on allowed training/validation splits. Do not reuse the present development sample as an untouched confirmation set or select models using the locked final.
7. For numerical comparison, run PriVoke and a precisely configured baseline on identical examples and labels. Report raw confusion counts, class/group support, failures and paired group-resampled uncertainty. Span systems need separate span metrics; agent tasks need leakage/utility metrics. Record truncation and timing boundaries.

No future target is guaranteed by this plan. The immediately useful discussion is that current false alarms, missed annotation presence, entity relevance and inappropriate disclosure are different failure modes requiring different evidence.

## Evidence ledger and unresolved checks

| Claim ID | Source locator | Confidence / remaining check |
| --- | --- | --- |
| LIT-SPY | Paper §§3, 5.2–5.3; official README/card, visible card revision `093be5a` | High for design and declared license; generation reproducibility, loader and lineage untested |
| LIT-TAB | Paper §4.3/Table 1, §§6–7; official v1.0 README | High for task/release; case/person overlap audit pending |
| LIT-PL | Paper §§3–4, Appendix G.2/G.5/G.6; official README/card, visible revision `7dc406e` | High for task/probe limitation; permitted-flow control and origin audit pending |
| LIT-PC | Paper §§3.1–3.4, 4.3, Appendix B; official README | High for task, medium for acquisition; release location, count discrepancy and source terms unresolved |
| LIT-CAS | Paper §§7.2–7.3, Tables 3–5 | High for denominator interpretation; original corpus release unresolved |
| LIT-CL | Official n2c2 index, 2014/2016 entries | High for metadata restriction; organizer full text, portal access and artifact unavailable in this review |
| LIT-CI | Paper Dataset/Table 1, Benchmark, Experiments, Limitations | High for paper design; low acquisition readiness; artifact/language/data license unresolved |
| LIT-PB | Paper §§3, 4.2, 5.1/Table 1; linked artifact README | High for paper design; artifact completeness/license unresolved |
| LIT-PIIMB | Current card Tasks, Sentence splitting, Metrics | High for current documented composition; experiment calculations remain tied to local preserved predictions |

All paper versions above are dated before the research checkpoint. No later version, current download success, human annotation agreement, row-level independence, or numerical superiority is implied. URLs support their adjacent claims; unavailable sources are recorded as unavailable rather than treated as read.
