# Bibliography history and source audit

**Record:** BIBREST19. **Date:** 17 October 2026. **Input:** `249aa0a90040b1d02f31ed15d5a1ab5acbe1caeb`, branch `docs/paper`.

## Request and questions

Exact user request:

> Go through the git history and restore any deletions of the bibliography, modifications can be kept intact. Ensure bibliography is also consistent with the sources, including authors, title or any other parameters. Where you can, source the bibliography through google researches inbuilt get bibtex feature.

The questions were (1) whether any bibliography records or files disappeared from reachable Git history, (2) whether currently stored metadata matches the cited edition, and (3) which official BibTeX exports are available. This is a bibliography audit, not a new literature or experimental study. The seven-unit manuscript scope, body text, citation keys, three pinned model-card footnotes and empirical claims are preserved.

The user subsequently clarified: **“Restore the sources only to the bibtex document, so that future rewrites can reference the previous sources. Also document that rewrites of the paper should not remove sources from the source pool”.** This is now a durable rule in [REWRITE_SCOPE.md](../REWRITE_SCOPE.md#bibliography-source-pool-preservation).

## History result

The four databases loaded by `main.tex` contain **81 keys**: 76 in `ref.bib`, one in `research/paper-completion-sources-20261014.bib`, three in `manuscript-completion-sources-20261014.bib`, and one in `research/literature-baseline-sources-20261015.bib`. The history audit scanned 24 commits touching `*.bib`, `*.bibtex` or `*.bbl` across all reachable refs (`git log --all --format=%H -- '*.bib' '*.bibtex' '*.bbl'`), compared historical blob key unions for all four databases, and checked removed fields and historical manuscript citation keys. It found **no missing records, deleted bibliography files or renamed bibliography files**. Consequently no record restoration was needed. Seventeen source keys are cited in the current manuscript; 64 catalog keys remain uncited (including the IEEEtran control record). Fifty-seven historically removed in-text citation keys still exist in the catalog. Restoring those citations or using `\nocite{*}` would expand the paper rather than recover lost bibliography data, so neither was done.

The repository had 738 commits reachable from `--all` at the input revision. Per-path `git log --all --format=%H -- <path>` followed by `git show <SHA>:<path>` and brace-aware record parsing examined 23 database snapshots in 22 unique commits: `ref.bib` 16, research completion 3, manuscript completion 3, and literature baseline 1. The broader extension-pattern log returns 24 commits; that is a different count from the four active paths. Earliest scanned snapshots were respectively `fd91b25953f833db079bce57afeaf7a9300699ad`, `ff6b84358b233fa3f7c2df0a92c8366946f91002`, `023251a082afc128cdfd966111fdd647ea76c8cc`, and `5326ec713aee19d448c993f7f88d3fddcea1549c`. An all-ref name-status scan found no `D`/`R` bibliography paths. The historical `main.tex` citation union was 74 keys, with 17 current and 57 removed-but-preserved catalog keys. The history parser was run inline; no reusable script is claimed.

Only two formerly present fields are absent now: `Casper2024.month=08` belonged to the old 2024 preprint, while the current key denotes the 2025 proceedings; `kelecspromptshield.month=jan` was removed because the thesis month was unverified. Neither field is supported for its current record, so neither was reinstated. Existing corrected authors, publication identities and years were preserved.

## Method and exports

Opened primary arXiv records, publishers, author/institutional pages, official software/model cards and documentation. Publisher-deposited Crossref records supplied missing DOI, author, volume and page metadata where publisher web pages were unavailable; source conflicts were checked against the original PDF or institutional record, not silently resolved by majority. Metadata access is not evidence that a study's scientific claims or historical software execution were reproduced.

Google Research's RAPPOR page exposes **Copy Bibtex** through its `input.glue-copy-value`; its actual decoded value was retrieved, not reconstructed from memory. The Google Research tuning-playbook repository supplies an official README citation block, also retrieved. ACL and NeurIPS exports were retrieved for MEDEC and reconstruction. Exact exports and per-source metadata receipts are preserved in [the audit data](bibliography-audit-sources-20261017.json). Existing keys were retained rather than replaced by export-generated keys. RAPPOR's existing more specific ACM proceedings title/DOI were retained; its missing pages came from ACM-deposited metadata. Google Research searches for `Well-Read Students Learn Better` returned no matching export, so the original arXiv record was used. BERT and Attention Is All You Need were discovery checks only, not missing catalog records; no new citation was added. No Google Scholar export was acquired and no access challenge was bypassed.

Key exact search strings included `site:research.google/pubs "RAPPOR"`, `site:research.google "Well-Read Students Learn Better"`, `"User Privacy and Large Language Models" King Klyman`, `"The Digital Privacy Paradox" Athey Catalini Tucker`, `"Understanding LLMs: A comprehensive overview from training to inference" Neurocomputing 129190`, `"Security concerns for large language models: A survey" 104284`, `"A Lifecycle-Oriented Survey" IEEE`, `"Zero Trust, Full Intelligence" Pradhan`, `site:aclanthology.org "MEDEC" "22539"`, and `"When Public Text Becomes Private Risk" Ngai` (no located public record).

## Corrections

- `Athey2017`: author, doi, url.
- `King2025`: url, eprint, archivePrefix.
- `Florian2025`: month, howpublished, entry type.
- `MEDEC2024`: title, author, doi, url.
- `PromptShield2025`: author.
- `GoogleWarns2023`: author.
- `LIANG2025101366`: doi.
- `courseraTransformersConvolutional`: author, year, note.
- `LearnMicrosoft2026`: author.
- `Mousumi_Bakshi2025`: entry type.
- `ErlingssonRappor2014`: pages.
- `tamkin2024clio`: author, url, title.
- `zhong2023chatradio`: author, url, title.
- `Llama2023`: author, title.
- `liu2025understanding`: title, author, doi, url.
- `li2025security`: author, doi, url.
- `de2025lifecycle`: volume, pages, doi, url.
- `haim2022reconstructing`: booktitle, doi, url, entry type.
- `pradhan2025zero`: doi, url.
- `cormode2018privacy`: doi, url.
- `cortes2016differential`: doi, url.
- `priyanshu2023chatbots`: url.
- `koraag2025comparing`: url.
- `munnangi2024brief`: url.
- `googleResearchTuningPlaybook`: author, year, note.
- `CasperAbstract2026`: author.
- `PromptShieldAbstract2026`: author.

Authors are now explicit where the source supplied the complete list; BibTeX's style can still abbreviate their presentation. Personal names, corporate authors, technical title capitals, entry types and canonical DOI strings were corrected without renaming keys. `King2025` remains the September preprint. The Coursera record now explicitly describes the live 2026 update, rather than implying that the current page is the historical 2025 edition.

## Per-record verification and limits

“Identity checked” below means the opened source supports the cited object/title and the available bibliographic fields; it does not promise that every optional field exists, revalidate historical access dates or reproduce experimental provenance notes. Specific partial/unavailable/conflicting fields are recorded explicitly. Software/model artifacts remain pinned where the existing entry pinned them; no weights were downloaded or executed.

| Key | Evidence | Result |
| --- | --- | --- |
| `PIIMBPinned2026` | [source](https://huggingface.co/datasets/piimb/pii-masking-benchmark/blob/4a13e9ffe6fd0d275efbde8afd4d8d8f1ffc2133/README.md) | Identity checked against opened official source; existing metadata retained. |
| `arpaly2026advpiibench` | [source](https://huggingface.co/datasets/roei-ar/AdvPIIBench) | Identity checked against opened official source; existing metadata retained. |
| `LinuxCgroupV2Interfaces2026` | [source](https://docs.kernel.org/admin-guide/cgroup-v2.html) | Identity checked against opened official source; existing metadata retained. |
| `DualAxis2026` | Repository/control record | Unverified: no URL or located public record; keep user-supplied metadata intact. |
| `PresidioNlpConfiguration2026` | [source](https://github.com/data-privacy-stack/presidio/blob/main/docs/analyzer/customizing_nlp_models.md) | Identity checked against opened official source; existing metadata retained. |
| `CasperAbstract2026` | [source](https://researchwith.njit.edu/en/publications/casper-prompt-sanitization-for-protecting-user-privacy-in-web-bas/) | Identity checked against opened official source; corrected fields listed above. |
| `PromptShieldAbstract2026` | [source](https://research.itu.edu.tr/en/publications/promptshield-policy-aware-dlp-framework-for-generative-al-prompts/) | Identity checked against opened official source; corrected fields listed above. |
| `Casper2024` | [source](https://doi.org/10.1109/CSCloud66326.2025.00027) | Verified institutional author/title/venue/year/122--131; conflicting Crossref 122--133 retained in receipt, not applied. |
| `IEEEexample:BSTcontrol` | Repository/control record | Not a source: IEEEtran formatting control. |
| `kelecspromptshield` | [source](https://web.itu.edu.tr/bahtiyars/SB-Students.html) | Partial: supervisor list confirms author/title/year; month and repository record still unavailable. Do not restore January. |
| `PromptShield2025` | [source](https://doi.org/10.1109/UBMK67458.2025.11206862) | Identity checked against opened official source; corrected fields listed above. |
| `HaS2024` | [source](https://arxiv.org/abs/2309.03057) | Identity checked against opened official source; existing metadata retained. |
| `priyanshu2023chatbots` | [source](https://arxiv.org/abs/2305.15008) | Identity checked against opened official source; corrected fields listed above. |
| `tamkin2024clio` | [source](https://arxiv.org/abs/2412.13678) | Identity checked against opened official source; corrected fields listed above. |
| `barbera2025ai` | [source](https://www.edpb.europa.eu/system/files/2025-04/ai-privacy-risks-and-mitigations-in-llms.pdf) | Identity checked against opened official source; existing metadata retained. |
| `ProSan2024` | [source](https://arxiv.org/abs/2406.14318) | Identity checked against opened official source; existing metadata retained. |
| `Gupta2024` | [source](https://api.crossref.org/works/10.1016/j.compeleceng.2024.109215) | Identity checked against opened official source; existing metadata retained. |
| `LIANG2025101366` | [source](https://api.crossref.org/works/10.1016/j.patter.2025.101366) | Identity checked against opened official source; corrected fields listed above. |
| `koraag2025comparing` | [source](https://arxiv.org/abs/2509.24344) | Identity checked against opened official source; corrected fields listed above. |
| `Crane2025` | [source](https://www.federalreserve.gov/econres/notes/feds-notes/measuring-ai-uptake-in-the-workplace-20240205.html) | Identity checked against opened official source; existing metadata retained. |
| `Zahra2025` | [source](https://techcouncil.com.au/newsroom/new-report-shows-aussies-embracing-ai-in-the-workplace/) | Partial: title and 20 August 2025 date confirmed; Hagop Zahra byline not shown in opened page. |
| `Athey2017` | [source](https://www.nber.org/papers/w23488) | Identity checked against opened official source; corrected fields listed above. |
| `King2025` | [source](https://arxiv.org/abs/2509.05382) | Verified September 2025 arXiv version; unrelated Gupta DOI URL replaced. Do not silently substitute October AIES publication. |
| `Llama2023` | [source](https://arxiv.org/abs/2302.13971) | Identity checked against opened official source; corrected fields listed above. |
| `Florian2025` | [source](https://aiexpjourney.substack.com/p/the-number-of-parameters-of-gpt-4o) | Identity checked against opened official source; corrected fields listed above. |
| `MEDEC2024` | [source](https://aclanthology.org/2025.findings-acl.1159.bib) | Official ACL BibTeX exported: Ben Abacha surname and Yetisgen corrected; DOI/URL added; 2025 venue/pages preserved. |
| `LearnMicrosoft2026` | [source](https://learn.microsoft.com/en-us/microsoft-copilot-studio/admin-api-quarantine) | Partial: corporate author/title/source identity confirmed; original June 2026 publication date not independently established. |
| `courseraTransformersConvolutional` | [source](https://www.coursera.org/articles/transformers-vs-convolutional-neural-networks) | Current edition: page says updated 24 June 2026; year corrected from 2025, access/update note added. |
| `liu2025understanding` | [source](https://api.crossref.org/works/10.1016/j.neucom.2024.129190) | Identity checked against opened official source; corrected fields listed above. |
| `zhong2023chatradio` | [source](https://arxiv.org/abs/2310.05242) | Identity checked against opened official source; corrected fields listed above. |
| `li2025security` | [source](https://api.crossref.org/works/10.1016/j.jisa.2025.104284) | Identity checked against opened official source; corrected fields listed above. |
| `de2025lifecycle` | [source](https://api.crossref.org/works/10.1109/ACCESS.2025.3619764) | Identity checked against opened official source; corrected fields listed above. |
| `haim2022reconstructing` | [source](https://proceedings.neurips.cc/paper_files/paper/2022/file/906927370cbeb537781100623cca6fa6-Bibtex-Conference.bib) | Official NeurIPS BibTeX exported: proceedings type/booktitle and DOI/URL corrected; volume/pages/authors/year agree. |
| `Mousumi_Bakshi2025` | [source](https://www.linkedin.com/pulse/prompt-sanitization-unseen-hero-behind-safe-reliable-genai-bakshi-zfzsc/) | Identity checked against opened official source; corrected fields listed above. |
| `pradhan2025zero` | [source](https://ijctece.com/index.php/IJCTEC/article/view/255) | Identity checked against opened official source; corrected fields listed above. |
| `munnangi2024brief` | [source](https://arxiv.org/abs/2411.05057) | Identity checked against opened official source; corrected fields listed above. |
| `cormode2018privacy` | [source](https://wrap.warwick.ac.uk/id/eprint/100940/) | Identity checked against opened official source; corrected fields listed above. |
| `cortes2016differential` | [source](https://experts.illinois.edu/en/publications/differential-privacy-in-control-and-network-systems/) | Identity checked against opened official source; corrected fields listed above. |
| `SamsungBans2023` | [source](https://www.forbes.com/sites/siladityaray/2023/05/02/samsung-bans-chatgpt-and-other-chatbots-for-employees-after-sensitive-code-leak/) | Identity checked against opened official source; existing metadata retained. |
| `BBCChatGPTHistoryBug2023` | [source](https://www.bbc.com/news/technology-65047304) | Identity checked against opened official source; existing metadata retained. |
| `GoogleWarns2023` | [source](https://www.itnews.com.au/news/google-one-of-ais-biggest-backers-warns-own-staff-about-chatbots-596961) | Partial original access: Reuters 401; licensed Reuters republication confirms title/byline and Jeffrey spelling. Original URL retained. |
| `ChatGPTChildProtection` | [source](https://ovic.vic.gov.au/wp-content/uploads/2024/11/DFFH-ChatGPT-investigation-report-20240924-Re-upload.pdf) | Identity checked against opened official source; existing metadata retained. |
| `ClaudeDay2026` | [source](https://www.oasis.security/blog/claude-ai-prompt-injection-data-exfiltration-vulnerability) | Identity checked against opened official source; existing metadata retained. |
| `OpenAINavierStokes2026` | [source](https://openai.com/index/navier-stokes-solution/) | Identity checked against opened official source; existing metadata retained. |
| `BuckmasterStatement2026` | [source](https://cims.nyu.edu/~tristanb/statement.pdf) | Partial: author-hosted statement opened; descriptive title and exact posting date are not printed in PDF. Retain historical date with this limit. |
| `NYUCourant2026` | [source](https://cims.nyu.edu/dynamic/news/1528/) | Identity checked against opened official source; existing metadata retained. |
| `tunstall2022setfit` | [source](https://arxiv.org/html/2209.11055v1) | Verified pinned arXiv v1 author list/title/date; retain 2022 preprint, not later publication. |
| `benbaruch2021asymmetric` | [source](https://arxiv.org/abs/2009.14119v4) | Verified version: 2021 is arXiv v4 revision year; initial submission was 2020. Keep v4 author order, not conference-author order. |
| `lipton2014thresholding` | [source](https://arxiv.org/abs/1402.1892v2) | Identity checked against opened official source; existing metadata retained. |
| `sentenceTransformersMiniLML6v2` | [source](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/blob/1110a243fdf4706b3f48f1d95db1a4f5529b4d41/README.md) | Identity checked against opened official source; existing metadata retained. |
| `sentenceTransformersMiniLMOnnx` | [source](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/blob/1110a243fdf4706b3f48f1d95db1a4f5529b4d41/onnx/model.onnx) | Identity checked against opened official source; existing metadata retained. |
| `sentenceTransformersEfficiency` | [source](https://www.sbert.net/docs/sentence_transformer/usage/efficiency.html) | Identity checked against opened official source; existing metadata retained. |
| `onnxruntimePythonAPI` | [source](https://onnxruntime.ai/docs/api/python/api_summary.html) | Identity checked against opened official source; existing metadata retained. |
| `huggingfaceTokenizersAPI` | [source](https://huggingface.co/docs/tokenizers/api/tokenizer) | Partial: correct official Tokenizer endpoint; live main documentation now says API reference not generated. Historical 0.22.1 usage is not revalidated here. |
| `onnxruntimeLicense` | [source](https://github.com/microsoft/onnxruntime/blob/main/LICENSE) | Identity checked against opened official source; existing metadata retained. |
| `huggingfaceTokenizersLicense` | [source](https://github.com/huggingface/tokenizers/blob/main/LICENSE) | Identity checked against opened official source; existing metadata retained. |
| `huggingfaceSetfitLicense` | [source](https://github.com/huggingface/setfit/blob/main/LICENSE) | Identity checked against opened official source; existing metadata retained. |
| `sentenceTransformersMiniLMConfig` | [source](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/blob/1110a243fdf4706b3f48f1d95db1a4f5529b4d41/config.json) | Identity checked against opened official source; existing metadata retained. |
| `sentenceTransformersMiniLMSentenceConfig` | [source](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/blob/1110a243fdf4706b3f48f1d95db1a4f5529b4d41/sentence_bert_config.json) | Identity checked against opened official source; existing metadata retained. |
| `zinkevichRulesML` | [source](https://developers.google.com/machine-learning/guides/rules-of-ml) | Identity checked against opened official source; existing metadata retained. |
| `googleResearchTuningPlaybook` | [source](https://github.com/google-research/tuning_playbook) | Official README BibTeX exported: five authors, 2023, Version 1.0. Existing URL and access note retained. |
| `privokeTW01TaskQueryWindow20261012` | Repository/control record | Internal: docs/task-query-window-20261012.md title/date/partial-study status checked; no rerun. |
| `googleBertL4H128A2` | [source](https://huggingface.co/google/bert_uncased_L-4_H-128_A-2/blob/c29bee83fc7f003ac8c5e6e135529da4ecddb7c3/README.md) | Identity checked against opened official source; existing metadata retained. |
| `googleBertL2H256A4` | [source](https://huggingface.co/google/bert_uncased_L-2_H-256_A-4/blob/4e937a8675e5afd9a4836735c186ec01695bc3ea/README.md) | Identity checked against opened official source; existing metadata retained. |
| `googleBertL12H256A4` | [source](https://huggingface.co/google/bert_uncased_L-12_H-256_A-4/blob/2ab9a0f41435a4d23d4cbc11cc3e7c922545f13d/README.md) | Identity checked against opened official source; existing metadata retained. |
| `pytorchPreviousVersions` | [source](https://pytorch.org/get-started/previous-versions/) | Identity checked against opened official source; existing metadata retained. |
| `pytorch27Blackwell` | [source](https://pytorch.org/blog/pytorch-2-7/) | Identity checked against opened official source; existing metadata retained. |
| `pytorch211Serialization` | [source](https://docs.pytorch.org/docs/2.11/notes/serialization.html) | Identity checked against opened official source; existing metadata retained. |
| `huggingfaceTransformers4571Bert` | [source](https://huggingface.co/docs/transformers/v4.57.1/en/model_doc/bert) | Identity checked against opened official source; existing metadata retained. |
| `pytorchCu130TorchIndex` | [source](https://download.pytorch.org/whl/cu130/torch/) | Identity checked against opened official source; existing metadata retained. |
| `pytorch212Release` | [source](https://pytorch.org/blog/pytorch-2-12-release-blog/) | Identity checked against opened official source; existing metadata retained. |
| `pytorchStartLocally` | [source](https://docs.pytorch.org/get-started/locally/) | Identity checked against opened official source; existing metadata retained. |
| `nvidiaCudaGpus` | [source](https://developer.nvidia.com/cuda/gpus) | Identity checked against opened official source; existing metadata retained. |
| `turc2019WellReadStudents` | [source](https://arxiv.org/abs/1908.08962) | Identity checked against opened official source; existing metadata retained. |
| `privokeAU3Audience20261013` | Repository/control record | Internal: docs/audience-v3-training.md title/date/record identity checked; no rerun. |
| `NissenbaumContextualIntegrity2004` | [source](https://digitalcommons.law.uw.edu/wlr/vol79/iss1/10/) | Identity checked against opened official source; existing metadata retained. |
| `YanPositiveCongruent2021` | [source](https://openaccess.thecvf.com/content/CVPR2021/html/Yan_Positive-Congruent_Training_Towards_Regression-Free_Model_Updates_CVPR_2021_paper.html) | Identity checked against opened official source; existing metadata retained. |
| `ErlingssonRappor2014` | [source](https://research.google/pubs/rappor-randomized-aggregatable-privacy-preserving-ordinal-response/) | Google Research Copy Bibtex exported; title/authors/year agree. Existing ACM venue/DOI retained; ACM-deposited pages 1054--1067 added. |
| `DworkRothFoundations2014` | [source](https://www.cis.upenn.edu/~aaroth/Papers/privacybook.pdf) | Verified against author-hosted PDF cover (211--407); newer Emerald/Crossref 211--487 conflict not applied. |
| `CasperPreprintV12024` | [source](https://arxiv.org/abs/2408.07004v1) | Identity checked against opened official source; existing metadata retained. |
| `SpacyLarge371Release2026` | [source](https://github.com/explosion/spacy-models/releases/tag/en_core_web_lg-3.7.1) | Identity checked against opened official source; existing metadata retained. |

## Access limits and conflicts

`DualAxis2026` has no public locator and could not be independently verified. The thesis month, Zahra byline, Microsoft page's original publication month and Buckmaster posting date remain only partially verified; their existing values were preserved rather than guessed. Reuters direct access was refused, but the licensed iTnews republication exposed the original authors. Current Tokenizers main documentation has drifted to an incomplete v1 reference; the existing historical package-version note was not treated as current documentation evidence.

For Dwork/Roth, the author-hosted PDF cover explicitly states 211--407 and the original nowpublishers indexed suggested citation agrees; the newer Emerald/Crossref record says 211--487. Retain the original source-supported 211--407 and disclose the conflict. For Casper, NJIT gives 122--131 and ten pages; Crossref gives 122--133. Retain the institutional value pending the original IEEE proceedings PDF. IEEE/ITU metadata spells PromptShield's final acronym as `Al` in some exports; the meaningful `AI` in the existing title is preserved rather than adopting that apparent transcription defect.

## Validation

Passed on the final bibliography sources:

- All 81 original keys retained, zero duplicate or missing keys; all 17 active citations resolve. Historical key union and current catalog match.
- Native MiKTeX `bibtex main` and separate `bibtex catalog` (temporary all-key catalog AUX) both exited 0 without bibliography warnings. The all-key check does not modify the manuscript or force uncited references into it.
- Isolated `pdflatex -interaction=nonstopmode -halt-on-error` / BibTeX / repeated LaTeX passes in `evaluation/results/bibliography_audit_20261017` produced **10 pages and 17 references**, with no undefined citations/references, overfull boxes or rerun request. Environment: `TEXINPUTS=.;D:/Git Repositories/Privoke-Research-Project/paper//;` and the same `BIBINPUTS`, so local generated AUX/BBL files precede stale source-tree auxiliaries.
- `paper/main.tex` is byte-unchanged. Extracted text on pages 1--9 matches the prior PDF exactly. Page 10 was rendered with Poppler and visually inspected: reference labels 1--17, corrected names, RAPPOR pages and final column fit are legible without clipping or overlap. This task's visual review covers the changed reference page; it does not claim a new all-page review.
- One pre-existing compiler warning remains: the architecture image is PDF 1.7 while the document requests PDF 1.5. The image renders and is unchanged. MiKTeX also reports its routine update-check notice.
- `git diff --check` passed. PDF SHA-256: `3af8b9630a234dae6b6bb48daa62e31fecfbb98115c007c7235fe166dfadcec4`.

The initial sandboxed MiKTeX call could not access its user configuration; narrow approved compiler calls completed the build. The PATH-selected MiKTeX text extractor also lacked configuration access; bundled host Python/pypdf was used for extraction and page comparison. These were tooling failures, not successful validation evidence. Machine-readable key/numbering/hash checks are retained in the audit data; detailed local compiler logs and receipts remain in the isolated build directory. No models, test containers, study scoring or protected datasets were used.
