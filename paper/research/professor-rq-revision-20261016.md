# Professor feedback revision: three research questions

Record ID: `PROF-RQ-20261016`. Date: 16 October 2026. Status: **root accepted source, PDF, scientific review and all-page visual QA**, not submission approval. Authoritative checkout: `D:/Git Repositories/Privoke-Research-Project`, branch `docs/paper`, input commit `dacc7c5d8d6a1bf6fa0bb0f22e226355c2d820ba`. This revision changes the manuscript, its compiled PDF and three architecture figures; it introduces no model, dataset, experimental or product changes.

## Exact active request

The manager supplied this exact user request; it is retained verbatim, including the professor's wording. The phrase about adding results is interpreted with the subsequent instruction to organize experiments already conducted, not as authority for costly new training or protected-data rescoring.

```text
I recieved this email from my professor, take his feedback and apply it when you revise the paper now:

----

I have skimmed through the paper once. The work has a strong research core, but the biggest problem isn't a lack of work; now, in the paper, you try to report too many experimental branches at once, making the central PriVoke contribution hard to see.

Our system idea is good, that is local prompt inspection + explicit enforcement + guarded model update + separate privacy-preserving telemetry. That is a coherent systems/privacy contribution, and the paper correctly emphasizes that telemetry is separate from training and that adaptation is not automatically assumed to be beneficial. The architecture section also has substance, including our local browser interception, gRPC-Web/native messaging, local inference, fail-closed behavior, guarded publication, version-bound updates, compare-and-swap checks, replay protection, and streaming parameter refresh. This is much more than a conceptual architecture, and it falls very well, I would say.

The main issue you need to address first is adding more results. The paper doesn't currently have a single, clear research story. It contains V1/V3, PH3, EN3, AU3, PIPE3, HEADS/FULL, PIIMB, AdvPIIBench, Presidio-small, Presidio-large, browser enforcement, telemetry audits, finite-kernel privacy analysis, capsule replay, detector ablation, etc. Individually, these are useful, but together they make the paper feel like a repository audit rather than a sharply framed research paper. Even the abstract is carrying too many numbers and caveats. I would assume this is because you used the repo and got, like, you know, the text in the paper. That is actually the issue. If someone reads the paper, they will say it has a lot of technical jargon. We shouldn't allow that.

I suggest restructuring everything around three research questions:RQ1: Does PriVoke detect and enforce privacy-sensitive prompt policies effectively? RQ2: Can PriVoke update its detector without sacrificing previously protected behavior? RQ3: What systems and privacy overhead does PriVoke introduce?

Almost every experiment you conducted already fits under one of these. The paper just doesn't currently organize them that way. A reader should finish the main paper remembering: PriVoke intercepts prompts locally, makes contextual privacy decisions, enforces them before transmission, can receive guarded detector improvements without application redevelopment, and exposes only locally randomized telemetry.

I suggest you spend some time revising this version before submitting it on Moodle. Could you please try to restructure the paper?

Here, you are missing the privacy ground truth, generalization evidence, and novelty articulation, and the presentation/story is too complex. Nick, please skim through some of the referenced papers in your list. Please review those and try to understand how we present work in a paper.

Please try to bring more simplicity into the paper. For people who know or work in this field, it should be very easy to understand what we are trying to do. People who do not work directly in this area but come from other engineering fields should also understand the overall idea, even if not as easily as someone working in this field. Most importantly, you are missing an architecture diagram and supporting sub-diagrams. If you reduce some of the technical jargon, you will have enough space to include these figures within the 10-page limit.

You can use a heavy preset for this, but do not overallocate the model. Ensure you use the cheapest model that will get the job done correctly.
```

## Plan, scope and instruction checkpoint

The pre-execution checkpoint loaded the shared workflow, leaf role, implementer profile, coordination, validation, Git, coding standards, research, architecture and vision owners under `D:/Git Repositories/Agent-Custom-Workflow/`. The PDF and writing-style skills were also read. The correct outer workflow link supplied by the user is authoritative; the malformed inner `Agent-Custom-WorkflowAGENTS.md` link does not override it. No applicable owner was inaccessible. The writing-reference tool catalog contained no Write Like Me actions, so no retrieved personal style match is claimed. Writing follows the supplied manuscript and explicit engineering-reader brief.

The manager assigned a single writer and a separate read-only critic, with no child agents or worktree. The author used `gpt-6.1-sol` at high effort as selected by the manager for the bounded writing/figure task. No quantitative price comparison was available; this is a suitability decision, not a measured cost claim. The writer did not change the current branch or touch code, bibliography, historical research records or supplied source papers.

The plan sent before authoring was: exact three questions in the introduction; concise prior-work/contribution boundary; system overview and two supporting flows; existing evidence mapped to RQ1/RQ2/RQ3 with explicit answers; discussion that preserves missing truth/generalization/utility; protocol chronology and detailed tables in appendices. Acceptance required at most ten main pages, actual-pixel inspection of every page, resolved citations, embedded fonts, no clipping or overfull boxes, unchanged scientific results and a colocated final `paper/main.pdf`.

## Editorial decisions and evidence map

| Requirement / question | Final treatment | Decisive retained evidence |
| --- | --- | --- |
| Coherent system story | Introduction, Design, RQ answers and Conclusion repeat one protection/update/telemetry lifecycle. | Local user-text inspection, explicit actions, exact-base update publication, separate locally randomized telemetry. |
| RQ1 contextual detection/action | Main Table II and paired gains/harms, plus balanced detector removal. Historical/updated replaces recipe identifiers in the narrative. | [Product comparison](pipeline-comparison-20261014.md), compact JSON; [controlled studies](controlled-studies-20261014.md), JSON. Joint E/B/Q 266/160/226 to 693/717/879 of 1,560; action regressions 3/6/0; removal fixes 139 restrictions but loses eighteen correct actions. |
| RQ1 broader checks | Main Table III retains all final confusion counts and poor specificity. Source-category and configured recognizer outcomes are separate targets. | [Final semantic evidence](final-semantic-evidence-20261014.json), [external source-category record](external-native-identifiers-20261014.md). Same-artifact contextual specificity 98.40–99.87% versus final 13.36–21.76%; changed texts/targets, not an intervening model change. |
| RQ1 enforcement | Main receiver observations and diagram distinguish decision from exposure. | [Installed client record](installed-client-evidence-20261014.md): 33 probes, eighteen unchanged-body sends/fifteen zero sends; full-mode stream fallback can execute rules/NER and forward. WARN does not await acknowledgement; masked spans do not rewrite traffic. |
| RQ2 retention | Main Table IV, paired losses and explicit guard answer. Historical failed branches remain negative; attempted budgets move to Appendix C. | [Controlled studies](controlled-studies-20261014.md): three matched head-only/full-model seeds, 1,080 cases, every full-model candidate guard-rejected, no publication/promotion. Guard scope and weak zero-head baseline remain explicit. |
| RQ3 systems cost | Main scoped latency/CPU/memory result, detailed cell/startup tables in appendices. | [Installed client record](installed-client-evidence-20261014.md): 360 rules/NER decisions, twelve profiles, medians 27.9–35.0 ms, 193.29 container CPU-s, sampled maximum 1,267.91 MiB. No semantic/incremental overhead or unprotected baseline. |
| RQ3 privacy/utility | Main finite nominal-budget failure and synthetic error/selection bias; finite formula and ledger details in appendix. | [Telemetry record](telemetry-evidence-20261014.md), JSON. Tiny nominal excess remains a failed exact bound; entropy/build assumptions, contribution selection and metadata exclusions remain visible. |
| Missing privacy truth/generalization | Method and Discussion distinguish provisional contextual truth from annotation/source-category proxies; no invented adjudication or new final scoring. | Existing evidence and [claims ledger](claims.md). Opened/reused authored workload, source dependence/imbalance and poor final specificity remain limitations. |
| Bounded novelty | Related work identifies existing local layered inspection and trained protection, then focuses on measured guarded lifecycle/request contract. | [Literature review](literature-baseline-review-20261015.md); existing citation keys reused, no bibliography edits. |

The source papers were skimmed as writing models, not rerun. The author read their abstracts, introductions and early functional descriptions. The independent critic read decisive design/results sections and rendered Casper p.2, HaS p.2 and ProSan p.8. Their useful presentation patterns were early role/dataflow pictures, a separation of training and inference, and a short contribution statement. Their strong abstract claims were not copied. Casper's metric/version distinctions, HaS's whole-text dissimilarity score and ProSan's item-replacement proxy remain qualified in Appendix D.

## Architecture correspondence

The editable SVGs and embedded-font PDF assets are generated by [`../figures/create_architecture.py`](../figures/create_architecture.py). They show the overview, enforcement branch and guarded update flow. The generator uses ReportLab plus Windows Arial files; it requires neither experimental data nor weights. It can be rerun from the repository root with the maintained bundled Python.

Inspected implementation and critic locators: `extension/src/page-interceptor.js` fetch lines 14–58 and XHR decision near 322; `content-script.js` lines 18–39 for non-awaited notice/result; background/runtime-client and supervisor bridge for loopback analysis/lifecycle; detector pipeline and gRPC server for rule short-circuit/fallback; fuzzer trainer/service for supplied examples; parameter updater validation/server and artifact publication for exact-base/tensor checks; streaming server and streamed-model refresh for parameters; runtime telemetry emitter and collector storage for report separation. The critic's decisive mapping included `trainer` 163–207, fuzzer service 437–462, updater server 104–144, artifact 166–182, streaming server 24–45/110–124, streamed model 172–206, emitter 35–58/93–106 and telemetry storage 99–139.

No arrow sends user prompts to server training or telemetry to training. Supervisor arrows are lifecycle control. Publication is atomic per artifact, with head and underlying-model stages separate; a rejected later stage does not promise rollback of an accepted head stage. Guards are strategy-configured and bounded. Failed historical candidates are not all claimed to have retained weight files. The final arrow repair makes runtime-to-ledger input enter from above rather than point upward from inside the box.

## Build, review and retained checks

The PDF skill's operation marker succeeded once before the first authoring command. Build directory: `evaluation/results/professor_rq_revision_20261016/` (ignored). Initial Windows command length and one working-directory mistake failed before the intended assembly; bounded writes corrected them. MiKTeX compilation required approved narrow access to its user configuration; no installation/update was performed.

Compilation used installed `pdflatex`, `bibtex`, then cross-reference passes from `paper/`. Final accepted-source passes are `compile-accepted1.txt` and `compile-accepted2.txt`; `main.log`, `.aux`, `.bbl` and `fonts.txt` remain in the build directory. `pdftoppm -r 125 -png` generated `page-01.png` through `page-15.png` for the actual final PDF. Every page was viewed, including each diagram and appendix table/plot. Standard `raggedbottom` avoids stretched vertical gaps; no text size, margins or page dimensions were reduced. Main page eight ends naturally with whitespace; the main-text limit is a ceiling, not a target to pad.

Initial font QA detected an unused ReportLab Helvetica resource. Setting its initial font to embedded Arial removed all unembedded fonts. Final audit lists only embedded Type 1, TrueType and CID TrueType fonts; no Type 3. Final logs have no undefined citation/reference, multiply defined label, missing glyph or overfull box. Underfull text warnings were visually assessed; no clipping, collision, missing content or unreadable diagram was found. References resolve across the four unchanged bibliography inputs. The existing `astextplain` Git PDF driver causes binary whitespace false positives; `git -c diff.astextplain.binary=true diff --cached --check` treats those artifacts as binary without changing repository/global configuration. Staged artifact blobs are checked byte-for-byte against the accepted filesystem outputs.

Main physical pages **1–8**, appendices **9–14**, references **15**, with explicit page breaks. The final PDF is colocated with the source; build-PDF bytes were compared before removing the disposable duplicate. Logs, page PNGs and the validation JSON remain. No Python detector tests, training, model inference, protected-data rescoring or services ran during this writing task.

### Final artifact binding

- Source `paper/main.tex`: SHA-256 `39c1ff39e19c9695b1f368e4d6b15c63cd834bbe29e4327845e759cfaa7f8a60`.
- Output `paper/main.pdf`: SHA-256 `ad39dc1319d6c1e49f092c386fd0073ddc12fa7f8df6791dcf020aa724d50bf7`.
- Unchanged `paper/ref.bib`: SHA-256 `6a113e2abfb20e45d26bde6a961a0cec9a23a5264cd9db360f15eb372c1c03f7`.
- Machine-readable build/page/font bindings: [validation](professor-rq-revision-20261016.json).

Root independently reconciled decisive claims, verified both final wording repairs and the source/PDF/bibliography hashes, and inspected all fifteen final rendered pages. Root accepted the artifact on 16 October 2026. Root publication remains separate from the writer's scoped commit. Scientific limitations remain missing adjudicated contextual privacy truth, weak broader specificity, uncertain useful adaptation, bounded installed coverage, no human utility evidence and conditional telemetry utility/privacy assumptions. Editorial completion does not resolve them or establish venue/submission readiness.

### Abstract style revision, 16 October 2026

At the user's request, the abstract now follows the previous version's fuller connected academic prose and transitions while retaining the current revision's scope, results and limitations. No results, citations or other manuscript sections changed. The rebuilt `paper/main.pdf` remains 15 pages; only rendered pages 1–2 differ from the previously accepted PDF. The writer inspected those pages without finding clipping or overlap; root review of this revision is pending. Current source/PDF hashes and this revision's exact QA scope are recorded in [validation](professor-rq-revision-20261016.json); the earlier all-page acceptance is retained there as historical evidence for its original source/PDF bytes.
