# Approved empirical scope for future paper rewrites

This document records the user's instruction of 17 October 2026: **“Document inside the paper directory that these studies should be the only ones covered in future rewrites”.** It fixes the empirical scope established by the accepted no-appendix revision in [main.tex](main.tex), committed as `e839593cdd3d13bd26046b30ebc62a9dd89ca37a`. The selection rationale and acceptance evidence are recorded under **NOAPPX17** in the [revision record](research/rubric-rewrite-20261017.md#noappx17-self-contained-paper-with-a-reduced-evidence-set).

**The following seven evidence units are the only empirical studies to cover in future manuscript rewrites.** Preserve the set, all retained treatment arms and material negative findings. Expanding, replacing or removing a unit requires a direct user instruction changing this scope. The existence of historical results, newly available measurements, an earlier manuscript, or a recommendation in an old review does not authorize a scope change.

## RQ1: Detection and enforcement

1. **Full-product contextual package comparison, all three tiers.** Retain historical and updated efficient, balanced and quality packages on the same 1,560 authored provisional cases (810 sensitive, 750 clean). Distinguish label-and-action joint agreement, allowed-action agreement and binary classification. Keep paired gains and losses, the shared 139 unnecessary restrictions, package/configuration confounds and the absence of independently adjudicated contextual truth. This is full-product evidence with actual cascade execution recorded, not a semantic-only result. See [pipeline aggregates](research/pipeline-comparison-20261014.json).

2. **Targeted balanced-package detector ablation.** Cover only the full `[2,3,4]`, no-rules `[3,4]` and no-NER `[2,4]` contrasts on the same package, inputs and policy. Retain both the action-agreement improvement from 1,409 to 1,530 and the eighteen lost correct actions, with under-restriction increasing from twelve to thirty. Preserve the declared paired uncertainty/grouping limitations. No-NER equality applies to this fixture with zero converted NER findings; it does not justify disabling NER generally. See [controlled-study evidence](research/controlled-studies-20261014.md).

3. **Frozen final 498-row semantic annotation-presence check, all six arms.** Retain all historical/updated tier pairs, the 236 positive/262 negative targets and full confusion counts. Explicit sole-semantic execution, frozen selection, source-group uncertainty and no subsequent tuning are essential. Keep poor updated specificity of 13.36–21.76% alongside recall/accuracy gains. Annotation presence is distinct from contextual authorization and official character-masking/F2 scoring; it is not a controlled continuation of the full-product target. See [final semantic aggregates](research/final-semantic-evidence-20261014.json).

4. **Thirty-three installed receiver-enforcement probes.** Retain the installed Linux Chromium/native path with the historical balanced detector and synthetic HTTPS receiver: eighteen unchanged-body sends and fifteen zero-send outcomes. Preserve WARN forwarding, failure versus reduced-layer fallback, disabled-protection bypass and recovery. Keep earlier failed captures separate. These probes establish the declared request behavior, not real-provider compatibility, cross-platform coverage or user benefit. See [installed-client evidence](research/installed-client-evidence-20261014.md).

## RQ2: Updates and retained behavior

5. **Matched HEADS/FULL continuation and its sixteen-case retention guard.** This is the only adaptation experiment to report. Retain seeds 42/43/44, the common intact pretrained balanced base with zero task heads, matched 4,096 exposures/64 steps, all six terminal candidates and the unchanged base. Preserve the 1,080 reused-case assessment, exclusions and actual sole-semantic in-process scope. Distinguish allowed-action assessment from the guard's single derived target action. Keep paired gains and losses, directional harms, all FULL rejections, HEADS 42/44 passes and HEADS 43 rejection. No candidate was published; a small guard and weak base do not establish protection without regression. Do not restore empirical publication/client-refresh success claims from excluded experiments. See [controlled-study evidence](research/controlled-studies-20261014.md) and [aggregates](research/controlled-studies-20261014.json).

## RQ3: Systems and privacy overhead

6. **Installed rules/NER browser cost.** Retain 360 measured decisions across twelve fresh profiles, including all six fetch/XHR/action cells. Preserve the different executed paths (240 rules/NER ALLOW/WARN decisions and 120 rules-only BLOCK decisions), latency boundary, warmups, two profile clusters per cell and observed-maximum interpretation. Keep whole-container CPU/charged-memory boundaries, included infrastructure/observer/cache and sampling gaps. These measurements exclude semantic processing and lack an unprotected baseline or per-role attribution; do not label them incremental firewall overhead. See [installed-browser protocol](research/installed-browser-protocol.md) and [installed-client aggregates](research/installed-client-evidence-20261014.json).

7. **Telemetry finite privacy, estimator error and ledger/selection behavior as one reporting mechanism.** Retain the five domains, ideal and finite equations, three audited budgets, fingerprinted host and independent-uniform-entropy assumptions; disclose the small excess over nominal privacy loss. Preserve the 180-cell/10,000-repetition fixed-contributor simulation design and both already reported illustrative category cells at `n=80` and `n=8000`, including clipping, bias, RMSE and incoherent totals. Keep reservation persistence, concurrency and failure accounting, plus the 32-event order-reversal example. These properties do not establish representative or useful deployment monitoring, and the content bound excludes participation, delivery and metadata. See [telemetry evidence](research/telemetry-evidence-20261014.md) and [aggregates](research/telemetry-evidence-20261014.json).

## Excluded from manuscript coverage

Do not reintroduce these omitted families as experiments, result catalogues, extra benchmarks or indirect claims:

- Small/large Presidio contextual comparisons and the restricted five-type external reference.
- The 2,000-row AdvPIIBench category experiment.
- The historical 502-row development comparison, adaptation grids, curricula, accelerated studies and their attempted-budget catalogues.
- The separate EN3-to-AU3 semantic comparison and full selected-epoch ancestry table. Keep only the compact lineage and native settings needed to interpret the retained package comparison.
- The other detector-ablation configurations, detailed per-label subgroup catalogues and repeated-call inventories as additional evidence. Preserve necessary denominators and dependence qualifications without turning repeated execution into independent samples.
- Host-RPC latency/RSS comparisons, training timing/CUDA-peak comparisons and browser-startup interval catalogues.
- The 195-pin/24-probe reconstruction capsule and fifty-three synthetic client-event tests.
- External systems' incompatible numerical-result rankings or detailed function tables. Qualitative, accurately cited related-work synthesis remains appropriate and does not expand the empirical study set.
- Duplicate result plots and detailed enforcement/update diagrams formerly carried outside the main paper. The current overview and necessary mechanisms remain in the self-contained account.

Underlying research records, aggregates, reusable assets and Git history remain preserved for provenance. Their availability does **not** make the omitted studies reportable in the paper. Exclude both favourable and unfavourable results from those families; never use omission to imply superiority or suppress adverse outcomes within a retained unit.

## Requirements for every rewrite

- Keep the paper self-contained and at most ten complete pages, including references, without reducing prescribed typography. **No appendix or supplement is permitted**, including a renamed companion or “supporting detail” workaround. Essential definitions, methods, results and limitations for the retained units must appear in the paper itself.
- Preserve the three research questions, explanatory writing style, actual quantitative findings and relevant uncertainty. Preserve all arms within retained comparisons and material negative outcomes; do not cherry-pick a tier, seed, detector contrast or simulation example to improve the apparent result.
- Keep provisional labels distinct from independent ground truth; prediction agreement distinct from enforcement; full-product results distinct from semantic-only results; candidate assessment distinct from publication; and conditional telemetry content privacy distinct from participation or deployment utility.
- This scope document authorizes no new experiments, training, inference, scoring, resampling or protected-data access. New execution requires its own authorization; even authorized new measurements do not automatically enter the manuscript's approved scope.
- If a direct user instruction changes the approved set or format, update this document with that instruction and its rationale before the corresponding rewrite. Preserve the historical revision record rather than silently replacing its decisions.
