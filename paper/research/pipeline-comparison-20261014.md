# Native product and external comparison paper record (PAPER14)

Research/edit date: 14 October 2026. Branch/base: `feat/dev-testing`,
`a08c4d674bf9715ac66a92493498e691957558f9`. This record extends the existing
[claim ledger](claims.md); historical studies and their results are unchanged.

## Exact request and question map

```text
Reread the entire agents.md workflow again

Can you now do a writeup into the results and discussion section of the paper and add in updated diagrams with comparisons of performance of PriVoke vs other models as well, rewriting any part of the methodology you need to as well.
```

| Question | Evidence and result | Interpretation boundary |
| --- | --- | --- |
| How do original V1 and AU3-selected V3 perform through the current product handler? | PIPE3 first-pass joint counts E/B/Q 266/160/226 to 693/717/879 of 1560; action 1029/1026/1073 to 1415/1409/1421. Accepted analysis and independent all-pass review below. | Reused assistant-provisional AU3 synthetic cases, native packages and thresholds, full regex-first product pipeline; no architecture/pretraining causal estimate or promotion. |
| Which regressions remain despite gains? | Joint improved/regressed E/B/Q 484/57, 573/16, 671/18; action 389/3, 389/6, 348/0. All V3 over-enforce the same 139 cases. | Counts are same-case descriptive results. Trace provenance identifies regex maximum actions, not a removal ablation. |
| How does a configured external recognizer behave on the same cases? | Presidio TP367/TN539/FP211/FN443, zero errors, recall367/810 and specificity539/750. Six existing PIPE3 first passes paired by exact ID. | Native entity recognition deliberately differs from contextual disclosure truth. No severity/audience/category/action/joint adaptation; one small-model configuration, not optimized SOTA or external human validation. |
| Can published work be placed on the same score axis? | Four verified source families report detection, sanitization, adversarial recovery, utility and policy metrics with different corpora. | Separate context table with native metrics and known denominators; no shared ranking or reconstructed numerator from rounded scores. |
| Does correct policy action prevent outgoing content? | Browser source `extension/src/page-interceptor.js:24-35` and XHR decision branch forward originals unless BLOCK. | WARN is not prevented disclosure or sanitized transmission; installed-client receiver evidence remains incomplete. |

## Latest measurements and provenance

The [compact tracked aggregate](pipeline-comparison-20261014.json) contains only
counts, metrics, execution scope and provenance commitments. It has no prompts,
weights, final cases, text-bearing entity findings or fitted vocabulary.
`paper/scripts/plot_pipeline_comparison.py` derives rates from counts, checks
paired arithmetic and emits three PNG/SVG/PDF figure sets with a hash manifest.
Independent study reviews support source integrity; this writer did not rerun
PriVoke or perform new training. A separate root-authorized host Presidio run
used the unchanged wrapper once and retained its raw outputs before analysis.

| Source | SHA256 / scope |
| --- | --- |
| PIPE3 analysis | `evaluation/results/pipeline_v1_v3_20261014/runs/cpu-01/analysis.json`, `2d9190cc26003e9916719c96127791b6b348e1a0683a30b11891a058a96a302f` |
| PIPE3 independent final raw review | `evaluation/results/pipeline_v1_v3_20261014/planning/results-review-final-01.json`, `7739f7f2e6d9ad907775606353e84cad42556c8915820f420f3d5302717790f0`; all18 passes, 294 dependence-sensitivity intervals and raw wires reconciled |
| PIPE3 protocol | `938f626bec9b5810a34e6e9f33d1d28f0070fbc10ac6a570e568b41c39346ed7`; raw inventory `d68f9cb08b4d3f16db396a4f3fea4c5c8764803c3a387ff87719f637e7184da7` |
| Actual PIPE3 source closure | `bf022fc18b16aebfdbcc75e68ef92e28ffb4f4765015c74fc56e95e1047864fa`; includes preexisting dirty dependencies, so harness commit `6637468` alone is insufficient |
| AU3 release07 manifest / FRESH | `41cfd9e476f3d0a17c2a4997efab2afbb6b044c5fbd55217b0614525a2571fe0` / `e965c21a0d43babc0984f46eb70785c8d66d878e00e647eefb9565f219b2da0c` |
| Presidio reference analysis | `evaluation/results/paper_revision_20261014/presidio-au3/analysis.json`, `0fb898b44020a09a1856864fd29ff842a28c3ccfc291deb4db3a567f64ecde1a` |
| Presidio raw / protocol | `ce72efabc79cf4f58edda618acc7bf05790f7ecd0d2b197c73593a0aca4984d3` / `eab5ca47221f4cd4b4c91cd9688cf9435bb7b4be7be042873112b5d2cce564f0` |
| Presidio execution/reconciliation handoff | `b7bd2079e119cb053a77ca271d5e0ee0057b058a52553991e133bfdb8a18b093`; one invocation,1560 exact-order cases, zero errors; root accepted independent raw-count/protobuf critique |
| Presidio independent critic review | `evaluation/results/paper_revision_20261014/planning/presidio-review.md`, `9f1f61064a67ca6bf2a6d1b17d7074f32348baeeebb59a7bd844b6016ba78b1b`; raw recognizer outcomes and all six native product first-pass protobuf records reconciled; new bootstrap intervals not independently recomputed or used in manuscript |

PIPE3 explicitly requested `[2,3,4]` with regex FIRST and empty hints. Regex ran
on all1560; NER/semantic ran on1271 and legitimately skipped289 per package/pass.
The installed spaCy model generated zero converted PriVoke NER findings, not
zero raw entities or zero execution. First-pass primary n=1560; three identical
passes are repeatability observations. The source has35 families/24 audience
expression groups and provisional labels. Separate family/expression paired
intervals describe dependence sensitivity, not crossed independence.

V3 selected encoder/pooler epochs E/B/Q30/20/8 and heads42/27/12 combine PH3,
EN3 and AU3 selected ancestry; upstream language-pretraining counts are unknown.
V1 has zero optimizer-trained encoder epochs and220/360/520 synthetic bootstrap
head epochs. Native tokenizers, caps, thresholds, histories and backends differ.
AU3 was fresh at its sealed semantic comparison; PIPE3 and Presidio reuse it.
AU3 semantic joint excludes policy action, whereas PIPE3 product joint includes
an allowed action. Neither is binary annotation presence or browser prevention.

The new Presidio projection retains exact ordered texts/IDs and uses the exact
PIPE3 positivity rule (nonS0 or nonempty category set). Only text/language/0.5
threshold enter inference, with no target hints, PriVoke rules, entity mapping,
tuning or exclusions. Presidio2.2.363/spaCy3.7.5/en_core_web_sm3.7.1 and native
recognizers are pinned. Errors would count incorrect in full class denominators,
while successful confusion and errors are separate; actual errors are zero.
Its direct analyzer timer is excluded from the product RPC cost chart. Root
accepted point estimates and paired counts, not new interval claims.

## External source ledger (opened and verified 14 October 2026)

The comparator researcher verified the following primary full text or
institutional records. Its accepted checkpoint is ignored
`planning/comparator-review.md`, SHA256
`8d9a745332330a99efe7890709a56fe8429f4dd497816d6359331b9d2ab57e40`.
No external implementation was run or revision-matched. Literature results
remain source-reported; these sources do not corroborate PriVoke measurements.

| ID / citation | Verified source locator and retained result | Limits |
| --- | --- | --- |
| CMP-CAS-PUB; `Casper2024`, `CasperAbstract2026` | [NJIT institutional proceedings abstract](https://researchwith.njit.edu/en/publications/casper-prompt-sanitization-for-protecting-user-privacy-in-web-bas/), DOI10.1109/CSCloud66326.2025.00027: PII92.6%, topic92.5–94.0%, pseudonymization92.0%, response cosine0.538; describes4500 synthetic/2000 real-world prompts. | Full published per-metric allocation, class supports, model/configuration and implementation parity unavailable. No n=6500 claim for every metric. No numbers taken from the distinct2024 preprint. |
| CMP-HAS; `HaS2024` (actual2023 arXiv v1) | [Full text sections4.1–4.3, Tables1–2](https://arxiv.org/html/2309.03057v1): label-based black-box protection0.4070; generative560M0.3121; BBC microF1 91.36 versus91.20 without obscuring. Privacy corpus19703,80/20 split; additional30000 attacker examples; BBC1490 labels. | Protection is1−difflib similarity of original/attacker-recovered text, not recall. Exact integer privacy test count not given. BLOOMZ560M/1.7B; no repository parity claim. |
| CMP-PROSAN; `ProSan2024` arXiv v1 | [Full text sectionVI-A/B, TablesII–V](https://arxiv.org/html/2406.14318v1): overall privacy hiding96.0% dataset-generation/99.8% prompt-anonymization; latter SAMSum name-discrimination F1 .787.1000 test prompts per augmented MedQA/SAMSum/CodeAlpaca. | Hiding-rate denominator is privacy items, exact pooled count unavailable. LLaMA2-7B/RoBERTa-base generation, FlanT5-base anonymizer. Not2026 journal evidence or prompt-level detection. |
| CMP-PS; `PromptShield2025`, `PromptShieldAbstract2026` | [ITU institutional conference abstract](https://research.itu.edu.tr/en/publications/promptshield-policy-aware-dlp-framework-for-generative-al-prompts/), DOI10.1109/UBMK67458.2025.11206862: enterprise role/policy accuracy72.92%,900 synthetic training/development,435 independent test prompts. | Full-text model, class supports, exact split/aggregation unavailable. No numerator back-calculated from rounded72.92%. Distinct2026 thesis/same-name injection tools. |
| CMP-PRESIDIO; `PresidioNlpConfiguration2026` | [Official NLP configuration documentation](https://github.com/data-privacy-stack/presidio/blob/main/docs/analyzer/customizing_nlp_models.md); retained local configured wrapper and versioned raw outputs. | Documents configuration, not a published benchmark result or strongest configuration. Historical502 annotation-presence result remains separate. |

Every manuscript citation uses existing stable bibliography keys or new
institutional/configuration entries. The earlier HaS2024 key retains its legacy
suffix while the manuscript explicitly identifies2023v1. No claim relies on
unretrieved Casper/PromptShield full text or ProSan's later journal version.

## Reproduction and review boundary

```powershell
python paper/scripts/plot_pipeline_comparison.py --validate-only
python paper/scripts/plot_pipeline_comparison.py --overwrite
```

The generator checks compact aggregate arithmetic and regenerates figures
without raw prompts or ignored assets. It does not reconstruct raw-wire audits;
their immutable commitments and actual scope remain above. The three figures
use different outcomes with explicit denominators, no invented uncertainty,
no mixed historical/latest workload and no unmatched published score axis.
Root owns current-rendered-page acceptance, scoped staging/commit and final
push. Existing unstaged main.tex/ref.bib edits are preserved through separate
initial snapshots and a HEAD-only owned projection; no source commit occurs in
the writer. Unused minted loading is removed so portable TeX does not require
shell escape for this manuscript, which contains no minted environments.
