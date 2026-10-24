# Fresh evaluation data: sources, exclusion procedure, protocol and power (2026-10-24)

**Scope: planning only. Nothing here was downloaded or scored. All data described is for detector-layer (regex + NER) and, where stated, span-level evaluation. It is not LLM-only or semantic-layer evidence.**

Task `w1-b-data` (items 2 and 3, data side). Web pages (dataset cards, file listings, licence files) were read on 2026-10-24; no dataset or model file was downloaded. User instruction recorded in the brief: "Test all of these in parallel and integrate promising ones" (research follow-ups to PR #5), later "you have my permission to download anything <5GB for testing, and if the tests are not integrated please delete the download". The exact download list is in `docs/research/download-request-20261024.md`; the pre-registration is `docs/research/preregistration-detector-v2-20261024.md`.

## 1. Why fresh data is needed

- `final.jsonl` (498 rows) was scored once and then re-derived once more for per-row pairing (`docs/experiments/detector-precision-installed-20261024.md`, `docs/experiments/detector-uncertainty-20261024.md`). It is consumed for the frozen old/new pair and cannot adjudicate any new configuration.
- dev-TUNE and personalized were design sets; dev-CHECK and openai were inspected after review (post-review, not blind).
- On real text the observed effects are a handful of discordant rows (regex specificity 3 vs 0 flips, regex recall 0 vs 3, union recall 13 vs 14, union specificity 7 vs 6, all on final). None is statistically distinguishable from zero. Power is the binding problem (section 5).
- The previously planned natural-benign set (Rotten Tomatoes) is missing, so real-world false-positive rates on ordinary prompts are unmeasured (section 4).

## 2. Fresh PIIMB sample, disjoint from the locked partitions

### 2.1 How the locked partitions were built (verified in code)

- Builder: `evaluation/prepare_public_splits.py` calling `privoke_eval.datasets.load_piimb` (`evaluation/privoke_eval/datasets.py` lines 614-660). Config `sentences`, split `test`, streamed from `piimb/pii-masking-benchmark` at the pinned revision `4a13e9ffe6fd0d275efbde8afd4d8d8f1ffc2133`, English only, `seed=3102026`, strategy `balanced`, 1000 rows (500 PII / 500 clean) via per-label reservoirs over the whole population (107,488 eligible of 150,022 rows; 15,354 duplicates; 598 conflicting duplicate-label rows; 27,180 non-English rows removed).
- Group id = `parent_id or source_uid or uid` (source document). Documents were then shuffled with the same seed and split by group in half: development (502 rows, 465 groups) and final (498 rows, 464 groups); zero group overlap.
- Label definition: positive iff the sentence has at least one entity span; "clean" means no annotated entity in that sentence. Negatives are therefore sentence fragments from documents that mostly contain PII, not natural prompts. Unannotated PII in "clean" sentences is possible (annotation noise is documented for Nemotron-PII).
- The locked records stored only presence and category names; spans were not kept. A fresh draw must keep the `entities` list for span-level work (H4).
- Source mix of the locked 1000 (by `source_dataset`, from `group_id` metadata only): Nemotron-PII 602 rows (about 60 %), ai4privacy OpenPII-1M English 189, Gretel PII-masking-EN 163, Privy 40, MAPA EUR-Lex 3, ai4privacy multilingual 3.

### 2.2 Authorized exclusion-set derivation

The brief authorized reading only the `id` and `group_id` fields of `final.jsonl`. A script (kept in scratch, not committed) read `id`, `group_id` and the label/source metadata from both partitions without ever printing or storing text. Results (hashes are sha256 of the sorted ids/groups joined by newlines):

| Set | Rows | Groups | sha256 of sorted ids | sha256 of sorted groups |
|---|---|---|---|---|
| development | 502 | 465 | `80e3002ba524306b9d7dcb314012e621d72b4d5d3c6b0d2c76b50ec8421b4c8d` | `7ee581117e4db8eaa61657d070d6d3022d19b96bc83bf9d526b543998b4eb631` |
| final | 498 | 464 | `7fdc9aec04ec1e0b0c9b3630efd5cbf12e6f9761afc159a19d828e895c5aeeb2` | `6f926104ec6f03e5ecaeba6b3494806011e619579b6efebcba49df0432d86ab0` |
| union | 1000 | 929 | `51933a2c2655f0e10efebc041dd3a28b8297423b8aef04bed303a69c55fda4e1` | `16e2006bfa5a4dff86e0bd8a77d0bc43f831bb407c9f988257f36d953da78b45` |

The id and group lists live in the scratch directory only (`.../wave1/b-data/exclusion_set.json`). The Wave 2 builder can regenerate them from the gitignored locked files with `fresh_set_plan.py hash` (verifies the hashes) because the files are in the main checkout.

### 2.3 Wider exclusion: PIIMB test rows were already used elsewhere

The repository reused the same PIIMB test pool for training and validation material, so "never scored" is not the same as "never seen":

- `evaluation/prepare-public-negatives.py` (seed 4102026) drew 2400 clean PIIMB rows as a training curriculum (`evaluation/results/public-negative-curriculum/`).
- `evaluation/prepare-representation-study.py` (seeds 5102026 / 6102026) and `evaluation/prepare-external-pii-study.py` (train/validation material), plus the validation prediction files with 959 PIIMB rows and `text_control_20261004_v1/selection.json` (about 14,300 group-id mentions), show further PIIMB rows used for fitting or validation.

For detector-layer (regex and spaCy NER) evaluation these uses do not train the detectors, so overlap is tolerable. For any semantic-layer or fitted-profile study it is not. The builder must therefore also exclude every PIIMB group id that appears in any training/validation artifact. A scan of `evaluation/results/**` for group-id tokens was started to size this exclusion (it excludes `final.jsonl` itself); `fresh_set_plan.py draw --exclude` takes any number of group-id files, so the union is a flag, not a code change. The result of the scan is reported in the return message of this task, if it finished, and is otherwise the first step of the builder.

### 2.4 Local copy and what to download

No local PIIMB copy or Hugging Face cache exists (the only hub cache entry is an unrelated FLUX model; there is no `datasets` cache; the `datasets` package is not installed in `evaluation/.venv-v1-v3-pipeline`). The builder needs exactly one file:

- `data/test_sentences.jsonl` at revision `4a13e9ffe6fd0d275efbde8afd4d8d8f1ffc2133`, 60,412,185 bytes (60.4 MB), LFS sha256 `5ff46f3a80316318794f94596fa374060d70f2f32a85909f958cbabc70bae41f`. Not gated. Licence CC BY-NC 4.0 (card), with per-source licences CC BY 4.0 (ai4privacy OpenPII-1M, Nemotron-PII, MAPA), Apache 2.0 (Gretel), MIT (Privy). The sentences are derived from documents with SaT `sat-12l-sm`; entities are `{start, end, label}` in sentence-relative character offsets.
- The `full_text` config (`data/test.jsonl`, 24,728,217 bytes, whole documents) is optional and not needed.
- The current repository HEAD of the dataset (lastModified 2026-10-17, sha `72ea3393...`) differs from the pinned revision; always fetch by the pinned revision and verify the sha256.

### 2.5 Draw procedure (`evaluation/fresh_set_plan.py draw`, stdlib only, no network)

1. Verify the file sha256. Apply the same row filters as `load_piimb` (English, valid offsets, strip + NFC text normalisation, duplicate-text and conflicting-label removal).
2. Drop every row whose group id is in the exclusion union.
3. Rank rows and groups by `sha256(seed:key)` (order-independent, unlike the original file-order reservoir). Keep at most `--max-per-group` sentences per source document, select positives first, then clean rows from groups not already used, so no document appears in both classes.
4. Store `entities` re-based onto the stored (stripped, NFC) text so span scoring is possible; write a manifest with source-file sha256, exclusion-set sha256, population counts, selected counts by source, output sha256 and script sha256.
5. Post-check: no selected group in the exclusion set, group cap respected.

The script was smoke-tested on a fabricated 1200-row file (labelled synthetic; offsets, language filter, exclusion, per-group cap and both classes verified). It has not seen real PIIMB data.

Proposed fresh draw (sizes justified in section 5): seed `8102026`, 10,000 positives and 6,600 clean, `--max-per-group` 1 if the exclusion-filtered pool fills both quotas, otherwise the smallest cap in {2, 3} that does. Report results stratified by `source_dataset` (the pool is Nemotron-dominated) and analyse with the grouped bootstrap of `evaluation/detector_stats.py` (agent A, branch `research/wt-a-stats`).

## 3. Span-labelled candidates (item 2)

PIIMB itself provides character spans and entity types (field `entities`: `start`, `end`, `label`, offsets relative to the sentence), so one download serves presence-level and span-level work. The independent-source candidates are for sensitivity analysis and prompt-style fit.

| Candidate | Source | Exact files (size) | Licence | Gated / registration | Language | Span schema | Fit for prompt-style evaluation |
|---|---|---|---|---|---|---|---|
| PIIMB (primary) | https://huggingface.co/datasets/piimb/pii-masking-benchmark | `data/test_sentences.jsonl` (60,412,185 B) | CC BY-NC 4.0 overall; sources CC BY 4.0 / Apache 2.0 / MIT | No | Mostly English; multilingual parts exist | `entities[{start,end,label}]`, char offsets | Sentences from synthetic or legal documents, not user prompts. Same population as the locked sets (fresh groups only). |
| SPY | https://huggingface.co/datasets/mks-logic/SPY ; code https://github.com/LogicZMaksimka/SPY_Dataset | `data/legal_questions_placeholders.jsonl` (45,690,405 B), `data/medical_consultations_placeholders.jsonl` (44,188,672 B); `SPY.py` (5,959 B, read only) | CC BY 4.0 | No | English | Token-level BIO (`tokens`, `trailing_whitespace`, `ent_tags`); entity values are placeholders filled by Python Faker at load time, no character offsets in the files | Best prompt-style fit: LLM-generated legal questions (4,197) and medical consultations (4,491) with 7 types (name, email, phone, address, url, username, id_num). Needs the Faker fill step reimplemented from `SPY.py` (do not use `trust_remote_code`), and a `faker` install in the new venv only. Fully synthetic. |
| Text Anonymization Benchmark (TAB) | https://github.com/NorskRegnesentral/text-anonymization-benchmark (head 558e09e2, 2026-01-19; paper arXiv:2202.00443) | `echr_test.json` (13,103,290 B), `echr_dev.json` (12,643,092 B), `guidelines.md` (19,788 B), `LICENSE.txt`; skip `echr_train.json` (47,503,662 B) | MIT | No | English | Stand-off JSON: entity mention with `start_offset`, `end_offset`, `entity_type` (PERSON, CODE, LOC, ORG, DEM, DATETIME, QUANTITY, MISC), `identifier_type` DIRECT / QUASI / NO_MASK | Weak prompt fit: 1,268 long ECHR judgments. Real personal data from public court documents (ethics caution, text must not be copied into the repo). The DIRECT/QUASI mask decision does not map one to one onto PriVoke categories. Useful only as a secondary real-text span check on names, dates, locations. |
| Gretel synthetic PII finance (multilingual) | https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual | `data/English_test-00000-of-00001.parquet` (2,720,729 B), `data/English_train-00000-of-00001.parquet` (24,403,359 B) | Apache 2.0 | No | EN, FR, DE, ES, IT, NL, SV (use English files) | `pii_spans` JSON string `{start,end,label}` | Finance documents (contracts, emails, forms). Already a loader in the repo (positives only). Parquet needs `pyarrow`. Overlap with earlier use not audited. |
| Gretel PII masking EN v1 | https://huggingface.co/datasets/gretelai/gretel-pii-masking-en-v1 | `data/test-...parquet` (2,029,143 B), train 20,313,313 B | Apache 2.0 | No | English | Entity strings and type lists only, no offsets (PIIMB's copy has computed offsets) | Already inside PIIMB's pool; not an independent source. Skip. |
| Nemotron-PII train | https://huggingface.co/datasets/nvidia/Nemotron-PII | `data/train-00000-of-00001.parquet` (156,334,329 B) | CC BY 4.0 | No | English | `spans` string of `{start,end,text,label}` | Synthetic documents in 30 domains; PIIMB's test pool already contains the `test` split. Train is a different set of documents, so it is a reserve if the PIIMB pool is exhausted after exclusion. Noted annotation noise on the card. |
| ai4privacy pii-masking-300k | https://huggingface.co/datasets/ai4privacy/pii-masking-300k | `data/validation/1english_openpii_8k.jsonl` (27,338,200 B), `data/train/1english_openpii_30k.jsonl` (102,804,743 B) | Custom `license.md`; the 400k version's text reads academic research and non-commercial only, commercial use needs a licence from AI4Privacy (not independently verified for 300k: the file was not retrievable) | No | EN, FR, DE, IT, ES, NL | `privacy_mask[{label,start,end,value}]` | Synthetic, with documented label problems. Non-commercial terms make it a poor choice; not recommended. |
| ai4privacy OpenPII-1M | https://huggingface.co/datasets/ai4privacy/pii-masking-openpii-1m | `data/validation.jsonl` (920,284,464 B), `data/train.jsonl` (3,690,456,830 B) | `license: other` with `license_name: cc-by-4.0` | No | 23 languages | `privacy_mask[{label,start,end,value}]` | Already the source of the locked `ai4privacy-en` rows via PIIMB, 4.6 GB for a mostly multilingual file. Not recommended. |
| n2c2 / i2b2 2014 de-identification | https://n2c2.dbmi.hms.harvard.edu/data-sets | not downloadable without registration | Data Use Agreement; no redistribution, no posting to GitHub | Gated: registration and signed DUA | English clinical records | PHI tags | Real (de-identified) clinical text, the best real-text PHI benchmark, but access is restricted. Under the project rules this is reported, not requested. |
| Meddies PII | repo loader exists (`Meddies/meddies-pii`) | not re-checked | not re-checked | not re-checked | English | label mapping | Positives only; not evaluated here. |

Recommendation: PIIMB for the decisive presence-level sample and for span-level scoring (H4), SPY as the prompt-style synthetic second source, TAB as an optional real-text span cross-check. Do not use the non-commercial ai4privacy files.

## 4. Natural benign prompts (item 3)

Goal: measure real-world false-positive rates on ordinary prompts, replacing the missing Rotten Tomatoes set. Natural prompts are not guaranteed PII-free, which changes the label problem.

| Candidate | Source | Exact files (size) | Licence | Gated | Notes and PII risk |
|---|---|---|---|---|---|
| OpenAssistant oasst2 | https://huggingface.co/datasets/OpenAssistant/oasst2 | `2023-11-05_oasst2_prompts.messages.jsonl.gz` (15,560,794 B): 64,592 kept initial prompts, about 41 % to 48 % English | Apache 2.0 | No | Volunteer-written prompts for an assistant; per-message `labels` include a `pii` reviewer flag (definition not documented). Low real-PII density, instruction-style. Good for a clean-ish benign baseline. |
| Databricks Dolly 15k | https://huggingface.co/datasets/databricks/databricks-dolly-15k | `databricks-dolly-15k.jsonl` (13,085,339 B), 15k English instruction/context/response records | CC BY-SA 3.0 | No | Written by employees, `context` often Wikipedia text (public figures' names appear). Treat `instruction` as the prompt; `context` is a harder variant. Share-alike licence applies if redistributed. |
| WildChat-1M | https://huggingface.co/datasets/allenai/WildChat-1M | 14 parquet shards, total 3,360,836,020 B; one shard is 181-336 MB (`data/train-00000-of-00014.parquet` = 230,786,095 B). 838k conversations, 74 languages; toxic ones removed | ODC-BY (changed from ImpACT on 2024-06-26, retroactive) | No (the `WildChat-1M-Full` variant is gated and is not proposed) | Real ChatGPT user prompts, closest to the target distribution. De-identified with Presidio plus hand-written rules; the card does not claim full removal, so residual PII is expected, and some users paste real personal text. This is the most informative and the riskiest source. Re-identification is not mentioned in the licence but must not be attempted. |
| LMSYS-Chat-1M | https://huggingface.co/datasets/lmsys/lmsys-chat-1m | 1.49 GB parquet | Dataset-specific agreement | Gated: login and licence acceptance | Only person names redacted (OpaquePrompts), 154 languages, not decontaminated. Gated, so reported and not requested. |
| Rotten Tomatoes | not recoverable | not applicable | not applicable | not applicable | Original benign set is missing; its reviews were never prompt-like, so no loss in realism. |

Proposed natural-benign sample (seed `9102026`, English only after a fixed language filter): 2,000 oasst2 initial prompts, 2,500 WildChat first user turns from one shard (a second shard only if English yield is short), 1,500 Dolly instructions, total 6,000. Cap length at the 99th percentile of PIIMB text length to avoid giant pasted documents dominating latency; record the cap in the manifest. Do not commit any prompt text; commit only ids, hashes and counts. Keep the texts in the gitignored external-data directory.

### 4.1 Screening and labelling protocol that does not use our detectors as ground truth

The unit of interest is "does this prompt contain personal data of an identifiable person". Our detectors cannot define it, because that would measure agreement with ourselves.

1. Pre-registered label definition (frozen before any detector runs): P = contains a real or plausibly real identifiable person's personal data of a type in the PriVoke taxonomy (direct identifiers, contact data, government or financial identifiers, health or other sensitive attributes tied to a person). N = does not. U = ambiguous (public figure facts only, fictional characters, placeholders, generic examples). The guideline lists boundary cases (celebrity names, "John Smith" style examples, code strings that resemble identifiers) and is hashed.
2. Pooled adjudication (as in retrieval evaluation): the review pool is the union of prompts flagged by any frozen configuration (old, new, regex, NER, each H3 model) plus a uniform random audit sample of 400 unflagged prompts drawn with a fixed seed. Reviewers see the prompt text only: no detector output, no configuration name, shuffled order.
3. Two independent raters per pooled prompt. The user is the final adjudicator for disagreements. If a second human is not available, a model-assisted second rating is acceptable provided it is recorded as such, uses a different prompt from any detector, and the human adjudicates every disagreement and a 10 % random sample of agreements. Report inter-rater agreement (Cohen's kappa) on P vs not-P.
4. Dataset-native flags (oasst `labels.pii`, WildChat `redacted`) are used only as stratification hints and reported next to the final labels, never as labels.
5. Denominator and bias control: every prompt that is not adjudicated P counts as benign. The random audit sample estimates the PII rate among unflagged prompts (exact binomial CI); if it exceeds 0.5 %, the benign set is declared contaminated and the false-positive estimates carry the audit-based correction and are marked exploratory.
6. A false positive is a flagged prompt adjudicated N. Flagged prompts adjudicated P are true positives (reported as a real-prompt detection yield, not mixed into specificity). U prompts are reported both ways (counted benign, counted excluded).
7. Privacy handling: adjudication happens locally; prompts with real-looking personal data are not quoted in any document, issue or paper; only ids and hashes are stored; no re-identification attempts.

## 5. Power analysis (item 4)

Tool: `evaluation/fresh_set_plan.py power` (stdlib, exact two-sided McNemar for superiority, Wald non-inferiority with a Monte Carlo check). Definitions: `delta` = true gain of the candidate over the baseline in correct decisions on the class (p10 - p01), `psi` = discordant proportion (p10 + p01); alpha 0.05 two-sided for superiority, 0.025 one-sided for non-inferiority, power 0.80. Machine-readable output is in the scratch file `power.json` and reproduced here.

The discordant proportions that matter are observable from agent A's per-row analysis of the already-used final set (`docs/experiments/detector-uncertainty-20261024.md`), and set the planning values:

| Quantity (final) | Gains / losses | psi | delta |
|---|---|---|---|
| regex specificity | 3 / 0 | 1.15 % of 262 | +1.15 pt |
| regex recall | 0 / 3 | 1.27 % of 236 | -1.27 pt |
| union specificity | 7 / 6 | 5.0 % of 262 | +0.4 pt |
| union recall | 13 / 14 | 11.4 % of 236 | -0.4 pt |
| NER-only recall | 23 / 29 | 22 % of 236 | -2.5 pt |

### 5.1 Required items per class (80 % power)

Superiority, exact McNemar, alpha 0.05 two-sided (n = negatives for specificity, positives for recall):

| delta \ psi | 1 % | 2 % | 3 % | 4 % | 6 % | 8 % | 12 % |
|---|---|---|---|---|---|---|---|
| 0.5 pt | 3,373 | 6,580 | 9,752 | 12,914 | 19,204 | 25,489 | 38,059 |
| 1 pt | 790 | 1,686 | 2,489 | 3,290 | 4,876 | 6,457 | 9,602 |
| 2 pt | n/a | 394 | 615 | 843 | 1,244 | 1,645 | 2,438 |

Extra points: regex specificity at the observed delta 1.15 pt, psi 1.15 pt needs 687 negatives. Union specificity superiority at delta 0.4 pt, psi 5 % needs 24,992 negatives (not achievable; union specificity is exploratory only). A 2 pt recall gain at the NER-only discordance of 22 % needs 4,407 positives; a 5 pt gain needs 722.

Non-inferiority, margin 1 pt, one-sided alpha 0.025 (n = positives for recall):

| true delta \ psi | 1 % | 2 % | 4 % | 6 % | 8 % | 12 % |
|---|---|---|---|---|---|---|
| 0 | 785 | 1,570 | 3,140 | 4,710 | 6,280 | 9,419 |
| -0.5 pt | 3,132 | 6,272 | 12,551 | 18,830 | 25,109 | 37,667 |

Union recall (psi 11.4 %), by margin and true delta:

| margin \ true delta | 0 | -0.2 pt | -0.4 pt |
|---|---|---|---|
| 1 pt | 8,948 | 13,981 | 24,852 |
| 1.5 pt | 3,977 | 5,295 | 7,394 |
| 2 pt | 2,237 | 2,762 | 3,495 |

The Monte Carlo check of the Wald formula (n = 8,900, delta 0, psi 11.4 %, margin 1 pt) gives power 0.79 against 0.80 analytic.

### 5.2 What this implies

- H1 (regex specificity, delta about 1 pt, psi about 1 to 2 %): 1,700 negatives are enough; 3,000 give 97 % power at delta 1 pt, psi 2 %, and 66 % at delta 0.5 pt, psi 1.2 %. The previous 262 negatives could not have confirmed it: at psi 1.15 % the expected 3 discordant rows give a two-sided exact p of 0.25.
- H2 (union recall non-inferior within 1 pt) is the demanding hypothesis. If the true change is 0, 8,948 positives are needed; at the observed -0.4 pt, 24,852. The design therefore takes 10,000 positives (84 % power at true delta 0, 80 % at -0.05 pt, 66 % at -0.2 pt; the pool permitting), and the pre-registration states that a true loss of 0.2 pt or more makes a pass unlikely and an inconclusive result is not a pass.
- H3 (NER alternatives): differences between models have large discordance (about 20 %). With 10,000 positives a 2 pt recall difference at psi 20 % is well powered (about 4,000 to 4,400 needed for psi 20 % to 22 %), whereas 1 pt needs about 15,900 positives (60 % power at 10,000). H3 is therefore powered for effects of 2 pt or more; smaller differences are reported descriptively.
- Specificity side of H2/H3: union specificity non-inferiority (margin 1 pt) at delta 0 and psi 5 % needs 3,925 negatives (95 % power at 6,600); 6,600 negatives provide headroom for the Holm correction and for a 10 to 15 % design effect from multiple sentences per document.
- Natural benign prompts: 6,000 prompts support detecting a 0.5 pt regex specificity change when psi is at most about 1.8 %, and give a Wilson 95 % interval of about +/-0.25 pt on a 1 % false-positive rate. Human adjudication cost (section 4.1) is the practical limit, not detector time.
- Cost: detectors run at about 46 ms per prompt (regex + spaCy small), so 16,600 PIIMB rows plus 6,000 natural prompts cost about 17 minutes per configuration; larger NER models cost more and are agent D's budget.

## 6. Fresh set summary

| Set | Rows | Seed | Source | Label basis | Used for |
|---|---|---|---|---|---|
| F1 PIIMB fresh | 10,000 positives + 6,600 clean | 8102026 | PIIMB `test_sentences.jsonl`, group-disjoint from locked and from all training/validation uses | PIIMB spans | H1, H2, H3, H4 (presence and span level) |
| F2 natural benign | 6,000 | 9102026 | oasst2 2,000, WildChat 2,500, Dolly 1,500 | Pooled adjudication (4.1) | H1b (real-prompt false positives), H2 and H3 specificity side |
| F3 SPY | up to 2,000 (1,000 legal, 1,000 medical) | 10102026 | SPY after Faker fill | SPY BIO tags converted to spans | H4 secondary, prompt-style positives |
| F4 TAB (optional) | 300 documents (test) | 11102026 | `echr_test.json` | TAB mentions | H4 real-text span cross-check |

All F-sets are scored exactly once per frozen configuration (single-scoring rule in the pre-registration), and nothing is tuned on them.

## 7. Limitations

- PIIMB "clean" sentences are not natural prompts and may hide unannotated PII; F2 exists for that reason.
- The one-per-document cap may not be satisfiable; the cap relaxation rule and the grouped bootstrap handle that.
- Licence details for ai4privacy-300k come from the 400k licence text found by search; the 300k `license.md` returned 404 on direct fetch.
- SPY entity strings depend on a Faker seed; the builder must record the seed and Faker version.
- Source mix is Nemotron-heavy (about 60 % of the locked set); conclusions about "PIIMB" are conclusions about this mixture.
- The training/validation group scan (section 2.3) is not part of this commit's evidence unless reported in the return message.

## 8. Sources read (2026-10-24)

- https://huggingface.co/datasets/piimb/pii-masking-benchmark (card, file tree at the pinned revision, API metadata)
- https://huggingface.co/datasets/mks-logic/SPY, https://github.com/LogicZMaksimka/SPY_Dataset, https://aclanthology.org/2025.naacl-srw.23
- https://github.com/NorskRegnesentral/text-anonymization-benchmark (README, contents listing)
- https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual, https://huggingface.co/datasets/gretelai/gretel-pii-masking-en-v1
- https://huggingface.co/datasets/nvidia/Nemotron-PII
- https://huggingface.co/datasets/ai4privacy/pii-masking-openpii-1m, https://huggingface.co/datasets/ai4privacy/pii-masking-300k, https://huggingface.co/datasets/ai4privacy/pii-masking-400k (licence text via search)
- https://n2c2.dbmi.hms.harvard.edu/data-use-agreement and /data-sets
- https://huggingface.co/datasets/OpenAssistant/oasst2, https://huggingface.co/datasets/databricks/databricks-dolly-15k
- https://huggingface.co/datasets/allenai/WildChat-1M (card, LICENSE.md, file listing), https://huggingface.co/datasets/lmsys/lmsys-chat-1m
