# NER pattern detector vs spaCy NER (detector ablation)

Date: 2026-10-24. Task NERX-B, branch `experiment/ner-regex-recurrence`.

**Scope label.** This is an explicitly requested **NER-layer detector ablation**. It runs in process, calls the detector classes directly, and uses no gRPC, Docker, LLM or semantic layer. None of these numbers is LLM-layer evidence, and none is a full-pipeline measurement.

## Question

Can a no-ML, regex-style detector (field/cue patterns, value-shape patterns, in-text recurrence) replace or complement the spaCy `en_core_web_sm` NER layer for PERSON and location entities, **under the text the runtime actually gives that layer**?

The runtime lowercases text before the NER and regex layers: `extension/client-runtime/src/pipeline.py:173` calls `normalize_with_offsets`, which lowercases at `detection/preprocessing.py:60-61`. So the deployed NER sees lowercased text. Every system is therefore run under two conditions:

- **deployed**: `normalize_with_offsets(text).text` (lowercased, whitespace-collapsed). The deployed spaCy row is the primary baseline.
- **original**: the case-preserved prompt, to show what the capitalisation-dependent mechanisms would add if the layer saw original case.

Spans are in the coordinates of the text each detector was given; the evaluation is prompt-level, so spans are not compared.

## Systems

| System | Definition |
|---|---|
| spaCy | `EntityNERDetector` (`en_core_web_sm` 3.7.1) with the production label mapping |
| prototype: cues only | `PatternEntityDetector(use_shape=False, use_recurrence=False)` |
| prototype: cues + shape | `PatternEntityDetector(use_recurrence=False)` |
| prototype: cues + shape + recurrence | `PatternEntityDetector()` (the headline "prototype") |
| prototype + gazetteer | prototype with `use_gazetteer=True` (extra, see below) |
| union | spaCy entities plus prototype entities (family fires if either fires) |
| hybrid | `PatternEntityDetector(use_shape=False).augment_entities(text, spacy_results)`: spaCy entities are seeds, cue candidates are added, cue wins on overlap (it can relabel a spaCy span), and recurrence is applied over the union |

`extension/client-runtime/src/NER/pattern_entity_detector.py` keeps the `extract_entities(text) -> list[ClassificationResult]` contract and reuses `NER_LABEL_USE_CASES` (PERSON, GPE, LOC, FAC, ORG), so classifications and confidences equal the spaCy ones. Each result carries `metadata["mechanism"]` (`cue`, `shape`, `gazetteer`, `recurrence`) and `metadata["cue"]`.

- **Cues**: label fields (`Name:`, `Full name -`, `Employer:`), self-introductions (`my name is`, `call me`, `I am X`), salutations and sign-offs, honorifics, relation cues (`my manager X`, `my son named X`), residence verbs (`live in`, `based in`, `from`), organisation cues (`work at`, `employer is`, `student at`), and name-next-to-identifier cues (`X's employee id`, `X, policy ...`, `for X. The account ...`). Most cues accept lowercase values, so they survive the runtime's lowercasing.
- **Shape**: street addresses (`<number> <words> Street`), `City, ST ZIP`, `Elm Street`, `<Name> Inc/University/Hospital`, mid-sentence Title-case pairs, and sentence-initial pairs that head a form record (`Name, <digits or @>`). Street and ZIP shapes are digit-based, so they survive lowercasing; Title-case name shapes do not.
- **Recurrence**: after cues and shapes, every further occurrence of a found value (and of the first and last name of a found PERSON) is added; capitalised 2-3 word sequences that occur at least twice are promoted to PERSON.
- **Gazetteer (off by default, reported as a separate row)**: US states and DC (51), 57 countries, 49 large world cities (lowercase city names count only after `in/to/from/near`), 187 common US given names and 115 common US surnames (a given name plus a surname-list word, or two capitalised words). The lists were written from general knowledge, not extracted from the datasets, but the template generator draws names from a small pool (about 16 first names and 16 surnames); about half of those first names and nearly all of the surnames are on these lists. The gazetteer rows are therefore **not independent of the template data** and should be read as an upper bound for in-distribution data.

## Data and gold

| File | Rows | Generator | Labels |
|---|---:|---|---|
| `evaluation/datasets/privoke_personalized_synthetic.jsonl` | 2000 (1000 positive) | template generated | `expected_categories` (prompt level) |
| `evaluation/datasets/privoke_openai_synthetic.jsonl` | 1000 (500 positive) | LLM generated | coarse `expected_categories` plus `fine_pii_categories` |

There are no gold spans. Gold is prompt level:

- **PERSON family**: `FULL_NAME` in `expected_categories` (personalized) or in `fine_pii_categories` (openai).
- **Location family**: `ADDRESS` (personalized); `ADDRESS` or `PLACE_OF_BIRTH` in `fine_pii_categories` (openai). `PRECISE_LOCATION` (coordinates) and `LICENSE_PLATE` are excluded as not NER entities.
- **`IDENTITY` is not person identity.** It never occurs in the personalized file. In the openai file it is a coarse bucket of 371 prompts that contains phone, employee, passport, student, API-key, IP, MAC, VIN, ITIN, SSN and similar identifiers and only 24 `FULL_NAME` prompts, so it cannot serve as person gold; the fine labels are used instead.
- **ORG has no gold**; only ORG firing rates are reported.
- A system "fires" a family when any returned entity has that family's `entity_type` (`name`, `location`, `organization`). The **any** family is "any NER-mapped entity" against `expected_has_pii`; it is the quantity of the earlier casing diagnostic (`evaluation/results/ner-casing-development.json`: lowercase NER recall 20.8% / specificity 97.5% on another dataset), so only the order of magnitude is comparable.
- Specificity is computed on `expected_has_pii=false` prompts as 1 minus the share on which the family fires. Precision uses all prompts without the family's gold as negatives, so a correctly detected name in a prompt whose labels omit `FULL_NAME` counts as a false positive (see the audit below).

## Anti-leakage protocol

- The personalized file is split 50/50 with a seeded shuffle (`random.Random(20261024)` over id-sorted rows). Patterns were developed only on the dev half, using `compare_ner_pattern_detector.py --dev-only` (six dev runs; the dev half reaches 100% recall at 100% precision for the original-case location and person families, so it is saturated and has little further signal).
- **Frozen at commit `d42e1ef5`** (detector, tests, evaluation script) before the first held-out or OOD run. The detector was not changed afterwards; defects found in the post-freeze error analysis are listed under Limitations, not fixed.
- Before designing the patterns I read about 20-25 random rows of the openai file for schema inspection (FULL_NAME/IDENTITY/ADDRESS/LOCATION samples). That is a mild exposure; the cue families come from the task brief and general English, but I cannot rule out that the sample influenced them. The OOD file was not otherwise used for tuning.
- Some cues were added after reading dev errors (the `X's <identifier>`, `X, <identifier>` and `for X. The account` adjacency cues, the `Student X` role prefix, record-style sentence-initial names, and ambiguous state abbreviations such as `, ID`). Template prompts share exactly these structures, so held-out personalized numbers for the cue and shape rows are optimistic; the OOD file is the generalisation check.

## Metrics

Prompt-level TP/FP/FN, precision, recall and specificity with Wilson 95% intervals; F1 with a 1000-round percentile bootstrap over prompts (seed 7); latency is the mean and p95 of in-process `extract_entities` wall time per prompt (single thread, Windows host CPU, `time.perf_counter`; the union and hybrid rows include the spaCy pass). Multiple comparisons: no significance tests are claimed; read intervals, not p-values.

## Summary of findings

Numbers below are copied from the generated tables; held-out is the 1000 withheld personalized rows, OOD is the whole openai file.

1. **Deployed spaCy is the weak baseline the brief expects.** Held-out PERSON recall 72.0% at 91.4% precision; location recall 74.1% at 78.9% precision. OOD any-entity recall is 29.0% at 98.4% specificity (original case: 48.2% recall, 86.8% specificity), the same order as the earlier diagnostic.
2. **The prototype alone is not a drop-in replacement under lowercasing.** Held-out PERSON recall 58.8% at 100% precision (spaCy 72.0% / 91.4%); OOD PERSON recall 58.3% at 48.3% precision (spaCy 75.0% / 21.4%, both deflated by incomplete name labels, see audit). Held-out location is 116/116 with no false positives and OOD location recall 63.6% at 73.7% precision (spaCy 88.6% / 68.4%). Its cost is about 0.2-0.4 ms per prompt against 3.8-5.8 ms for spaCy (roughly 15x faster).
3. **Union and hybrid recover the recall at spaCy-level precision.** Held-out deployed PERSON recall rises from 72.0% (spaCy) to 86.8% with unchanged false positives (26); OOD PERSON recall 75.0% to 83.3%. The hybrid is not better than the union on these prompt-level metrics except that cue priority relabels some spaCy mislabels (held-out deployed location false positives 23 for spaCy and union, 11 for the hybrid).
4. **Mechanisms under lowercasing.** Cue and digit-based shape patterns (street, ZIP) survive. Title-case person shapes contribute nothing in the deployed condition (cues+shape equals cues for PERSON), but in original case they raise OOD PERSON recall from 75.0% to 100% while adding 13 false positives (25 to 38). Recurrence never changed a prompt-level outcome in any table (identical TP/FP with and without it): the prompts mention each entity once or the first mention was already found. Its benefit, covering every mention for masking, needs span-level gold and is **not measured here**.
5. **The gazetteer is the largest lowercase gain and the least trustworthy.** Held-out deployed PERSON recall 58.8% to 74.1% and OOD 58.3% to 79.2% (location 63.6% to 90.9%), with 6 more OOD PERSON false positives, but see the name-pool overlap above.
6. **ORG.** The prototype's ORG rules fire on 1.7% of OOD prompts (never on clean ones) and on 0% of personalized prompts; deployed spaCy fires on 2.6% of OOD prompts (0% of clean), original-case spaCy on 20.2% (12.6% of clean prompts). No ORG gold exists, so no accuracy is claimed.
7. **Hybrid architecture candidate.** The evidence supports "spaCy seeds plus cues plus recurrence" or "union" over "prototype only" if spaCy stays in the loop. It does not show that dropping spaCy is safe, because the prototype's deployed recall is below spaCy's on the LLM-generated OOD set for locations (63.6% vs 88.6%) and its precision is limited by name-like identifiers.

<!-- BEGIN GENERATED -->
## Generated results

Generated by `evaluation/compare_ner_pattern_detector.py` at git revision `d42e1ef53db9d15f8fdec8219733a675c2bd2295` (dirty working tree: False). Raw numbers: `docs/experiments/ner-pattern-detector-20261024.json`.

Environment: Python 3.11.9, spaCy 3.7.5, numpy 1.26.4, en_core_web_sm 3.7.1, Windows-10-10.0.26200-SP0

### Data

| Dataset | File SHA-256 | Rows | `expected_has_pii=true` |
|---|---|---:|---:|
| personalized_synthetic | `fd045ac1bd77fa27...` | 2000 | 1000 |
| openai_synthetic | `8e8e611b9d40f7d5...` | 1000 | 500 |

Personalized split: ids sorted, shuffled with `random.Random(20261024)`, first 1000 rows = dev (tuning only), remaining 1000 = held-out. Dev sha256 of ids: `30c0c2789cff8c47...`.

### Held-out personalized_synthetic (template generated; in-distribution to the dev half)

1000 held-out rows (495 `expected_has_pii=true`); 386 PERSON-gold and 116 location-gold positives.

**PERSON family (gold: `FULL_NAME` in `expected_categories`) - Deployed condition: lowercased `normalize_with_offsets(text).text`**

| System | TP | FP | FN | Precision [95% CI] | Recall [95% CI] | F1 [95% boot CI] | Specificity on clean [95% CI] | mean / p95 ms |
|---|---:|---:|---:|---|---|---|---|---|
| spaCy en_core_web_sm NER | 278 | 26 | 108 | 91.4% [88-94] | 72.0% [67-76] | 80.6% [77-84] | 100.0% [99-100] | 3.57 / 4.31 |
| prototype: cues only | 227 | 0 | 159 | 100.0% [98-100] | 58.8% [54-64] | 74.1% [70-78] | 100.0% [99-100] | 0.14 / 0.17 |
| prototype: cues + shape | 227 | 0 | 159 | 100.0% [98-100] | 58.8% [54-64] | 74.1% [70-78] | 100.0% [99-100] | 0.17 / 0.21 |
| prototype: cues + shape + recurrence | 227 | 0 | 159 | 100.0% [98-100] | 58.8% [54-64] | 74.1% [70-78] | 100.0% [99-100] | 0.22 / 0.39 |
| prototype + gazetteer (extra) | 286 | 0 | 100 | 100.0% [99-100] | 74.1% [70-78] | 85.1% [82-88] | 100.0% [99-100] | 0.62 / 0.72 |
| union: spaCy U prototype | 335 | 26 | 51 | 92.8% [90-95] | 86.8% [83-90] | 89.7% [87-92] | 100.0% [99-100] | 3.78 / 4.56 |
| hybrid: spaCy seeds + cues + recurrence | 335 | 26 | 51 | 92.8% [90-95] | 86.8% [83-90] | 89.7% [87-92] | 100.0% [99-100] | 3.73 / 4.50 |

**PERSON family (gold: `FULL_NAME` in `expected_categories`) - Case-preserved original text**

| System | TP | FP | FN | Precision [95% CI] | Recall [95% CI] | F1 [95% boot CI] | Specificity on clean [95% CI] | mean / p95 ms |
|---|---:|---:|---:|---|---|---|---|---|
| spaCy en_core_web_sm NER | 342 | 20 | 44 | 94.5% [92-96] | 88.6% [85-91] | 91.4% [89-93] | 96.2% [94-98] | 3.51 / 4.18 |
| prototype: cues only | 386 | 0 | 0 | 100.0% [99-100] | 100.0% [99-100] | 100.0% [100-100] | 100.0% [99-100] | 0.14 / 0.18 |
| prototype: cues + shape | 386 | 0 | 0 | 100.0% [99-100] | 100.0% [99-100] | 100.0% [100-100] | 100.0% [99-100] | 0.18 / 0.23 |
| prototype: cues + shape + recurrence | 386 | 0 | 0 | 100.0% [99-100] | 100.0% [99-100] | 100.0% [100-100] | 100.0% [99-100] | 0.20 / 0.30 |
| prototype + gazetteer (extra) | 386 | 0 | 0 | 100.0% [99-100] | 100.0% [99-100] | 100.0% [100-100] | 100.0% [99-100] | 0.62 / 0.73 |
| union: spaCy U prototype | 386 | 20 | 0 | 95.1% [93-97] | 100.0% [99-100] | 97.5% [96-98] | 96.2% [94-98] | 3.71 / 4.43 |
| hybrid: spaCy seeds + cues + recurrence | 386 | 20 | 0 | 95.1% [93-97] | 100.0% [99-100] | 97.5% [96-98] | 96.2% [94-98] | 3.67 / 4.40 |

**Location family (gold: `ADDRESS` in `expected_categories`) - Deployed condition: lowercased `normalize_with_offsets(text).text`**

| System | TP | FP | FN | Precision [95% CI] | Recall [95% CI] | F1 [95% boot CI] | Specificity on clean [95% CI] | mean / p95 ms |
|---|---:|---:|---:|---|---|---|---|---|
| spaCy en_core_web_sm NER | 86 | 23 | 30 | 78.9% [70-86] | 74.1% [65-81] | 76.4% [70-82] | 100.0% [99-100] | 3.57 / 4.31 |
| prototype: cues only | 0 | 0 | 116 | n/a | 0.0% [0-3] | 0.0% [0-0] | 100.0% [99-100] | 0.14 / 0.17 |
| prototype: cues + shape | 116 | 0 | 0 | 100.0% [97-100] | 100.0% [97-100] | 100.0% [100-100] | 100.0% [99-100] | 0.17 / 0.21 |
| prototype: cues + shape + recurrence | 116 | 0 | 0 | 100.0% [97-100] | 100.0% [97-100] | 100.0% [100-100] | 100.0% [99-100] | 0.22 / 0.39 |
| prototype + gazetteer (extra) | 116 | 0 | 0 | 100.0% [97-100] | 100.0% [97-100] | 100.0% [100-100] | 100.0% [99-100] | 0.62 / 0.72 |
| union: spaCy U prototype | 116 | 23 | 0 | 83.5% [76-89] | 100.0% [97-100] | 91.0% [87-94] | 100.0% [99-100] | 3.78 / 4.56 |
| hybrid: spaCy seeds + cues + recurrence | 86 | 11 | 30 | 88.7% [81-94] | 74.1% [65-81] | 80.8% [75-86] | 100.0% [99-100] | 3.73 / 4.50 |

**Location family (gold: `ADDRESS` in `expected_categories`) - Case-preserved original text**

| System | TP | FP | FN | Precision [95% CI] | Recall [95% CI] | F1 [95% boot CI] | Specificity on clean [95% CI] | mean / p95 ms |
|---|---:|---:|---:|---|---|---|---|---|
| spaCy en_core_web_sm NER | 112 | 42 | 4 | 72.7% [65-79] | 96.6% [91-99] | 83.0% [78-87] | 97.2% [95-98] | 3.51 / 4.18 |
| prototype: cues only | 0 | 0 | 116 | n/a | 0.0% [0-3] | 0.0% [0-0] | 100.0% [99-100] | 0.14 / 0.18 |
| prototype: cues + shape | 116 | 0 | 0 | 100.0% [97-100] | 100.0% [97-100] | 100.0% [100-100] | 100.0% [99-100] | 0.18 / 0.23 |
| prototype: cues + shape + recurrence | 116 | 0 | 0 | 100.0% [97-100] | 100.0% [97-100] | 100.0% [100-100] | 100.0% [99-100] | 0.20 / 0.30 |
| prototype + gazetteer (extra) | 116 | 0 | 0 | 100.0% [97-100] | 100.0% [97-100] | 100.0% [100-100] | 100.0% [99-100] | 0.62 / 0.73 |
| union: spaCy U prototype | 116 | 42 | 0 | 73.4% [66-80] | 100.0% [97-100] | 84.7% [80-89] | 97.2% [95-98] | 3.71 / 4.43 |
| hybrid: spaCy seeds + cues + recurrence | 112 | 41 | 4 | 73.2% [66-80] | 96.6% [91-99] | 83.3% [78-88] | 97.2% [95-98] | 3.67 / 4.40 |

**Any NER-mapped entity vs `expected_has_pii` (comparable to the earlier any-hit diagnostic) - Deployed condition: lowercased `normalize_with_offsets(text).text`**

| System | TP | FP | FN | Precision [95% CI] | Recall [95% CI] | F1 [95% boot CI] | Specificity on clean [95% CI] | mean / p95 ms |
|---|---:|---:|---:|---|---|---|---|---|
| spaCy en_core_web_sm NER | 397 | 0 | 98 | 100.0% [99-100] | 80.2% [76-83] | 89.0% [87-91] | 100.0% [99-100] | 3.57 / 4.31 |
| prototype: cues only | 227 | 0 | 268 | 100.0% [98-100] | 45.9% [42-50] | 62.9% [59-67] | 100.0% [99-100] | 0.14 / 0.17 |
| prototype: cues + shape | 308 | 0 | 187 | 100.0% [99-100] | 62.2% [58-66] | 76.7% [74-80] | 100.0% [99-100] | 0.17 / 0.21 |
| prototype: cues + shape + recurrence | 308 | 0 | 187 | 100.0% [99-100] | 62.2% [58-66] | 76.7% [74-80] | 100.0% [99-100] | 0.22 / 0.39 |
| prototype + gazetteer (extra) | 342 | 0 | 153 | 100.0% [99-100] | 69.1% [65-73] | 81.7% [79-84] | 100.0% [99-100] | 0.62 / 0.72 |
| union: spaCy U prototype | 418 | 0 | 77 | 100.0% [99-100] | 84.4% [81-87] | 91.6% [90-93] | 100.0% [99-100] | 3.78 / 4.56 |
| hybrid: spaCy seeds + cues + recurrence | 418 | 0 | 77 | 100.0% [99-100] | 84.4% [81-87] | 91.6% [90-93] | 100.0% [99-100] | 3.73 / 4.50 |

**Any NER-mapped entity vs `expected_has_pii` (comparable to the earlier any-hit diagnostic) - Case-preserved original text**

| System | TP | FP | FN | Precision [95% CI] | Recall [95% CI] | F1 [95% boot CI] | Specificity on clean [95% CI] | mean / p95 ms |
|---|---:|---:|---:|---|---|---|---|---|
| spaCy en_core_web_sm NER | 436 | 51 | 59 | 89.5% [86-92] | 88.1% [85-91] | 88.8% [87-91] | 89.9% [87-92] | 3.51 / 4.18 |
| prototype: cues only | 386 | 0 | 109 | 100.0% [99-100] | 78.0% [74-81] | 87.6% [85-90] | 100.0% [99-100] | 0.14 / 0.18 |
| prototype: cues + shape | 386 | 0 | 109 | 100.0% [99-100] | 78.0% [74-81] | 87.6% [85-90] | 100.0% [99-100] | 0.18 / 0.23 |
| prototype: cues + shape + recurrence | 386 | 0 | 109 | 100.0% [99-100] | 78.0% [74-81] | 87.6% [85-90] | 100.0% [99-100] | 0.20 / 0.30 |
| prototype + gazetteer (extra) | 386 | 0 | 109 | 100.0% [99-100] | 78.0% [74-81] | 87.6% [85-90] | 100.0% [99-100] | 0.62 / 0.73 |
| union: spaCy U prototype | 438 | 51 | 57 | 89.6% [87-92] | 88.5% [85-91] | 89.0% [87-91] | 89.9% [87-92] | 3.71 / 4.43 |
| hybrid: spaCy seeds + cues + recurrence | 438 | 51 | 57 | 89.6% [87-92] | 88.5% [85-91] | 89.0% [87-91] | 89.9% [87-92] | 3.67 / 4.40 |

**ORG firing rates (no gold; share of prompts with at least one ORG entity)**

| System | Condition | All prompts | `expected_has_pii=true` | `expected_has_pii=false` |
|---|---|---|---|---|
| spaCy en_core_web_sm NER | deployed | 10.4% [9-12] | 21.0% [18-25] | 0.0% [0-1] |
| spaCy en_core_web_sm NER | original | 27.9% [25-31] | 52.7% [48-57] | 3.6% [2-6] |
| prototype: cues only | deployed | 0.0% [0-0] | 0.0% [0-1] | 0.0% [0-1] |
| prototype: cues only | original | 0.0% [0-0] | 0.0% [0-1] | 0.0% [0-1] |
| prototype: cues + shape | deployed | 0.0% [0-0] | 0.0% [0-1] | 0.0% [0-1] |
| prototype: cues + shape | original | 0.0% [0-0] | 0.0% [0-1] | 0.0% [0-1] |
| prototype: cues + shape + recurrence | deployed | 0.0% [0-0] | 0.0% [0-1] | 0.0% [0-1] |
| prototype: cues + shape + recurrence | original | 0.0% [0-0] | 0.0% [0-1] | 0.0% [0-1] |
| prototype + gazetteer (extra) | deployed | 0.0% [0-0] | 0.0% [0-1] | 0.0% [0-1] |
| prototype + gazetteer (extra) | original | 0.0% [0-0] | 0.0% [0-1] | 0.0% [0-1] |
| union: spaCy U prototype | deployed | 10.4% [9-12] | 21.0% [18-25] | 0.0% [0-1] |
| union: spaCy U prototype | original | 27.9% [25-31] | 52.7% [48-57] | 3.6% [2-6] |
| hybrid: spaCy seeds + cues + recurrence | deployed | 9.1% [7-11] | 18.4% [15-22] | 0.0% [0-1] |
| hybrid: spaCy seeds + cues + recurrence | original | 25.3% [23-28] | 47.5% [43-52] | 3.6% [2-6] |

**Mechanisms (prompt counts; prototype rows only; 'gold+' = prompts that are gold-positive for that family)**

| System | Condition | Family | Mechanism | Prompts | Gold+ |
|---|---|---|---|---:|---:|
| prototype: cues + shape + recurrence | deployed | person | cue | 227 | 227 |
| prototype: cues + shape + recurrence | deployed | person | recurrence | 74 | 74 |
| prototype: cues + shape + recurrence | deployed | location | shape | 116 | 116 |
| prototype: cues + shape + recurrence | original | person | cue | 386 | 386 |
| prototype: cues + shape + recurrence | original | person | recurrence | 112 | 112 |
| prototype: cues + shape + recurrence | original | location | shape | 116 | 116 |
| hybrid: spaCy seeds + cues + recurrence | deployed | person | cue | 227 | 227 |
| hybrid: spaCy seeds + cues + recurrence | deployed | person | recurrence | 79 | 79 |
| hybrid: spaCy seeds + cues + recurrence | deployed | person | spacy | 144 | 118 |
| hybrid: spaCy seeds + cues + recurrence | deployed | location | recurrence | 1 | - |
| hybrid: spaCy seeds + cues + recurrence | deployed | location | spacy | 97 | 86 |
| hybrid: spaCy seeds + cues + recurrence | deployed | org | spacy | 91 | - |
| hybrid: spaCy seeds + cues + recurrence | original | person | cue | 386 | 386 |
| hybrid: spaCy seeds + cues + recurrence | original | person | recurrence | 103 | 103 |
| hybrid: spaCy seeds + cues + recurrence | original | person | spacy | 50 | 30 |
| hybrid: spaCy seeds + cues + recurrence | original | location | spacy | 153 | 112 |
| hybrid: spaCy seeds + cues + recurrence | original | org | spacy | 253 | - |

### OOD: whole openai_synthetic (LLM generated; never used for development)

1000 OOD rows (500 `expected_has_pii=true`); 24 PERSON-gold and 44 location-gold positives.

**PERSON family (gold: `FULL_NAME` in `fine_pii_categories`) - Deployed condition: lowercased `normalize_with_offsets(text).text`**

| System | TP | FP | FN | Precision [95% CI] | Recall [95% CI] | F1 [95% boot CI] | Specificity on clean [95% CI] | mean / p95 ms |
|---|---:|---:|---:|---|---|---|---|---|
| spaCy en_core_web_sm NER | 18 | 66 | 6 | 21.4% [14-31] | 75.0% [55-88] | 33.3% [21-45] | 98.6% [97-99] | 5.71 / 9.34 |
| prototype: cues only | 14 | 15 | 10 | 48.3% [31-66] | 58.3% [39-76] | 52.8% [35-67] | 100.0% [99-100] | 0.29 / 0.58 |
| prototype: cues + shape | 14 | 15 | 10 | 48.3% [31-66] | 58.3% [39-76] | 52.8% [35-67] | 100.0% [99-100] | 0.37 / 0.74 |
| prototype: cues + shape + recurrence | 14 | 15 | 10 | 48.3% [31-66] | 58.3% [39-76] | 52.8% [35-67] | 100.0% [99-100] | 0.40 / 0.79 |
| prototype + gazetteer (extra) | 19 | 21 | 5 | 47.5% [33-63] | 79.2% [60-91] | 59.4% [43-72] | 100.0% [99-100] | 1.21 / 2.33 |
| union: spaCy U prototype | 20 | 70 | 4 | 22.2% [15-32] | 83.3% [64-93] | 35.1% [23-47] | 98.6% [97-99] | 6.11 / 10.16 |
| hybrid: spaCy seeds + cues + recurrence | 20 | 70 | 4 | 22.2% [15-32] | 83.3% [64-93] | 35.1% [23-47] | 98.6% [97-99] | 6.02 / 10.04 |

**PERSON family (gold: `FULL_NAME` in `fine_pii_categories`) - Case-preserved original text**

| System | TP | FP | FN | Precision [95% CI] | Recall [95% CI] | F1 [95% boot CI] | Specificity on clean [95% CI] | mean / p95 ms |
|---|---:|---:|---:|---|---|---|---|---|
| spaCy en_core_web_sm NER | 23 | 78 | 1 | 22.8% [16-32] | 95.8% [80-99] | 36.8% [26-48] | 99.4% [98-100] | 5.59 / 9.45 |
| prototype: cues only | 18 | 25 | 6 | 41.9% [28-57] | 75.0% [55-88] | 53.7% [37-68] | 99.6% [99-100] | 0.30 / 0.59 |
| prototype: cues + shape | 24 | 38 | 0 | 38.7% [28-51] | 100.0% [86-100] | 55.8% [42-68] | 99.6% [99-100] | 0.37 / 0.75 |
| prototype: cues + shape + recurrence | 24 | 38 | 0 | 38.7% [28-51] | 100.0% [86-100] | 55.8% [42-68] | 99.6% [99-100] | 0.40 / 0.81 |
| prototype + gazetteer (extra) | 24 | 38 | 0 | 38.7% [28-51] | 100.0% [86-100] | 55.8% [42-68] | 99.6% [99-100] | 1.21 / 2.33 |
| union: spaCy U prototype | 24 | 88 | 0 | 21.4% [15-30] | 100.0% [86-100] | 35.3% [25-45] | 99.0% [98-100] | 5.99 / 10.29 |
| hybrid: spaCy seeds + cues + recurrence | 23 | 86 | 1 | 21.1% [14-30] | 95.8% [80-99] | 34.6% [24-45] | 99.0% [98-100] | 5.91 / 10.08 |

**Location family (gold: `ADDRESS` or `PLACE_OF_BIRTH` in `fine_pii_categories`) - Deployed condition: lowercased `normalize_with_offsets(text).text`**

| System | TP | FP | FN | Precision [95% CI] | Recall [95% CI] | F1 [95% boot CI] | Specificity on clean [95% CI] | mean / p95 ms |
|---|---:|---:|---:|---|---|---|---|---|
| spaCy en_core_web_sm NER | 39 | 18 | 5 | 68.4% [56-79] | 88.6% [76-95] | 77.2% [68-85] | 99.8% [99-100] | 5.71 / 9.34 |
| prototype: cues only | 10 | 10 | 34 | 50.0% [30-70] | 22.7% [13-37] | 31.2% [16-45] | 100.0% [99-100] | 0.29 / 0.58 |
| prototype: cues + shape | 28 | 10 | 16 | 73.7% [58-85] | 63.6% [49-76] | 68.3% [56-79] | 100.0% [99-100] | 0.37 / 0.74 |
| prototype: cues + shape + recurrence | 28 | 10 | 16 | 73.7% [58-85] | 63.6% [49-76] | 68.3% [56-79] | 100.0% [99-100] | 0.40 / 0.79 |
| prototype + gazetteer (extra) | 40 | 12 | 4 | 76.9% [64-86] | 90.9% [79-96] | 83.3% [74-91] | 100.0% [99-100] | 1.21 / 2.33 |
| union: spaCy U prototype | 43 | 27 | 1 | 61.4% [50-72] | 97.7% [88-100] | 75.4% [66-84] | 99.8% [99-100] | 6.11 / 10.16 |
| hybrid: spaCy seeds + cues + recurrence | 40 | 26 | 4 | 60.6% [49-71] | 90.9% [79-96] | 72.7% [63-82] | 99.8% [99-100] | 6.02 / 10.04 |

**Location family (gold: `ADDRESS` or `PLACE_OF_BIRTH` in `fine_pii_categories`) - Case-preserved original text**

| System | TP | FP | FN | Precision [95% CI] | Recall [95% CI] | F1 [95% boot CI] | Specificity on clean [95% CI] | mean / p95 ms |
|---|---:|---:|---:|---|---|---|---|---|
| spaCy en_core_web_sm NER | 44 | 28 | 0 | 61.1% [50-72] | 100.0% [92-100] | 75.9% [67-84] | 99.8% [99-100] | 5.59 / 9.45 |
| prototype: cues only | 10 | 10 | 34 | 50.0% [30-70] | 22.7% [13-37] | 31.2% [16-45] | 100.0% [99-100] | 0.30 / 0.59 |
| prototype: cues + shape | 44 | 10 | 0 | 81.5% [69-90] | 100.0% [92-100] | 89.8% [82-96] | 100.0% [99-100] | 0.37 / 0.75 |
| prototype: cues + shape + recurrence | 44 | 10 | 0 | 81.5% [69-90] | 100.0% [92-100] | 89.8% [82-96] | 100.0% [99-100] | 0.40 / 0.81 |
| prototype + gazetteer (extra) | 44 | 11 | 0 | 80.0% [68-88] | 100.0% [92-100] | 88.9% [81-95] | 100.0% [99-100] | 1.21 / 2.33 |
| union: spaCy U prototype | 44 | 36 | 0 | 55.0% [44-65] | 100.0% [92-100] | 71.0% [61-79] | 99.8% [99-100] | 5.99 / 10.29 |
| hybrid: spaCy seeds + cues + recurrence | 44 | 36 | 0 | 55.0% [44-65] | 100.0% [92-100] | 71.0% [61-79] | 99.8% [99-100] | 5.91 / 10.08 |

**Any NER-mapped entity vs `expected_has_pii` (comparable to the earlier any-hit diagnostic) - Deployed condition: lowercased `normalize_with_offsets(text).text`**

| System | TP | FP | FN | Precision [95% CI] | Recall [95% CI] | F1 [95% boot CI] | Specificity on clean [95% CI] | mean / p95 ms |
|---|---:|---:|---:|---|---|---|---|---|
| spaCy en_core_web_sm NER | 145 | 8 | 355 | 94.8% [90-97] | 29.0% [25-33] | 44.4% [39-49] | 98.4% [97-99] | 5.71 / 9.34 |
| prototype: cues only | 63 | 0 | 437 | 100.0% [94-100] | 12.6% [10-16] | 22.4% [18-27] | 100.0% [99-100] | 0.29 / 0.58 |
| prototype: cues + shape | 83 | 0 | 417 | 100.0% [96-100] | 16.6% [14-20] | 28.5% [24-33] | 100.0% [99-100] | 0.37 / 0.74 |
| prototype: cues + shape + recurrence | 83 | 0 | 417 | 100.0% [96-100] | 16.6% [14-20] | 28.5% [24-33] | 100.0% [99-100] | 0.40 / 0.79 |
| prototype + gazetteer (extra) | 106 | 0 | 394 | 100.0% [97-100] | 21.2% [18-25] | 35.0% [30-40] | 100.0% [99-100] | 1.21 / 2.33 |
| union: spaCy U prototype | 164 | 8 | 336 | 95.3% [91-98] | 32.8% [29-37] | 48.8% [44-53] | 98.4% [97-99] | 6.11 / 10.16 |
| hybrid: spaCy seeds + cues + recurrence | 163 | 8 | 337 | 95.3% [91-98] | 32.6% [29-37] | 48.6% [44-53] | 98.4% [97-99] | 6.02 / 10.04 |

**Any NER-mapped entity vs `expected_has_pii` (comparable to the earlier any-hit diagnostic) - Case-preserved original text**

| System | TP | FP | FN | Precision [95% CI] | Recall [95% CI] | F1 [95% boot CI] | Specificity on clean [95% CI] | mean / p95 ms |
|---|---:|---:|---:|---|---|---|---|---|
| spaCy en_core_web_sm NER | 241 | 66 | 259 | 78.5% [74-83] | 48.2% [44-53] | 59.7% [56-64] | 86.8% [84-89] | 5.59 / 9.45 |
| prototype: cues only | 74 | 2 | 426 | 97.4% [91-99] | 14.8% [12-18] | 25.7% [21-31] | 99.6% [99-100] | 0.30 / 0.59 |
| prototype: cues + shape | 125 | 2 | 375 | 98.4% [94-100] | 25.0% [21-29] | 39.9% [35-45] | 99.6% [99-100] | 0.37 / 0.75 |
| prototype: cues + shape + recurrence | 125 | 2 | 375 | 98.4% [94-100] | 25.0% [21-29] | 39.9% [35-45] | 99.6% [99-100] | 0.40 / 0.81 |
| prototype + gazetteer (extra) | 126 | 2 | 374 | 98.4% [94-100] | 25.2% [22-29] | 40.1% [35-45] | 99.6% [99-100] | 1.21 / 2.33 |
| union: spaCy U prototype | 251 | 68 | 249 | 78.7% [74-83] | 50.2% [46-55] | 61.3% [58-65] | 86.4% [83-89] | 5.99 / 10.29 |
| hybrid: spaCy seeds + cues + recurrence | 251 | 68 | 249 | 78.7% [74-83] | 50.2% [46-55] | 61.3% [58-65] | 86.4% [83-89] | 5.91 / 10.08 |

**ORG firing rates (no gold; share of prompts with at least one ORG entity)**

| System | Condition | All prompts | `expected_has_pii=true` | `expected_has_pii=false` |
|---|---|---|---|---|
| spaCy en_core_web_sm NER | deployed | 2.6% [2-4] | 5.2% [4-8] | 0.0% [0-1] |
| spaCy en_core_web_sm NER | original | 20.2% [18-23] | 27.8% [24-32] | 12.6% [10-16] |
| prototype: cues only | deployed | 1.5% [1-2] | 3.0% [2-5] | 0.0% [0-1] |
| prototype: cues only | original | 1.5% [1-2] | 3.0% [2-5] | 0.0% [0-1] |
| prototype: cues + shape | deployed | 1.7% [1-3] | 3.4% [2-5] | 0.0% [0-1] |
| prototype: cues + shape | original | 1.7% [1-3] | 3.4% [2-5] | 0.0% [0-1] |
| prototype: cues + shape + recurrence | deployed | 1.7% [1-3] | 3.4% [2-5] | 0.0% [0-1] |
| prototype: cues + shape + recurrence | original | 1.7% [1-3] | 3.4% [2-5] | 0.0% [0-1] |
| prototype + gazetteer (extra) | deployed | 1.7% [1-3] | 3.4% [2-5] | 0.0% [0-1] |
| prototype + gazetteer (extra) | original | 1.7% [1-3] | 3.4% [2-5] | 0.0% [0-1] |
| union: spaCy U prototype | deployed | 3.1% [2-4] | 6.2% [4-9] | 0.0% [0-1] |
| union: spaCy U prototype | original | 20.6% [18-23] | 28.6% [25-33] | 12.6% [10-16] |
| hybrid: spaCy seeds + cues + recurrence | deployed | 2.9% [2-4] | 5.8% [4-8] | 0.0% [0-1] |
| hybrid: spaCy seeds + cues + recurrence | original | 19.9% [18-22] | 27.2% [23-31] | 12.6% [10-16] |

**Mechanisms (prompt counts; prototype rows only; 'gold+' = prompts that are gold-positive for that family)**

| System | Condition | Family | Mechanism | Prompts | Gold+ |
|---|---|---|---|---:|---:|
| prototype: cues + shape + recurrence | deployed | person | cue | 29 | 14 |
| prototype: cues + shape + recurrence | deployed | location | cue | 20 | 10 |
| prototype: cues + shape + recurrence | deployed | location | shape | 18 | 18 |
| prototype: cues + shape + recurrence | deployed | org | cue | 15 | - |
| prototype: cues + shape + recurrence | deployed | org | shape | 2 | - |
| prototype: cues + shape + recurrence | original | person | cue | 43 | 18 |
| prototype: cues + shape + recurrence | original | person | shape | 20 | 7 |
| prototype: cues + shape + recurrence | original | location | cue | 20 | 10 |
| prototype: cues + shape + recurrence | original | location | shape | 34 | 34 |
| prototype: cues + shape + recurrence | original | org | cue | 15 | - |
| prototype: cues + shape + recurrence | original | org | shape | 2 | - |
| hybrid: spaCy seeds + cues + recurrence | deployed | person | cue | 29 | 14 |
| hybrid: spaCy seeds + cues + recurrence | deployed | person | recurrence | 2 | - |
| hybrid: spaCy seeds + cues + recurrence | deployed | person | spacy | 64 | 8 |
| hybrid: spaCy seeds + cues + recurrence | deployed | location | cue | 20 | 10 |
| hybrid: spaCy seeds + cues + recurrence | deployed | location | spacy | 52 | 35 |
| hybrid: spaCy seeds + cues + recurrence | deployed | org | cue | 15 | - |
| hybrid: spaCy seeds + cues + recurrence | deployed | org | spacy | 17 | - |
| hybrid: spaCy seeds + cues + recurrence | original | person | cue | 43 | 18 |
| hybrid: spaCy seeds + cues + recurrence | original | person | recurrence | 1 | - |
| hybrid: spaCy seeds + cues + recurrence | original | person | spacy | 70 | 6 |
| hybrid: spaCy seeds + cues + recurrence | original | location | cue | 20 | 10 |
| hybrid: spaCy seeds + cues + recurrence | original | location | spacy | 62 | 35 |
| hybrid: spaCy seeds + cues + recurrence | original | org | cue | 15 | - |
| hybrid: spaCy seeds + cues + recurrence | original | org | recurrence | 1 | - |
| hybrid: spaCy seeds + cues + recurrence | original | org | spacy | 186 | - |

### Qualitative examples - held-out personalized

**spaCy en_core_web_sm NER (deployed)** - 49 FP and 138 FN prompt-family cases in total; seeded sample:

- FP [location] `privoke_synth_sensitive_000903` detected=['rivera'] via ['spacy']: Help me ask my doctor about my lab results. Patient Riley Rivera, DOB 1970-09-08, insurance ID INS-85773321, has recurring chest pain.
- FP [person] `privoke_synth_sensitive_000005` detected=['temppass3621'] via ['spacy']: Can you help me write an account recovery note? Email omar.morgan479@example.com, temporary password TempPass3621!, last login IP 192.0.2.203.
- FP [person] `privoke_synth_sensitive_000341` detected=['temppass2511'] via ['spacy']: Can you help me write an account recovery note? Email avery.williams813@example.com, temporary password TempPass2511!, last login IP 192.0.2.16.
- FP [person] `privoke_synth_sensitive_000128` detected=['temppass7590'] via ['spacy']: Can you help me write an account recovery note? Email sara.williams987@example.com, temporary password TempPass7590!, last login IP 192.0.2.22.
- FP [person] `privoke_synth_sensitive_000502` detected=['temppass8225'] via ['spacy']: Can you help me write an account recovery note? Email maya.miller90@example.com, temporary password TempPass8225!, last login IP 192.0.2.82.
- FN [person] `privoke_synth_sensitive_000229` detected=[] via []: Write a bank support message for Morgan Davis. The account number is 5376908082 and the callback number is 209-555-2091.
- FN [person] `privoke_synth_sensitive_000173` detected=[] via []: Draft a travel support email for Sara Garcia. Passport number X38147161, contact email sara.garcia996@example.com.
- FN [person] `privoke_synth_sensitive_000905` detected=[] via []: Help me ask my doctor about my lab results. Patient Sara Singh, DOB 1997-09-26, insurance ID INS-90542263, has recurring chest pain.
- FN [person] `privoke_synth_sensitive_000749` detected=[] via []: Help me draft a tax preparer email for Sara Khan. SSN 630-28-1253, mailing address 2049 Willow Way, Denver, CO 80202.
- FN [location] `privoke_synth_sensitive_000511` detected=[] via []: Summarize this insurance claim: Alex Morgan, policy INS-68293280, address 2342 Sunset Boulevard, Austin, TX 78701, water damage in kitchen.

**prototype: cues + shape + recurrence (deployed)** - 0 FP and 159 FN prompt-family cases in total; seeded sample:

- FN [person] `privoke_synth_sensitive_000055` detected=[] via []: Help me draft a tax preparer email for Maya Nguyen. SSN 329-23-6736, mailing address 5219 Lakeview Court, Springfield, IL 62704.
- FN [person] `privoke_synth_sensitive_000700` detected=[] via []: Write a bank support message for Omar Williams. The account number is 2277950614 and the callback number is 797-555-2291.
- FN [person] `privoke_synth_sensitive_000744` detected=[] via []: Write a bank support message for Leo Patel. The account number is 3584703554 and the callback number is 613-555-7744.
- FN [person] `privoke_synth_sensitive_000073` detected=[] via []: Draft a travel support email for Taylor Singh. Passport number X15684813, contact email taylor.singh91@example.com.
- FN [person] `privoke_synth_sensitive_000082` detected=[] via []: Write a bank support message for Iris Rivera. The account number is 5756663747 and the callback number is 447-555-4524.

**union: spaCy U prototype (deployed)** - 49 FP and 51 FN prompt-family cases in total; seeded sample:

- FP [person] `privoke_synth_sensitive_000828` detected=['temppass4495'] via ['spacy']: Can you help me write an account recovery note? Email sam.morgan82@example.com, temporary password TempPass4495!, last login IP 192.0.2.222.
- FP [person] `privoke_synth_sensitive_000680` detected=['temppass5228'] via ['spacy']: Can you help me write an account recovery note? Email casey.morgan889@example.com, temporary password TempPass5228!, last login IP 192.0.2.148.
- FP [person] `privoke_synth_sensitive_000502` detected=['temppass8225'] via ['spacy']: Can you help me write an account recovery note? Email maya.miller90@example.com, temporary password TempPass8225!, last login IP 192.0.2.82.
- FP [person] `privoke_synth_sensitive_000341` detected=['temppass2511'] via ['spacy']: Can you help me write an account recovery note? Email avery.williams813@example.com, temporary password TempPass2511!, last login IP 192.0.2.16.
- FP [location] `privoke_synth_sensitive_000360` detected=['temppass9866'] via ['spacy']: Can you format this deployment note? Use API key sk-test-457087342774145950059 and temporary password TempPass9866! for the staging check.
- FN [person] `privoke_synth_sensitive_000736` detected=[] via []: Help me draft a tax preparer email for Riley Rivera. SSN 477-82-2062, mailing address 1778 Lakeview Court, Denver, CO 80202.
- FN [person] `privoke_synth_sensitive_000015` detected=[] via []: Write a bank support message for Morgan Tan. The account number is 1189351213 and the callback number is 471-555-9280.
- FN [person] `privoke_synth_sensitive_000666` detected=[] via []: Draft a travel support email for Avery Morgan. Passport number X31527957, contact email avery.morgan372@example.com.
- FN [person] `privoke_synth_sensitive_000529` detected=[] via []: Help me draft a tax preparer email for Casey Nguyen. SSN 867-92-9938, mailing address 1037 Maple Street, San Jose, CA 95112.
- FN [person] `privoke_synth_sensitive_000173` detected=[] via []: Draft a travel support email for Sara Garcia. Passport number X38147161, contact email sara.garcia996@example.com.

**hybrid: spaCy seeds + cues + recurrence (deployed)** - 37 FP and 81 FN prompt-family cases in total; seeded sample:

- FP [person] `privoke_synth_sensitive_000646` detected=['temppass6681'] via ['spacy']: Can you help me write an account recovery note? Email sara.singh878@example.com, temporary password TempPass6681!, last login IP 192.0.2.105.
- FP [person] `privoke_synth_sensitive_000128` detected=['temppass7590'] via ['spacy']: Can you help me write an account recovery note? Email sara.williams987@example.com, temporary password TempPass7590!, last login IP 192.0.2.22.
- FP [person] `privoke_synth_sensitive_000341` detected=['temppass2511'] via ['spacy']: Can you help me write an account recovery note? Email avery.williams813@example.com, temporary password TempPass2511!, last login IP 192.0.2.16.
- FP [person] `privoke_synth_sensitive_000547` detected=['temppass9871'] via ['spacy']: Can you format this deployment note? Use API key sk-test-498361695059005437455 and temporary password TempPass9871! for the staging check.
- FP [location] `privoke_synth_sensitive_000203` detected=['singh'] via ['spacy']: Write a bank support message for Taylor Singh. The account number is 7015499403 and the callback number is 828-555-6621.
- FN [person] `privoke_synth_sensitive_000124` detected=[] via []: Draft a travel support email for Morgan Tan. Passport number X97977738, contact email morgan.tan905@example.com.
- FN [location] `privoke_synth_sensitive_000564` detected=[] via []: Summarize this insurance claim: Taylor Morgan, policy INS-33055557, address 1881 Pine Road, Austin, TX 78701, water damage in kitchen.
- FN [person] `privoke_synth_sensitive_000732` detected=[] via []: Draft a travel support email for Morgan Patel. Passport number X44245294, contact email morgan.patel626@example.com.
- FN [person] `privoke_synth_sensitive_000697` detected=[] via []: Help me draft a tax preparer email for Avery Ali. SSN 563-34-1060, mailing address 8199 Parkside Terrace, Denver, CO 80202.
- FN [person] `privoke_synth_sensitive_000373` detected=[] via []: Draft a travel support email for Nina Morgan. Passport number X24863801, contact email nina.morgan546@example.com.

**spaCy en_core_web_sm NER (original)** - 62 FP and 48 FN prompt-family cases in total; seeded sample:

- FP [location] `privoke_synth_sensitive_000051` detected=['INS-33386929'] via ['spacy']: Help me ask my doctor about my lab results. Patient Avery Williams, DOB 1989-05-26, insurance ID INS-33386929, has recurring chest pain.
- FP [location] `privoke_synth_clean_000203` detected=['US'] via ['spacy']: Can you show the format of a US phone number using placeholders like 555-0100? Keep it concise and write it for a project teammate before submitting the request.
- FP [location] `privoke_synth_sensitive_000034` detected=['DOB 1974-10-14'] via ['spacy']: Help me ask my doctor about my lab results. Patient Riley Singh, DOB 1974-10-14, insurance ID INS-33328859, has recurring chest pain.
- FP [location] `privoke_synth_sensitive_000142` detected=['EMP-30644'] via ['spacy']: Draft a message to HR saying Omar Rivera's employee ID is EMP-30644 and SSN is 482-94-7481.
- FP [person] `privoke_synth_clean_000434` detected=['Xs'] via ['spacy']: Can you give an example credit card format using Xs instead of real digits? Keep it professional and write it for a help center after a missed update.
- FN [person] `privoke_synth_sensitive_000015` detected=[] via []: Write a bank support message for Morgan Tan. The account number is 1189351213 and the callback number is 471-555-9280.
- FN [person] `privoke_synth_sensitive_000884` detected=[] via []: Help me ask my doctor about my lab results. Patient Morgan Nguyen, DOB 1996-02-01, insurance ID INS-28907022, has recurring chest pain.
- FN [person] `privoke_synth_sensitive_000732` detected=[] via []: Draft a travel support email for Morgan Patel. Passport number X44245294, contact email morgan.patel626@example.com.
- FN [person] `privoke_synth_sensitive_000731` detected=[] via []: Can you rewrite this professionally? My name is Morgan Khan, my email is morgan.khan917@example.com, and my phone number is 260-555-2249.
- FN [location] `privoke_synth_sensitive_000448` detected=[] via []: Summarize this insurance claim: Omar Rivera, policy INS-23078988, address 2565 Willow Way, Austin, TX 78701, water damage in kitchen.

**prototype: cues + shape + recurrence (original)** - 0 FP and 0 FN prompt-family cases in total; seeded sample:


**union: spaCy U prototype (original)** - 62 FP and 0 FN prompt-family cases in total; seeded sample:

- FP [location] `privoke_synth_sensitive_000310` detected=['INS-47281925'] via ['spacy']: Help me ask my doctor about my lab results. Patient Riley Patel, DOB 1986-09-14, insurance ID INS-47281925, has recurring chest pain.
- FP [location] `privoke_synth_sensitive_000338` detected=['STU-460875'] via ['spacy']: Can you clean up this school form note? Student Leo Davis, ID STU-460875, date of birth 1997-11-05, needs records updated.
- FP [location] `privoke_synth_clean_000876` detected=['US'] via ['spacy']: Can you show the format of a US phone number using placeholders like 555-0100? Keep it formal and write it for a bank representative before submitting the request.
- FP [location] `privoke_synth_sensitive_000931` detected=['Riley Rivera'] via ['spacy']: Improve the contact section of my resume: Riley Rivera, riley.rivera910@example.com, 339-555-5904.
- FP [location] `privoke_synth_sensitive_000372` detected=['ID STU-966621'] via ['spacy']: Can you clean up this school form note? Student Leo Khan, ID STU-966621, date of birth 1985-02-11, needs records updated.

**hybrid: spaCy seeds + cues + recurrence (original)** - 61 FP and 4 FN prompt-family cases in total; seeded sample:

- FP [person] `privoke_synth_clean_000354` detected=['Xs'] via ['spacy']: Can you give an example credit card format using Xs instead of real digits? Keep it direct and write it for an HR coordinator for a shared team document.
- FP [location] `privoke_synth_clean_000158` detected=['US'] via ['spacy']: Can you show the format of a US phone number using placeholders like 555-0100? Keep it simple and write it for a project teammate for a shared team document.
- FP [person] `privoke_synth_clean_000273` detected=['Xs'] via ['spacy']: Can you give an example credit card format using Xs instead of real digits? Keep it direct and write it for a bank representative before the deadline.
- FP [person] `privoke_synth_clean_000662` detected=['Xs'] via ['spacy']: Can you give an example credit card format using Xs instead of real digits? Keep it reassuring and write it for a bank representative before submitting the request.
- FP [person] `privoke_synth_clean_000634` detected=['Xs'] via ['spacy']: Can you give an example credit card format using Xs instead of real digits? Keep it friendly and write it for a help center for next week.
- FN [location] `privoke_synth_sensitive_000920` detected=[] via []: Make this tenant message clearer: I am Evan Nguyen at 4511 Willow Way, Austin, TX 78701, and you can call me at 575-555-4519.
- FN [location] `privoke_synth_sensitive_000507` detected=[] via []: Summarize this insurance claim: Evan Khan, policy INS-33946564, address 5350 Willow Way, Austin, TX 78701, water damage in kitchen.
- FN [location] `privoke_synth_sensitive_000448` detected=[] via []: Summarize this insurance claim: Omar Rivera, policy INS-23078988, address 2565 Willow Way, Austin, TX 78701, water damage in kitchen.
- FN [location] `privoke_synth_sensitive_000644` detected=[] via []: Make this tenant message clearer: I am Morgan Chen at 597 Willow Way, Austin, TX 78701, and you can call me at 316-555-2410.

### Qualitative examples - OOD openai

**spaCy en_core_web_sm NER (deployed)** - 84 FP and 11 FN prompt-family cases in total; seeded sample:

- FP [person] `privoke_openai_synth_sensitive_000225` detected=['alex williams'] via ['spacy']: I need to rewrite an email for account recovery that includes some sensitive information. Here are the key points I want to cover:   - Mention my full name, Alex Williams - Reference the performance warning from my manag
- FP [person] `privoke_openai_synth_sensitive_000017` detected=['iris garcia'] via ['spacy']: Hey, I just need a quick summary of this doc I copied, you know, the one with the info on our employee Iris Garcia, she's got the ID EMP-64949, super important for the customer support stuff we're dealing with. Can you h
- FP [person] `privoke_openai_synth_sensitive_000163` detected=['alex patel'] via ['spacy']: I would appreciate your assistance in summarizing a document regarding my recent medical issues. It details my recurring chest pain and includes my personal information, specifically my name, Alex Patel, along with my lo
- FP [person] `privoke_openai_synth_sensitive_000451` detected=['gb94barc1316372702583515'] via ['spacy']: Hey, I need help rewriting this email. I'm trying to ask my accountant about a payment I made recently, but I keep mixing it up. I want to include my business bank info like GB94BARC1316372702583515 and my tax ID which i
- FP [location] `privoke_openai_synth_sensitive_000466` detected=['x64694810'] via ['spacy']: I need help with a legal message for my tenant regarding their lease. Can you assist me in drafting something that includes their ID, which is X64694810?
- FN [location] `privoke_openai_synth_sensitive_000110` detected=[] via []: Hey! Can you help me rewrite this email about the tenant dispute hearing on unpaid rent at 136 Maple Street, Austin, TX 78701? Also, I mentioned my weekly mosque volunteer work in it, so I want to make sure that sounds g
- FN [person] `privoke_openai_synth_sensitive_000313` detected=[] via []: I would like to formally submit a complaint regarding the recent changes in my employment terms. My name is Casey Singh, and my employee ID is X35831420. I was originally presented with a salary offer of $118,500, which 
- FN [location] `privoke_openai_synth_sensitive_000119` detected=[] via []: Hey, can you help me with my account? I think I need to check on a transaction related to my ID X69076543. Also, I noticed something off with my BOFAUS3N150 details. I'm based in Queens, NY, so if you could get back to m
- FN [person] `privoke_openai_synth_sensitive_000075` detected=[] via []: Hey! Can you help me with something? I need to submit a disciplinary note from the registrar for Avery Nguyen. Also, I've got my insurance info handy—INS-60641630, just in case it's needed for health stuff. Thanks!
- FN [person] `privoke_openai_synth_sensitive_000177` detected=[] via []: Hey, so I need to share some details for a job application I'm working on, but I want to make sure everything's handled carefully. My name is Nina Patel, and just a heads up, I’ve got a protective order case number CIV-2

**prototype: cues + shape + recurrence (deployed)** - 25 FP and 26 FN prompt-family cases in total; seeded sample:

- FP [location] `privoke_openai_synth_sensitive_000077` detected=['coordinates'] via ['cue']: Could you please assist me in addressing a performance warning from my manager while I am currently located at the coordinates 30.80922, -102.592832? Thank you.
- FP [person] `privoke_openai_synth_sensitive_000013` detected=['iris rivera'] via ['cue']: I need to write up a complaint about my health issues, specifically this recurring chest pain I've been having. It's really affecting my life and I don't know what to do. Also, my name is Iris Rivera and I'm located in S
- FP [person] `privoke_openai_synth_sensitive_000385` detected=['maya davis'] via ['cue']: Could you please help me rewrite an email regarding my recent travel booking? My name is Maya Davis, and I want to ensure it's polished for a corporate audience. Also, I'd like to mention that my partner and I are a same
- FP [person] `privoke_openai_synth_sensitive_000267` detected=['casey ali'] via ['cue']: Hi there, I hope you can help me out because I’m feeling a bit overwhelmed. So, I think I need assistance regarding my account, and my name is Casey Ali. I’ve been trying to sort through some verification stuff and I bel
- FP [person] `privoke_openai_synth_sensitive_000197` detected=['omar davis'] via ['cue']: I hope this message finds you well. I am reaching out to seek your assistance regarding a form that I am currently completing. The form requires specific personal details, and I would appreciate your guidance on how to a
- FN [location] `privoke_openai_synth_sensitive_000447` detected=[] via []: I'm in the process of filling out a school form for my child's upcoming travel and I need your assistance. Specifically, I want to ensure that my financial details like my bank account number BOFAUS3N965 and my home IP a
- FN [location] `privoke_openai_synth_sensitive_000306` detected=[] via []: Hey! I'm trying to file a complaint about something that happened at school, but I have to include my location, right? I’m in Austin, TX. Also, I think they need my IP address for some reason, which is 192.0.2.10. Can I 
- FN [person] `privoke_openai_synth_sensitive_000182` detected=[] via []: I need help with my travel booking form, but I have a sealed arrest record from 2021 under my name, Riley Garcia. Can you assist me with that?
- FN [location] `privoke_openai_synth_sensitive_000063` detected=[] via []: I'm really worried and overwhelmed right now because I’ve been trying to get my landlord to fix some repairs in my apartment in Austin, TX, and it just seems like nothing's happening. I mean, I have this issue with my he
- FN [person] `privoke_openai_synth_sensitive_000355` detected=[] via []: Hey, I’m Sara Garcia and I filled out the contact form on your website but it didn’t go through or somethin'. Can you help me with my inquiry? I really need to get this sorted out soon! Thanks!

**union: spaCy U prototype (deployed)** - 97 FP and 5 FN prompt-family cases in total; seeded sample:

- FP [person] `privoke_openai_synth_sensitive_000373` detected=['kinda'] via ['spacy']: hey, so im trying to get my account back, but im stuck on this form. It keeps asking for my address and i wrote Boston, MA but idk what else to do. also, they want my bank details and my code is 4d:83:98:5d:07:7b but it 
- FP [person] `privoke_openai_synth_sensitive_000086` detected=['omar brooks'] via ['spacy']: Can you help me draft a message for my tenant, Omar Brooks? I need to include some important info related to their lease, specifically STU-800901. Also, I want to make sure they know my contact number is 630-555-2086 if 
- FP [person] `privoke_openai_synth_clean_000263` detected=['jargon'] via ['spacy']: Hey there! I’ve got this document related to our upcoming travel bookings for the business, and I really need help summarizing it. I’m a bit anxious about making sure that all the necessary details are included without o
- FP [person] `privoke_openai_synth_sensitive_000310` detected=['stu-754558'] via ['spacy']: Hey, can you help me check the status of the claim for STU-754558? I need to get some info on that as soon as possible. Thanks!
- FP [person] `privoke_openai_synth_sensitive_000308` detected=['alex chen', 'alex chen'] via ['cue', 'spacy']: I am submitting a request to reset my password on the school portal. My name is Alex Chen, and my identification number is 940-77-9947. You can find the reset link here: https://portal.example.com/reset?token=tok_9214763
- FN [person] `privoke_openai_synth_sensitive_000095` detected=[] via []: Hey, can you help me rewrite this email about Avery Nguyen? I need to include their financial info—like the account number 4520399955—and also mention their address at 417 Maple Street, Denver, CO 80202. It's kinda messy
- FN [location] `privoke_openai_synth_sensitive_000238` detected=[] via []: Can you help me rewrite an email regarding a disciplinary note from the registrar? I need to include information about a case involving a financial matter and the identity associated with it, specifically the number 7259
- FN [person] `privoke_openai_synth_sensitive_000113` detected=[] via []: Hey, it's Sara Patel. I just got a salary offer of $118,500 and I'm trying to book a trip to the location with coordinates 26.163284, -91.397257. Can you help me out with that? Thanks!
- FN [person] `privoke_openai_synth_sensitive_000075` detected=[] via []: Hey! Can you help me with something? I need to submit a disciplinary note from the registrar for Avery Nguyen. Also, I've got my insurance info handy—INS-60641630, just in case it's needed for health stuff. Thanks!
- FN [person] `privoke_openai_synth_sensitive_000355` detected=[] via []: Hey, I’m Sara Garcia and I filled out the contact form on your website but it didn’t go through or somethin'. Can you help me with my inquiry? I really need to get this sorted out soon! Thanks!

**hybrid: spaCy seeds + cues + recurrence (deployed)** - 96 FP and 8 FN prompt-family cases in total; seeded sample:

- FP [location] `privoke_openai_synth_sensitive_000394` detected=['https://portal.example.com/reset?token=tok_2929660093544524327'] via ['spacy']: So, um, I'm really trying to fill out this school form, but I'm feeling super anxious about it. I just want to make sure I'm doing everything right because my kid's health is really important to me, you know? And I have 
- FP [person] `privoke_openai_synth_sensitive_000451` detected=['gb94barc1316372702583515'] via ['spacy']: Hey, I need help rewriting this email. I'm trying to ask my accountant about a payment I made recently, but I keep mixing it up. I want to include my business bank info like GB94BARC1316372702583515 and my tax ID which i
- FP [person] `privoke_openai_synth_clean_000149` detected=['info', 'info'] via ['recurrence', 'spacy']: Need help filling out the form for [medical procedure]. I’m stuck on the section about [insurance provider]. What info do I need to add? Also, concerned about privacy when sharing [personal info]—is this secure? Thanks!
- FP [location] `privoke_openai_synth_sensitive_000226` detected=['x18321907'] via ['spacy']: Can you please summarize the pasted document while ensuring that the sensitive information, including the health details related to X18321907, the identity code 6EG5915TE7, and the device ID 3c:40:6f:e5:4b:93, is handled
- FP [person] `privoke_openai_synth_sensitive_000473` detected=['c7'] via ['spacy']: I need some assistance regarding a sealed arrest record from 2021 that is connected to my identity verification process. I also have a MAC address, 8e:60:8c:89:22:c7, that might be relevant. Additionally, my contact numb
- FN [location] `privoke_openai_synth_sensitive_000110` detected=[] via []: Hey! Can you help me rewrite this email about the tenant dispute hearing on unpaid rent at 136 Maple Street, Austin, TX 78701? Also, I mentioned my weekly mosque volunteer work in it, so I want to make sure that sounds g
- FN [person] `privoke_openai_synth_sensitive_000075` detected=[] via []: Hey! Can you help me with something? I need to submit a disciplinary note from the registrar for Avery Nguyen. Also, I've got my insurance info handy—INS-60641630, just in case it's needed for health stuff. Thanks!
- FN [person] `privoke_openai_synth_sensitive_000113` detected=[] via []: Hey, it's Sara Patel. I just got a salary offer of $118,500 and I'm trying to book a trip to the location with coordinates 26.163284, -91.397257. Can you help me out with that? Thanks!
- FN [location] `privoke_openai_synth_sensitive_000217` detected=[] via []: Hey! I'm having some issues with my place at 1865 Maple Street, Austin, TX 78701. Can you help me with the details? Also, my reference number is RVT-5475, and I need to clarify a payment issue linked to my account BOFAUS
- FN [person] `privoke_openai_synth_sensitive_000355` detected=[] via []: Hey, I’m Sara Garcia and I filled out the contact form on your website but it didn’t go through or somethin'. Can you help me with my inquiry? I really need to get this sorted out soon! Thanks!

**spaCy en_core_web_sm NER (original)** - 106 FP and 1 FN prompt-family cases in total; seeded sample:

- FP [person] `privoke_openai_synth_sensitive_000453` detected=['EMP-12820'] via ['spacy']: Hey, I really need some help here because I’m kind of freaking out. I’m trying to fill out this form for my financial aid, but I’m stuck on a couple of things. For my identity verification, it keeps asking for my employe
- FP [person] `privoke_openai_synth_sensitive_000167` detected=['Omar Ali', 'QPX-4182'] via ['spacy']: I need help recovering my account. I have a sealed arrest record from 2021 under the name Omar Ali, and my case number is QPX-4182.
- FP [person] `privoke_openai_synth_sensitive_000306` detected=['https://portal.example.com/reset?token=tok_4837059738715579892'] via ['spacy']: Hey! I'm trying to file a complaint about something that happened at school, but I have to include my location, right? I’m in Austin, TX. Also, I think they need my IP address for some reason, which is 192.0.2.10. Can I 
- FP [person] `privoke_openai_synth_sensitive_000125` detected=['Sam Garcia'] via ['spacy']: I'm really worried about this issue I'm having, and I feel like I need to get some help with it. So, my name is Sam Garcia, and I was born on 1989-02-01, just so you have my information. I’ve been dealing with some billi
- FP [person] `privoke_openai_synth_sensitive_000211` detected=['Iris Miller', 'maya_ali_40'] via ['spacy']: Hey, I’m filling out this job application and I’m stuck on a couple of things. Do I really need to put my ID number, like 2EG3231TE9, and my health details in there? Also, it asks for my name, should I just use Iris Mill
- FN [person] `privoke_openai_synth_sensitive_000075` detected=[] via []: Hey! Can you help me with something? I need to submit a disciplinary note from the registrar for Avery Nguyen. Also, I've got my insurance info handy—INS-60641630, just in case it's needed for health stuff. Thanks!

**prototype: cues + shape + recurrence (original)** - 48 FP and 0 FN prompt-family cases in total; seeded sample:

- FP [person] `privoke_openai_synth_sensitive_000435` detected=['Maya Tan'] via ['shape']: Please summarize the document I just pasted, which includes everything about Maya Tan and her ID 954-71-8154.
- FP [location] `privoke_openai_synth_sensitive_000273` detected=['coordinates'] via ['cue']: I need assistance with an account recovery process for a patient located at coordinates 37.755298, -94.231392. Additionally, I want to mention that my partner and I are a same-sex couple to ensure all relevant informatio
- FP [person] `privoke_openai_synth_sensitive_000225` detected=['Alex Williams'] via ['shape']: I need to rewrite an email for account recovery that includes some sensitive information. Here are the key points I want to cover:   - Mention my full name, Alex Williams - Reference the performance warning from my manag
- FP [person] `privoke_openai_synth_sensitive_000175` detected=['Leo Brooks'] via ['cue']: I'm really worried and need some help with my account recovery issue because I think I've forgotten my password, and it's just so stressful. My name is Leo Brooks, and my account number is X98510975. I've tried a few tim
- FP [person] `privoke_openai_synth_clean_000481` detected=['SSNs'] via ['cue']: Could you provide guidance on how to securely handle sensitive information, such as employee SSNs, when completing school enrollment forms for our staff members? Maintaining privacy and compliance is crucial for us.

**union: spaCy U prototype (original)** - 124 FP and 0 FN prompt-family cases in total; seeded sample:

- FP [location] `privoke_openai_synth_sensitive_000287` detected=['INS-16410920'] via ['spacy']: Can you help me rewrite the email for the travel booking? I need to include my insurance number, which is INS-16410920. Just make sure it sounds professional but casual. Thanks!
- FP [person] `privoke_openai_synth_sensitive_000042` detected=['BOFAUS3N769'] via ['spacy']: I need assistance with my bank account. My account number is BOFAUS3N769, and I think I might have forgotten my RVT-9021 code. I live in Boston, MA, and I’m trying to resolve this issue as soon as possible. Can someone h
- FP [person] `privoke_openai_synth_sensitive_000399` detected=['Avery Williams', 'Avery Williams'] via ['shape', 'spacy']: Hi there, I really hope you can help me with this, it's kind of a mess and I’m feeling a bit overwhelmed. So, I’m trying to fill out this form for a customer, and I need to make sure everything is correct, but I'm having
- FP [person] `privoke_openai_synth_sensitive_000225` detected=['Alex Williams', 'Alex Williams'] via ['shape', 'spacy']: I need to rewrite an email for account recovery that includes some sensitive information. Here are the key points I want to cover:   - Mention my full name, Alex Williams - Reference the performance warning from my manag
- FP [person] `privoke_openai_synth_sensitive_000233` detected=['MD2659332'] via ['spacy']: hey, i'm trying to recover my account but I'm having trouble, I think it might be linked to my bank details as I remember using my card that ends with GB52BARC7644830566113473 for payments and my health insurance number 

**hybrid: spaCy seeds + cues + recurrence (original)** - 122 FP and 1 FN prompt-family cases in total; seeded sample:

- FP [location] `privoke_openai_synth_sensitive_000348` detected=['RVT-3316'] via ['spacy']: I am writing to express my dissatisfaction with a recent travel booking experience I had while at RVT-3316.
- FP [person] `privoke_openai_synth_clean_000003` detected=['info'] via ['spacy']: hey, I need help with applying for jobs online but I’m worried about privacy. what info should I avoid including on my resume or cover letter? also, any tips on how to redact sensitive details when submitting application
- FP [location] `privoke_openai_synth_sensitive_000353` detected=['INS-92928942'] via ['spacy']: Can you summarize this document I just pasted? It's related to a project I'm working on and contains some details about insurance claims, including INS-92928942. I'd appreciate it if you could highlight the key points in
- FP [person] `privoke_openai_synth_sensitive_000436` detected=['Sam Rivera'] via ['cue']: Hey! I need help recovering my account. I think my info might be tied to my social, 974-79-8272, and my insurance number is INS-37758869. Oh, and my name is Sam Rivera. Can you assist me with this? Thanks!
- FP [location] `privoke_openai_synth_sensitive_000466` detected=['X64694810'] via ['spacy']: I need help with a legal message for my tenant regarding their lease. Can you assist me in drafting something that includes their ID, which is X64694810?
- FN [person] `privoke_openai_synth_sensitive_000075` detected=[] via []: Hey! Can you help me with something? I need to submit a disciplinary note from the registrar for Avery Nguyen. Also, I've got my insurance info handy—INS-60641630, just in case it's needed for health stuff. Thanks!

<!-- END GENERATED -->


## Post-hoc error analysis (exploratory, after the freeze)

**Manual audit of OOD PERSON false positives.** Of the OOD prompts without `FULL_NAME` gold, original-case spaCy detects a PERSON in 78 and the prototype in 38. I read a seeded sample (`random.seed(5)`, 25 each, single reviewer, original case) and judged whether the detected span is a person name:

| System | Sampled detections that are real person names | Other detections |
|---|---:|---|
| spaCy | 13 / 25 | identifiers (`EMP-37800`, `MD9039184`, `BOFAUS3N894`, `GB24...`), a username, a coordinate fragment, `kinda`, a MAC fragment |
| prototype | 20 / 25 | `BOFAUS`, `INS-` (from `it's <ID>` self-introduction cue), `SSNs`, `iris` (from a username), `San Diego` (Title-case shape, no gazetteer) |

So the OOD PERSON precision against gold (21-48%) is **a lower bound**: the generator mentions names ("My name is Sam Garcia") without always labelling `FULL_NAME`. An audited precision would be roughly 52% for spaCy and 80% for the prototype on these samples (n = 25 each, so wide intervals; this audit is manual and not regenerated by the script). The ordering between systems on gold-based precision is consistent with the audit, but absolute OOD PERSON precision should not be quoted.

**Known prototype defects (not fixed after the freeze).**

- The `it's <X>` cue (`self_intro_this_is`) and the `customer_of` cue capture identifier prefixes (`BOFAUS`, `INS-`) because the token scan stops at digits instead of rejecting the token; the `role_prefix` cue turns `employee SSNs` into a name.
- `located at coordinates ...` yields a location false positive (`coordinates`) through the `residence_verb` and `lives_in` cues (8 OOD prompts); this accounts for several of the 10 cue-only OOD location false positives.
- Without the gazetteer, city names with no residence cue or ZIP are not recognised, and a Title-case city pair such as `San Diego` is read as a PERSON shape.
- Lowercased person names with no cue (`write a message for evan khan`) are not found; this is why deployed PERSON recall stays at 58.8% held-out and 58.3% OOD. The `for X. The account ...` cue is restricted to capitalised values.
- Sentence-initial Title-case names need a cue, recurrence or a form-record context.

## Limitations

- **Synthetic, template-biased data.** The personalized file is template generated; the same sentence frames, name pool (about 16 first names and 16 surnames) and `City, ST ZIP` address format recur. Cue, shape and especially gazetteer rows reach 100% on frames the dev half exposed. Held-out personalized is *in-distribution to the dev half*, not independent evidence of generalisation.
- **OOD is also synthetic.** The LLM-generated file uses the same name pool for incidental names, has a small number of gold positives for these families (24 PERSON, 44 location), and omits `FULL_NAME` labels for names that are present. Intervals are wide, and the PERSON precision is deflated as shown above.
- **No span gold.** Everything is prompt level. Span precision, overlap, masking coverage, label correctness (GPE vs FAC vs PERSON) and the benefit of recurrence for masking every mention are untested.
- **Gold covers only some entity families.** ORG has no gold. Location gold does not include city or country mentions that are not part of an address or place of birth, so correctly detected incidental places count as false positives for every system.
- **Deployed condition is lowercased only.** I did not test other normalisations or the full pipeline (regex layer plus NER), and the regex layer already catches street addresses via `rules_location.py`; this study does not measure how much of the prototype's location recall is redundant with it. This is a detector ablation, not a product end-to-end result.
- **Single run, single machine, single spaCy model.** Latency is wall time from one run on a Windows host (no pinned CPU, no warm-up beyond one call), only for prompts of the lengths in these files. No `en_core_web_md/lg` or transformer model was tried.
- **Prototype robustness untested beyond unit tests.** No fuzzing for catastrophic backtracking beyond observed latency (p95 below 1 ms for the headline prototype); multilingual and non-US address forms are out of scope.
- **Wiring.** `PatternEntityDetector` is not wired into the pipeline; importing `src.NER.pattern_entity_detector` still imports spaCy through `src/NER/__init__.py` because that package file was left unchanged.

## Reproduction

From the repository root, host Python only (no Docker); the environment used is `evaluation/.venv-v1-v3-pipeline` (Python 3.11.9, spaCy 3.7.5, `en_core_web_sm` 3.7.1, numpy 1.26.4):

```
evaluation/.venv-v1-v3-pipeline/Scripts/python.exe -m unittest discover -s extension/client-runtime/test -p test_pattern_entity_detector.py
evaluation/.venv-v1-v3-pipeline/Scripts/python.exe evaluation/compare_ner_pattern_detector.py            # held-out + OOD, rewrites the generated block and the JSON
evaluation/.venv-v1-v3-pipeline/Scripts/python.exe evaluation/compare_ner_pattern_detector.py --dev-only --examples 10   # dev half only, writes nothing
```

The script rewrites only the region between the `BEGIN GENERATED` and `END GENERATED` markers; text outside them is hand-written. Latency figures vary from run to run; counts, precision, recall and F1 are deterministic (spaCy inference and the seeded split and bootstrap).

Independent check: held-out PERSON and location TP/FP/FN for spaCy (278/26/108, 86/23/30) and the headline prototype (227/0/159, 116/0/0) in the deployed condition were recomputed with a separate short script that re-implements the split, gold and counting; all twelve counts matched. Positives in each table equal TP + FN (386 PERSON, 116 location held-out).
