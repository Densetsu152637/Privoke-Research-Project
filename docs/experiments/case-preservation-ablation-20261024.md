# Case-preservation ablation (regex and NER detector layers)

Detector-layer ablation (regex and spaCy `en_core_web_sm` NER). This is not LLM-only or semantic evidence.

Change: `PRIVOKE_CASE_PRESERVING_DETECTORS=1` (`GLOBAL_CONFIG.case_preserving_detectors`, default off; now default on since 6a0c9ca3) gives regex/NER
case-preserved normalized text (`normalize_with_offsets(text, lowercase=False)`); semantic layers always stay lowercased.
Only casing varies (NFKC, whitespace and `[at]`/`(at)` handling are identical, case-insensitive).

Method: host Python, `pipeline.analyse_text(layers=["regex","ner"], regex_first=False)` per prompt; per-layer results
are split to give regex-only and ner-only, and unioned for regex+ner. Positive = any hit with sensitivity != S0 or categories
(so NER ORG hits, S1, count as positive). Datasets: development (502), personalized synthetic (2000), openai synthetic (1000).
final.jsonl was not opened. Mean ms/prompt (regex+ner together) is equal across modes: 27.3/27.3, 28.4/28.4, 31.9/32.1.

| Dataset | Layers | Mode | TP | TN | FP | FN | Recall | Specificity |
|---|---|---|---|---|---|---|---|---|
| development | regex | lower / case | 169 / 169 | 234 / 234 | 4 / 4 | 95 / 95 | .640 / .640 | .983 / .983 |
| development | ner | lower / case | 55 / 121 | 232 / 201 | 6 / 37 | 209 / 143 | .208 / .458 | .975 / .845 |
| development | regex+ner | lower / case | 191 / 222 | 228 / 197 | 10 / 41 | 73 / 42 | .723 / .841 | .958 / .828 |
| personalized | regex | lower / case | 1000 / 1000 | 1000 / 1000 | 0 / 0 | 0 / 0 | 1.0 / 1.0 | 1.0 / 1.0 |
| personalized | ner | lower / case | 800 / 871 | 1000 / 919 | 0 / 81 | 200 / 129 | .800 / .871 | 1.0 / .919 |
| personalized | regex+ner | lower / case | 1000 / 1000 | 1000 / 919 | 0 / 81 | 0 / 0 | 1.0 / 1.0 | 1.0 / .919 |
| openai | regex | lower / case | 448 / 448 | 466 / 466 | 34 / 34 | 52 / 52 | .896 / .896 | .932 / .932 |
| openai | ner | lower / case | 145 / 241 | 492 / 434 | 8 / 66 | 355 / 259 | .290 / .482 | .984 / .868 |
| openai | regex+ner | lower / case | 463 / 471 | 458 / 407 | 42 / 93 | 37 / 29 | .926 / .942 | .916 / .814 |

Regex: zero per-example flips; hit lists (rule, text, sensitivity, categories) identical in all 3502 prompts.
NER flips (lower -> case): development FN->TP 70, TN->FP 33, TP->FN 4, FP->TN 2; personalized FN->TP 112, TN->FP 81, TP->FN 41;
openai FN->TP 109, TN->FP 60, TP->FN 13, FP->TN 2. Driving labels: FN->TP is ORG and PERSON (then GPE); TN->FP is mostly ORG
(openai: 60 of 61), PERSON/ORG/GPE on personalized. Prompts with a PERSON hit: development 36 -> 81, personalized 617 -> 727, openai 84 -> 102.

## Follow-up: ORG hits not counted as positive

Recomputed from the saved per-hit outputs (no re-run). NER-noORG counts PERSON, GPE, LOC and FAC hits; PERSON-only counts PERSON hits. Regex+NER variants union the regex layer (unchanged). Detector-layer evidence only. Span examples are short fragments.

**development** (N=502)

| Definition | Mode | TP | TN | FP | FN | Recall | Spec |
|---|---|---|---|---|---|---|---|
| NER-noORG | lower | 45 | 237 | 1 | 219 | 0.170 | 0.996 |
| NER-noORG | case | 88 | 223 | 15 | 176 | 0.333 | 0.937 |
| regex+NER-noORG | lower | 189 | 233 | 5 | 75 | 0.716 | 0.979 |
| regex+NER-noORG | case | 208 | 219 | 19 | 56 | 0.788 | 0.920 |
| PERSON-only | lower | 36 | 238 | 0 | 228 | 0.136 | 1.000 |
| PERSON-only | case | 69 | 226 | 12 | 195 | 0.261 | 0.950 |
| regex+PERSON-only | lower | 186 | 234 | 4 | 78 | 0.705 | 0.983 |
| regex+PERSON-only | case | 200 | 222 | 16 | 64 | 0.758 | 0.933 |

- NER-noORG flips: {'FN->TP': 44, 'TN->FP': 14, 'TP->FN': 1}
  - TN->FP labels (NER-noORG): GPE 2 e.g. 'Affidavit', 'JSON'; PERSON 12 e.g. 'Tax', 'Proposal', 'Psychiatric History'; LOC 1 e.g. 'Application Date'
- regex+NER-noORG flips: {'FN->TP': 19, 'TN->FP': 14}
- PERSON-only flips: {'FN->TP': 34, 'TN->FP': 12, 'TP->FN': 1}
  - TN->FP labels (PERSON-only): PERSON 12 e.g. 'Tax', 'Proposal', 'Psychiatric History'
- regex+PERSON-only flips: {'FN->TP': 14, 'TN->FP': 12}

**personalized** (N=2000)

| Definition | Mode | TP | TN | FP | FN | Recall | Spec |
|---|---|---|---|---|---|---|---|
| NER-noORG | lower | 704 | 1000 | 0 | 296 | 0.704 | 1.000 |
| NER-noORG | case | 723 | 946 | 54 | 277 | 0.723 | 0.946 |
| regex+NER-noORG | lower | 1000 | 1000 | 0 | 0 | 1.000 | 1.000 |
| regex+NER-noORG | case | 1000 | 946 | 54 | 0 | 1.000 | 0.946 |
| PERSON-only | lower | 617 | 1000 | 0 | 383 | 0.617 | 1.000 |
| PERSON-only | case | 697 | 970 | 30 | 303 | 0.697 | 0.970 |
| regex+PERSON-only | lower | 1000 | 1000 | 0 | 0 | 1.000 | 1.000 |
| regex+PERSON-only | case | 1000 | 970 | 30 | 0 | 1.000 | 0.970 |

- NER-noORG flips: {'TN->FP': 54, 'FN->TP': 76, 'TP->FN': 57}
  - TN->FP labels (NER-noORG): PERSON 30 e.g. 'Xs', 'Xs', 'Xs'; GPE 24 e.g. 'US', 'US', 'US'
- regex+NER-noORG flips: {'TN->FP': 54}
- PERSON-only flips: {'FN->TP': 134, 'TN->FP': 30, 'TP->FN': 54}
  - TN->FP labels (PERSON-only): PERSON 30 e.g. 'Xs', 'Xs', 'Xs'
- regex+PERSON-only flips: {'TN->FP': 30}

**openai** (N=1000)

| Definition | Mode | TP | TN | FP | FN | Recall | Spec |
|---|---|---|---|---|---|---|---|
| NER-noORG | lower | 125 | 492 | 8 | 375 | 0.250 | 0.984 |
| NER-noORG | case | 155 | 495 | 5 | 345 | 0.310 | 0.990 |
| regex+NER-noORG | lower | 460 | 458 | 42 | 40 | 0.920 | 0.916 |
| regex+NER-noORG | case | 462 | 461 | 39 | 38 | 0.924 | 0.922 |
| PERSON-only | lower | 77 | 493 | 7 | 423 | 0.154 | 0.986 |
| PERSON-only | case | 98 | 496 | 4 | 402 | 0.196 | 0.992 |
| regex+PERSON-only | lower | 456 | 459 | 41 | 44 | 0.912 | 0.918 |
| regex+PERSON-only | case | 457 | 462 | 38 | 43 | 0.914 | 0.924 |

- NER-noORG flips: {'FN->TP': 44, 'TP->FN': 14, 'FP->TN': 4, 'TN->FP': 1}
  - TN->FP labels (NER-noORG): PERSON 1 e.g. 'Sparky'
- regex+NER-noORG flips: {'FP->TN': 4, 'FN->TP': 2, 'TN->FP': 1}
- PERSON-only flips: {'FN->TP': 33, 'TP->FN': 12, 'FP->TN': 4, 'TN->FP': 1}
  - TN->FP labels (PERSON-only): PERSON 1 e.g. 'Sparky'
- regex+PERSON-only flips: {'FP->TN': 4, 'FN->TP': 1, 'TN->FP': 1}
