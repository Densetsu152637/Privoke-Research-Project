# Case-preservation ablation (regex and NER detector layers)

Detector-layer ablation (regex and spaCy `en_core_web_sm` NER). This is not LLM-only or semantic evidence.

Change: `PRIVOKE_CASE_PRESERVING_DETECTORS=1` (`GLOBAL_CONFIG.case_preserving_detectors`, default off) gives regex/NER
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
