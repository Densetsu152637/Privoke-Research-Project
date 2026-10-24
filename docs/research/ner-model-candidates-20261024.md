# NER model candidates for the NER layer (scouting, 2026-10-24)

Desk research only: no model, package or dataset was downloaded or installed. Sources are model cards, the Hugging Face API file listing (sizes), spaCy model metadata and PyPI metadata, read on 2026-10-24. Figures marked "unverified" were not confirmed from a primary page. Companion measurement: `docs/experiments/ner-role-20261024.md`.

## What the integration needs

`src/NER/ner_detector.py` loads a spaCy pipeline and maps `PERSON`, `GPE`, `LOC`, `FAC`, `ORG` entities to PriVoke classifications. `src/NER/ner_postfilter.py` consumes a **spaCy `Doc`**: several rules use dependency and POS information (`_possessed_role_head`, `line_has_verb`, common-word re-tagging) and the model's lemmatizer lexicon. Consequences:

- Any spaCy-format model (`md`, `lg`, `trf`) is a drop-in: change the model name. `PRIVOKE_NER_MODEL` (default-off option added in this work) already does that.
- Non-spaCy backends (GLiNER, Hugging Face token classifiers, Flair, Presidio engines) emit character spans and labels only. They need a new backend class and a way to keep the post-filter: run `en_core_web_sm` in parallel for syntax and attach the foreign spans with `doc.char_span(..., alignment_mode="expand")`, or run only the span-independent rules. Medium effort (new class, label mapping to `NER_LABEL_USE_CASES`, tests); the label scheme of PII-tuned models (name, address parts, phone, ...) is richer than the five spaCy labels, so the use-case table and the regex overlap policy (the regex layer owns structured identifiers) need a decision.
- Case: the detectors now receive case-preserved text. Cased models (spaCy, GLiNER with a cased BPE tokenizer) benefit; an uncased model would not.

## Candidates

| Candidate | Exact id / package | Download | Licence | CPU latency expectation | English PII label coverage | Integration | Case |
|---|---|---|---|---|---|---|---|
| spaCy sm (current) | `en_core_web_sm` 3.7.1 | 12 MB | MIT | baseline: regex+NER measured 46 ms/prompt on this machine | OntoNotes 18 types; used: PERSON, GPE, LOC, FAC, ORG. NER F 84.6 (PERSON 87.7, GPE 90.4, ORG 80.9, LOC 69.7, FAC 32.2) | in place | cased |
| spaCy md | `en_core_web_md` 3.7.1 | 40 MB | MIT | same CNN as sm plus vectors; about sm speed | same labels; NER F 85.2 (PERSON 89.6, GPE 91.7, ORG 82.1, LOC 67.5, FAC 40.8) | drop-in | cased |
| spaCy lg | `en_core_web_lg` 3.7.1 | 560 MB (**already installed in `evaluation/.venv-v1-v3-pipeline`**) | MIT (trained on OntoNotes licensed by Explosion) | spaCy facts page: 10,014 words/s on CPU (hardware unspecified) | same labels; NER F 85.4 (PERSON 89.6, GPE 91.6, ORG 82.4, LOC 65.0, FAC 41.6) | drop-in (`PRIVOKE_NER_MODEL`) | cased |
| spaCy trf | `en_core_web_trf` 3.7.3 (roberta-base) + `spacy-curated-transformers>=0.2.0,<0.3.0` | 436 MB model + small wheels | MIT | 684 words/s on CPU (spaCy facts page), about 15x slower than lg | same labels; NER F 90.2 (PERSON 95.3, GPE 95.3, ORG 90.4, LOC 81.6, FAC 64.3) | drop-in once the package is installed; torch 2.11 CPU already in the pipeline venv | cased |
| GLiNER PII small | `knowledgator/gliner-pii-small-v1.0` + `gliner==0.2.29` | `pytorch_model.bin` 326,195,231 B (311 MiB); ONNX int8 79 MiB; tokenizer 3.4 MiB | Apache-2.0 (model and package) | no published CPU figure for this checkpoint. Backbone ettin-encoder-68m (ModernBERT, 19 layers, hidden 512), max length 2048 tokens. Third-party small GLiNER ONNX builds report 236 to 512 ms on a long multi-entity text on an Intel CPU (different model, unverified here). Expect 10x to 50x spaCy sm per prompt | 60+ zero-shot PII labels: name, first/last name, email, phone, ip, url, address/street/city/state/country/zip, dob, age, ssn, passport, driver licence, credit card, cvv, account/routing numbers, username, password, medical terms. Vendor benchmark (own synthetic set): P 79.0 / R 74.8 / F1 76.8 | new backend; labels are caller-supplied strings | cased tokenizer (BPE); confirm on a probe |
| GLiNER PII edge | `knowledgator/gliner-pii-edge-v1.0` | 181 MB `.bin`; ONNX int8 46 MB | Apache-2.0 | smaller (ettin-encoder-32m, 10 layers); faster than small | same label set; vendor F1 75.5 | as above | cased |
| GLiNER PII base | `knowledgator/gliner-pii-base-v1.0` | 664 MB | Apache-2.0 | slower (larger encoder) | vendor F1 81.0; large 83.3 | as above | cased |
| GLiNER multi PII | `urchade/gliner_multi_pii-v1` (Presidio's default GLiNER) | 1.16 GB `.bin` (mDeBERTa) | Apache-2.0 | slow on CPU | about 53 PII types, six languages; vendor F1 76.9 on the same benchmark | as above; Presidio `GLiNERRecognizer` wraps it (present in installed presidio_analyzer 2.2.363; needs the `gliner` extra) | cased |
| Presidio transformers engine | Presidio `TransformersNlpEngine` with `StanfordAIMI/stanford-deidentifier-base` (docs example) + `en_core_web_sm` | 438 MB `.bin` | MIT | BERT-base, roughly 10x to 30x spaCy sm (unverified) | de-identification labels trained on radiology reports (patient, staff, hospital, date, id, age, phone, vendor) mapped to PERSON/LOCATION/...; domain mismatch to chat prompts | Presidio engine; spaCy still supplies tokens, so the post-filter still has a Doc, but entity alignment is by token | uncased, case-insensitive |
| HF NER (CoNLL) | `dslim/bert-base-NER` | about 433 MB (108M params) | MIT | BERT-base class, 10x+ slower than sm | only PER, ORG, LOC, MISC; no GPE/FAC | new backend | cased |
| Flair | `flair/ner-english-ontonotes-fast` | 1.30 GB | no licence tag on the card (Flair classic models are described as non-commercial: do not use without confirmation) | LSTM-CRF with Flair embeddings; slower than spaCy | OntoNotes 18 types, F1 89.3 | new backend, new framework | cased |
| Piiranha | `iiiorg/piiranha-v1-detect-personal-information` | 278M params (deberta-v2) | CC BY-NC-ND 4.0 | slow | about 17 PII types (unverified); trained on ai4privacy | excluded: non-commercial/no-derivatives licence, and ai4privacy is also a source of the development set (contamination) | cased |
| Gretel GLiNER | `gretelai/gretel-gliner-bi-small-v1.0` | 757 MB | Apache-2.0 | bi-encoder, heavier than knowledgator small | PII/PHI | not recommended: trained on `gretelai/gretel-pii-masking-en-v1`, which is also a development-set source (contamination) | cased |

## Notes on risk

- **Training-data contamination**: the development set draws on nemotron-pii, ai4privacy, gretel and privy. Models trained on those corpora (Piiranha, Gretel GLiNER) must not be scored on `development.jsonl`. The knowledgator checkpoints were fine-tuned on `data/pii_full.json` (synthetic multi-PII); its provenance and overlap with those corpora is **unknown** and should be checked before development-set numbers are interpreted; the fresh held-out set (item 2) is the safe scoring set.
- **Label scheme**: GLiNER returns the labels that are asked for. Scoring uses flag-level positives (any entity), so a permissive label list inflates false positives; the label list is a tuned hyperparameter and must be fixed on design splits only.
- **Dependencies** for GLiNER (`gliner 0.2.29`, released 2026-09-08, Python >= 3.10): `torch>=2.0`, `transformers>=4.51.3,<5.17`, `huggingface_hub`, `numpy`, `safetensors`, `tqdm`, `sentencepiece`; optional `onnxruntime` for the ONNX files. The pipeline venv already has torch 2.11 CPU and transformers 4.57.6, so the version windows are compatible, but the product runtime pins must not change.
- **Size**: the extension ships the runtime locally. lg adds about 550 MB over sm, trf about 424 MB plus torch, GLiNER small about 311 MiB (79 MiB as int8 ONNX) plus torch or onnxruntime. Any of these is a distribution decision for the user, independent of accuracy.

## Recommendation for Wave 2 (in priority order)

1. **`en_core_web_lg` through the product pipeline** (`PRIVOKE_NER_MODEL=en_core_web_lg`). No download. The offline run in `ner-role-20261024.md` shows a post-review gain (dev-CHECK +4 TP and -4 FP versus sm, openai +1 TP and -3 FP) but no design-split gain; test it on the fresh held-out split and record latency.
2. **`en_core_web_trf`**: the best accuracy of the drop-in spaCy models (PERSON F 95.3 vs 87.7 for sm), the same labels and post-filter, no backend work. Cost: 436 MB and about 15x slower CPU inference; decide on a latency budget.
3. **`knowledgator/gliner-pii-small-v1.0`**: the only candidate that covers PII categories the spaCy labels cannot (address parts, dates of birth, ids), permissive licence, Apache-2.0 tooling. Requires the new backend class and a label-list decision; test the int8 ONNX variant if latency is too high. Not recommended beyond these three: the rest are larger, unlicensed for this use, contaminated against development data, or domain-mismatched.

## Download requests (none performed; each needs explicit approval)

| Name | Source | Size | Licence | Purpose |
|---|---|---|---|---|
| `en_core_web_trf` 3.7.3 | https://github.com/explosion/spacy-models/releases/tag/en_core_web_trf-3.7.3 | about 436 MB (spaCy metadata) | MIT | drop-in accuracy ceiling for the spaCy label scheme |
| `spacy-curated-transformers` (>=0.2.0,<0.3.0), `curated-transformers`, `curated-tokenizers` | PyPI | a few MB each (unverified); pulls no new torch if the venv below reuses a CPU torch wheel | MIT (unverified) | runtime for `en_core_web_trf` |
| `knowledgator/gliner-pii-small-v1.0` | https://huggingface.co/knowledgator/gliner-pii-small-v1.0 | 311 MiB `pytorch_model.bin` + 3.4 MiB tokenizer (optional ONNX int8: 79 MiB). `from_pretrained` may also fetch the backbone's tokenizer/config from `jhu-clsp/ettin-encoder-68m` (small; licence to confirm) | Apache-2.0 | PII-label NER candidate |
| `gliner==0.2.29` | https://pypi.org/project/gliner/0.2.29/ | 256 KiB wheel; torch/transformers/sentencepiece come from the new venv | Apache-2.0 | GLiNER runtime |

New dependencies must not enter the existing pipeline venv. Proposal (not created): venv `evaluation/.venv-ner-models` (Python 3.11) from `evaluation/requirements-ner-models.txt` containing `spacy==3.7.5`, `numpy==1.26.4`, `torch==2.11.0` (CPU wheel, same as the pipeline venv), `transformers==4.57.6`, `gliner==0.2.29`, `onnxruntime` (optional), `spacy-curated-transformers>=0.2.0,<0.3.0`, plus the `en_core_web_*` wheels. Reinstalling the CPU torch wheel in that venv is itself a large download (hundreds of MB, unverified); to avoid it the venv could be created with `--system-site-packages`-style reuse only if the user prefers, otherwise treat torch as part of this request.
