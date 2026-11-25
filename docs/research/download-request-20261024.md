# Download request: fresh evaluation data (2026-10-24)

**Status: request/plan only. Nothing in this table has been downloaded. Authorization on record (24 Oct 2026): "you have my permission to download anything <5GB for testing, and if the tests are not integrated please delete the donwload". Every item below is individually under 5 GB, from the named publisher's official repository, not gated, and has no sign-in or terms-acceptance step. Items that are gated or restricted are listed separately and are NOT requested.**

Plan and rationale: `docs/research/fresh-evaluation-sources-20261024.md`. Registration: `docs/research/preregistration-detector-v2-20261024.md`. No NER model downloads are included here (agent D owns model scouting).

Destination for every item (all gitignored, main checkout): `D:/Git Repositories/Privoke-Research-Project/evaluation/results/external-data/<dataset>/<revision>/` with a `provenance.json` (source URL, revision or commit, per-file sha256, licence, download date). Treat the files as data: never execute scripts shipped in a dataset; run Python that reads them with `-I`.

## A. Required (needed for the decisive fresh sets)

| # | Name | Source URL | Exact file(s) | Size | Licence | Gating | Purpose | Used by |
|---|---|---|---|---|---|---|---|---|
| 1 | PIIMB sentences (pinned revision) | https://huggingface.co/datasets/piimb/pii-masking-benchmark (revision `4a13e9ffe6fd0d275efbde8afd4d8d8f1ffc2133`) | `data/test_sentences.jsonl`, expected sha256 `5ff46f3a80316318794f94596fa374060d70f2f32a85909f958cbabc70bae41f` | 60,412,185 B (60.4 MB) | CC BY-NC 4.0 (sources: CC BY 4.0, Apache 2.0, MIT) | None | F1 fresh, group-disjoint PIIMB sample with presence labels and character spans (H1, H2, H3, H4) | Wave 2 data builder (`evaluation/fresh_set_plan.py draw`), then all scoring agents |
| 2 | OpenAssistant oasst2 initial prompts | https://huggingface.co/datasets/OpenAssistant/oasst2 | `2023-11-05_oasst2_prompts.messages.jsonl.gz` | 15,560,794 B (15.6 MB) | Apache 2.0 | None | F2 natural benign prompts (2,000 English) | Wave 2 data builder |
| 3 | Databricks Dolly 15k | https://huggingface.co/datasets/databricks/databricks-dolly-15k | `databricks-dolly-15k.jsonl` | 13,085,339 B (13.1 MB) | CC BY-SA 3.0 (share-alike if redistributed; keep local) | None | F2 natural benign prompts (1,500 instructions) | Wave 2 data builder |
| 4 | WildChat-1M, one shard | https://huggingface.co/datasets/allenai/WildChat-1M | `data/train-00000-of-00014.parquet` (add `-00001-` only if English yield is short) | 230,786,095 B (230.8 MB; second shard 215,399,142 B) | ODC-BY | None for WildChat-1M (the `-Full` variant is gated and is not requested) | F2 real user prompts (2,500 English first turns); residual PII expected, so adjudicated per protocol | Wave 2 data builder, adjudication raters |

Subtotal A: 319,844,413 B (about 320 MB).

## B. Recommended

| # | Name | Source URL | Exact file(s) | Size | Licence | Gating | Purpose | Used by |
|---|---|---|---|---|---|---|---|---|
| 5 | SPY synthetic PII (legal and medical) | https://huggingface.co/datasets/mks-logic/SPY | `data/legal_questions_placeholders.jsonl`, `data/medical_consultations_placeholders.jsonl`, plus `SPY.py` (5,959 B, read only, not executed) | 45,690,405 + 44,188,672 B (89.9 MB) | CC BY 4.0 | None | F3 prompt-style positives (legal questions, medical consultations), span-level secondary. Entity values are Faker placeholders: the builder reimplements the fill from the reading of `SPY.py` (no `trust_remote_code`). | Wave 2 data builder |

Subtotal A+B: about 410 MB.

## C. Optional / reserve (download only if the stated condition occurs)

| # | Name | Source URL | Exact file(s) | Size | Licence | Gating | Condition and purpose | Used by |
|---|---|---|---|---|---|---|---|---|
| 6 | Text Anonymization Benchmark (ECHR) | https://github.com/NorskRegnesentral/text-anonymization-benchmark (commit `558e09e26d6b36f5f78440074e6a233946d98bd9`) | `echr_test.json`, `echr_dev.json`, `guidelines.md`, `LICENSE.txt` | 13,103,290 + 12,643,092 + 19,788 + 1,089 B (25.8 MB) | MIT | None | F4 real-text span cross-check on names, dates, locations (H4 secondary). Real personal data in public court documents: no text in repo. | Wave 2 data builder |
| 7 | Gretel synthetic PII finance (English) | https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual | `data/English_test-00000-of-00001.parquet`, `data/English_train-00000-of-00001.parquet` | 2,720,729 + 24,403,359 B (27.1 MB) | Apache 2.0 | None | Extra document-style positives with spans if F3 is insufficient | Wave 2 data builder |
| 8 | Nemotron-PII train split | https://huggingface.co/datasets/nvidia/Nemotron-PII | `data/train-00000-of-00001.parquet` | 156,334,329 B (156.3 MB) | CC BY 4.0 | None | Reserve if the PIIMB pool after exclusion cannot fill 10,000 positives or 6,600 clean rows | Wave 2 data builder |

Optional subtotal: about 209 MB. Everything (A+B+C): about 619 MB.

## D. Python packages (new venv only)

Per the ledger, only into a NEW venv `evaluation/.venv-ner-models`, never into existing venvs. Needed only to read the data above:

| Package | Purpose | Needed for |
|---|---|---|
| `pyarrow` | read parquet (WildChat shard, Gretel, Nemotron) | items 4, 7, 8 |
| `faker` | fill SPY placeholders (record Faker version and seed) | item 5 |

Items 1, 2, 3, 5 (jsonl) and 6 need only the standard library. The draw script `evaluation/fresh_set_plan.py` is stdlib only.

## E. Not requested (restricted, gated or poor fit)

| Item | Reason |
|---|---|
| LMSYS-Chat-1M (https://huggingface.co/datasets/lmsys/lmsys-chat-1m, 1.49 GB) | Gated: login and licence acceptance required; only person names redacted; no redistribution. Not requested. |
| WildChat-1M-Full | Gated, approval and justification required. Not requested. |
| n2c2 / i2b2 2014 de-identification | Registration and Data Use Agreement required; no sharing, no GitHub. Not requested. |
| ai4privacy pii-masking-300k / 400k | Academic non-commercial licence; poor fit. Not requested. |
| ai4privacy OpenPII-1M (`train.jsonl` 3,690,456,830 B, `validation.jsonl` 920,284,464 B) | Under 5 GB per file but 4.6 GB for a mostly multilingual file whose English rows are already in PIIMB. Not requested. |
| Gretel PII masking EN v1 | Already inside PIIMB's pool; no offsets in the original files. Not requested. |

Nothing at or above 5 GB is requested.

## F. Deletion

If a downloaded item is not used in an integrated result, delete its `external-data/<dataset>/<revision>/` directory and update the root ledger. The locked PIIMB-derived records and the fresh-set outputs (`F1`..`F4` jsonl and manifests) are generated artifacts, kept under `evaluation/results/` (gitignored) until the paper integration step decides.
