# PriVoke Evaluation

This folder contains everything needed to benchmark the PriVoke detector against public PII and NER datasets. It is completely standalone — it has nothing to do with Docker or the application stack. It imports the `privoke_client_runtime` package directly and runs your detector in-process on your local machine.

---

## Setup

**Step 1 — Create a virtual environment inside this folder.**

On macOS (Homebrew Python) you must use a venv to avoid the `externally-managed-environment` error. 

```bash
cd evaluation
python3 -m venv venv
source venv/bin/activate
```

**Step 2 — Install the evaluation dependencies.**

```bash
pip install -r requirements.txt
```

**Step 3 — Install the PriVoke client runtime.**

Your detector must be pip-installed as an editable package. A plain folder path does not work because `pyproject.toml` maps the `src/` directory to the `privoke_client_runtime` package name — that mapping only happens through setuptools.

```bash
pip install -r ../services/client-runtime/requirements.txt
pip install -e ../services/client-runtime
```

**Every time you come back**, activate the venv first:

```bash
source venv/bin/activate
```

---

## Running Tests

### Layers

There are three layers you can test independently.

| Layer | What it runs | External dependencies |
|---|---|---|
| `regex` | Regex rule detector only | None — always works |
| `ner` | spaCy NER detector only | None — always works |
| `pipeline` | Full detector (regex + NER + semantic) | Needs a semantic backend — see below |

`regex` and `ner` are the safest starting point. They have zero network or container dependencies and test the deterministic parts of your detector directly.

`pipeline` runs the full detector including the semantic classifier. Override the backend with an environment variable:

```bash
# Use the streamed backend (needs model-streaming-service container running)
PRIVOKE_LLM_CHOICE=streamed python evaluate.py --dataset ai4privacy --layer pipeline

# Use OpenAI
PRIVOKE_LLM_CHOICE=openai OPENAI_API_KEY=sk-... python evaluate.py --dataset ai4privacy --layer pipeline
```

---

### Commands

**AI4Privacy** (177,652 rows)
```bash
python evaluate.py --dataset ai4privacy --samples 500  --layer regex
python evaluate.py --dataset ai4privacy --samples 500  --layer ner
python evaluate.py --dataset ai4privacy --samples all  --layer regex
python evaluate.py --dataset ai4privacy --samples all  --layer ner
```

**CoNLL-2003** (3,453 rows)
```bash
python evaluate.py --dataset conll2003 --samples 200  --layer regex
python evaluate.py --dataset conll2003 --samples 200  --layer ner
python evaluate.py --dataset conll2003 --samples all  --layer ner
```

**PIIBench** (799,948 rows)
```bash
python evaluate.py --dataset piibench --samples 500  --layer regex
python evaluate.py --dataset piibench --samples 500  --layer ner
python evaluate.py --dataset piibench --samples all  --layer regex
```

**Gretel Finance** (5,594 rows)
```bash
python evaluate.py --dataset gretel-finance --samples 500  --layer regex
python evaluate.py --dataset gretel-finance --samples 500  --layer ner
python evaluate.py --dataset gretel-finance --samples all  --layer regex
python evaluate.py --dataset gretel-finance --samples all  --layer ner
```

**Nemotron-PII** (100,000 rows)
```bash
python evaluate.py --dataset nemotron --samples 500  --layer regex
python evaluate.py --dataset nemotron --samples 500  --layer ner
python evaluate.py --dataset nemotron --samples all  --layer regex
```

**Meddies PII** (47,744 rows)
```bash
python evaluate.py --dataset meddies --samples 500  --layer regex
python evaluate.py --dataset meddies --samples 500  --layer ner
python evaluate.py --dataset meddies --samples all  --layer ner
```

**PII Shield** (-)
```bash
python evaluate.py --dataset pii-shield --samples 500  --layer regex
python evaluate.py --dataset pii-shield --samples 500  --layer ner
```

**Full pipeline (needs semantic backend running)**
```bash
PRIVOKE_LLM_CHOICE=openai OPENAI_API_KEY=sk-... \
  python evaluate.py --dataset ai4privacy --samples 500 --layer pipeline
```

**Quick smoke test — 20 samples to check everything is wired up**
```bash
python evaluate.py --dataset ai4privacy --samples 20 --layer regex
```

`--samples all` loads every row in the dataset. `--samples N` takes the first N rows.

---

## What the Output Looks Like

```
=== PriVoke Evaluation: gretel-finance (ner) ===

| Metric              |    Value |
|---------------------|----------|
| Requested samples   |   10     |
| Loaded samples      |   10     |
| Errors              |    0     |
| Precision           |    1     |
| Recall              |    0.778 |
| F1                  |    0.875 |
| Accuracy            |    0.8   |
| Specificity         |    1     |
| False Positive Rate |    0     |
| False Negative Rate |    0.222 |
| Avg Latency Ms      |  513.801 |
| P95 Latency Ms      |  630.471 |
| Min Latency Ms      |  407.941 |
| Max Latency Ms      |  630.471 |
| True Positives      |    7     |
| True Negatives      |    1     |
| False Positives     |    0     |
| False Negatives     |    2     |

False negatives (missed PII): 2
False positives (over-flagged): 0

Sample failures (first 5):
  [false_negative] action=ALLOW categories=[]
    text: Humanitarian Aid Fund, Inc. Investment Prospectus...
```

A full JSON report including every failure is saved to `results/<dataset>_<layer>_results.json`.

---

## Metric Definitions

| Metric | What it means for a privacy tool |
|---|---|
| **Precision** | Of everything your detector flagged, how much actually contained PII. High precision = few false alarms. |
| **Recall** | Of all the real PII in the dataset, how much your detector caught. **This is the most important metric** — a miss means sensitive data goes undetected. |
| **F1** | Harmonic mean of precision and recall. Best single summary of overall detector quality. |
| **Accuracy** | Overall fraction of correct allow/flag decisions. Less informative when the dataset is heavily imbalanced toward PII. |
| **Specificity** | Of all the clean (no-PII) samples, how many your detector correctly left alone. |
| **False Positive Rate** | Fraction of clean samples incorrectly flagged. |
| **False Negative Rate** | Fraction of real PII samples your detector missed. Minimising this is the primary goal. |
| **False negatives** | PII samples your detector returned ALLOW on — the misses you want to eliminate. |
| **False positives** | Clean text your detector flagged — annoying but less harmful than false negatives for a privacy tool. |
| **`detected_categories: []` on false negatives** | Always expected. A false negative means ALLOW was returned, and ALLOW means no `ClassificationResult` object exists to pull categories from. |

---

## Datasets

### 1. AI4Privacy — `ai4privacy/pii-masking-300k`
**HuggingFace:** https://huggingface.co/datasets/ai4privacy/pii-masking-300k  
**Size:** 177,652 rows  
**License:** Custom academic/research  

The closest public dataset to real-world LLM prompt PII. Each row contains a raw source text and a list of annotated PII spans, where each span includes the exact character offsets and a label such as `USERNAME`, `EMAIL`, `FIRSTNAME`, `SSN`, `CREDITCARDNUMBER`, `DATE_OF_BIRTH`, `IBAN`, `BITCOINADDRESS`, and many more. Texts are synthetic but realistic — they look like emails, form submissions, support tickets, and chat messages.

**Schema:**
```json
{
  "source_text": "Hi, my name is wennmann27 and my SSN is 219-09-9999.",
  "privacy_mask": [
    {"label": "USERNAME",  "value": "wennmann27",  "start": 15, "end": 25},
    {"label": "SSN",       "value": "219-09-9999", "start": 42, "end": 53}
  ]
}
```

**Best for:** Primary benchmark. The widest variety of PII types, the most realistic text, and the largest usable sample count. Run this first and run it on `--samples all`.

> Note: We use `pii-masking-300k`, not `pii-masking-400k`. The 400k version requires written permission from AI4Privacy for use beyond a narrow set of listed purposes. The 300k version has no such restriction.

---

### 2. CoNLL-2003 — `eriktks/conll2003`
**HuggingFace:** https://huggingface.co/datasets/eriktks/conll2003  
**Size:** 3,453 rows (test split)  
**License:** Research use  

The standard NER benchmark built from 1990s Reuters newswire articles. Token-by-token annotation with four entity types: `PER` (person), `ORG` (organisation), `LOC` (location), `MISC` (miscellaneous).

**Schema:**
```json
{
  "tokens":   ["EU", "rejects", "German", "call", "to", "boycott", "British", "lamb"],
  "ner_tags": [3,    0,         7,        0,      0,    0,         7,         0    ]
}
```
Tags are numeric indices into the label list: `O`, `B-PER`, `I-PER`, `B-ORG`, `I-ORG`, `B-LOC`, `I-LOC`, `B-MISC`, `I-MISC`.

**Best for:** Isolating NER layer specifically. CoNLL-2003 was purpose-built to test NER models so it gives the clearest signal on whether spaCy `en_core_web_sm` is correctly finding named entities in natural language text.

> Important caveat: This is a news dataset, not a privacy dataset. Many sentences contain entities like `"EU"` or `"Germany"` that are not personal PII. Low recall on CoNLL-2003 does not mean your detector is broken — use AI4Privacy as your primary benchmark and CoNLL-2003 only for diagnosing NER layer behaviour.

> Note on loading: Plain `load_dataset("conll2003")` is broken on recent `datasets` library versions because HuggingFace no longer auto-executes loading scripts. The script pins to `eriktks/conll2003` at the `refs/convert/parquet` revision, which is the documented workaround.

---

### 3. PIIBench — `Pritesh-2711/pii-bench`
**HuggingFace:** https://huggingface.co/datasets/Pritesh-2711/pii-bench  
**Size:** 799,948 rows  
**License:** Research use  
**Paper:** https://arxiv.org/pdf/2604.15776  

A purpose-built multi-source PII benchmark that consolidates and standardises several existing NER and PII datasets into one unified corpus. It was specifically designed to address the gap that most NER benchmarks (like CoNLL-2003) were not built for PII detection — they include entity types that are not sensitive (ANIMAL, FOOD, VEHICLE) while omitting PII types that matter in production (financial identifiers, government IDs). PIIBench covers person names, locations, organisations, dates, phone numbers, emails, and addresses with consistent annotation across all source datasets.

**Best for:** Large-scale evaluation at nearly 800k rows. Useful for getting statistically reliable recall numbers for names and locations, and for comparing your detector against published baseline results from the paper.

---

### 4. NVIDIA Nemotron-PII — `nvidia/Nemotron-PII`
**HuggingFace:** https://huggingface.co/datasets/nvidia/Nemotron-PII  
**Size:** 100,000 rows  
**License:** Research use  

Fully synthetic, persona-grounded dataset generated with NVIDIA NeMo Data Designer. Spans 50+ industries and covers 55+ PII/PHI entity types including both US and international formats. Includes structured documents (forms, tables) and unstructured prose. Designed specifically to train and evaluate NER models for healthcare, finance, legal, and enterprise compliance scenarios.

**Best for:** Stress-testing the detector against a wider variety of PII types than AI4Privacy — particularly healthcare PHI categories (diagnoses, medications, patient IDs) which map directly to your `HEALTH` category. Also good for testing your detector on formal document formats rather than conversational text.

---

### 5. Gretel Synthetic PII Finance — `gretelai/synthetic_pii_finance_multilingual`
**HuggingFace:** https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual  
**Size:** 5,594 rows (test split)  
**License:** Apache 2.0  

Synthetic financial documents in 7 languages (English, Spanish, German, French, Italian, Dutch, Swedish). Generated using Gretel Navigator with Mistral-7B. Covers 100+ financial document formats including bank statements, loan applications, tax documents, and compliance reports. PII types include `iban`, `bban`, `credit_card_number`, `bank_routing_number`, `ssn`, `first_name`, `last_name`, `street_address`, `email`, `phone_number`, `passport_number`, and more.

**Schema:**
```json
{
  "generated_text": "Dear Mr. Smith, your IBAN is GB29NWBK60161331926819...",
  "pii_spans": "[{\"label\": \"name\", \"start\": 8, \"end\": 16}, {\"label\": \"iban\", \"start\": 28, \"end\": 50}]",
  "language": "English",
  "document_type": "bank_statement"
}
```

**Best for:** Evaluating your `FINANCIAL` category rules specifically — this is the most realistic financial document dataset available, testing whether your regex rules for IBAN, credit cards, bank accounts, and SSNs hold up against documents that actually look like real financial paperwork.

---

### 6. PII Shield — `auren-research/pii-shield`
**HuggingFace:** https://huggingface.co/datasets/auren-research/pii-shield  
**Size:** -  
**License:** Research use  

Synthetic privacy-focused dataset containing user prompts annotated with personally identifiable information (PII) entities and privacy risk labels. Designed around realistic LLM interaction scenarios where users may unintentionally expose sensitive information while communicating with AI systems. Covers a range of PII categories including names, emails, phone numbers, addresses, financial details, credentials, and other sensitive attributes. Provides labelled examples suitable for evaluating PII detection, entity extraction, and privacy warning systems.

**Best for:** Evaluating PriVoke in realistic AI assistant scenarios because examples resemble actual user prompts rather than traditional documents. Useful for testing whether the detector can identify accidental privacy leakage during LLM interactions and correctly trigger warnings before data is shared with external AI services.

---

### 7. Meddies PII — `Meddies/meddies-pii`
**HuggingFace:** https://huggingface.co/Meddies/meddies-pii  
**Size:** 47,744 rows  
**License:** Research use  

Multilingual PII extraction dataset containing clinical and administrative text annotated with structured PII entity labels. Focuses on high-risk healthcare and enterprise privacy scenarios, including medical records, patient information, and administrative documents. Contains realistic sensitive information across multiple languages and document formats, enabling evaluation of PII detection models in domain-specific environments. Provides raw text samples with corresponding entity annotations for categories such as personal identifiers, contact information, and healthcare-related sensitive attributes.

**Best for:** Testing PriVoke’s ability to detect high-impact privacy leaks in healthcare and administrative contexts. Particularly valuable for evaluating the detector’s HEALTH risk category, where combinations such as patient names, medical information, and identifiers should receive higher severity scores. Complements conversational datasets like PII-Shield by providing more formal document-style privacy exposure scenarios.

---

## References

1. `ai4privacy/pii-masking-300k` (177,652 rows): https://huggingface.co/datasets/ai4privacy/pii-masking-300k
2. `eriktks/conll2003` (3,453 rows): https://huggingface.co/datasets/eriktks/conll2003
3. `Pritesh-2711/pii-bench` (799,948 rows): https://huggingface.co/datasets/Pritesh-2711/pii-bench
4. `nvidia/Nemotron-PII` (100,000 rows): https://huggingface.co/datasets/nvidia/Nemotron-PII
5. `gretelai/synthetic_pii_finance_multilingual` (5,594 rows): https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual
6. `auren-research/pii-shield`: https://huggingface.co/datasets/auren-research/pii-shield
7. `Meddies/meddies-pii` (47,744 rows): https://huggingface.co/Meddies/meddies-pii