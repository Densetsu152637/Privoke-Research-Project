# PriVoke Phase 1: Runtime Privacy Protection Pipeline

A python based runtime AI safety pipeline that detects and enforces privacy protections on user input text in real time.

## Overview

PriVoke Phase 1 processes user input through a **hybrid detection system** combining:
- **Rule-based detector** (regex patterns for common PII)
- **Entity/NER detector** (spaCy ML-based named entity recognition)
- **Semantic LLM classifier** (OpenAI GPT-4o-mini for contextual understanding)

And produces decisions:
- **ALLOW** - No privacy risk detected
- **WARN_AND_MASK** - Medium risk, mask sensitive entities
- **BLOCK_PROMPT** - High privacy risk, reject input

Plus **structured metadata events** for telemetry (Phase 3).

## Architecture

```
User Prompt (Input)
  ↓
[LAYER 1] Browser Extension (Intercept)
  ↓
[LAYER 2] Preprocessing (Normalization)
  - Unicode normalization
  - Lowercase conversion
  - De-obfuscation (e.g., "[at]" → "@")
  - Whitespace cleanup
  ↓
[LAYER 3] Internal Model Service (Hybrid Detection)
  [3A] Rule-Based Detector (50% weight)
       ├─ Email, phone, SSN, credit cards
       ├─ Structured identity fields
       ├─ Family/health/financial keywords
       └─ Personal narratives
  [3B] Entity/NER Detector (spaCy)
       ├─ Regex-based: emails, phones, URLs, credit cards
       └─ ML-based: PERSON, GPE (location), PRODUCT (usernames)
  [3C] Semantic LLM Classifier (30% weight)
       ├─ Implicit/ contextual privacy risks
       ├─ Entity detection with reasoning
       └─ Risk category: PII/CREDENTIAL/FINANCIAL/HEALTH/NORMAL
  ↓
[LAYER 4] Fusion Engine (Risk Scoring)
  - Combines: Rule (50%) + LLM (30%) + Entity Boost (20%)
  - Risk score: 0.0 (safe) → 1.0 (critical)
  - Data type classification: DIRECT_PII, QUASI_PII, AUTH, CONTEXTUAL, NORMAL
  ↓
[LAYER 5] Enforcement Engine (Final Decision)
  - HIGH risk / DIRECT_PII → BLOCK_PROMPT
  - MEDIUM risk / QUASI_PII → WARN_AND_MASK
  - LOW risk → ALLOW
  ↓
[LAYER 6] Structured Event Emitter (Telemetry)
  - Time bucket, risk category, risk score bucket
  - Action taken, detector version
  - NO raw text (metadata only)
  ↓
[LAYER 7] Target Application
  - Original text, normalized text, or masked text
  - User notification (if WARN_AND_MASK)
  - Rejection message (if BLOCK_PROMPT)
```

## Compatible Datasets

PriVoke Phase 1 works with **any privacy-sensitive text dataset**, including:
- **PANORAMA** (Hugging Face): Privacy-sensitive text dataset (dataset used for testing so far)

## How to start?

### 1. Install Dependencies

```bash
cd runtime

# Create virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install packages
pip install -r requirements.txt

# Download spaCy model for NER
python -m spacy download en_core_web_sm
```

### 2. Set Up API Key

Create a `.env` file in the `runtime` directory:

```bash
cat > .env << EOF
OPENAI_API_KEY=sk-your-openai-api-key-here
EOF
```

### 3. Run the Pipeline

```bash
python main.py
```

This will:
- Process 8 test cases with privacy-sensitive text
- Display full detection output for each step
- Show enforcement decisions and masked outputs
- Emit structured telemetry events
- Output batch JSON for Phase 3 telemetry collection

### Example Output

```
[LAYER 1] USER INPUT FROM BROWSER EXTENSION
Original: My email is alice@example.com please reset my password

[LAYER 2] PREPROCESSING - TEXT NORMALIZATION
Normalized: my email is alice@example.com please reset my password

[LAYER 3A] RULE-BASED DETECTOR (Fast Pattern Matching)
  Category: PII
  Severity: HIGH
  Signals: email

[LAYER 3B] ENTITY/NER DETECTOR (Structured Entity Extraction)
  Emails detected: True
  Total entities: 1

[LAYER 3C] SEMANTIC LLM RISK DETECTOR (OpenAI GPT-4o-mini)
  Category: PII
  Severity: HIGH
  Reasoning: Email address is direct identifier with password reset request context

[LAYER 4] FUSION ENGINE - WEIGHTED RISK SCORING
  Final Category: PII
  Final Severity: HIGH
  Risk Score: 0.950
  Data Type: DIRECT_PII

[LAYER 5] ENFORCEMENT ENGINE - FINAL DECISION
  ACTION: BLOCK_PROMPT
  Reason: Direct PII detected (DIRECT_PII)

[LAYER 6] STRUCTURED EVENT EMITTER - METADATA TELEMETRY
  Event ID: evt_20260429140000_a1b2c3d4e5f6
  Risk Category: PII
  Risk Score: 0.95 (bucket: 0.8-1.0)
  Action Taken: BLOCK_PROMPT
  Detector Version: v1

[LAYER 7] TARGET APPLICATION OUTPUT
  Enforcement Action: BLOCK_PROMPT
  Display to User: [BLOCKED - Input rejected due to privacy risk]
```

## Project Structure

```
runtime/
├── main.py                          # Main pipeline entry point
├── requirements.txt                 # Python dependencies
├── .env                             # Environment variables (OPENAI_API_KEY)
│
├── preprocessing/
│   └── normalizer.py               # Text normalization
│       ├── Unicode normalization (NFKC)
│       ├─ Lowercase conversion
│       ├─ Obfuscation fixes ([at] -> @)
│       └─ Whitespace cleanup
│
└── detection/
    ├── rule_detector.py            # Pattern-based PII detection
    │   ├─ Emails, phones, SSN, credit cards
    │   ├─ Structured identity fields
    │   ├─ Health/financial/workplace keywords
    │   ├─ Personal narratives
    │   └─ Multiple patterns optimized for cross-domain privacy detection
    │
    ├── ner_detector.py             # Entity/NER extraction 
    │   ├─ Regex-based: emails, phones, URLs, credit cards, SSN
    │   ├─ spaCy ML-based: PERSON, GPE (location), PRODUCT
    │   ├─ Entity risk signal extraction
    │   └─ High-risk combination detection
    │
    ├── llm_classifier.py           # Semantic risk classification
    │   ├─ OpenAI GPT-4o-mini API calls
    │   ├─ Conservative privacy-first prompting
    │   ├─ Implicit risk detection
    │   ├─ JSON-structured responses
    │   └─ Fallback handling
    │
    ├── fusion.py                   # Risk scoring & fusion
    │   ├─ Weighted combination (Rule 50% + LLM 30% + Entity 20%)
    │   ├─ Entity boost for dangerous combinations
    │   ├─ Data type classification (DIRECT_PII, QUASI_PII, etc.)
    │   └─ Disagreement detection
    │
    ├── enforcement_engine.py       # Final enforcement decision
    │   ├─ Rule-based action selection
    │   ├─ Text masking for sensitive entities
    │   └─ Reason generation for decisions
    │
    └── event_emitter.py            # Structured telemetry events
        ├─ Metadata-only events (no raw text)
        ├─ Time/risk buckets
        ├─ Detector version tracking
        └─ Batch serialization for Phase 3
```

## Detection Components

### Rule Detector 
**Coverage:** High for known patterns  
**Patterns:**
- **Direct PII:** Email, US/Intl phone, SSN, credit cards, passport, IBAN
- **Quasi-PII:** Structured fields (name:, username:, location:), date fields, social handles
- **Contextual:** Family disclosure, health keywords, financial keywords, workplace info
- **Behavioral:** Timestamps, personal narratives (>80 words)

### Entity/NER Detector 
**Coverage:** Medium-high with ML + regex combination  
**Methods:**
- **Regex extraction:** Highly optimized patterns for emails, phones, credit cards, SSN
- **spaCy NER:** Trained model for PERSON, GPE (location), PRODUCT entities
- **Risk signal generation:** Entity combinations that increase risk
- **High-risk combinations:** Email+phone, name+location, email+name, credential+identity

### LLM Classifier
**Coverage:** Highest - catches implicit/contextual risks  
**Categories:**
- `PII`: Personally Identifiable Information
- `CREDENTIAL`: Login credentials, passwords, API keys
- `FINANCIAL`: Bank accounts, credit cards, salary, investments
- `HEALTH`: Medical conditions, medications, mental health
- `NORMAL`: Non-sensitive content

**Detects:**
- Implicit identifiers (unusual combinations)
- Contextual risks (job + location -> identifiable)
- Indirect threats (sensitive characteristic disclosure)

### Fusion Engine (Layer 4)
**Scoring Formula:**
```
raw_score = (rule_severity × 0.50) + (llm_severity × 0.30) + (entity_boost × 0.20)
```

**Entity Boost Rules:**
- Credentials + identity -> 3.0x (CRITICAL)
- Credentials alone -> 2.5x (HIGH)
- Name + location -> 2.0x (MEDIUM-HIGH)
- Email/phone -> 1.8x (MEDIUM)
- Single identifier -> 1.3x (LOW-MEDIUM)
- Quasi-identifiers -> 1.1x (LOW)

**Data Type Classification:**
- `DIRECT_PII`: Email, phone, credit card, SSN, or complete identifying profile
- `QUASI_PII`: Two or more weak identifiers (name+location, username+location)
- `AUTH`: Structured identity/credential fields
- `CONTEXTUAL`: Behavioral/relationship/health/workplace disclosure
- `NORMAL`: No detected risks

### Enforcement Engine (Layer 5)
**Decision Rules:**
```
IF severity == HIGH OR data_type == DIRECT_PII
  → ACTION = BLOCK_PROMPT
ELSE IF severity == MEDIUM OR data_type IN [QUASI_PII, AUTH]
  → ACTION = WARN_AND_MASK (mask entities)
ELSE
  → ACTION = ALLOW
```

**Masking Strategy:**
- Emails -> `[EMAIL]`
- Phone numbers -> `[PHONE]`
- Names -> `[NAME]`
- Locations -> `[LOCATION]`
- Credit cards -> `[CC]`
- SSN -> `[SSN]`

### Event Emitter (Layer 6)
**Structured Event Format:**
```json
{
  "event_id": "evt_20260429140000_a1b2c3d4e5f6",
  "timestamp": "2026-04-29T14:00:00Z",
  "time_bucket": "2026-04-29 14:00",
  "date_bucket": "2026-04-29",
  "risk_category": "PII|HEALTH|FINANCE|CREDENTIALS|NORMAL",
  "risk_score": 0.95,
  "risk_score_bucket": "0.8-1.0",
  "action_taken": "ALLOW|WARN_AND_MASK|BLOCK_PROMPT",
  "data_type": "DIRECT_PII|QUASI_PII|AUTH|CONTEXTUAL|NORMAL",
  "detector_version": "v1",
  "metadata": {
    "text_length": 48,
    "entities_detected": ["email"],
    "rule_severity": "HIGH",
    "llm_severity": "HIGH",
    "disagreement": false
  }
}
```

**Key Features:**
- **No raw text** - metadata only
- **Deaggregation-friendly** - time + risk buckets for privacy
- **Versioning** - track detector improvements (v1 -> v2 -> v2.1)

## Detector Versions

### v1 (Initial - Current)
- Rule-based patterns + baseline LLM
- Covers common PII types
- Works with any privacy-sensitive dataset

### v2 (Phase 2)
- Enhanced rules from fuzzer-discovered patterns
- Model retraining with hard examples
- Domain-specific pattern additions
- Updated thresholds based on feedback

### v2.1+ (Patches)
- Threshold tweaks
- New regex patterns for emerging threats
- Minor fixes and optimizations

## Data Flow Example

**Input:**
```
"My email is alice@example.com, please reset my password"
```

**Normalization:**
```
"my email is alice@example.com, please reset my password"
```

**Detection Results:**
- **Rule:** Category=PII, Severity=HIGH, Signals="email"
- **NER:** emails=[alice@example.com], total_entities=1
- **LLM:** Category=PII, Severity=HIGH, Reasoning="Email + password context"

**Fusion:**
```
raw_score = (3×0.5) + (3×0.3) + (1.8×0.2) = 1.5 + 0.9 + 0.36 = 2.76 → severity=HIGH
data_type = DIRECT_PII
```

**Enforcement:**
```
Action = BLOCK_PROMPT (HIGH severity + DIRECT_PII)
Reason = "Direct PII detected"
```

**Event:**
```json
{
  "event_id": "evt_...",
  "risk_category": "PII",
  "risk_score": 0.92,
  "action_taken": "BLOCK_PROMPT",
  "detector_version": "v1"
}
```

## Testing & Validation

### Test Cases Included
The pipeline includes 8 cross-domain test cases demonstrating privacy detection across multiple sensitive data types:
1. Email + password context (credentials)
2. Phone number detection (direct PII)
3. Name + location combination (quasi-PII)
4. Generic/safe content (baseline)
5. Username + location (quasi-PII)
6. Credit card number (financial PII)
7. Health information (medical data)
8. Financial information (salary/financial data)

These cases show the system works across domains: PII, credentials, financial, and health sectors.

### Running Custom Tests

```python
from preprocessing.normalizer import TextNormalizer
from detection.rule_detector import RuleDetector
from detection.ner_detector import initialize_ner_detector
from detection.llm_classifier import LLMClassifier
from detection.fusion import FusionEngine

normalizer = TextNormalizer()
rule_engine = RuleDetector()
ner_detector = initialize_ner_detector()
llm_engine = LLMClassifier()
fusion_engine = FusionEngine()

text = "Your test input here"
normalized = normalizer.normalize(text)
rule_result = rule_engine.analyze(normalized)
ner_result = ner_detector.extract_entities(normalized)
llm_raw = llm_engine.classify(normalized)
llm_result = json.loads(llm_raw)
fused = fusion_engine.fuse(rule_result, llm_result, ner_result)

print(f"Risk Score: {fused['raw_score']:.3f}")
print(f"Data Type: {fused['data_type']}")
```

## Dependencies

- `openai` - OpenAI API client
- `python-dotenv` - Load environment variables from `.env`
- `datasets` - Hugging Face Datasets
- `huggingface_hub` - Hugging Face Hub access
# client-runtime

Primary Python runtime for the PriVoke client-side privacy pipeline.

## CLI

Run the existing privacy pipeline:

```bash
python cli.py pipeline
```

Fetch model parameters from the Go streaming service:

```bash
python cli.py fetch-params --target localhost:50051 --model-id privoke-baseline
```
