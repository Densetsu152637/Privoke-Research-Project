# PriVoke Client Runtime

The client runtime is the reference implementation of PriVoke's prompt privacy pipeline. It is responsible for inspecting prompt text before it leaves the client, assigning a structured privacy `Classification`, deriving a `RiskVector`, deciding enforcement, and emitting metadata-only telemetry.

The runtime follows a three-layer detection design similar to Casper-style prompt sanitization research:

1. Rule-based filtering with regex and deterministic heuristics.
2. NER/entity extraction for structured identity evidence.
3. Semantic context detection for implicit privacy disclosures.

The layers are intentionally separate so future subagents can improve each detector independently while preserving a shared output contract.

## Core Contract

Every detector should produce evidence that maps into `classification.py`.

`Classification` has three dimensions:

- `Sensitivity`: `S0`, `S1`, `S2`, `S3`
- `Visibility`: `P0`, `P1`, `P2`, `P3`, `P4`, `PU`
- `Category`: `HEALTH`, `POLITICS`, `RELIGION`, `CRIMINAL`, `FINANCIAL`, `SEXUAL`, `CHILD`, `LOCATION`, `IDENTITY`, `THIRD_PARTY`

`RiskVector` is derived from the final fused `Classification`. It is not a fourth detector dimension.

Current vectors:

- `NORMAL`: no meaningful privacy signal.
- `CONTEXTUAL`: sensitive context without direct identifier dominance.
- `AUTH`: structured identity/authentication context, commonly restricted behind authentication.
- `QUASI_PII`: weak or combined identifiers that can become identifying.
- `DIRECT_PII`: direct identifiers or high sensitivity identifier/financial/location disclosures.

## Pipeline

```text
raw prompt
  -> TextNormalizer
  -> RuleDetector
  -> EntityNERDetector
  -> LLMClassifier
  -> FusionEngine
  -> EnforcementEngine
  -> StructuredEventEmitter
```

### Preprocessing

`detection/preprocessing.py` normalizes text before detection. It should:

- normalize Unicode,
- reduce obfuscation such as `[at]`,
- collapse whitespace,
- preserve enough original structure for span-based detectors.

Normalization should not remove sensitive content. It prepares text for consistent matching.

### Layer 1: Regex and Rules

`regex/rule_detector.py` is the fastest and most deterministic layer. It should detect:

- direct identity patterns: email, phone, SSN, passport, government ID,
- financial identifiers: cards, account numbers, IBAN, salary amounts,
- precise location: street addresses, coordinates, route disclosures,
- sensitive categories: health, politics, religion, criminal, sexual, child, third-party disclosures,
- visibility context: public, semi-public, restricted, group-private, personal-private.

Output must include:

- merged `Classification`,
- packed classification,
- individual rule matches,
- signal list.

Rules should not return legacy category or severity strings.

### Layer 2: NER and Entity Extraction

`NER/ner_detector.py` extracts structured entities. It should combine:

- deterministic extraction for email, phone, URLs, cards, SSNs, usernames,
- spaCy or another NER model for names, locations, organizations, and related entities,
- span metadata,
- confidence metadata,
- entity summary flags for fusion.

NER should be precise about spans because enforcement masking depends on it.

### Layer 3: Semantic Context

`transformer/llm_classifier.py` handles implicit and contextual privacy risk. It should detect cases that rules and NER miss, such as:

- sensitive self-disclosure without obvious identifiers,
- third-party disclosures,
- indirect identification through occupation, location, timing, or relationship context,
- semantic categories such as health, politics, religion, sexuality, criminal history, and child information.

The semantic detector may use a remote LLM during prototyping, but its boundary must return a `Classification` object and not leak raw model labels through the rest of the runtime.

## Fusion

`detection/fusion.py` joins detector outputs into one final `Classification`.

Fusion should:

- preserve the strongest sensitivity from any detector,
- merge categories without duplication,
- preserve the strongest known visibility, treating `PU` as unknown with comparison score zero,
- account for entity combinations with a bounded boost,
- derive `RiskVector` from the fused `Classification`,
- keep detector evidence attached for telemetry and debugging.

Fusion output shape:

```python
{
    "classification": Classification(...),
    "packed_classification": int,
    "risk_vector": RiskVector,
    "risk_vector_explanation": {
        "reason": str,
        "signals_used": list[str],
        "entity_boost_applied": float,
    },
    "raw_score": float,
    "risk_score_details": dict,
    "rule": dict,
    "llm": dict,
    "ner": dict | None,
}
```

## Enforcement

`detection/enforcement_engine.py` converts fused risk into action.

Current policy:

- `BLOCK_PROMPT`: `S3` or `RiskVector.DIRECT_PII`.
- `WARN_AND_MASK`: `S2`, `RiskVector.QUASI_PII`, or `RiskVector.AUTH`.
- `ALLOW`: `S0` or `S1` without an elevated vector.

Enforcement should be deterministic and auditable. Masking should use entity spans where possible, with regex fallback when span data is missing.

## Telemetry

`telemetry/event_emitter.py` emits metadata-only events.

Telemetry must not include raw prompt text. It may include:

- event ID,
- time bucket,
- risk score bucket,
- action,
- classification dictionary,
- risk vector,
- detector version,
- detector disagreement metadata,
- entity type names.

## CLI

Run the sample pipeline:

```bash
python cli.py pipeline
```

Fetch model parameters:

```bash
python cli.py fetch-params --target localhost:50051 --model-id privoke-baseline
```

## Local Setup

```bash
cd services/client-runtime
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

For semantic LLM experiments, configure:

```bash
OPENAI_API_KEY=...
```

## Subagent Work Packages

Rule detector subagent:

- add rule definitions with `Classification` mappings,
- improve false positive controls,
- add tests for packed classification round trips,
- keep visibility rules separate from category rules where possible.

NER subagent:

- improve span extraction,
- add confidence scoring,
- normalize entity records,
- ensure masked output uses entity spans.

Semantic detector subagent:

- improve prompts or local model interface,
- return `Classification` only,
- add fallback handling for malformed model output,
- cover implicit sensitive disclosures.

Fusion/enforcement subagent:

- improve `RiskVector` derivation,
- tune entity boosts,
- test disagreement behavior,
- ensure enforcement actions are explainable.

Telemetry subagent:

- ensure events remain metadata-only,
- add privacy-preserving aggregation fields,
- maintain detector versioning.

## Verification

Use compile checks after refactors:

```bash
python -m compileall services\client-runtime
```

Recommended smoke checks:

- direct email should produce `IDENTITY` and `DIRECT_PII`,
- structured username under restricted visibility should produce `AUTH`,
- group chat context should produce `P3`,
- personal diary/private note context should produce `P4`,
- safe text should produce `RiskVector.NORMAL`.
