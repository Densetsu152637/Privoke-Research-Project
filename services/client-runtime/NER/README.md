# NER Entity Detector

This directory contains layer 2 of the PriVoke detection pipeline: named entity and structured entity extraction.

NER sits between deterministic regex rules and semantic context detection. Its job is to find entity spans and entity combinations that rules may miss or that semantic detection should not have to reconstruct from raw text.

## Responsibilities

The NER detector should extract:

- email addresses,
- phone numbers,
- usernames and handles,
- names,
- locations,
- credit cards,
- SSNs,
- URLs,
- organization or workplace references when useful,
- raw model entities when an ML NER backend is available.

The detector may combine regex extraction with spaCy or another NER model. Regex extraction is appropriate for rigid formats such as email and cards. ML NER is appropriate for names, locations, organizations, and other natural-language entities.

## Output Contract

`EntityNERDetector.extract_entities(text)` should return a dictionary with:

- typed entity lists,
- `span` for each entity where available,
- confidence values,
- `RiskVector` metadata for entity type,
- raw NER model entities,
- `entity_summary` boolean flags.

Fusion currently consumes the summary flags, while enforcement should increasingly use spans for masking.

## Design Requirements

NER should be precise about spans. A false positive span can cause bad masking; a missing span can force enforcement into weaker regex fallback.

Entity objects should be shaped consistently:

```python
{
    "text": "...",
    "span": (start, end),
    "confidence": 0.90,
    "type": RiskVector.QUASI_PII,
    "source": "regex" | "spacy" | "model"
}
```

## Fallback Behavior

The detector should still work when spaCy is unavailable. Regex-only mode should:

- extract rigid identifiers,
- populate `entity_summary`,
- avoid raising exceptions during pipeline execution.

## Subagent Tasks

NER subagents should:

- improve span precision,
- deduplicate overlapping entities,
- normalize entity schemas,
- add confidence calibration,
- add tests for fallback mode,
- connect masking to entity spans instead of broad regex replacement,
- add domain-specific entity types only when they map cleanly into `Classification` or `RiskVector`.
