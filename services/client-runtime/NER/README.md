# NER Entity Detector

This directory contains layer 2 of the PriVoke detection pipeline: named entity extraction.

NER sits between deterministic regex rules and semantic context detection. Its job is to find natural-language entity spans and entity combinations that rules may miss or that semantic detection should not have to reconstruct from raw text.

## Responsibilities

The NER detector extracts model-backed entities such as:

- names,
- locations,
- organization or workplace references when useful,
- raw model entities when a NER backend is available.

Rigid formats such as emails, phone numbers, cards, SSNs, URLs, and handles belong in the regex pass. NER should use spaCy or another NER model for names, locations, organizations, and related natural-language entities.

## Output Contract

`EntityNERDetector.extract_entities(text)` should return a dictionary with:

- `classification`: merged `Classification` for all classified NER entities,
- `packed_classification`: 16-bit packed value,
- `risk_vector`: derived `RiskVector`,
- `entities`: flat list of classified NER entities,
- `raw_entities`: raw backend entities,
- `signals`: ordered signal names.

Fusion should consume the detector-level `Classification` and derived `RiskVector`. Enforcement should use entity spans where masking is needed.

## Design Requirements

NER should be precise about spans. A false positive span can cause bad masking; a missing span can force enforcement into weaker regex fallback.

Entity objects should be shaped consistently:

```python
{
    "text": "...",
    "span": (start, end),
    "label": "PERSON",
    "signal": "name",
    "confidence": 0.90,
    "classification": Classification(...),
    "packed_classification": 8222,
    "risk_vector": RiskVector.QUASI_PII,
    "source": "spacy"
}
```

## Fallback Behavior

spaCy is a required runtime dependency for this detector. Missing spaCy or a missing model should fail during detector initialization rather than silently changing detection behavior.

## Subagent Tasks

NER subagents should:

- improve span precision,
- deduplicate overlapping entities,
- normalize entity schemas,
- add confidence calibration,
- connect masking to entity spans instead of broad regex replacement,
- add domain-specific entity types only when they map cleanly into `Classification`.
