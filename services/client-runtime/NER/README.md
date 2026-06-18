# NER Entity Detector

This directory contains layer 2 of the PriVoke detection pipeline: named entity extraction.

NER sits between deterministic regex rules and semantic context detection. Its job is to find natural-language entity spans and entity combinations that rules may miss or that semantic detection should not have to reconstruct from raw text.

## Responsibilities

The NER detector should extract model-backed entities such as:

- names,
- locations,
- organization or workplace references when useful,
- raw model entities when a NER backend is available.

Rigid formats such as emails, phone numbers, cards, SSNs, URLs, and handles belong in the regex pass. NER should use spaCy or another NER model for names, locations, organizations, and related natural-language entities.

## Output Contract

`EntityNERDetector.extract_entities(text)` should return a dictionary with:

- typed entity lists,
- `span` for each entity where available,
- confidence values,
- `Classification` metadata for classified entity use cases,
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
    "classification": Classification(...),
    "packed_classification": 8222,
    "source": "spacy" | "model"
}
```

## Fallback Behavior

The detector should still work when spaCy is unavailable. Disabled-backend mode should return empty entity lists, a neutral `Classification`, an empty `entity_summary`, and avoid raising exceptions during pipeline execution.

## Subagent Tasks

NER subagents should:

- improve span precision,
- deduplicate overlapping entities,
- normalize entity schemas,
- add confidence calibration,
- add tests for fallback mode,
- connect masking to entity spans instead of broad regex replacement,
- add domain-specific entity types only when they map cleanly into `Classification`.
