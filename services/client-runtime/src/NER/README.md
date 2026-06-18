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

`EntityNERDetector.extract_entities(text)` should return `list[ClassificationResult]`.
Each classified model entity should produce one result containing:

- `classification`: mapped `Classification`,
- `section_of_text`: entity text,
- `span`: entity span,
- `reasoning`: model-label explanation,
- `confidence`: label confidence,
- `metadata`: entity-specific context such as label and model.

Fusion should consume `ClassificationResult` values from every detector. Enforcement should use result spans where masking is needed.

## Design Requirements

NER should be precise about spans. A false positive span can cause bad masking; a missing span can force enforcement into weaker regex fallback.

Entity objects should be shaped consistently:

```python
{
    "section_of_text": "...",
    "span": (start, end),
    "confidence": 0.90,
    "classification": Classification(...),
    "metadata": {
        "label": "PERSON",
        "entity_type": "name",
        "model": "en_core_web_sm"
    }
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
