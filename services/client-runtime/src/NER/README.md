# NER Entity Detector

This directory contains layer 2 of the PriVoke client-runtime detector pipeline: named entity recognition backed by spaCy.

`EntityNERDetector.extract_entities(text)` returns `list[ClassificationResult]`. It only classifies natural-language model entities that are mapped in `use_cases.py`.

## Current Behavior

`EntityNERDetector`:

- imports spaCy directly,
- loads `en_core_web_sm` during initialization,
- raises the normal spaCy import or model-load exception when dependencies are missing,
- deduplicates by `(start_char, end_char, label, text)`.

Install runtime dependencies before running NER:

```bash
pip install -r services/client-runtime/requirements.txt
```

## Label Mapping

Current mappings:

- `PERSON` -> `S2`, `PU`, `IDENTITY`, confidence `0.85`
- `GPE` -> `S2`, `PU`, `LOCATION`, confidence `0.85`
- `LOC` -> `S2`, `PU`, `LOCATION`, confidence `0.85`
- `FAC` -> `S2`, `PU`, `LOCATION`, confidence `0.80`
- `ORG` -> `S1`, `PU`, `IDENTITY`, confidence `0.75`

Rigid formats such as emails, phone numbers, cards, SSNs, URLs, and handles belong in the regex pass.

## Output Contract

Each mapped entity becomes:

```python
ClassificationResult(
    classification=use_case.classification,
    section_of_text=ent.text,
    reasoning=f"spaCy labelled this span as {ent.label_}",
    span=(ent.start_char, ent.end_char),
    confidence=use_case.confidence,
    metadata={
        "label": ent.label_,
        "entity_type": use_case.entity_type,
        "model": "en_core_web_sm",
    },
)
```

Spans refer to the normalized text passed into NER by the pipeline.

## Subagent Tasks

NER subagents should:

- improve span precision and overlap handling,
- expand label mappings only when they map cleanly into `Classification`,
- add confidence calibration,
- test hosted masking behavior for NER-selected `WARN` results.
