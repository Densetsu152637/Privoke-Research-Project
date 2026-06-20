# NER Entity Detector

This directory contains layer 2 of the PriVoke client-runtime detector pipeline: named entity recognition backed by spaCy.

`EntityNERDetector.extract_entities(text)` returns `list[ClassificationResult]`. It only classifies natural-language model entities that are mapped in `use_cases.py`.

## Current Behavior

`EntityNERDetector`:

- calls `require_package("spacy")`, which attempts to install spaCy if the package is missing,
- tries to load `en_core_web_sm`,
- sets `self.nlp = None` if the model cannot be loaded,
- returns an empty result list when `self.nlp` is `None`,
- deduplicates by `(start_char, end_char, label, text)`.

Install the model for NER results:

```bash
python -m spacy download en_core_web_sm
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

- decide whether missing spaCy models should fail fast or keep returning no results,
- improve span precision and overlap handling,
- expand label mappings only when they map cleanly into `Classification`,
- add confidence calibration,
- test hosted masking behavior for NER-selected `WARN` results.
