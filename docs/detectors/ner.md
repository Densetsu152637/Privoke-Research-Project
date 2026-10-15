# NER Entity Detector

> Source area: `extension/client-runtime/src/NER`. Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

This directory contains layer 2 of the PriVoke client-runtime detector pipeline: named entity recognition backed by spaCy.

`EntityNERDetector.extract_entities(text)` returns `list[ClassificationResult]`. It only classifies natural-language model entities that are mapped in `use_cases.py`.

## Current Behavior

`EntityNERDetector`:

- imports spaCy directly,
- loads `en_core_web_sm` on the first runtime use and reuses the process-local cached pipeline for later detector instances,
- keeps a bounded least-recently-used cache of at most two model-name entries; a detector already holding an evicted entry can continue using it, so this is not a strict cap on total live model memory,
- serializes each shared pipeline's inference and conversion to plain `ClassificationResult` values with a per-pipeline lock; `Doc` and `Span` objects remain request-local,
- raises the normal spaCy import or model-load exception when dependencies are missing,
- does not cache failed model loads, so a later construction may retry,
- deduplicates by `(start_char, end_char, label, text)`.

The runtime has no per-request NER model-path selector. `model_name` is a
construction-time argument for direct detector users; request text cannot choose or
mutate a loaded spaCy pipeline. This cache changes model lifecycle and concurrency,
not label mappings or classification policy. Focused tests cover single-load
concurrency, cache eviction, retry after load failure, and serialized inference;
they do not establish a latency benchmark or prediction parity against a separately
captured live corpus.

Install runtime dependencies before running NER:

```bash
pip install -r extension/client-runtime/requirements.txt
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

Direct detector spans refer to the text passed into NER. The pipeline maps spans and evidence back to the original request before exposing per-layer or aggregate results and warning masks.

## Subagent Tasks

NER subagents should:

- improve span precision and overlap handling,
- expand label mappings only when they map cleanly into `Classification`,
- add confidence calibration,
- test hosted masking behavior for NER-selected `WARN` results.
