# Detection Preprocessing

This package currently contains the text normalizer used before all detector layers. It does not contain the full fusion or enforcement logic described by older PriVoke design notes.

## Current File

- `preprocessing.py`: `normalize_text(text)` prepares text for regex, NER, and semantic detection.

## Normalization Behavior

`normalize_text` currently:

- applies Unicode NFKC normalization,
- lowercases the whole prompt,
- replaces `[at]` and `(at)` with `@`,
- removes spaces between adjacent digits,
- collapses horizontal spaces and tabs,
- collapses repeated newlines,
- trims leading and trailing whitespace.

Normalization should not delete sensitive content. It prepares a canonical string for matching, but span offsets in detector results refer to the normalized text, not necessarily the original request text.

## Where Pipeline Decisions Live

- `src/pipeline.py` orchestrates regex, NER, semantic classification, regex short-circuiting, and strongest-result selection.
- `src/classification/classification_policy.py` derives `PriVokeAction` from each `ClassificationResult`.
- `src/hosting/analyzer.py` applies request-level `visibility_hint` after pipeline analysis.
- `src/hosting/serialization.py` builds the HTTP response and performs warning-span masking.

There is no active `fusion.py` or `enforcement_engine.py` in this package.

## Subagent Tasks

Good tasks in this package:

- improve normalization tests,
- document span offset expectations,
- add targeted de-obfuscation rules,
- avoid transformations that make evidence spans unusable.
