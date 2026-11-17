# Detection Preprocessing

> Source area: `extension/client-runtime/src/detection`. Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

This package currently contains the text normalizer used before all detector layers. It does not contain the full fusion or enforcement logic described by older PriVoke design notes.

## Current File

- `preprocessing.py`: `normalize_text(text)` prepares text for regex, NER, and semantic detection.

## Normalization Behavior

`normalize_text` currently:

- applies Unicode NFKC normalization,
- lowercases the whole prompt for the semantic/LLM layer. Regex and NER instead receive a case-preserved variant (`normalize_with_offsets(text, lowercase=False)`) by default; `PRIVOKE_CASE_PRESERVING_DETECTORS=0` restores lowercased input for them as well,
- replaces `[at]` and `(at)` with `@`,
- removes spaces between adjacent digits,
- collapses horizontal spaces and tabs,
- collapses repeated newlines,
- trims leading and trailing whitespace.

### Optional robustness canonicalisations (default off)

Four opt-in flags undo common input obfuscation. They are off by default, apply only to the case-preserved detector view (`normalize_with_offsets(text, lowercase=False)`; the lowercased semantic view and the semantic training/reference preprocessing never use them), and every rewrite is offset-mapped like the rest of the normalizer. An explicit `RobustnessOptions` argument to `normalize_with_offsets` overrides the flags (used by tests). With `PRIVOKE_CASE_PRESERVING_DETECTORS=0` the detectors receive the lowercased view and these flags have no effect.

| Flag | Effect |
| --- | --- |
| `PRIVOKE_STRIP_FORMAT_CHARS=1` | Drops Unicode category `Cf` characters (zero-width space/joiner, word joiner, BOM, soft hyphen, bidi marks, tag characters). The preceding character's source interval covers the dropped ones. |
| `PRIVOKE_CANONICALISE_DIGITS=1` | (a) Joins a chain of single digits written with one repeated separator (`5-5-5-1-2-3-4` becomes `5551234`; at least 4 digits for `-`, at least 7 for `.` and `/`, so dates, ratios, versions, IPv4 addresses and any grouped number are left alone). Only the single-digit chain is joined: `1-9-7-3-01-29` becomes `1973-01-29`. (b) Reads a run of at least 7 spelled digit words (`zero`, `oh`, `one` .. `nine`, separated by spaces or a hyphen) as digits, keeping a hyphen as a group separator; counting sequences and runs of mostly `oh` are skipped. Whitespace-only spelled digits carry no grouping, so the result is one ungrouped run. |
| `PRIVOKE_CANONICALISE_EMAIL_WORDS=1` | Rewrites `[dot]`, `(dot)` and ` dot ` to `.` inside an e-mail-shaped token (local part, at-sign, domain, final letters-only label), and ` at ` to `@` when the final label is a two-letter country code or a common TLD and the local part is not an ordinary function word or an `at`-taking verb. A real `a@b.c` address and prose such as "look at example dot com" are untouched. `[at]` and `(at)` are always handled. |

`PRIVOKE_NER_CASELESS_GATE` is described in [the NER notes](ner.md). Evidence: [robustness fixes](../experiments/robustness-fixes-20261024.md).

Normalization should not delete sensitive content. It prepares a canonical string for matching, and `normalize_with_offsets` records each canonical character's source interval. The pipeline maps detector spans and evidence back to the exact original request before returning per-layer or aggregate results. Unicode expansions share a source interval; replacements and collapsed spans cover their complete source interval.

## Where Pipeline Decisions Live

- `src/pipeline.py` orchestrates regex, NER, semantic classification, regex short-circuiting, and strongest-result selection.
- `src/classification/classification_policy.py` derives `PriVokeAction` from each `ClassificationResult`.
- `src/hosting/analyzer.py` applies request-level `visibility_hint` to the combined classification without lowering an existing enforcement decision.
- `src/hosting/serialization.py` builds the HTTP response and performs warning-span masking.

There is no active `fusion.py` or `enforcement_engine.py` in this package.

## Subagent Tasks

Good tasks in this package:

- improve normalization tests,
- document span offset expectations,
- add targeted de-obfuscation rules,
- avoid transformations that make evidence spans unusable.
