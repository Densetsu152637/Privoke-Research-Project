# Annotation marker decision: the `fresh_eval-folio-NN` leak (Stage 13a-0)

Date: 24 November 2026. Decision D5 of the [Stage 13 plan](../plans/asiaccs-stage13-experiments.md) is **provisional**: the user has not answered, so the plan's default stands and this note records it as such. If the user changes D5, a later dated note supersedes this one.

No annotator sheet, label or prompt text is written in this note.

## The finding (Stage 8)

Every one of the 1,560 AU3 `fresh_eval` texts contains a token of the form `fresh_eval-folio-NN`. The token has 24 distinct values and follows the audience-expression groups. It therefore names the dataset partition and hints at a label-correlated grouping, which breaks the protocol's rule that dataset names never reach annotators. See [packet status, finding 1](annotation-packet-status-20261116.md#5-tooling-findings).

## Resolution

1. **AU3 `fresh_eval` is ineligible as the 13a set.** 13a needs prompts that were never used in development, tuning or earlier evaluation. `fresh_eval` is the RQ1 AU3 evaluation set. 13a uses a new set that writers produce, so the token cannot reach it. Stage 13 does not run the AU3 packet.
2. **Normalisation rule for the deferred AU3 provisional-target packet**, to apply whenever that packet is run:
   - Before pre-registration, replace every whole token that matches `fresh_eval-folio-<digits>` with the constant `folio`.
   - Apply the replacement identically for every annotator. The sampler does it once, before sampling, so every sheet carries the same text.
   - Record both set hashes. `key/manifest.json` carries `blinding_audit.normalisation = {pattern, replacement, original_sha256, normalised_sha256}`. `original_sha256` is the sha256 of the input file. `normalised_sha256` is the sha256 of the normalised rows, serialised as canonical JSONL (sorted keys, one object per line).
   - Run any PriVoke scoring against the normalised text, never the original.
   - Command shape: `sample_annotation.py --input <fresh_eval.jsonl> --output-dir <dir> --fail-on-marker --normalise-marker folio`.
3. **The sampler's marker check is a hard gate.**
   - `--fail-on-marker` exits non-zero and writes nothing when any sampled text matches a marker pattern.
   - The built-in pattern is `fresh_eval|release-\d+|AU3|folio-\d+`. After normalisation, the `folio-\d+` alternative no longer matches (the constant has no digits), and the `fresh_eval` alternative still catches any partial replacement. The whole pattern is therefore the complete gate.
   - The normaliser replaces whole tokens only. A token that is glued to other word characters, or a half-edited token, is left in place and fails the gate. Tests cover a normalised fixture (no alternative matches) and three partial-replacement fixtures (all fail).
   - `--marker-pattern <regex>` (repeatable) adds the source names that the 13a-1 contamination step finds. They join the same gate and are listed in `blinding_audit.patterns`.
   - Without `--fail-on-marker`, the sampler keeps its earlier behaviour: it warns and records the count.

## Deviation from the protocol

The 24 October protocol advises committing the pre-registration and artefacts before annotation, and its packet runbook has the coordinator keep completed sheets. Those sheets contain prompt text. Stage 13 commits **label-only** files instead (`item_id,sensitive,subject,audience,categories,action`: no `text`, no `notes`) together with hashes and counts, and keeps sheets, keys, the adjudication export and raw prompts in the Git-ignored `evaluation/results/s13a/` directory of the main checkout. The commit-hygiene check (S13-G8) enforces this.

## Status

- Provisional on D5. No AU3 packet is run in Stage 13.
- The AU3 input exists only in the main checkout. It is passed with `--input` and is never copied into a worktree or committed.
