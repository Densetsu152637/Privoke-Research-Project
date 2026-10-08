# Dataset-centred results and comparison research

Prepared 6 October 2026 (Australia/Sydney). Analysis checkout: `feat/dev-testing`, commit `0dcabc4971b14b63ab43be6388cf519ce1deed48`.

This folder answers the request to recalculate preserved results by originating dataset and find datasets from other papers for a better discussion. It is a separate research record. No paper source, bibliography, reference manuscript, figure, existing research note, detector, model, or dataset is edited.

## Reading order

1. [Results by dataset](results-by-dataset.md): recalculated confusion counts, dataset-specific failure patterns, supported denominators, and interpretation.
   The [complete stratified tables](all-stratified-results.md) retain every recalculated configuration and external partition.
2. [Comparison datasets from other papers](comparison-datasets.md): primary-source shortlist, access and overlap constraints, and a fair comparison design.
3. [Evidence and reproduction](evidence-and-reproduction.md): exact inputs, hashes, computation procedure, validation, and remaining limitations.

## Question map and decisions

| Question | Evidence needed | Decision rule |
| --- | --- | --- |
| Which dataset strata expose detection failures? | Saved development predictions, originating source, labels, groups, errors | Report recall and specificity separately, with confusion counts and class denominators. Missing classes produce unavailable rates. |
| Does a dataset itself have quality problems? | Independent annotation audit, target definition, provenance and split checks | Detector mistakes alone cannot establish defective labels. Record suspected mismatch separately from demonstrated defects. |
| What masks poor performance in a pooled score? | Per-source sample composition and source contributions to errors | Explain composition and group dependence; retain the pooled count as a bookkeeping check, not a replacement for the stratified tables. |
| Which published datasets would improve the discussion? | Primary paper, official artifact, labels, domain, access, source lineage and original metric | Prioritize distinct diagnostic questions: annotated presence, irrelevant/public entity mentions, contextual disclosure, and adversarial identifiers. |
| Can published scores be compared numerically? | Same examples, labels, prediction unit, operating point and uncertainty method | Treat unmatched published numbers as methodological context. A numerical system comparison requires a new matched experiment. |

The main recalculation reuses existing development predictions. It does not rerun inference, tune thresholds, train a model, promote an artifact, or inspect the locked final partition. Positive-only source-heldout results are documented separately from the mixed-class development sample. New external datasets are investigated through papers and metadata; candidate examples are not downloaded for evaluation.

## Meaning of “bad”

Use **poor performance on this sampled stratum** when the detector misses positives or flags clean-labelled examples. Use **limited benchmark suitability** when the dataset lacks the required labels, negative class, independent provenance, or deployment context. Use **annotation defect** only when an independent audit establishes one. These descriptions lead to different remedies and should not be conflated.

The present quantitative target is prompt/sentence-level **annotated-PII presence**, as defined in [the evaluation guide](../README.Evaluation.md). A detected sentence does not prove recovery of all PII spans, an appropriate privacy action, or prevention of harmful disclosure. Previously selected models and development-informed research remain exploratory; regrouping the same examples does not create a new independent test.

## Work record

- Root owns all new Markdown writes. The numerical and literature workstreams operate read-only against bounded inputs; a separate critic reviews the integrated notes.
- The existing paper directory was fingerprinted before work. Final integrity validation compares its file inventory and SHA-256 hashes with that snapshot.
- Research gathering stops after the shortlist covers the decision-relevant gaps and primary evidence supports material claims. No new runtime measurement or final evaluation is part of this request.
