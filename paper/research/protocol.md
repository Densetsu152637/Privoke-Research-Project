# Experimental protocol and decision record

Recorded 3 October 2026, before scoring the locked public final partition.
All merged branch tips are ancestors of `5e71717`. Tested workplace correction:
`c2bd6ad`; tested central evaluation and experiment source: `712ed72`.

## Question and boundaries

Do bounded template-driven head updates improve prompt-level detection on unseen
source documents without increasing clean false alarms? The encoder is frozen.
Updates are centralized synthetic training, not federated or private learning.
Secondary questions concern layer contributions and bounded browser enforcement.
An internal review paper is the current deliverable; submission requires a
venue-specific assessment and author approval.

## Data and metrics

- Synthetic development: 500 balanced examples, seed 2026. This supplies debugging
  evidence only; templates may overlap the model's calibration distribution.
- Public benchmark: English PIIMB sentences at revision
  `4a13e9ffe6fd0d275efbde8afd4d8d8f1ffc2133`. Selection seed 3102026,
  1,000 balanced rows, exact deduplication and source-document grouping.
- Locked development: 502 rows (264 annotated positive, 238 clean), SHA-256
  `65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095`.
- Locked final: 498 rows (236 annotated positive, 262 clean), SHA-256
  `613a78b9e5fa677904125b4c056fb8d57d15fb6ebd9c443a75f406ae3ac05515`.
  Do not inspect final failures or tune against final metrics. Split construction
  examined labels and group identifiers, not model outcomes.
- At a 90% independent-binomial rate, these final class denominators imply an
  approximate 95% half-width of four percentage points. Shared documents reduce
  effective precision: report actual source-cluster intervals, not this planning
  approximation. The sample is a bounded pilot, not a precise rare-category study.
- Binary positive means returned sensitivity S1–S3 or any category. This is distinct
  from action correctness, span detection and prevention of transmission.
- Report confusion counts, recall, specificity, balanced accuracy, F1/F2 and 95%
  intervals. Bootstrap 2,000 times, grouped by source when repeated. Record errors
  separately and retain failed runs; primary comparisons require zero runtime errors.
- Balanced-sample precision is not deployment precision. PIIMB annotation presence
  includes public names/dates and does not establish private contextual disclosure.

## Comparisons and stopping

Match regex, NER, semantic, regex+NER and full pipeline on identical IDs. Archive
all successful predictions, errors and per-layer model identity when returned.
Compare baseline versus updated semantic and pipeline predictions pairwise.
Independent Presidio baseline: upstream English recognizers, spaCy
`en_core_web_sm`, score threshold 0.5, no PriVoke rules, no tuning against final.
This uses a smaller NLP model than Presidio's default large model; disclose that
choice and avoid characterizing it as the strongest available Presidio system.

User-approved development targets are at least 90% sensitive recall and 90% clean
specificity, plus the completion plan's evidence requirements. Targets apply to
development decisions and are not acceptance guarantees. An accepted update RPC
or a passing training safety guard does not meet these targets.

First run one 256-example cycle per independent seed 42, 1337 and 2026, restoring
the same original artifact between seeds and preserving receipts/audit histories.
Use unique request IDs. Keep public rows out of fuzzer training. Check exactly
which artifact each client used; restart the isolated runtime between artifacts.
An exploratory seed-42 cycle was accepted before public development scoring.
Artifact inspection shows its base was already v0.3.0+train.1 and its output was
v0.3.0+train.2. Preserve both snapshots, exclude this pilot from independent-seed
comparisons, and restore the checked-in v0.3.0 artifact for those comparisons.
The initial synthetic ablations also used the pre-cycle trained artifact; they
are debugging runs, not the immutable original baseline.

For the initial bounded study, if comparisons identify a trainable deficit, perform at most two more
cycles per seed, checking development recall and specificity at each checkpoint.
Select by development balanced accuracy subject to no degradation of either
class rate relative to baseline; ties prefer fewer cycles. Do not expand the
search or change model architecture to pursue favorable final scores. Later
user-authorized development extensions are recorded below. If targets remain
unmet, retain the null/negative findings and keep submission readiness
unresolved. Final evaluation waits for frozen rules, model selection and run manifests.

## Evidence not replaced by detector scores

### Authorized development extension

After the three initial seeds and ordinary-example controls showed increased
false positives, the user explicitly requested continued development on3 October:
reduce false positives, change learning rate where useful, and restart from the
original model. This extends the earlier bounded experiment budget for development;
it does not authorize using final failures for training or changing provided labels.
Compare existing learning rates0.01 and0.003 with0.03, using the same three seeds,
256 source prompts, original artifact and pinned runtime source712ed72. The fuzzer
samples templates deterministically and has no generative temperature control.
Positive scalar temperature on sensitivity softmax would not change its argmax;
optional hosted-classifier temperatures are outside this streamed experiment.

Evaluate narrowed financial/location rules separately against the original model.
Keep old baselines and run hashes, record all regressions and select only using
development outcomes. Source-image pinning is required across seed restarts. The
interrupted `lr001_updates_20261003` batch is excluded from primary comparisons
because an independent build changed the mutable runtime tag between seeds.

The completed extension also tests a fictional clean-topic curriculum, then adds
16 existing bootstrap anchors after the unanchored seed-42 batch fails the
pre-training exact-match guard. Preserve that failure. Compare anchored rates
0.03, 0.01 and 0.003 with transformations disabled; retain rejected held-out
outcomes for seeds42 and1337 at0.03. No safety gate or target is relaxed.
The conservative selection rule requires no recall/specificity loss in **both**
semantic and pipeline against the original, then maximizes pipeline balanced
accuracy; ties prefer fewer cycles and then lower seed. This is stricter than
pipeline-only selection and applies to this extension.

The selected seed42 first-cycle anchored0.003 artifact corrects one clean
prediction without changing positive predictions. Cycle2 loses one semantic
positive, so stop before cycle3 and restore cycle1. Separately integrate source
`cbaecf8` narrowed rules; its live selected-model development result is
TP247/TN54/FP184/FN17. The specificity target remains unmet. All configurations,
failed attempts and selected checksums are in `false-positive-experiments.md`.
Further development must declare its bounded question before execution, preserve
these comparisons and leave final outcomes unavailable to training/selection.

Measure browser request capture and outage behavior, warm/cold end-to-end timings,
resource costs and the stated telemetry mechanism's privacy scope. Unit tests
alone cannot establish browser transmission prevention. Contextual/action labels
must remain provisional until confirmed independently.

The user authorized a provisional agent assessment and requested professor
confirmation by [git4san](https://github.com/git4san). No independent human review
or two-annotator agreement is claimed. Track concrete review requests in
`review-requests.md`; final publication readiness remains conditional on them.

The [PIIMB dataset card](https://huggingface.co/datasets/piimb/pii-masking-benchmark)
lists CC BY-NC 4.0 and multiple upstream sources. Preserve attribution and audit
the pinned source licenses before redistributing raw examples. The
[Presidio configuration documentation](https://github.com/data-privacy-stack/presidio/blob/main/docs/analyzer/customizing_nlp_models.md)
supports supplying a configured NLP engine. Sources inspected 3 October 2026.
