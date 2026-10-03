# Current research integration record

## Current checkpoint — 4 October 2026

### Primary contextual cascade — terminal exploratory result

The primary original-control cascade completed at source `d1e7e3ca77eaef9101907e9082fee3bc0dcbf766`. Efficient/balanced/quality development counts were 242/175/63/22, 242/169/69/22, and 242/159/79/22 (TP/TN/FP/FN): 91.67% recall and 73.53%, 71.01%, 66.81% specificity. Compared with ordinary original control 247/53/185/17, each gate misses five more positive-labelled rows while false positives fall by 122/116/106. The 90% specificity target remains unmet. Current trained-control pairs were ineligible and skipped; their curriculum overlaps validation. Paired intervals are uncomputed; action transitions are reported separately. The independent terminal checkpoint and root-proof join verified inputs, reports, restoration and unchanged runtime images; final examples remain unparsed and unscored. See [cascade results](../docs/contextual-cascade-results.md), [protocol](../paper/research/contextual-cascade-protocol.md), and claim C18. The separate 48-case provisional fixture study at source `4fa43bf` is still pending and does not supply human-confirmed contextual truth.
### External positive-data expansion and live profile comparison

The completed source-expansion comparison expanded the separate binary annotation-presence task with pinned Nemotron and Meddies positive-only training data. Preparation retained 19,993 training rows (3,832 original, 13,168 Nemotron, 2,993 Meddies), kept the existing 968-row validation selection unchanged, and held out 1,000 Nemotron and 999 Meddies positive rows. All three sparse profiles completed the fixed live comparison: 18 matched reports / 17,802 prompt RPCs, zero errors, verified restoration, and unchanged runtime image IDs. The aggregate is [`external_pii_summary_20261004_v1.json`](../evaluation/results/external_pii_summary_20261004_v1.json), SHA-256 `e5e138d42f0930390702fb56a745ae0b8e7f7772791d8ed473ab56d51b250c2d`; run manifest is [`run-manifest.json`](../evaluation/results/external_pii_rpc_20261004_v2/run-manifest.json), SHA-256 `62b28e0f6c2e8006915e9bdc8498462d636e44d5bb397f8704a95d96d2ab8671`. See the [data analysis](../docs/PII-dataset-analysis.md) for source pins, preparation counts, results, licenses and limits.

Expanded validation TP/TN/FP/FN were efficient `428/330/163/47`, balanced `428/396/97/47`, and quality `430/384/109/45` (recall 90.11%, 90.11%, 90.53%; specificity 66.94%, 80.32%, 77.89%). Matched frozen controls were `429/378/115/46`, `428/392/101/47`, and `428/394/99/47`. Paired source-group specificity deltas and 95% intervals were −9.74 pp [−13.43, −6.30], +0.81 pp [−1.46, +3.08], and −2.03 pp [−4.71, +0.43]; intervals are descriptive and conditional on validation-based selection. All three expanded profiles detected 1,000/1,000 Nemotron and 999/999 Meddies source-heldout positives; these positive-only sets cannot estimate specificity. This is annotation-presence evidence, not contextual privacy, action, span, or population-level evidence. The current selected contextual pipeline remains at 90.53% recall and 29.41% specificity; it does not meet the joint development targets. Final remains locked and unscored.

An earlier completed profile run fit three sparse binary annotation-presence
models and measured each against the same 502 locked development rows. The
validation-selected runtime bases scored 249/169/69/15 (efficient),
247/181/57/17 (balanced), and 247/189/49/17 (quality), in TP/TN/FP/FN order;
all three had zero errors and exact ID/label/group joins. This is a separate
binary task, not a contextual severity or policy result. The live selected
contextual pipeline remains at 90.53% recall and 29.41% specificity; final
remains unscored. See [sparse presence profile results](../docs/presence-model-improvements.md)
and the [prospective protocol](../paper/research/model-refactor-protocol.md).
The evaluator suite passed 96 tests at source `e519a77f`; see the
[test log](presence-study-evaluator-tests-v2.log). The served-base audit passed 42 checks
for IDs, labels, groups, counts, identities, and local/RPC parity.
The fixed-seed update study and independent audit are complete. All nine
updates were accepted, but none improved validation specificity; the three
fitted bases were retained and restoration of the live contextual checkpoint
was verified. The 59,214-check audit and per-seed results are in
[the profile results record](../docs/presence-model-improvements.md). This
does not improve the live contextual result or meet the specificity target.
Further work should test representation or contextual hard-negative coverage
under a new protocol; changing sampling temperature is not applicable to this
deterministic update path.

The current local evidence package is
[`research-20261004-presence-refactor.zip`](artifacts/research-20261004-presence-refactor.zip):
46,340,661 bytes, 1,132 hashed records, source `bba23579b4d4fe8f474f76b74ebed23c369ffd96`.
Archive SHA-256: `9e9d354c2eec0f79751d18539e3520cb1cba8a4ce2d8f0ce93706fd7969e47a7`.
The [external manifest](../paper/research/presence-refactor-artifact-manifest.json)
records every included file; ZIP integrity and all recorded hashes passed.
This local package includes the fits, served reports, update receipts and audits;
it does not establish a clean-room reproduction or permission to redistribute data.

The completed [sparse text control](../paper/research/text-control-results.md)
selected C=1 using validation before development scoring. It scored
TP248/TN186/FP52/FN16 on development (93.94% recall, 78.15% specificity),
with no fit warnings or failures. Evaluator74 passed at source `6f777104`.
The largest source family, Nemotron, has 83.15% specificity in this control.
This is an offline annotation-presence result; the existing live contextual
pipeline remains at 90.53% recall and 29.41% specificity. Final remains unscored.

An additive sparse presence serving/training interface was integrated
under a separate prospective protocol. Shared inference and typed contracts
were integrated at `39778b6`; the profile fit and runtime-base results are
recorded above. The original contextual API and its policy decisions are preserved.
The historical archived package below predates the text control and this refactor.

Latest contextual training study: [public-negative results](../paper/research/public-negative-results.md).
Nine independent attempts at0.03/0.1/0.3 produce six scored candidates and three
held-out rejections. Three0.03 seeds tie on pipeline239/70/168/25; prospective
selection chooses seed42. Compared with prior247/54/184/17, false positives fall
by16 while false negatives rise by eight. Current recall90.53%, specificity29.41%:
the90% specificity target remains unmet. Final498 remains unscored.

The triggered cycle2 gives236/78/160/28 (recall89.39%), so it fails selection.
Cycle3 is not attempted; cycle1 is restored and its parsed payload/checksum is
verified against the live volume. Selected checksum:
`8c139431ba8605a3d6817d24d233cce78fc22a086fdeb3ee99702ada86c80015`.
All study/curve processes are complete at this checkpoint. Startup training
remains disabled. Serving images are unchanged throughout the matched study.

Historical checkpoint suites were runtime83, fuzzer26 and evaluator50;
evaluator53 passed at source `b733960079babc9fc695fdc6ba836ac7ae87b86e`
after the released-profile identity tests. That checkpoint's affected suite was
evaluator68 (`representation-v3-tests.log`). Source `4f224ba`
adds grouped internal-guard exclusions and training/serving normalization alignment;
`2f1ec91` fixes cross-platform artifact paths. `2e8ca5c` adds strict matched-row/raw-
count selection checks, tested failure restoration and the bounded curve caller.
The independent audit verified all six scored candidates' report/artifact hashes,
model fingerprints and eligibility, plus the three unscored rejection records.
The stricter validator was applied after the live study completed and before the
curve began; no process/request ID was restarted to apply it.

The new read-only receipt snapshot has32 rows and passes SQLite integrity_check;
its audit/model identity manifest is in `results/public_negative_curve_20261003/`.
The [methodology draft](../docs/research-methodology-draft.md) records the current
design and pending evidence. Professor confirmation, installed-extension/client
cost evidence, final testing and paper/figure completion remain outstanding.

Released-model inference profiles were measured on the same502 locked development
rows under the prospective [profile protocol](../paper/research/model-profile-protocol.md).
The [results record](../paper/research/model-profile-results.md) reports the
original efficient, balanced and quality profiles, raw counts, runtime costs,
paired descriptive intervals and provenance. Study source revision
`b733960079babc9fc695fdc6ba836ac7ae87b86e` completed with zero errors, restored
the previously selected balanced checkpoint, and left serving image IDs
unchanged. This tests multi-size inference; fuzzer training so far remains on the
balanced profile. No causal model-size or superiority conclusion follows, and
final498 remains unscored. An earlier review of the frozen-representation
diagnostic found interface/integrity gaps; these were corrected and revalidated
before the completed v3 execution below.

The amended frozen-representation diagnostic is now complete. Evaluator68 passed
before execution (`representation-v3-tests.log`). Attempts v1 and v2 remain
preserved as pre-fit failures: v1 stopped on Windows text transport, and v2
stopped at the unique-source-ID gate after preparation/export. V3 excluded all
ambiguous source IDs before selection and fit all three predefined C values with
no errors. Validation selected C=0.1 before development scoring. The standalone
probe scored238/112/126/26; the offline probe plus reused regex/NER outputs scored
250/108/130/14 (94.70% recall,45.38% specificity). This is not a live pipeline
measurement and does not meet the90% specificity target. Current live selected
balanced remains90.53%/29.41%, with serving model unchanged; final498 remains
unscored. See the [protocol](../paper/research/representation-protocol.md) and
[results](../paper/research/representation-results.md) for selection, paired
descriptive intervals, hashes and scope limits. The next prospective branch is
a bounded binary-head/update-interface investigation with contextual and policy
validation, not direct deployment of the offline probe.

The newest local evidence package is
`evaluation/artifacts/research-20261004-profiles-representation.zip`
(32,120,849 bytes, 886 records; SHA-256
`333e3fd6fb7891a64953b98dc954fabbff1e7edc95f6696aeefa42358b1bc207`), with
scope and provenance in [the artifact locator](../paper/research/artifacts.md)
and [external manifest](../paper/research/profiles-representation-artifact-manifest.json).
It preserves profile inference plus the offline v3 diagnostic and pre-fit
failures; it does not contain final-scoring reports. The research goal remains
unfinished: live selected recall/specificity are 90.53%/29.41%, offline
probe-plus-rule diagnostic values are 94.70%/45.38%, and final data remain
unscored. The next bounded step is a prospective interface/evidence
investigation with contextual and policy validation, not deployment.

Source `c035bc7` and766 file records are preserved in the new18.0MB local package,
`evaluation/artifacts/research-20261003-public-negative.zip`. Exact hashes and
scope are in `paper/research/artifacts.md` and the new external manifest. The
earlier14.6MB package is preserved unchanged. No upload occurred.

### Earlier checkpoint and preserved comparisons

Test invocation is centralized by committed revision `712ed72`; component test
sources and the fuzzer loop remain in their original locations. The corrected
personal-workplace rule is committed as `c2bd6ad`; narrowed financial/location
rules and their regression cases are committed as `cbaecf8`. All branch merges are complete
and were verified against merge revision `5e71717`.

Docker checks passed: browser94, revised-rule runtime82, evaluator41, fuzzer24, updater17,
telemetry11, shared13, supervisor21 with one platform skip, and Go race checks.
Deployment/TLS smoke also passed (`deployment-central-smoke.log`). Eight native
Chromium page-hook fetch/XHR decision and silent-broker cases passed, using a real
loopback receiver and controlled broker; this excludes the full installed extension.
Remote CI remains unrun.

Frozen original-model public development: pipeline TP247/TN47/FP191/FN17,
recall93.56%, specificity19.75%, zero errors on502 rows. Presidio achieved78.79%
recall and79.41% specificity. Three transformed-example updates and three ordinary
controls start from exact v0.3.0; none improves pipeline recall or passes the
no-class-regression selection criterion. The original was retained at that checkpoint.

User steering: continue reducing false positives, try different learning rates,
and restart from the original. Final498-row holdout remains unscored. The fuzzer
has deterministic template sampling, not a generation-temperature setting.
Learning-rate comparisons at0.01 and0.003 versus prior0.03 completed against
an immutable source context from712ed72. An interrupted first LR batch is excluded
because a separate build changed the mutable runtime image tag between seeds.
Narrowed financial/coarse-location rules are evaluated separately to avoid mixing
effects. The anchored fictional0.003 curriculum corrects one clean prediction
across all three seeds, without losing semantic or pipeline recall. Seed42 cycle1
is selected; cycle2 loses one semantic positive, so it is rejected for selection,
cycle3 is not attempted, and cycle1 is restored. Original source/model and all
failed candidate outcomes are retained. Do not change serving images or data
during a matched batch.

The live selected model with revised rules gives TP247/TN54/FP184/FN17:
recall93.56%, specificity22.69%, zero errors on502 rows. Relative to the frozen
original, seven clean false alarms are removed with unchanged positive predictions.
Both development targets are still not met. Selected artifact:
`results/calibration0003_20261003/seed42-model.json`, internal checksum
`494cdafa337b9c93325e8262704978e2e7b55b2011b9403716996399a85ed309`.
The live stack uses revised rules, not the pinned old-rule training image.
At that checkpoint there were no pending training/test processes. Automatic updater training remains
disabled; isolated research volumes retain the selected model.

The final25-row read-only update-receipt snapshot passes SQLite integrity_check;
`results/update-receipts-final.sqlite3` SHA256:
`223cf46e6f705b4133940727143614de898fa2780bba33386d247eb09a6f9ecb`.
`results/update-audit-final.jsonl` SHA256:
`45ffb567b44dd8ec869df43f0931d81bc368220ce6bbb3315a5d91a9aea3483a`.
The earlier nine-row snapshot is retained. The training RPC does not create the
separate prompt-testing dumps. A read-only Economy worker (`gpt-6-luna`, medium
effort, balanced ceiling) verified35 report hashes, all candidate artifact hashes,
matched IDs/labels/groups and the live selected result; no discrepancies found.
This computational audit does not replace independent human labeling/review.
Professor [git4san](https://github.com/git4san) confirmation remains pending; agent
assessment is provisional. No GitHub notification or artifact upload has occurred.

Full attempts and counterevidence: `paper/research/false-positive-experiments.md`;
earlier comparisons: `paper/research/development-results.md`. Preserve source,
models, predictions and logs in a local hash-verified package before paper figures.
Checkpoint source `a14b0b9` and 646 file records are now preserved in the local
14.6 MB development ZIP. Exact archive/source/file hashes and limitations are in
`paper/research/artifacts.md` and `paper/research/artifact-manifest.json`.
The archive passes ZIP integrity and per-file SHA checks; clean-environment
reproduction remains unperformed.
Current next research action: investigate representation and training-distribution
coverage rather than repeat the stopped curve. The bootstrap encoder is randomly
initialized and frozen; threshold/casing-only diagnoses do not meet both targets.
Any new development study needs a bounded recorded protocol and separate training
data. Do not score final or generate favorable paper claims while iterating.
The goal remains active: final results, sufficient evidence, measured paper figures,
paper integration and professor confirmation remain outstanding.

### New development study prepared after the archived checkpoint

`paper/research/public-negative-protocol.md` declares a custom within-corpus
negative-coverage study before candidate scoring. The prepared curriculum contains
2,400 public annotation-negative rows from1,814 groups plus43 original bootstrap
samples. All929 locked groups and1,000 locked IDs/text keys were excluded;
selection from38,000 eligible clean rows has zero protected overlaps. The pinned
population scan retains conflict/language exclusions. Data SHA:
`61b0d5c5f06fe0d948092f86044eb21c64a08c5f6d4f60ec6ecfb1466d42ecda`.
Raw data remain ignored/local; they are not part of the earlier artifact ZIP.

Fuzzer held-out generation now reserves declared source groups and excludes their
siblings from training. Runtime training/held-out inputs now use serving's
canonical normalizer, avoiding a Unicode/obfuscation/digit-spacing representation
mismatch. Before launching this study, Docker checks passed: fuzzer26, runtime83,
evaluator46; earlier unaffected component checks remain recorded above.
The prior image/source comparisons remain historical and are not pooled with this
training-path correction. Next action: run the nine prospective independent
updates (rates0.03/0.1/0.3, seeds42/1337/2026), measure development only, and restore
the selected checkpoint. No new candidate has yet been selected at this checkpoint.
The initial launch stopped before any training because a Windows-style artifact
path was passed to the Linux evaluator. Its terminal exit1, traceback and
`public_negative_study_20261003/selection.json` are preserved; the manifest confirms
the prior selected model was restored. The corrected retry uses fresh prefix
`public_negative_v2_20261003`, forward-slash container paths and recorded source
revision. This infrastructure failure is not a rejected training candidate.

## Historical notes (superseded by the checkpoint above)

Objective: merge main and every other branch into `feat/dev-testing`, keep test
invocation under evaluation, validate in Docker, iterate on development data,
then generate measured Python figures and integrate supported findings into the paper.

## Integration and ownership

- Root is the sole writer in `D:/Git Repositories/Privoke-Research-Project`.
- Remote refs were refreshed. Every local branch and fetched remote branch was
  verified as an ancestor of merged revision `5e71717`; backup branches were included.
- Conflicts were resolved individually, retaining newer fail-closed protection,
  request cancellation, cache identity, precise candidate arithmetic, held-out
  partitioning, and safety/replay checks. Generated Firefox bundles remain locally
  available and are untracked. No push, branch deletion or external PR merge occurred.
- User clarified that invocation belongs in evaluation, while component test
  sources and the fuzzer loop stay in their original locations. Central runners
  update Docker/CI invocation paths.
  These changes require an integrated commit after affected checks pass.

## Actual validation so far

| Docker check | Result | Local evidence |
| --- | --- | --- |
| Browser suite | 94 passed | `browser-docker-rerun.log` |
| Client runtime on CPU | 76 passed | `client-runtime-cpu-docker.log` |
| Fuzzer | 24 passed | `fuzzer-docker.log` |
| Parameter updater | 17 passed | `param-update-docker.log` |
| Telemetry | 11 passed | `telemetry-docker.log` |
| Shared contracts/configuration | 13 passed | `shared-docker.log` |
| Supervisor | 21 run, one platform-specific skip, no failures | `supervisor-docker.log` |
| Go service | Race tests passed | `model-docker.log` |
| Evaluator before latest audit-record changes | 32 passed; affected tests require rerun | `evaluator-docker.log` |
| Live stack | Healthy; gRPC, streaming, analysis and synthetic randomized telemetry smoke passed without training | `stack-start.log`, `stack-smoke.log` |

Logs are ignored generated files, not publication results. The initial default
runtime test failure was caused by the user's `gpu` device value; the research
Compose override selects supported CPU mode without editing the user's settings.

## Research protocol and next actions

- User selected development targets: >=90% sensitive recall and >=90% clean
  specificity, plus the completion plan's evidence requirements. These are not
  acceptance thresholds. Final holdout outcomes must not drive further training.
- CPU research services use isolated `privoke-research-eval-20261003-*` container
  names and data volumes, preserving existing deployment artifacts.
- Five matched 500-example synthetic development ablations (seed 2026) are being
  measured. Initial regex result: 250/250 sensitive detected, 211/250 clean correctly
  classified (84.4% specificity), zero runtime errors. This is development evidence,
  not a final paper result or proof of real-world effectiveness.
- Workplace keyword matching is a plausible source of false positives; confirm
  per-layer evidence before changing it. Semantic training cannot undo a regex
  classification under strongest/union aggregation, so train only where evidence
  identifies a trainable semantic deficit.
- Rerun evaluator audit-record/ablation tests; retain baseline reports and freeze
  final source/family-disjoint data before tuning. Archive exact model snapshots,
  raw predictions, manifests and all update outcomes.
- Independent baselines, public holdout results, contextual annotation, browser
  transmission captures, independent critique and final paper evidence remain pending.
- Python figure scripts currently contain hypothetical curves and must be replaced
  only with actual measured results. The referenced `AGENTS.vision.md` companion is
  missing from this checkout. Disclose the missing companion and perform visual
  checks under the available shared policy and tool instructions.

Use `evaluation/README.md` for the current Docker test and measurement commands.
Do not mark the goal complete based on green unit tests alone.

## Invocation clarification validation

- Central browser entry point: 94 passed.
- Central evaluator entry point in Docker: 36 passed.
- Component sources restored; all central suite checks passed (runtime 78,
  evaluator 36, browser 94, fuzzer 24, updater 17, telemetry 11, shared 13,
  supervisor 21 with one platform skip, Go race tests passed).
- The fuzzer loop remains in its original service.

- Artifact audit corrected a pilot provenance error: baseline-model.json is
  v0.3.0+train.1 and the exploratory seed-42 output is v0.3.0+train.2.
  Neither is the immutable checked-in v0.3.0 baseline. Preserve pilot artifacts
  and rerun original-baseline comparisons with unique update IDs.
- Independent Presidio public development: TP208/TN189/FP49/FN56,
  recall78.79%, specificity79.41%, 502 rows, zero errors.

- Public baseline batch was invalidated by the version guard: updater startup
  inherited FUZZER_PROMPT_COUNT=128 and published +train.1 automatically.
  Research override now disables startup training with FUZZER_PROMPT_COUNT=0.
  Preserve failed batch, restore v0.3.0 after updater recreation and rerun.
