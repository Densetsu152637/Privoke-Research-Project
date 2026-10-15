# TW01: task-query window study (12 October 2026)

The stored goal was: “Run a controlled semantic-only training study comparing the revised architecture and loop against the current baseline, and report whether results improve. Do not use protected final data or promote any model.” The original prompt was: “Do not implement anything or test anything, but iterate the current model training loop and also the model architecture to see if you can improve the results.” The later authorized protocol compared a frozen TRAIN-window update with the matched legacy update for v1 and v2 model starts across seeds 42, 43 and 44. The user then approved the exact twelve comparisons and development scoring: “Approve the 12 comparisons and development scoring”. Finally, the user directed: “If you are not seeing good results, early terminate the goal and move to the next prompt when it comes.” This record is a **user-terminated partial development study**, not a completed fourteen-candidate comparison or a model promotion.

The [frozen protocol](../evaluation/results/task_query_window_20261012/host-v2/protocol.fit-r3b.json) requested explicit semantic layer `[4]` and checked actual sole-layer execution. All twelve physical fits reached known terminal outcomes: seven selected an update and five were known no-update. The [matrix settlement](../evaluation/results/task_query_window_20261012/host-v2/matrix-settlement.json) pins each request, audit, receipt where applicable, effective artifact, source inventory and server image. It has SHA-256 `e758a2066a83190e6db7b5586afd5ae23dae64406d3ae74ef964784d89a115c8`. The approved development [endpoint release](../evaluation/results/task_query_window_20261012/host-v2/root-release.endpoints.json) has SHA-256 `4b436d413f9768513a5414434cfdb00fd72c1712028406960d451dea495e2aa8`.

Scoring completed four candidates (`v1-legacy-42`, `v1-window-42`, `v2-legacy-42`, `v2-window-42`) across context64, context320, binary502 and hazard48. Each complete binary set kept its eleven native overlength errors: 491 successful of 502 requested. The fifth candidate, `v1-legacy-43`, completed context64 and context320, then stopped during binary502 after 23 completed row responses and one request without response. The remaining nine candidates, including both initial controls, were not scored. No full-matrix analysis was run.

The decisive frozen seed-42 primary comparison, `v1-legacy-42` to `v2-window-42`, used 64 successful semantic-only rows per model:

| Measure | Baseline | Candidate |
| --- | ---: | ---: |
| Sensitive joint | 0/32 | 0/32 |
| All joint | 2/64 | 10/64 |
| Sensitive recall | 23/32 | 27/32 |
| Clean specificity | 30/32 | 19/32 |
| Severity | 45/64 | 35/64 |
| Category | 30/64 | 30/64 |
| Visibility | 14/64 | 25/64 |
| Action | 44/64 | 34/64 |

The matched candidate gained no sensitive-joint cases and regressed eleven clean-specificity, ten severity and ten action cases. Independent reconciliation found newly incorrect actions of 17 on primary context64, 29 on context320 and five on hazard48; under-restrictions were 6/0/1 and over-restrictions 12/29/4, respectively. This fails the frozen per-seed non-regression and harm gates regardless of unscored seeds. These are development findings only; they do not isolate architecture or prove a general training effect.

The immutable [early-termination record](../evaluation/results/task_query_window_20261012/host-v2/early-termination.json) (SHA-256 `efb164d624b7699eea0383c8a5841d04bc58339fc5306de207c4c40155ca77f9`) and [partial completion inventory](../evaluation/results/task_query_window_20261012/host-v2/partial-completion-inventory.json) (SHA-256 `ac5875d8341796693902ba51bb9f492a548d77111119055e31b6ab9651a4c7f6`) bind the preserved per-row files and interrupted server log. The host scorer exited; its exact owned Docker servers and network were removed. All twelve effective weights and reusable originals remain under `models/experiments/task_query_window_20261012/`. The original zero-compute admission/dependency failures and recovery revisions remain in the run's attempt archives and source/image release chain. No protected-final input was read and no model was promoted.

For source traceability, this internal record is bibliography key `privokeTW01TaskQueryWindow20261012`. The study's final frozen [source attestation](../evaluation/results/task_query_window_20261012/host-v2/source-attestation.fit-r3c.json) and [image manifest](../evaluation/results/task_query_window_20261012/host-v2/images.fit-r3.json) are retained with the raw run. Any future comparison needs a new authorized, versioned run; these partial score files remain historical evidence.
