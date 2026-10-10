# Manuscript progress evidence record — 5 October 2026

Scope: interim research progress, not final evaluation or submission readiness. Workspace D:/Git Repositories/Privoke-Research-Project, branch feat/dev-testing, base 2c663e5b1e485be022914291b24260ef9cbe6ae6. Writer owns paper/main.tex, this record, and a targeted C13 arithmetic correction in paper/research/claims.md. Existing dirty evaluation work is preserved. No code, models or datasets changed; final examples not opened or scored.

## Question map and decisions

| Question | Checkpoint answer | Uncertainty / acceptance boundary |
| --- | --- | --- |
| RQ1 layer contribution | Full pipeline recall increases with annotation-negative detections | Contextual legitimacy of flags; final generalization |
| RQ2 bounded updates | Initial updates worsen specificity; selected negative curriculum removes17 false positives with8 more false negatives versus revised original | No monotone learning; representation/data versus policy-label mismatch |
| RQ3 presence/gate | Sparse runtime specificity ranges 71.01%–79.41%; gate adds 5 misses and fixture keeps 2 required-BLOCK failures | Human adjudication; safe-action generalization |
| RQ4 runtime/enforcement | Detector cost measured; installed study incomplete | Complete end-to-end cost and coverage |
| Telemetry | Event-value LDP implemented; training separate | Utility; report presence/counts/metadata not hidden |

Observation, implementation, inference and pending work are distinguished. Casper's layered overlap is credited with existing Casper2024 citation. No blanket static-system, superiority or usability claim. The joint 90/90 development target remains unmet; final 498 locked/unscored.

## Architecture evidence ledger

Review locators below refer to the assigned checkout. Root coordinated independent read-only source review and integrated findings; companion docs supply context rather than replacing source.

| ID / claim | Source path / locator | Evidence / assumptions / boundary |
| --- | --- | --- |
| A1 independent deployments | extension/runtime-supervisor/src/main.py:64; docs/project/overview.md Current Runtime Path; docker-compose.yml | Workstation control 50056, detector 50057, bridge 8080; Compose 50054 independent; no fallback |
| A2 hook actions/extraction | extension/src/page-interceptor.js:28,:252; interception-failure.js | POST fetch/async XHR; WARN forwards original, BLOCK cancels; no extracted prompt can pass; limited paths |
| A3 trust/failures | page-interceptor.js:143; semantic-availability.js:2,:35,:47; extension/client-runtime/src/pipeline.py:82 | Same-window messaging trusted; known semantic outage omits the layer when others remain; requested error upgrades ALLOW only; surviving WARN/BLOCK retained |
| A4 normalization/layers | extension/client-runtime/src/detection/preprocessing.py:29; pipeline.py:190,:221,:421,:458 | NFKC/lowercase/deobfuscation, original spans; regex-first BLOCK skips remaining layers; otherwise concurrent execution; strongest/union fusion preserves actions |
| A5 categories/NER/actions | shared/python/privoke_contracts/classification.py:22; extension/client-runtime/src/NER/ner_detector.py:57; NER/use_cases.py:25; classification/classification_policy.py | P0–P4, PU; PERSON/GPE/LOC/FAC/ORG, not DATE; confidence <0.5 moderation; binary prediction differs from action |
| A6 contextual encoder | models/generate_baseline.py:40,:68,:146,:181; extension/client-runtime/src/transformer_encoder.py:86; src/model.py:352,:402,:544 | Seeded random weights, hashed bounded tokens, 43 bootstrap examples, six trainable heads; device support; not a pretrained LLM |
| A7 streaming/cache | services/model-streaming-service/cmd/server/streaming_server.go:158; extension/client-runtime/src/LLM/privoke/parameter_stream.py:53,:189; streamed_model.py:105,:232 | Per-request immutable version, validation, short cache; no subscription or historical alias |
| A8 publication | services/param-update-service/app/server.py:115,:151; docs/services/parameter-updates.md | Bounded heads, stale rejection, sequential atomic replacement, durable replay receipts; not federated |
| A9 sparse task/gate | shared/python/privoke_model/presence.py:24,:25,:150; presence_training.py:36; runtime grpc_server.py:159,:197,:446; pipeline.py:254 | Separate TF-IDF presence, blocked heads, frozen features; explicit gate affects only semantic findings; ABSENT is not safe |
| A10 scratch mechanics | shared/python/privoke_model/scratch_presence.py:12,:20,:199; runtime scratch_presence_model.py:22,streamed_model.py:195; evaluation/privoke_eval/in_house_transformer_training.py,in_house_presence_training.py | Six scratch inference IDs; offline head/full-encoder explicit labels, finite checks, clipping, rollback, export; no research fit or quality result |
| A11 telemetry | extension/client-runtime/src/grpc_main.py:50; privacy modules; docs/services/telemetry.md; docker-compose.yml:166 | Workstation opt-in versus Compose; event epsilon 1, daily 8, five fields; trusted emitter and ledger; reports separate from training; utility unmeasured |

Source confidence is high for implemented behavior, with empirical coverage bounded as stated. Read context: AGENTS.md, AGENTS.research.md, docs/git-usage.md, root/docs READMEs, docs/Research-paper-writing-guide.md, research-methodology-draft.md, architecture/model/result docs, paper/main.tex, paper/ref.bib, paper/research/claims.md and protocol.md. Requested root-level Semantic/Model README paths resolve under docs/.

## Numerical table-to-raw-path map

All paths are relative to workspace root. Local ignored raw artifacts are not automatically public. The read-only numerical worker independently recomputed decisive raw counts; root validated manuscript transcription/arithmetic. Source identity review used existing pinned reports and documentation, rather than re-auditing every hash or RPC. No final file was read. Tables are direct transcription of verified results, without fabricated trend plots.

| Table / paragraph | Raw source and locator | Version / scope |
| --- | --- | --- |
| tab:ablations | evaluation/results/original_public_development_frozen/local-jsonl_{regex,ner,regex-ner,semantic}_original_public_development_frozen_results.json and local-jsonl_pipeline_streamed_original_public_development_frozen_results.json; metrics.true_positives/true_negatives/false_positives/false_negatives/evaluated_samples and predictions | v0.3.0, source 712ed72, same 502 rows; paper/research/development-results.md |
| Presidio | evaluation/results/presidio_public_development_metrics.json; raw presidio_public_development.json | Small English model, threshold 0.5, same 502 rows |
| Initial updates | evaluation/results/original_updates_20261003/ and original_updates_20261003_seed{42,1337,2026}_cycle1/; paired_augmentation_*.json | Independent exact starts, transformed/ordinary rate 0.03; development-results.md |
| Historical lower-rate/rules | paper/research/false-positive-experiments.md raw attempted-run locators | Prior selected 247/54/184/17 distinct baseline |
| tab:updates | evaluation/results/public_negative_v2_20261003_lr003_seed42_cycle1/local-jsonl_pipeline_streamed_public_negative_v2_20261003_lr003_seed42_cycle1_results.json |239/70/168/25; public-negative-results.md |
| Update intervals/stopping | evaluation/results/public_negative_v2_20261003/ twelve paired reports; public_negative_curve_20261003/ | Revised original 247/53/185/17; cycle two 236/78/160/28 then restored |
| tab:presence / sparse timing | evaluation/results/presence_profiles_20261004_v1/runtime-base/{efficient,balanced,quality}/{report,predictions,run-manifest}.json; metrics.tp/tn/fp/fn |502 each, zero errors; docs/presence-model-improvements.md |
| Nine sparse updates | evaluation/results/presence_updates_20261004_v1/ |9 accepted, none retained, validation specificity unchanged |
| Offline text control | evaluation/results/text_control_20261004_v1/{report,selection,run-manifest}.json; audit/audit.json | C=1 selected on validation;248/186/52/16 |
| External expansion | evaluation/results/external_pii_rpc_20261004_v2/{efficient,balanced,quality}/expanded/{validation,nemotron_heldout,meddies_heldout}/{predictions,run-manifest}.json |19,993 training rows, C=10; 1,000/1,000 and 999/999 per profile; repeated profiles are not 5,997 independent samples |
| tab:cascade | evaluation/results/contextual_cascade_20261004_v3/cascade-evidence/evaluate-development/original-{efficient,balanced,quality}/report.json and corresponding frozen predictions/bindings | source d1e7e3ca77eaef9101907e9082fee3bc0dcbf766;502 each, zero errors; intervals uncomputed |
| Gate thresholds / eligibility | Same cascade-evidence/evaluate-validation/ and selection bindings | Trained 426/475=89.6842% ineligible; original 435/122/371/40 |
| Residual union bound | evaluation/results/goal_audit_20261004/cascade-residual-analysis-v1/{analysis-v2.md,aggregate-v2.json} |193/225/13/71,225/238=94.54%; not an achieved full-pipeline result |
| Fixture | evaluation/results/contextual_fixtures_20261004_v1/pairs/original-{efficient,balanced,quality}/report.json; support rubric/review and study-run-manifest |41 primary cases, 7 excluded; ordinary 30 compatible, gates 32/31/31; 15/17 minimum private action for all; 2 BLOCK failures |
| tab:timing contextual | evaluation/results/model_profiles_20261003/{summary,hardware}.json; model_profiles_20261003_privoke-{efficient,balanced,quality}/ raw reports |source b733960079babc9fc695fdc6ba836ac7ae87b86e; first request included, sequential CPU, no browser/bridge |
| Structural scan | evaluation/results/advpii_structure_20261004_v1/{run-manifest,aggregate-report}.json |104,728 rows; paper/research/data-expansion-ledger.md; No broad-target labels or fit |

Important baselines: selected 239/70/168/25 has 23 fewer false positives than initial 247/47/191/17;17 fewer false positives than revised original 247/53/185/17;16 fewer false positives than prior selected 247/54/184/17. All lose 8 positive detections. Quoted +7.14 pp specificity interval uses revised original. Source-group bootstrap: 2,000 resamples, 95% intervals, seed 3102026, 465 groups; searched/selected and descriptive.

### Identity commitments

- PIIMB revision 4a13e9ffe6fd0d275efbde8afd4d8d8f1ffc2133; locked manifest evaluation/results/locked-public/manifest.json. Development SHA-256 65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095; final digest-only 613a78b9e5fa677904125b4c056fb8d57d15fb6ebd9c443a75f406ae3ac05515.
- Original balanced internal checksum 8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c. Selected v0.3.0+train.1 checksum 8c139431ba8605a3d6817d24d233cce78fc22a086fdeb3ee99702ada86c80015; archived file SHA-256 6f645057ad6cddfe6be3c00b85556ffda8c633834bda5e6a47ca2aee8babd921; live restored file e4363fc47b0b4663f92d923842e2bfe635b0d7b2b165c9cd4a8fb2f4a7e66d93. Parsed payload identical, bytes different. Float32 shape-inclusive fingerprint 3b9b63c14e5a5e3e3a82051cdc349a3c9d452b156f355594e5f7b49cb215758c.
- Prepared train SHA-256 da9a1b095587264714c5ae99c8a0f92329a04f6fc237a8ace7d71e837ede429d; validation d2d0c538e49f5bbc7a8f85887b9b8cfddb188a5ab9aae55c69ce26ae932be6d1; prepared development 45f91e320482dde4d0724cdf42a341649d52e33aeae326f059c714edc97cc706 (serialization differs from locked development).
- Presence fit source d52bf84d83addb827cc21b96f0be8ecc995bfaaa, scoring source 4615019e5d00d28a48cb05c1ea8324e87b684829; manifest SHA-256 5406a1b58d9bc49e8f36ad5da94d6f9f2f36a093ec640b67bd14922c899609b1.
- Nemotron pin b70ffaf5ff39e079776134c5bf4381f00a9fd1ed; Meddies 6a5c8f5441e3b421d983c9741770262365acdd77. External manifest SHA-256 62b28e0f6c2e8006915e9bdc8498462d636e44d5bb397f8704a95d96d2ab8671; aggregate e5e138d42f0930390702fb56a745ae0b8e7f7772791d8ed473ab56d51b250c2d.
- Cascade manifest SHA-256 45fd843f4590e43ee7ab740c1c5b8aa5e34b785a56140c3ea98ab4ed5773c792; fixture manifest dc92febae5515209172df0482970287ab88d49c766f62bae22dbf625a513ac27, source 4fa43bf1dfdbcec494153359b19094071ea5d76d.
- Augmentation pin 02741d9f99a91b8fdcf48f4316a2c73be7a7449a; full Parquet SHA-256 e97f6a32132e7fa058919798c030fca54aaad3318c47954d281717a435bfeb69. Source structural/protection checks not broad-target labels.

## Failed installed-extension validation

Latest evaluation/results/goal_audit_20261004/installed-browser-terminal-v9.json source 29a2301e9fbd7d4e7d407f1a20d93d3f7e113198, exit 1, successful_study=false. Root found nine failed receipts and no later complete study. v9 completed 3/12 cold sessions, 90/360 measured requests, 14 matrix probes and three finalized resource windows; four resource files instead of 12. Sampler missed owned detector startup identity in session 04-xhr-allow-r1; cleanup verification false. Partial 14 forwarding probes match eight exactly-once forwards and six zero sends, but are diagnostics only. p99 qualification incorrectly said 60 when fetch cells actually contained 30. Partial warm costs are not promoted in the paper. Source corrections differ from successful study evidence.

## AI assistance / review

Writer configured gpt-6.1-sol, Specialist under balanced ceiling, medium effort per root assignment. AI assisted substantive rewriting, table formatting, evidence synthesis, ledger and arithmetic correction. Root used independent read-only source/numerical reviewers; this is computational review, not human domain confirmation. Fixture labels remain assistant-provisional with professor confirmation pending. No new labels, fitting, data generation or external messages in this task. Authors must verify facts/citations and selected-venue disclosure; this record is not a finalized submission declaration.

## Validation and remaining work

- Root structural checks passed at draft checkpoint: brace balance, environment stack, all nine citation keys exist, labels unique/resolved, whitespace. Writer reruns affected source checks after requested wording/table changes.
- Root raw-count/source-identity review passed without reading final. All 15 table confusion rows satisfy TP+FN=264 and TN+FP=238; displayed recall/specificity match to two decimals (tolerance 0.005 percentage points).
- Five measured tables replace hypothetical curves; obsolete minted dependency removed with pseudocode, eliminating shell-escape/Pygments requirement.
- Built-in compiler preflight and edited-source retry failed with “Unable to find standard directories for platform.” No local compiler found. The final native compiler retry failed with the same platform-directory error; successful compilation is not established, PDF was not exported and visual layout review remains unrun. Timing table uses table* for normal-width layout; evidence path uses breakable path.
- Targeted claims.md C13 correction: standalone238/112/126/26 specificity 47.06%; reused-union250/108/130/14 specificity 45.38%. Other historical claims untouched.
- Pending: final 498 after freeze; human contextual/action adjudication; complete installed study/cost/coverage; reviewed whole-prompt augmentation labels and disjoint quota-feasible partitions; scratch encoder research fit; telemetry utility; raw licenses/artifact packaging; selected venue and AI checks.

Final independent methods/results review cleared the bounded manuscript scope; it did not re-audit every hash or RPC. Main source SHA-256 remains 563ff9b2f19128e5fdbc5e3c44414fc1a72b8e24a7c03761828853b08465f5dd.
