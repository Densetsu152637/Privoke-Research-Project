# Full-encoder privacy fine-tuning (EN3-R1)

Status: **completed and independently audited** on 13 October 2026. All three selected and terminal full-model exports passed checkpoint and native checks. The comparison below is on reused DEVELOPMENT data; it does not establish production safety or an independent test result.

Exact user request: “can you now fine tune the encoders for each tier?”

The three fits start from the corresponding [PH3 validation-selected packages](privacy-head-training-v3.md). Each new stage jointly updates the BERT encoder, first-token dense/tanh pooler, and sensitivity, visibility, and category heads through native differentiable forwards. PH3 fitted only the heads; its selected head epochs were 12, 7, and 4 for efficient, balanced, and quality. The upstream language-pretraining epoch and step counts are unknown. These histories are separate from the EN3 work below.

## Fixed method and provenance

The host controller is [run-privacy-encoder-v3.py](../evaluation/run-privacy-encoder-v3.py), backed by [privacy_encoder_v3.py](../evaluation/privoke_eval/privacy_encoder_v3.py). All three tiers use the admitted R3 6,240 TRAIN rows and 1,560 validation rows. The previously opened 1,560-row PH3 comparison fixture is excluded from fitting and selection. It is now **reused DEVELOPMENT**.

Every learned parameter is trainable. AdamW uses learning rate 2e-5 for encoder/pooler and 1e-4 for heads, betas 0.9/0.999, epsilon 1e-8, matrix decay 0.01, and zero bias/LayerNorm decay. Microbatches of 16 accumulate to an effective batch of 64. Weighted cross-entropy denominators cover the whole logical batch, including the final 32-row batch; category BCE divides by actual rows times 10. Gradients are clipped to norm 1 after accumulation. Encoder dropout 0.1 is active during training and disabled for validation and export. Float32 deterministic execution uses no AMP or TF32. Linear warmup spans 98 updates, with scale 1/98 on update 1 and full rate on update 98; fixed decay reaches zero at planned update 2,940. Selection uses the earliest trained epoch with strict weighted validation-loss improvement greater than 0.0001, minimum 5 and maximum 30 epochs, and patience 5. Epoch 0 is a reference, not a selectable checkpoint.

The actual full fits ran serially in host Python 3.11.9 with PyTorch 2.12.0+cu130 on CPU, using four threads. All three CPU and CUDA bounded TRAIN/validation resource probes passed. The matched warm quality pilot measured faster steady CUDA updates but left only 863 MiB free amid concurrent GPU load, so the frozen full-fit protocol chose the more stable CPU resource lane. The separate CUDA candidate and pilots are not CUDA fits or model-quality results. The old PyTorch 2.11.0 CPU environment serves and checks the native exports.

The fixed CPU run is under `evaluation/results/privacy_encoder_v3_20261013/runs/cpu-01/`, with models under `models/experiments/privacy_encoder_v3_20261013/runs/cpu-01/`. Its protocol SHA256 is `16d7074212d898555cd7d90662f2484bb8b48db15a27170f9ac68cd65abf6355`. The admitted 164-file source closure SHA256 is `49446bef90807d993bc5e05e20bd343dbc293d5b806c77fce8995db0b1535cf1`, based on task commit `aed68295240bfe44558251cbfc2dbfbdc093331f` plus preserved working-tree bytes for pre-existing dirty dependencies. HEAD alone is insufficient for exact replay. The original PH3 159-file closure, source, protocols, and evidence remain unchanged.

## Actual training and exports

| Tier | Inherited PH3 selected head epochs | New joint epochs completed / selected | New updates completed / selected | TRAIN exposures completed / selected | Best validation loss | Fit-loop seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Efficient | 12 | 24 / 19 | 2,352 / 1,862 | 149,760 / 118,560 | 1.801638 | 496.546 |
| Balanced | 7 | 19 / 14 | 1,862 / 1,372 | 118,560 / 87,360 | 1.748905 | 430.797 |
| Quality | 4 | 9 / 4 | 882 / 392 | 56,160 / 24,960 | 1.621702 | 685.734 |

All three fits stopped by validation patience. Total executed new work was **52 joint epochs, 5,096 optimizer updates, and 324,480 repeated TRAIN exposures**, with **1,613.077 fit-loop seconds (26.885 minutes)**. Each epoch repeats the same 6,240 TRAIN examples; exposures are not distinct examples. Fit-loop time includes validation and checkpoint work inside the loop and excludes initial loading, exports, audits, and scoring. The selected/terminal full checkpoints retain the model, optimizer, schedule, Python/NumPy/CPU/CUDA RNG state, epoch records, selection state, and provenance needed for epoch-boundary resume. All 52 checkpoints and all six exports passed independent audit.

| Tier | Native parameters | Changed tensors against PH3 selected | Selected manifest SHA256 | Terminal manifest SHA256 |
| --- | ---: | ---: | --- | --- |
| Efficient | 4,785,044 | 77 / 77 | `4850180c40710949c91e37f8bfad5787eb00a43992b419e23bfb8fd24e8c703e` | `aef438d7e3d6a27c34b122b4903f80d7f7217249374825159c8a09195023d107` |
| Balanced | 9,596,180 | 45 / 45 | `141dcd99e58becb0d1ee463da1bfdea9d31b92b1422b619777ee65be20954318` | `420ccdd847daee062267421daa34f951d21b6a463b52c816d07747ef2a30d562` |
| Quality | 17,493,780 | 205 / 205 | `1c5a962761b0699ac1bcf5b3753525819d7d4725e499f5a9f2eff295a06dccba` | `ab931425d6bad1e3d47084fd7b9f8d112c6c3c94b2a63e0f6ae2e950aa1d6ad0` |

Every encoder layer, embeddings, pooler, and six head tensors changed, with finite float32 native inventories matching the selected or terminal checkpoints. Config/vocabulary bytes and publisher ancestry remain fixed. Native `backbone_sha256` describes that ancestry; the selected manifest and full tensor inventory identify the adapted model. Standalone export verifiers each checked 16 validation rows but ran with 16 threads and deterministic mode off; their within-environment aggregates are not direct cross-version evidence. A separate fitted-native supplement compared all six PyTorch 2.12 CPU reference payloads directly with PyTorch 2.11 native outputs and a second native reload, using four CPU threads and deterministic mode in both processes. On VAL[:16], logits, packed/named classifications, confidence, and actions matched exactly with maximum logit difference zero. This bounded parity check does not establish universal numerical equivalence or model quality. See the [postfit evidence review](../evaluation/results/privacy_encoder_v3_20261013/planning/postfit-evidence-review-01.md) and [fitted-native proof](../evaluation/results/privacy_encoder_v3_20261013/implementation/fitted-native-01/proof.json).

## Reused DEVELOPMENT comparison

The selected EN3 packages were fixed after all three fits, all six exports, and audits before the old fixture payload was opened for this comparison. The accepted PH3 selected-package raw responses were imported as before controls. The new scoring paired exact case IDs, text, truth, and allowed actions across all 1,560 cases per tier; it did not rerun PH3 controls. Each new native RPC explicitly requested semantic layer `[4]`, asserted actual sole layer `[4]` and native model identity, and supplied no audience hint. There were zero errors in 4,680 new accuracy RPCs. Errors would have counted incorrect in the full denominator.

| Tier | Joint correct PH3 → EN3 / 1,560 | Category-bearing joint PH3 → EN3 / 720 | Category macro F1 PH3 → EN3 | Sensitive recall PH3 → EN3 / 810 | Clean specificity PH3 → EN3 / 750 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Efficient | 358 → 858 | 64 → 370 | 0.532 → 0.875 | 763 → 784 | 564 → 646 |
| Balanced | 396 → 889 | 77 → 351 | 0.597 → 0.880 | 757 → 794 | 520 → 624 |
| Quality | 360 → 888 | 48 → 363 | 0.444 → 0.932 | 663 → 808 | 494 → 670 |

Same-case joint improvements/regressions were 538/38, 559/66, and 560/32 for efficient, balanced, and quality, for net gains of 500, 493, and 528. Action distance worsened on 19 over-action and 4 under-action cases for efficient, 20 and 1 for balanced, and 40 and 1 for quality; all 1,560 paired cases per tier were comparable with zero error pairs. Overall action-distance totals improved from 325 over/62 under to 153/7 for efficient, 349/96 to 203/10 for balanced, and 365/144 to 102/1 for quality. These totals are distances, not counts of distinct harms. Balanced exceeds quality by one joint-correct case (889 versus 888), while quality has the highest category macro F1, sensitive recall, and clean specificity in this fixture; no universal tier ranking follows. [Complete analysis](../evaluation/results/privacy_encoder_v3_20261013/runs/cpu-01/comparison/analysis.json) retains per-category precision, recall, F1 and support, component confusion matrices, all slices, paired changes, action distances, and separate descriptive latency records. Its SHA256 is `04338a881f517b22c7571bf6a589e219252153ead373c658782ff865f356600d`; the independent [comparison review](../evaluation/results/privacy_encoder_v3_20261013/planning/comparison-review-final-01.json) passed.

The 35 synthetic families have assistant-provisional labels and shared general concepts. This already opened fixture is reused DEVELOPMENT, not a new independent or protected final test. Same-case pairing supports a descriptive before/after accuracy comparison, but prior exposure, correlated rows, and the absence of an untouched control limit causal and generalization claims. PH3 and EN3 latency came from different runs, so their medians are separate observations and do not establish a speedup. No legacy publication guard, production promotion, or real-world safety claim follows from these results.

## Reproduction and boundaries

Run Python tests, fitting, export checks, and dataset scoring in the host environment. Docker Compose may host loopback servers only. The focused synthetic mechanics suite is `evaluation/.venv-v3-study/Scripts/python.exe -m unittest discover -s evaluation/tests -p test_privacy_encoder_v3.py`. Reproduction requires fresh assigned paths and protocol-bound root acceptance; existing immutable runs must not be overwritten. `prepare` pins the PH3 selected assets, R3 data, environment, and retained source bytes; a bounded TRAIN/validation `probe` preceded the accepted serial `fit` runs. `export`, `audit-training`, and old-CPU `verify-export` fix and check the six packages. Comparison is separately admitted only after all export seals. Failed attempts, immutable checkpoints, audit reports, original PH3 packages, and independently pinned linguistic ORIGINAL weights remain retained under their provenance paths.
