# Evidence, provenance and reproduction

Checkpoint: 6 October 2026 (Australia/Sydney). Integration checkout: `feat/dev-testing`, HEAD `0dcabc4971b14b63ab43be6388cf519ce1deed48`. Existing archived reports were read-only; new deliverables are confined to this Markdown folder.

## Validation receipt

The numerical worker and root separately executed the reaggregation against the same preserved inputs. Root used Python 3.13 with the standard library only; this procedure neither imports the evaluator nor runs a detector.

- **Passed:** 17 complete development configurations have exactly the same 502 unique IDs, truth labels and groups. Their confusion matrices exactly match the saved report totals; all have zero errors.
- **Passed:** five originating-dataset strata reconstruct the complete development counts. AI4Privacy's two task strata are merged, with the saved source field checked against ID prefixes. No class denominator is invented.
- **Passed:** all 18 external runs reconstruct their saved confusion counts. The six model/control combinations within each partition match hashed row IDs, truth, groups and source; returned artifact identities/thresholds and recorded prediction-file hashes match. Total archived scored requests: 17,802, zero errors.
- **Passed:** cascade prediction-file hashes match their reports. All ordinary/gated responses used here are error-free. Sparse development rows agree with reported returned model identity. Strict Boolean-label/prediction and nonmissing identity/group assertions pass.
- **Passed:** root generated the Markdown tables directly from the computed aggregates, rounding percentages only for display. The digest inventory below covers 58 numerical input files.
- **Passed at root checkpoint:** the inventory and SHA-256 hashes of all 47 existing files under `paper/` match the pre-work snapshot. Paper sources, reference manuscript, bibliography, figures and existing paper research notes are unchanged.
- **Not run:** new inference, fitting, threshold selection, deployment, new source acquisition, final evaluation, contextual annotation or significance testing. No source-code change requires a runtime regression suite. Numerical reconciliation and document/source review are the applicable checks.

Independent critical review passed the integrated notes. The critic separately recomputed the five current-source confusion sets and group counts, checked contextual identities against the three archived manifests, executed the exact embedded reproduction script, verified all 58 numerical digests and checked the support/rate arithmetic in all 121 detailed Markdown rows. Primary-source review confirmed Casper's denominators, PrivacyLens's all-No/evaluation-only boundary, the SPY/TAB target distinctions and declared artifact terms. The PrivaCI-Bench total-count discrepancy was repaired in the literature note.

Root also passed the exact Markdown-code replay, checked all 121 detailed table rows, Markdown fence balance, every local reference path and a clean tracked Git diff. Only this new Markdown folder is added. The paper inventory and all 47 hashes matched again at the final integrity checkpoint. Remaining external-access, annotation and generalization limitations are explicit research findings, not unreported completed experiments.

## Scoring and partition boundaries

For standard contextual/Presidio reports, the saved Boolean `detected_sensitive` is used. Its task is prompt-level annotated-PII presence: nonzero sensitivity or any returned category, independent of action. Sparse rows use `predicted_present` at their saved thresholds. Cascade classification is positive when sensitivity is not S0 or its categories are nonempty. Full prompt text and clinical content are never printed or included in these notes; cascade JSON containers are parsed to extract the required fields.

```text
recall = TP / (TP + FN), if positive support exists
specificity = TN / (TN + FP), if clean support exists
false-positive rate = FP / (TN + FP), if clean support exists
balanced accuracy = (recall + specificity) / 2, only if both classes exist
```

Rows in error are not silently converted to negatives. All included runs have zero errors. Pipeline layer skips after regex short-circuit are not request failures: the contextual archives have 396 rows with NER/semantic run and 106 with those layers intentionally skipped, but valid final detections for all 502 rows.

This is saved development-data reaggregation. No locked final file is opened or scored. The reference mapping comes from the efficient sparse profile's existing development predictions, not a new read of a final or partition-preparation file. Source-heldout clinical/Nemotron runs are handled separately and do not become final-test evidence. Historical reports contain text-bearing fields; only reviewed aggregate metrics and provenance are documented.

## Model identities and checkpoint differences

Artifact checksums below are logical artifact checksums, distinct from file-byte SHA-256. A version string alone cannot identify the evaluated model.

“Current selected” names the archived research selection, not a newly measured serving state. A read-only check of tracked `models/privoke-balanced.json` returned original v0.3.0 and checksum `8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c`. No live service was queried or reconfigured.

| Contextual checkpoint | Version | Artifact checksum |
| --- | --- | --- |
| Original contextual | v0.3.0 | `8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c` |
| Earlier selected contextual | v0.3.0+train.1 | `494cdafa337b9c93325e8262704978e2e7b55b2011b9403716996399a85ed309` |
| Current selected contextual | v0.3.0+train.1 | `8c139431ba8605a3d6817d24d233cce78fc22a086fdeb3ee99702ada86c80015` |

Identity bindings are in the [original manifest](../../evaluation/results/original_public_development_frozen/manifest.json), [earlier selected manifest](../../evaluation/results/selected_context_development_20261003/manifest.json) and [current selected manifest](../../evaluation/results/public_negative_v2_20261003_lr003_seed42_cycle1/manifest.json). These supply artifact checksums separately from the numerical prediction-row inventory below.

The gate study uses its own ordinary original control and later rule/source checkpoint. Its baseline confusion counts differ from the older original archive despite matching development IDs. Its expanded comparison must not be framed as a pure semantic-only or training-only effect relative to the older run.

Sparse development identities are described in [the preserved profile record](../presence-model-improvements.md). The external study's validation C/threshold choices and positive-only heldout provenance are described in [the preserved data analysis](../PII-dataset-analysis.md). These files were not edited.

## Inputs and hashes

All paths below are explicitly enumerated by the script. Ordinary evaluation reports include their prediction rows internally. Sparse, cascade and external predictions are sidecars. No recursive glob over experiments/final partitions is used.

| Numerical input | SHA-256 |
| --- | --- |
| [evaluation/results/contextual_cascade_20261004_v3/cascade-evidence/evaluate-development/original-balanced/predictions.json](../../evaluation/results/contextual_cascade_20261004_v3/cascade-evidence/evaluate-development/original-balanced/predictions.json) | `9dea83b34914e31cc33ad47d7bf69e2c136cd0bfde3b1ef65e847ae00375fa76` |
| [evaluation/results/contextual_cascade_20261004_v3/cascade-evidence/evaluate-development/original-balanced/report.json](../../evaluation/results/contextual_cascade_20261004_v3/cascade-evidence/evaluate-development/original-balanced/report.json) | `e5f86a517b654602fcd38e466572d0fac6ab5fd7c991cf187a8747433adc16c6` |
| [evaluation/results/contextual_cascade_20261004_v3/cascade-evidence/evaluate-development/original-efficient/predictions.json](../../evaluation/results/contextual_cascade_20261004_v3/cascade-evidence/evaluate-development/original-efficient/predictions.json) | `e8ffb14c6b4171abc9e8516adcfcf74c2f0fdedb26404cbe0ceac7a4304aa532` |
| [evaluation/results/contextual_cascade_20261004_v3/cascade-evidence/evaluate-development/original-efficient/report.json](../../evaluation/results/contextual_cascade_20261004_v3/cascade-evidence/evaluate-development/original-efficient/report.json) | `9ff2d2df983b1520a6a14211ce0a8e6a964b63ff937cd5c45bf817fab8d75554` |
| [evaluation/results/contextual_cascade_20261004_v3/cascade-evidence/evaluate-development/original-quality/predictions.json](../../evaluation/results/contextual_cascade_20261004_v3/cascade-evidence/evaluate-development/original-quality/predictions.json) | `1be184ff3a48954f85528985059993ac5c194878cfb624ef43e9be0a509e6093` |
| [evaluation/results/contextual_cascade_20261004_v3/cascade-evidence/evaluate-development/original-quality/report.json](../../evaluation/results/contextual_cascade_20261004_v3/cascade-evidence/evaluate-development/original-quality/report.json) | `fcf5f1d19d3c0d29dc31bb18a1a754ce00854f57c360219fa755aeb65f732c1d` |
| [evaluation/results/external_pii_rpc_20261004_v2/balanced/baseline/meddies_heldout/predictions.json](../../evaluation/results/external_pii_rpc_20261004_v2/balanced/baseline/meddies_heldout/predictions.json) | `ed9a7ed92db363456c40f6244a8f832b94efb6448194ef88b3b8e576521458a1` |
| [evaluation/results/external_pii_rpc_20261004_v2/balanced/baseline/meddies_heldout/run-manifest.json](../../evaluation/results/external_pii_rpc_20261004_v2/balanced/baseline/meddies_heldout/run-manifest.json) | `c78249e26895f6646bbd634f59d9771e7cd8ce0c9717ac01c709746376dfb460` |
| [evaluation/results/external_pii_rpc_20261004_v2/balanced/baseline/nemotron_heldout/predictions.json](../../evaluation/results/external_pii_rpc_20261004_v2/balanced/baseline/nemotron_heldout/predictions.json) | `eaac4930f9b32be4ac1254b05f2f6f3a5514472e099adaed61cef61aae0567ac` |
| [evaluation/results/external_pii_rpc_20261004_v2/balanced/baseline/nemotron_heldout/run-manifest.json](../../evaluation/results/external_pii_rpc_20261004_v2/balanced/baseline/nemotron_heldout/run-manifest.json) | `834c500d73c3c2cf140fbd9705b5572c7f5fbddd0586e542efabb7bdc665d8a0` |
| [evaluation/results/external_pii_rpc_20261004_v2/balanced/baseline/validation/predictions.json](../../evaluation/results/external_pii_rpc_20261004_v2/balanced/baseline/validation/predictions.json) | `1c40763051ecab674d09e73c437413cf52f446826a3c027f7b717636a81035fa` |
| [evaluation/results/external_pii_rpc_20261004_v2/balanced/baseline/validation/run-manifest.json](../../evaluation/results/external_pii_rpc_20261004_v2/balanced/baseline/validation/run-manifest.json) | `a4aa8210037a8a3445a0b6f0f4b414ee6dc6e10f3e359f8e6328c11859f68b60` |
| [evaluation/results/external_pii_rpc_20261004_v2/balanced/expanded/meddies_heldout/predictions.json](../../evaluation/results/external_pii_rpc_20261004_v2/balanced/expanded/meddies_heldout/predictions.json) | `b791e043d169841ac2aa383d78ab861cc778af04cef1f9b19a5e43ffe9c03910` |
| [evaluation/results/external_pii_rpc_20261004_v2/balanced/expanded/meddies_heldout/run-manifest.json](../../evaluation/results/external_pii_rpc_20261004_v2/balanced/expanded/meddies_heldout/run-manifest.json) | `875ef98ae63d07355de1e83fa640eee4f11320825c6b44d6b9b8b411dacab91a` |
| [evaluation/results/external_pii_rpc_20261004_v2/balanced/expanded/nemotron_heldout/predictions.json](../../evaluation/results/external_pii_rpc_20261004_v2/balanced/expanded/nemotron_heldout/predictions.json) | `1b0a5fdef2ba2f3978247529576dfa8d2220a677c61a4a1c03785750884c05ac` |
| [evaluation/results/external_pii_rpc_20261004_v2/balanced/expanded/nemotron_heldout/run-manifest.json](../../evaluation/results/external_pii_rpc_20261004_v2/balanced/expanded/nemotron_heldout/run-manifest.json) | `8bb69b311447d410bfdd50c535c4ff26d95343ea8683d0b4ae92cf8afa2536ed` |
| [evaluation/results/external_pii_rpc_20261004_v2/balanced/expanded/validation/predictions.json](../../evaluation/results/external_pii_rpc_20261004_v2/balanced/expanded/validation/predictions.json) | `a2fe510d0cd1838d15104a997b739c351bb0937b3c2b7d7ef4b408eb64772d42` |
| [evaluation/results/external_pii_rpc_20261004_v2/balanced/expanded/validation/run-manifest.json](../../evaluation/results/external_pii_rpc_20261004_v2/balanced/expanded/validation/run-manifest.json) | `d604285830c3cc8964b940931902502531914c664b969add95529fbb7c7b97d9` |
| [evaluation/results/external_pii_rpc_20261004_v2/efficient/baseline/meddies_heldout/predictions.json](../../evaluation/results/external_pii_rpc_20261004_v2/efficient/baseline/meddies_heldout/predictions.json) | `cf90feaa8f722b65a006d748801de107e9d998cae708a75632c03dd4d85e64b0` |
| [evaluation/results/external_pii_rpc_20261004_v2/efficient/baseline/meddies_heldout/run-manifest.json](../../evaluation/results/external_pii_rpc_20261004_v2/efficient/baseline/meddies_heldout/run-manifest.json) | `c235d7cb35b663f81935fba6c3560add031121b3e8654291a895701ddfe63c88` |
| [evaluation/results/external_pii_rpc_20261004_v2/efficient/baseline/nemotron_heldout/predictions.json](../../evaluation/results/external_pii_rpc_20261004_v2/efficient/baseline/nemotron_heldout/predictions.json) | `1e64d0677cb3f8c436d798e0dda27b7f9372bf42373b2c9bcb4cf16f7ae73f55` |
| [evaluation/results/external_pii_rpc_20261004_v2/efficient/baseline/nemotron_heldout/run-manifest.json](../../evaluation/results/external_pii_rpc_20261004_v2/efficient/baseline/nemotron_heldout/run-manifest.json) | `38176f65c1b5489c17e31e8829d4e53afa691a01fbdfbb5a45e6e6242d5606d4` |
| [evaluation/results/external_pii_rpc_20261004_v2/efficient/baseline/validation/predictions.json](../../evaluation/results/external_pii_rpc_20261004_v2/efficient/baseline/validation/predictions.json) | `d7ff076dd233b7130bf2b4011fe58b46d096bffe97f24c39c38c1e306bf8cf78` |
| [evaluation/results/external_pii_rpc_20261004_v2/efficient/baseline/validation/run-manifest.json](../../evaluation/results/external_pii_rpc_20261004_v2/efficient/baseline/validation/run-manifest.json) | `cd13dd9919a37e449547b81be6369ce5a0b5e2f55f8f1b97f5748d6877000294` |
| [evaluation/results/external_pii_rpc_20261004_v2/efficient/expanded/meddies_heldout/predictions.json](../../evaluation/results/external_pii_rpc_20261004_v2/efficient/expanded/meddies_heldout/predictions.json) | `61a8eb1ec76566136c78d3089ea0402caff48a024d01f44c5ba95a5395ed7fce` |
| [evaluation/results/external_pii_rpc_20261004_v2/efficient/expanded/meddies_heldout/run-manifest.json](../../evaluation/results/external_pii_rpc_20261004_v2/efficient/expanded/meddies_heldout/run-manifest.json) | `369190d795535fae84298c88dfe02b0c740cd91254f0739edbc020ab16c82a88` |
| [evaluation/results/external_pii_rpc_20261004_v2/efficient/expanded/nemotron_heldout/predictions.json](../../evaluation/results/external_pii_rpc_20261004_v2/efficient/expanded/nemotron_heldout/predictions.json) | `f10437c94c77e4f3873b8223d6f0c4ce073b22eca8dc001b3ccce2f1dd4eea38` |
| [evaluation/results/external_pii_rpc_20261004_v2/efficient/expanded/nemotron_heldout/run-manifest.json](../../evaluation/results/external_pii_rpc_20261004_v2/efficient/expanded/nemotron_heldout/run-manifest.json) | `bf80ace749b8238306f26cc6a28578da1c85622c8635afe16bc4589ec48c6bbc` |
| [evaluation/results/external_pii_rpc_20261004_v2/efficient/expanded/validation/predictions.json](../../evaluation/results/external_pii_rpc_20261004_v2/efficient/expanded/validation/predictions.json) | `a67169da68f6f0595f4557eb2871421f4ff8879081c2211ceb2f483c0640e5c5` |
| [evaluation/results/external_pii_rpc_20261004_v2/efficient/expanded/validation/run-manifest.json](../../evaluation/results/external_pii_rpc_20261004_v2/efficient/expanded/validation/run-manifest.json) | `3dabdc7e8388a6f442e187eb1041f176329232ec5dc7b6cc9843bf99c54421d0` |
| [evaluation/results/external_pii_rpc_20261004_v2/quality/baseline/meddies_heldout/predictions.json](../../evaluation/results/external_pii_rpc_20261004_v2/quality/baseline/meddies_heldout/predictions.json) | `4b483bc535720303ffb5b6e1509ece1208600c0890eab36e741a96d400cfde2c` |
| [evaluation/results/external_pii_rpc_20261004_v2/quality/baseline/meddies_heldout/run-manifest.json](../../evaluation/results/external_pii_rpc_20261004_v2/quality/baseline/meddies_heldout/run-manifest.json) | `1ea188eeeae9cd4ffb14f98c9565b17cd52bccced30d58c2704cbbbc0ed5f733` |
| [evaluation/results/external_pii_rpc_20261004_v2/quality/baseline/nemotron_heldout/predictions.json](../../evaluation/results/external_pii_rpc_20261004_v2/quality/baseline/nemotron_heldout/predictions.json) | `dca84d07d8336170760ff77ba84a43fadfdcca69f505bb842c15149560129fd0` |
| [evaluation/results/external_pii_rpc_20261004_v2/quality/baseline/nemotron_heldout/run-manifest.json](../../evaluation/results/external_pii_rpc_20261004_v2/quality/baseline/nemotron_heldout/run-manifest.json) | `dad4e7fac4bac9951a1ea055f92edfdbb992519ce0235ce8a0c2a338d9893ef8` |
| [evaluation/results/external_pii_rpc_20261004_v2/quality/baseline/validation/predictions.json](../../evaluation/results/external_pii_rpc_20261004_v2/quality/baseline/validation/predictions.json) | `fb9d1ee44c3c965133c7bbe29b956ceb4ecea512f894d16ffad29dde937acca5` |
| [evaluation/results/external_pii_rpc_20261004_v2/quality/baseline/validation/run-manifest.json](../../evaluation/results/external_pii_rpc_20261004_v2/quality/baseline/validation/run-manifest.json) | `9c361d3a598d542fbf1f7db401220a56ffdf5ba9c4064eaeee4c6e278d8330e3` |
| [evaluation/results/external_pii_rpc_20261004_v2/quality/expanded/meddies_heldout/predictions.json](../../evaluation/results/external_pii_rpc_20261004_v2/quality/expanded/meddies_heldout/predictions.json) | `95edda4f6167a014dde7763ec2df38ebb178ea32ff32cffaafd03cfa82902300` |
| [evaluation/results/external_pii_rpc_20261004_v2/quality/expanded/meddies_heldout/run-manifest.json](../../evaluation/results/external_pii_rpc_20261004_v2/quality/expanded/meddies_heldout/run-manifest.json) | `5b37be0a49f49d3991d01bc2d1894273332513176696746f4c98d3402b69b484` |
| [evaluation/results/external_pii_rpc_20261004_v2/quality/expanded/nemotron_heldout/predictions.json](../../evaluation/results/external_pii_rpc_20261004_v2/quality/expanded/nemotron_heldout/predictions.json) | `304e45515b60cc68e4cc7bf0a0acbd512a98d60195486791909a76a762948b7c` |
| [evaluation/results/external_pii_rpc_20261004_v2/quality/expanded/nemotron_heldout/run-manifest.json](../../evaluation/results/external_pii_rpc_20261004_v2/quality/expanded/nemotron_heldout/run-manifest.json) | `3291a18ca1a5db78d7d1747b8275c60fcff91751bbf7d50e1ddbb6204b9f1b4f` |
| [evaluation/results/external_pii_rpc_20261004_v2/quality/expanded/validation/predictions.json](../../evaluation/results/external_pii_rpc_20261004_v2/quality/expanded/validation/predictions.json) | `2aac411706093bc0e25f8525023a60d7e070eede1151e1131dfd5802cd53104e` |
| [evaluation/results/external_pii_rpc_20261004_v2/quality/expanded/validation/run-manifest.json](../../evaluation/results/external_pii_rpc_20261004_v2/quality/expanded/validation/run-manifest.json) | `961fc4d7e24b06ecb12bfb13158ae9b5f563ff8f6b9e06060918f3b80c1c30d6` |
| [evaluation/results/original_public_development_frozen/local-jsonl_ner_original_public_development_frozen_results.json](../../evaluation/results/original_public_development_frozen/local-jsonl_ner_original_public_development_frozen_results.json) | `8825b9b3797f8a8d0dde0c0dd9a0e3d21fe25e22c5d9c49d4785afa47ef0157c` |
| [evaluation/results/original_public_development_frozen/local-jsonl_pipeline_streamed_original_public_development_frozen_results.json](../../evaluation/results/original_public_development_frozen/local-jsonl_pipeline_streamed_original_public_development_frozen_results.json) | `a8c4eee34ef8c28252304c717accaa269f864adb41b938ca65df1648169ebbf8` |
| [evaluation/results/original_public_development_frozen/local-jsonl_regex-ner_original_public_development_frozen_results.json](../../evaluation/results/original_public_development_frozen/local-jsonl_regex-ner_original_public_development_frozen_results.json) | `4518b76b0506ece9b5d9914b2b89c2a215916e59c91923b4c0f07c2c653a5a4a` |
| [evaluation/results/original_public_development_frozen/local-jsonl_regex_original_public_development_frozen_results.json](../../evaluation/results/original_public_development_frozen/local-jsonl_regex_original_public_development_frozen_results.json) | `3e700bef23d5f3ce365b07a42f9bbb4b937f39f58da46a08191ea0fdb97be8d3` |
| [evaluation/results/original_public_development_frozen/local-jsonl_semantic_original_public_development_frozen_results.json](../../evaluation/results/original_public_development_frozen/local-jsonl_semantic_original_public_development_frozen_results.json) | `6108300098c2fd993393fbe1f6d29ef8ae30ac9ebe9a44e86743db636d6f0daa` |
| [evaluation/results/presence_profiles_20261004_v1/runtime-base/balanced/predictions.json](../../evaluation/results/presence_profiles_20261004_v1/runtime-base/balanced/predictions.json) | `0d1e404e2b498c1d717580c696131e576a1cf2b3da9ce99871f8ed8200e4eed4` |
| [evaluation/results/presence_profiles_20261004_v1/runtime-base/balanced/report.json](../../evaluation/results/presence_profiles_20261004_v1/runtime-base/balanced/report.json) | `35a731c94f4b33a726be74d5ee7d960ed94723d54ea78f2d3ed5b488937027a7` |
| [evaluation/results/presence_profiles_20261004_v1/runtime-base/efficient/predictions.json](../../evaluation/results/presence_profiles_20261004_v1/runtime-base/efficient/predictions.json) | `79557ea893112a0de390cf5472d884f3a80ecffd59c2f8e96aa7c516d1268347` |
| [evaluation/results/presence_profiles_20261004_v1/runtime-base/efficient/report.json](../../evaluation/results/presence_profiles_20261004_v1/runtime-base/efficient/report.json) | `404f08ead396f4246a589c7ceea4846a07f9b34a11e3024ff17d557ae830d528` |
| [evaluation/results/presence_profiles_20261004_v1/runtime-base/quality/predictions.json](../../evaluation/results/presence_profiles_20261004_v1/runtime-base/quality/predictions.json) | `f5f37221e7551946dd76f4f69f34bc0ab3aff4828255a4ddc9828f822b4e6a4c` |
| [evaluation/results/presence_profiles_20261004_v1/runtime-base/quality/report.json](../../evaluation/results/presence_profiles_20261004_v1/runtime-base/quality/report.json) | `c338f8b4e3d3b032e3ce09183f2d0133f0683fb32af6066e52b57f8573a4106e` |
| [evaluation/results/presidio_public_development_metrics.json](../../evaluation/results/presidio_public_development_metrics.json) | `75a92da4f570f369e46d54e0757644b3ccfe14a8a26cea4e2d3af2f9c7cdd829` |
| [evaluation/results/public_negative_v2_20261003_lr003_seed42_cycle1/local-jsonl_pipeline_streamed_public_negative_v2_20261003_lr003_seed42_cycle1_results.json](../../evaluation/results/public_negative_v2_20261003_lr003_seed42_cycle1/local-jsonl_pipeline_streamed_public_negative_v2_20261003_lr003_seed42_cycle1_results.json) | `5fabc715d1db241d3227491b20004ceef44853acc790c8a87dfa9fe80855cf75` |
| [evaluation/results/public_negative_v2_20261003_lr003_seed42_cycle1/local-jsonl_semantic_public_negative_v2_20261003_lr003_seed42_cycle1_results.json](../../evaluation/results/public_negative_v2_20261003_lr003_seed42_cycle1/local-jsonl_semantic_public_negative_v2_20261003_lr003_seed42_cycle1_results.json) | `5f33f1fd90318c0d2cbffdf13940eb846afeeb7ed2abc7016bfdb252c0fb8edb` |
| [evaluation/results/selected_context_development_20261003/local-jsonl_pipeline_streamed_selected_context_development_20261003_results.json](../../evaluation/results/selected_context_development_20261003/local-jsonl_pipeline_streamed_selected_context_development_20261003_results.json) | `d9e303e3fd34d745efae88dfe11dc1fc105bec06815b14039ecdce6d2ebbe9c1` |
| [evaluation/results/selected_context_development_20261003/local-jsonl_regex_selected_context_development_20261003_results.json](../../evaluation/results/selected_context_development_20261003/local-jsonl_regex_selected_context_development_20261003_results.json) | `0d2fe8fb077a974838a3efdfffccb2c569e1de0bfb45e77e82f543d457d48240` |

The digest inventory binds the numerical inputs at this checkpoint; it does not claim independent annotation truth or redistribution rights. Archived source revisions and training manifests remain available in the preserved study directories linked by the reports.

## Reproduce the arithmetic without changing inputs

From the repository root, run the following Python block with a standard-library Python interpreter. In PowerShell, place the block between a literal `@'` and `'@ | python -` to execute via standard input. Do not run Python with `-O`, because the assertions are the validation checks.

The script prints aggregate JSON lines, source support, hashes and PASS markers to stdout. It creates no files, emits no row text/IDs, calls no services and accesses no final file. The script's path allowlist selects existing complete runs; missing or changed inputs fail rather than falling back to another experiment.

```python
import json, pathlib, collections, hashlib, math
R = pathlib.Path('evaluation/results')
def load(p): return json.loads(p.read_text(encoding='utf-8'))
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def rid(x): return x.get('example_id', x.get('id', x.get('row_id_sha256')))
def grp(x): return x.get('group_id', x.get('group_id_sha256'))
def cm(rows, pred):
    pairs = []
    for x in rows:
        truth, prediction = x['expected_has_pii'], pred(x)
        assert isinstance(truth, bool) and isinstance(prediction, bool)
        assert rid(x) is not None and grp(x) is not None
        pairs.append((truth, prediction))
    c = collections.Counter(pairs)
    return [c[True, True], c[False, False], c[False, True], c[True, False]]
def metric(c):
    tp, tn, fp, fn = c; pos, neg = tp+fn, tn+fp
    recall = tp/pos if pos else None; specificity = tn/neg if neg else None
    return dict(n_positive=pos, n_negative=neg, tp=tp, tn=tn, fp=fp, fn=fn,
        recall=recall, specificity=specificity,
        balanced_accuracy=(recall+specificity)/2 if pos and neg else None)
def verify(c, m):
    expected = [m.get(a, m.get(b)) for a,b in
        [('tp','true_positives'),('tn','true_negatives'),('fp','false_positives'),('fn','false_negatives')]]
    assert c == expected, (c, expected)
def sensitive(x):
    return x['classification']['sensitivity'] != 'S0' or bool(x['classification']['categories'])
def family(s): return 'ai4privacy' if s.startswith('ai4privacy-') else s
ref = load(R/'presence_profiles_20261004_v1/runtime-base/efficient/predictions.json')['rows']
reference = {rid(x):(x['expected_has_pii'],grp(x)) for x in ref}
assert len(reference) == len(ref) == 502
task = {rid(x):x['source_family'] for x in ref}
assert all(task[rid(x)] == rid(x).split(':')[1] for x in ref)
source = {k:family(v) for k,v in task.items()}
systems = []
for name, directory in [('original','original_public_development_frozen'),
    ('earlier_selected','selected_context_development_20261003'),
    ('current_selected','public_negative_v2_20261003_lr003_seed42_cycle1')]:
    for p in sorted((R/directory).glob('*results.json')):
        j = load(p)
        systems.append((name+'_'+j['layer'],p,j['metadata']['predictions'],
            lambda x:x['detected_sensitive'],j['metrics'],j['errors']))
p = R/'presidio_public_development_metrics.json'; j = load(p)
systems.append(('presidio',p,j['predictions'],lambda x:x['detected_sensitive'],j['metrics'],j['metrics']['runtime_errors']))
for profile in ['efficient','balanced','quality']:
    d = R/'presence_profiles_20261004_v1/runtime-base'/profile; p = d/'report.json'; j = load(p)
    rows = load(d/'predictions.json')['rows']
    assert all(all(x[k] == j['returned_identity'][k] for k in j['returned_identity']) for x in rows)
    systems.append(('presence_'+profile,p,rows,lambda x:x['predicted_present'],j['metrics'],len(j['errors'])))
for profile in ['efficient','balanced','quality']:
    d = R/'contextual_cascade_20261004_v3/cascade-evidence/evaluate-development'/('original-'+profile)
    p = d/'report.json'; j = load(p); rows = load(d/'predictions.json')
    assert all(not x['gated']['error'] and not x['ordinary']['error'] for x in rows)
    assert sha(d/'predictions.json') == j['predictions_sha256']
    systems.append(('cascade_'+profile,p,rows,lambda x:sensitive(x['gated']),j['metrics'],len(j['errors'])))
    if profile == 'efficient':
        systems.append(('cascade_ordinary_original',p,rows,lambda x:sensitive(x['ordinary']),j['ordinary_metrics'],len(j['errors'])))
assert len(systems) == 17
for name,p,rows,pred,m,errors in systems:
    assert errors == 0 and len(rows) == 502
    assert len({rid(x) for x in rows}) == 502
    assert {rid(x):(x['expected_has_pii'],grp(x)) for x in rows} == reference, name
    c = cm(rows,pred); verify(c,m); strata = []
    for s in sorted(set(source.values())):
        selected = [x for x in rows if source[rid(x)] == s]
        strata.append(dict(source=s,groups=len({grp(x) for x in selected}),**metric(cm(selected,pred))))
    print(json.dumps(dict(system=name,aggregate=metric(c),strata=strata,errors=errors,
        report=p.as_posix(),sha256=sha(p)),separators=(',',':')))
for s in sorted(set(source.values())):
    selected = [x for x in ref if source[rid(x)] == s]
    print(json.dumps(dict(support=s,rows=len(selected),groups=len({grp(x) for x in selected}),
        positive=sum(x['expected_has_pii'] for x in selected))))
print('PASS: 17 development systems, same 502 IDs/truth/groups, aggregate confusion matrices, zero errors')
def wilson(k,n):
    if not n: return None
    z=1.959963984540054; p=k/n; d=1+z*z/n
    center=(p+z*z/(2*n))/d
    margin=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d
    return [max(0,center-margin),min(1,center+margin)]
partition_refs={}; external_requests=0
for profile in ['efficient','balanced','quality']:
    for control in ['baseline','expanded']:
        for partition in ['validation','nemotron_heldout','meddies_heldout']:
            d=R/'external_pii_rpc_20261004_v2'/profile/control/partition
            p=d/'run-manifest.json'; j=load(p); rows=load(d/'predictions.json')['rows']
            assert not j['errors'] and j['successful_rows']==len(rows)
            keyed={rid(x):(x['expected_has_pii'],grp(x),x['source_family']) for x in rows}
            assert len(keyed)==len(rows)
            if partition not in partition_refs: partition_refs[partition]=keyed
            assert keyed==partition_refs[partition]
            identity={k:v for k,v in j['artifact_identity'].items() if k!='threshold'}
            assert all(x['response_identity']==identity and x['threshold']==j['artifact_identity']['threshold'] for x in rows)
            assert sha(d/'predictions.json')==j['predictions_sha256']
            c=cm(rows,lambda x:x['predicted_present']); verify(c,j['metrics']['overall'])
            strata=[]
            for s in sorted({family(x['source_family']) for x in rows}):
                selected=[x for x in rows if family(x['source_family'])==s]
                strata.append(dict(source=s,groups=len({grp(x) for x in selected}),
                    **metric(cm(selected,lambda x:x['predicted_present']))))
            external_requests += len(rows)
            print(json.dumps(dict(external=f'{profile}_{control}_{partition}',aggregate=metric(c),
                groups=len({grp(x) for x in rows}),strata=strata,errors=0,
                recall_wilson95=wilson(c[0],c[0]+c[3]),report=p.as_posix(),sha256=sha(p)),separators=(',',':')))
assert external_requests==17802
print('PASS: 18 external runs, 17802 rows, within-partition matched hashed IDs/truth/groups/source, identities, prediction hashes, confusion matrices, zero errors')
print(json.dumps(dict(descriptive_row_level_wilson95={
    'current_AI4_recall':wilson(71,81),'current_AI4_specificity':wilson(11,22),
    'current_Nemotron_recall':wilson(98,110),'current_Nemotron_specificity':wilson(51,184),
    'current_Gretel_specificity':wilson(7,28),'cascade_efficient_Nemotron_recall':wilson(97,110),
    'Privy_0of2_specificity':wilson(0,2),'perfect1000':wilson(1000,1000),'perfect999':wilson(999,999)})))
input_paths = {p for _,p,*_ in systems}
input_paths.add(R/'presence_profiles_20261004_v1/runtime-base/efficient/predictions.json')
for profile in ['efficient','balanced','quality']:
    input_paths.add(R/'presence_profiles_20261004_v1/runtime-base'/profile/'predictions.json')
    input_paths.add(R/'contextual_cascade_20261004_v3/cascade-evidence/evaluate-development'/('original-'+profile)/'predictions.json')
    for control in ['baseline','expanded']:
        for partition in ['validation','nemotron_heldout','meddies_heldout']:
            d = R/'external_pii_rpc_20261004_v2'/profile/control/partition
            input_paths.update([d/'run-manifest.json',d/'predictions.json'])
for p in sorted(input_paths):
    print(json.dumps(dict(input=p.as_posix(),sha256=sha(p))))
print('PASS: input digests emitted; no raw examples, predictions or IDs printed')

```

Expected decisive markers:

```text
PASS: 17 development systems, same 502 IDs/truth/groups, aggregate confusion matrices, zero errors
PASS: 18 external runs, 17802 rows, within-partition matched hashed IDs/truth/groups/source, identities, prediction hashes, confusion matrices, zero errors
PASS: input digests emitted; no raw examples, predictions or IDs printed
```

Expected current aggregate: TP239 / TN70 / FP168 / FN25; source counts are in [the primary table](results-by-dataset.md). Every sidecar and report digest must match the inventory above before treating another execution as reproduction of this checkpoint.

## Evidence ledger for numerical claims

| Claim ID | Evidence locator | Observation / limit |
| --- | --- | --- |
| NUM-01 | Current selected pipeline report; `metadata.predictions`, ID-prefix/source mapping, script strata | AI4Privacy 71/81 recall; Nemotron 98/110 recall; neither source meets 90% recall in this sample |
| NUM-02 | Current selected pipeline clean-class strata | Gretel 7/28 specificity, Nemotron 51/184; poor sampled clean-label performance does not prove bad annotation |
| NUM-03 | Same current strata plus total clean support | Nemotron contributes 133/168 FP and 184/238 clean rows; source count is confounded by support |
| NUM-04 | Preserved efficient gate predictions, `gated.classification`, mapped IDs | Nemotron gate recall 97/110 despite pooled 242/264; own ordinary control required for intervention comparison |
| NUM-05 | Support reference and exact cross-report joins | Privy only 2 clean; MAPA 2 clean/one group and no positives; missing rates unavailable |
| NUM-06 | External run manifests/predictions and identity/hash checks | All expanded heldout positives detected; no clean class, no specificity or balanced accuracy |
| NUM-07 | Recomputed Wilson arithmetic | Descriptive row-level intervals only; group/selection-adjusted inference uncomputed |
| NUM-08 | Root pre/post `paper/` snapshot | All 47 existing files unchanged; no manuscript/bibliography/reference edits |

Alternative explanations include sentence segmentation losing context, source class imbalance, narrow span taxonomies, topic/style shifts and model over-detection. These are hypotheses rather than newly established label defects or causal explanations. No new clean-label audit or deployment-representative population is supplied.

## Paper protection fingerprints

| Protected manuscript input | Unchanged SHA-256 |
| --- | --- |
| `paper/main.tex` | `563ff9b2f19128e5fdbc5e3c44414fc1a72b8e24a7c03761828853b08465f5dd` |
| `paper/ref.bib` | `e49a0d8cc3b9f3e88c052e513b40f06c16635a9e50e72fc72b87dec0e74770c4` |
| `paper/reference.tex` | `d52ae53efda6d55c922c73c15df9a31b4aa54b0e17638d6ecbf036a928d86db4` |

The root comparison also covered the remaining 44 existing paper files and exact inventory equality. No prior user changes were reset or overwritten; the checkout was clean before this work. There is no commit, push, PR, model promotion or paper compilation in this task.
