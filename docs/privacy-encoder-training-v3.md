# Full-encoder privacy fine-tuning (EN3-R1)

Status: implementation and synthetic mechanics preparation; real probes, fits, exports and reused-DEVELOPMENT comparison **PENDING**. No model improvement or production promotion is claimed.

Exact user request: “can you now fine tune the encoders for each tier?”

This continuation starts from all three [PH3 selected head exports](privacy-head-training-v3.md), preserving the earlier runs. Encoder, pooler and six affine head tensors train together through native BERT forward/backward; cached pooled features cannot implement this stage. Each tier retains its pretrained architecture, tokenizer and first-token dense+tanh pooler. Upstream language-pretraining epoch counts remain unknown. PH3 head epochs (selected12/7/4) and new joint encoder/head epochs are reported separately.

## Fixed prospective method

The new host controller is [run-privacy-encoder-v3.py](../evaluation/run-privacy-encoder-v3.py), backed by [privacy_encoder_v3.py](../evaluation/privoke_eval/privacy_encoder_v3.py). It uses the admitted R3 6,240 TRAIN and 1,560 validation rows. The opened PH3 fresh fixture is now explicitly **reused DEVELOPMENT**; it cannot select checkpoints or tune this recipe. Any before/after analysis must wait for all three selected/terminal export seals and bind the accepted PH3 raw baseline by exact case/text/truth/allowed-action equality. Latency across the two runs cannot establish a speedup.

All learned parameters are trainable. AdamW encoder/pooler LR2e-5, head LR1e-4, betas0.9/0.999, epsilon1e-8; matrix weight decay0.01, biases/LayerNorm zero. Effective batch64 uses microbatch16 accumulation; weighted CE denominators span the whole effective batch, including the final32 rows. Category BCE divides by actual rows×10. Gradient clipping1 follows accumulation. Encoder dropout0.1 is active during training and off during validation/export. Float32 deterministic execution uses no AMP or TF32. CPU/CUDA environment is frozen only after capability/resource checks; hardware presence alone is insufficient.

Update1 uses LR scale1/98, update98 scale1, then fixed linear decay reaches0 at update2940. Minimum5/maximum30epochs, patience5, strict total weighted validation-loss improvement greater than0.0001, earliest checkpoint within delta. Epoch0 is a reference only: selection chooses the best **trained** epoch≥1, even if all trained checkpoints regress from the reference. Such regressions must be reported. Every epoch visits the same6,240 rows in a deterministic seed42+epoch permutation; repeated exposures are not new examples.

New result/weight roots are `evaluation/results/privacy_encoder_v3_20261013/` and `models/experiments/privacy_encoder_v3_20261013/`. Preparation pins the PH3 selected assets, R3 data and full working-tree source closure with retained source bytes. Exact replay needs those retained bytes; Git HEAD alone may omit pre-existing dirty dependencies. The original PH3 159-file closure and all old protocols/evidence remain unchanged.

## Gates and reproduction

Host Python runs all tests, dataset loops and fitting. The assigned training environment may differ from the old CPU Torch2.11 native server environment; actual cross-environment serialization/parity is required before serving acceptance.

1. Run focused synthetic tests: `evaluation/.venv-v3-study/Scripts/python.exe -m unittest discover -s evaluation/tests -p test_privacy_encoder_v3.py`.
2. `prepare --device <cpu|cuda>` freezes source/data/initial/environment pins. Root `probe-acceptance.json` with accepted status, study ID and exact protocol SHA precedes each tier's bounded TRAIN/validation-only `probe`.
3. Root `prefit-acceptance.json` additionally binds all three probe hashes after independent review. Only then may `fit --tier <tier>` or explicit `resume` execute. A shared exclusive lock serializes tiers.
4. `export` retains full-state selected/terminal packages; `audit-training` replays epoch/checkpoint selection and work counts. `verify-export` must also run under the old CPU-serving environment on actual trained assets. CPU reference/reload logits and classification/confidence/action values are exact; CUDA/CPU comparison uses declared bounded logit tolerances and exact classification/actions.
5. After all seals, a separately admitted reused-DEVELOPMENT comparison may import immutable PH3 before-accuracy evidence and score the three new packages. No old fresh/unseen claim survives this reuse.

Full model/optimizer/schedule/Python/NumPy/CPU/CUDA RNG state, best trained model, patience, source identity and epoch record are atomically checkpointed. An incomplete epoch replays from the last durable epoch; changed identities, corrupt pointers and completed-run overwrite fail closed. Failed attempts and immutable checkpoints remain retained. Native manifests use `scope=full_encoder`, parent=PH3 selected, original=linguistic ORIGINAL and separate EN3 evidence. Publisher `backbone_sha256` describes ancestry; actual adapted encoder identity comes from the complete tensor inventory. No legacy guard pass is implied.

Actual per-tier completed/selected epochs, parameter changes, training duration, before/after outcomes and resource costs remain pending authorized execution and audit.
