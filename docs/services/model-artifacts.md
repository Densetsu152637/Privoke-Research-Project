# PriVoke model artifacts

> Source area: `models`. Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

PriVoke ships a family of compact contextual transformer classifiers and supports
a separate learned sparse annotation-presence family. Each artifact contains its
architecture configuration, tensor shapes, float32-compatible weights, version,
quality metadata, and checksum in one Git-friendly JSON file.

| Quality | Artifact | Encoder blocks | Hidden size | Context | Intended use |
| --- | --- | ---: | ---: | ---: | --- |
| Efficient | `privoke-efficient.json` | 1 | 24 | 64 | Lowest CPU and memory use |
| Balanced | `privoke-balanced.json` | 2 | 32 | 96 | Default release channel |
| Quality | `privoke-quality.json` | 3 | 32 | 128 | More contextual processing |

`privoke-baseline.json` remains available for backward compatibility. The model streaming service resolves `latest` to the current release-channel artifact (`privoke-balanced` by default), so clients can receive new trained revisions without changing settings.

## Opt-in Tiny task-query readouts

`privoke_tiny_transformer_v2` retains schema 1 and requires config
`readout: residual_task_query_v1`. It adds exactly three float32 vectors,
`readout.{sensitivity,visibility,category}.query`, each shaped `[hidden_size]`.
Head adaptation trains these queries together with the six affine head tensors;
last-block and full-encoder scopes include them too. Python, Go and streamed
runtime validation reject missing, extra, malformed or silently frozen queries,
and architecture/config mismatches. Existing parameter and context limits apply.

For real token states `H`, including the initial token, `m = mean(H)` and
`p = 0.5 H[0] + 0.5 m`. Task `t` uses
`z_t = p + (softmax(H q_t / sqrt(D)) H - m)` before its existing affine head.
Padding is excluded from both reductions. Labels, tokenizer, category threshold,
decoding and action rules are unchanged. Three queries add `3D` values: 96 for
Balanced, giving 36,852 parameters at the original 96-token capacity and 756
output trainables. Historical counts and scores describe v1.

`evaluation/prepare-task-query.py` requires a source, new output path, distinct
release version, timestamp, exact source commit and explicit training scope. It
preserves existing weight coordinates and initializes queries to zero, records
provenance and checksums, and performs no fitting or installation. Zero queries
recover legacy pooling in exact arithmetic; float32 reductions can differ slightly.
Prepare queries before binding optimizer/admission policies, then use the existing
full-encoder and training-policy preparation tools. Default model files and
`latest` are unchanged. Preparation and synthetic mechanics tests establish no
quality improvement or promotion.

## Experimental pretrained v3 artifacts

The [v3 family](../pretrained-v3-study.md#family-and-initialization) uses complete
Google BERT encoder/pooler tensors with three new zero affine heads.

| Explicit model ID | Complete parameters |
| --- | ---: |
| `privoke-v3-efficient` | 4,785,044 |
| `privoke-v3-balanced` | 9,596,180 |
| `privoke-v3-quality` | 17,493,780 |

Unlike the legacy JSON artifacts described above, v3 binds a canonical manifest
to finite float32 safetensors, native configuration and vocabulary, exact tensor
inventories and independently pinned official source revisions/hashes. Immutable
ORIGINALs retain every pretrained encoder/pooler value. Its dedicated binary
protocol admits at most 80 MiB per blob, 1 MiB per ordered chunk and 256 KiB per
manifest. These separate limits do not enlarge existing Go/Tiny contracts. Weights
and failed attempts remain ignored under `models/experiments/pretrained_v3_20261012/`;
fixed FULL seed-42 research exports do not promote a release or select a best seed.

## Sparse annotation-presence artifacts

Architecture `privoke_sparse_presence_v1` has task `annotation_presence`. Its
three explicit model IDs have these maximum capacities; learned vocabularies may
contain fewer features:

| Model ID | Word features | Character features | IDF + head numeric values |
| --- | ---: | ---: | ---: |
| `privoke-presence-efficient` | 2,000 | 2,000 | 8,001 |
| `privoke-presence-balanced` | 8,000 | 8,000 | 32,001 |
| `privoke-presence-quality` | 16,000 | 16,000 | 64,001 |

Config contains ordered train-only vocabularies, word/character n-gram rules,
`training_text_key_v1` normalization, independent L2 TF-IDF settings, profile,
word-before-character column order and frozen prediction threshold. Frozen tensors
are `features.word.idf` and `features.char.idf`. Only
`head.presence.weight.000`, `.001`, ... and `head.presence.bias` are trainable;
coefficient blocks cover contiguous columns and contain at most 4,096 values.
Changing vocabulary, IDF, normalization or threshold requires a new release.

Both Python and Go validators retain the 65,536 total numeric-value cap and
8 MiB artifact cap; presence config is bounded to 2 MiB. Shared CPU inference uses
transported float32 parameters, float64 normalized features and deterministic
`math.fsum` accumulation. Release calibration reloads serialized weights and fixes
the validation-selected threshold before development scoring. The prior offline
40,000-features-per-branch control is not directly deployable under these bounds.

These artifacts serve `DetectAnnotationPresence` and `ComputePresenceGradients`;
they are not accepted as contextual transformer artifacts. `latest` remains the
original balanced contextual release channel. An explicit, opt-in
`AnalyzePromptRequest.semantic_presence_gate` may use one of these presence IDs to
filter only the semantic findings from a request that explicitly selected
`privoke-balanced`. It leaves regex and NER findings intact. A binary presence score
supplies no severity, visibility, category or ALLOW/WARN/BLOCK policy label. A
per-request decision threshold is only a gate setting; it does not alter the frozen
artifact threshold or weights. This is a research option, not a default or safety
claim; see the [prospective semantic presence-cascade protocol](../../paper/research/contextual-cascade-protocol.md).
See the [prospective model-refactor protocol](../../paper/research/model-refactor-protocol.md)
for fitting, independent fuzzer cycles, locked-data protection and reporting rules.

## Contextual baseline and updates

Regenerate the deterministic release baseline:

```bash
python models/generate_baseline.py
```

For local integration, keep Compose services running as servers and issue a host
Python request with `python evaluation/run-fuzzer-tests.py train --model-id
privoke-balanced --prompt-count 32`. A successful cycle atomically updates the
balanced release-channel artifact from `v0.3.0` to `v0.3.0+train.1`, then onward.
For controlled experiments, retain temporary ORIGINAL weights, per-cell catalogs,
effective weights, and provenance pins under `models/experiments/<run>/`. Remove
redundant weight copies only after verifying byte hashes and recorded references.

Production Compose and Compute Engine persist trained artifacts in `model-data`; they do not rewrite repository files. Development Compose bind-mounts `./models`, so training updates those Git-reviewable files directly. Export a production artifact deliberately before reviewing it in Git.

The updater validates the exact base version and applies bounded deltas only to trainable tensors. A latest-update receipt is included atomically with trained weights; historical replay outcomes live in the updater SQLite database. Runtime candidate evaluation uses the same float32/clipping rules as publication, while the cached serving model remains unchanged during evaluation.

Review and commit development or exported trained weights like source:

```bash
git diff -- models/privoke-balanced.json
git add models/privoke-balanced.json
git commit -m "Update PriVoke semantic model weights"
```

The checked-in model is intentionally small enough for ordinary Git. If a future artifact approaches the hosting provider's file-size limit, keep the same manifest/streaming contract and move the tensor payload to Git LFS rather than committing an oversized blob.
