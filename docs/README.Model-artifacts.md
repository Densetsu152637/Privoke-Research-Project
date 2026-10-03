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
they are not accepted by the contextual classification path. `latest` remains
the original balanced contextual release channel. A binary presence score supplies
no severity, visibility, category or ALLOW/WARN/BLOCK policy label.
See the [prospective model-refactor protocol](../paper/research/model-refactor-protocol.md)
for fitting, independent fuzzer cycles, locked-data protection and reporting rules.

## Contextual baseline and updates

Regenerate the deterministic release baseline:

```bash
python models/generate_baseline.py
```

Run one fuzzer training request through the Compose stack with `docker compose exec -T privoke-fuzzer python src/cli.py train --prompt-count 32`. A successful cycle atomically updates the balanced release-channel artifact from `v0.3.0` to `v0.3.0+train.1`, then onward.

Production Compose and Compute Engine persist trained artifacts in `model-data`; they do not rewrite repository files. Development Compose bind-mounts `./models`, so training updates those Git-reviewable files directly. Export a production artifact deliberately before reviewing it in Git.

The updater validates the exact base version and applies bounded deltas only to trainable tensors. A latest-update receipt is included atomically with trained weights; historical replay outcomes live in the updater SQLite database. Runtime candidate evaluation uses the same float32/clipping rules as publication, while the cached serving model remains unchanged during evaluation.

Review and commit development or exported trained weights like source:

```bash
git diff -- models/privoke-balanced.json
git add models/privoke-balanced.json
git commit -m "Update PriVoke semantic model weights"
```

The checked-in model is intentionally small enough for ordinary Git. If a future artifact approaches the hosting provider's file-size limit, keep the same manifest/streaming contract and move the tensor payload to Git LFS rather than committing an oversized blob.
