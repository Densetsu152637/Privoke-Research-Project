# PriVoke model artifacts

> Source area: `models`. Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

PriVoke ships a family of compact transformer classifiers. Each artifact contains its architecture configuration, tensor shapes, float32-compatible weights, version, quality metadata, and checksum in one Git-friendly JSON file.

| Quality | Artifact | Encoder blocks | Hidden size | Context | Intended use |
| --- | --- | ---: | ---: | ---: | --- |
| Efficient | `privoke-efficient.json` | 1 | 24 | 64 | Lowest CPU and memory use |
| Balanced | `privoke-balanced.json` | 2 | 32 | 96 | Default release channel |
| Quality | `privoke-quality.json` | 3 | 32 | 128 | More contextual processing |

`privoke-baseline.json` remains available for backward compatibility. The model streaming service resolves `latest` to the current release-channel artifact (`privoke-balanced` by default), so clients can receive new trained revisions without changing settings.

Regenerate the deterministic release baseline:

```bash
python models/generate_baseline.py
```

Run one fuzzer training request through the Compose stack with `docker compose exec -T privoke-fuzzer python src/cli.py train --prompt-count 32`. A successful cycle atomically updates the balanced release-channel artifact from `v0.3.0` to `v0.3.0+train.1`, then onward.

Review and commit trained weights like source:

```bash
git diff -- models/privoke-balanced.json
git add models/privoke-balanced.json
git commit -m "Update PriVoke semantic model weights"
```

The checked-in model is intentionally small enough for ordinary Git. If a future artifact approaches the hosting provider's file-size limit, keep the same manifest/streaming contract and move the tensor payload to Git LFS rather than committing an oversized blob.
