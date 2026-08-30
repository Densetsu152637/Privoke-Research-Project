# PriVoke model artifacts

`privoke-baseline.json` is the canonical persistent semantic model. It is a compact transformer classifier containing its architecture configuration, tensor shapes, float32-compatible weights, version, metadata, and checksum in one Git-friendly JSON file.

Regenerate the deterministic release baseline:

```bash
python models/generate_baseline.py
```

Run one fuzzer training request through the Compose stack with `docker compose exec -T privoke-fuzzer python src/cli.py train --prompt-count 32`. A successful cycle atomically changes this file from `v0.2.0` to `v0.2.0+train.1`, then onward.

Review and commit trained weights like source:

```bash
git diff -- models/privoke-baseline.json
git add models/privoke-baseline.json
git commit -m "Update PriVoke semantic model weights"
```

The checked-in model is intentionally small enough for ordinary Git. If a future artifact approaches the hosting provider's file-size limit, keep the same manifest/streaming contract and move the tensor payload to Git LFS rather than committing an oversized blob.
