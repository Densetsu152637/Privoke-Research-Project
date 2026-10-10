"""Idempotently prepare the selected mutable Tiny model before serving it."""
from __future__ import annotations

import copy
import os
import sys
import time
from pathlib import Path

SHARED_DIR = Path(__file__).resolve().parents[3] / "shared/python"
if SHARED_DIR.exists():
    sys.path.insert(0, str(SHARED_DIR))

from privoke_model.artifact import (ModelArtifactError, artifact_checksum, load_artifact,
                                   write_artifact_atomic)
from privoke_model.contextual_training import (FULL_ENCODER_STRATEGY, STRATEGY_KEY,
                                             prepare_full_encoder_artifact)
from receipts import UpdateReceipts, RECEIPT_METADATA_KEY

# This commit implements the versioned pure preparation algorithm. Input model
# bytes are independently bound by preparation_base_checksum/version.
PREPARATION_CODE_REVISION = "d19ec2e09fcf052af408387b36f4ff033d17913a"


def bootstrap_model(model_path, audit_path, model_id, *, max_tokens=256, checkpoint_hook=None):
    """Migrate current learned weights, checkpoint receipts, and never reseed.

    The receipt transaction is also the cross-process model writer lock. Reload
    after every checkpoint boundary before inspecting or replacing model bytes.
    """
    model_path, audit_path = Path(model_path), Path(audit_path)
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    if type(max_tokens) is not int or not 1 <= max_tokens <= 512:
        raise ModelArtifactError("Bootstrap context must be an integer from 1 through 512.")
    with UpdateReceipts(audit_path) as receipts:
        artifact = load_artifact(model_path)
        if artifact["model_id"] != model_id:
            raise ModelArtifactError("Bootstrap selected model ID does not match the mutable artifact.")
        while receipts.recover(artifact):
            receipts.checkpoint()
            if checkpoint_hook:
                checkpoint_hook("after_checkpoint")
            artifact = load_artifact(model_path)
            if artifact["model_id"] != model_id:
                raise ModelArtifactError("Bootstrap selected model ID changed across the receipt checkpoint.")
        if artifact["model_id"] != model_id:
            raise ModelArtifactError("Bootstrap selected model ID does not match the mutable artifact.")
        if (artifact.get("metadata", {}).get(STRATEGY_KEY) == FULL_ENCODER_STRATEGY
                and artifact["config"]["max_tokens"] >= max_tokens):
            return artifact
        # recover() may return False for an already-durable receipt. All history
        # is now committed; only the private preparation copy loses its marker.
        if checkpoint_hook:
            checkpoint_hook("before_prepare")
        original_checksum = artifact["checksum"]
        clean = copy.deepcopy(artifact)
        clean.setdefault("metadata", {}).pop(RECEIPT_METADATA_KEY, None)
        clean["checksum"] = artifact_checksum({k:v for k,v in clean.items() if k != "checksum"})
        target = max(max_tokens, artifact["config"]["max_tokens"])
        prepared = prepare_full_encoder_artifact(clean,
            version=f"v0.4.0-full-ctx{target}-{original_checksum[:12]}",
            generated_at_unix=int(time.time()), source_revision=PREPARATION_CODE_REVISION,
            max_tokens=target)
        prepared["metadata"]["preparation_base_checksum"] = original_checksum
        prepared["checksum"] = artifact_checksum({k:v for k,v in prepared.items() if k != "checksum"})
        if checkpoint_hook:
            checkpoint_hook("before_publish")
        write_artifact_atomic(model_path, prepared)
        if checkpoint_hook:
            checkpoint_hook("after_publish")
        return prepared


def main():
    bootstrap_model(os.getenv("MODEL_ARTIFACT_PATH", "/state/models/privoke-balanced.json"),
                    os.getenv("PARAM_UPDATE_STORAGE_PATH", "/state/parameter-updates/updates.jsonl"),
                    os.getenv("MODEL_ID", "privoke-balanced"),
                    max_tokens=int(os.getenv("MODEL_TRAINING_MAX_TOKENS", "256")))


if __name__ == "__main__":
    main()
