"""Prepare immutable controlled training policies; preparation grants no fitting authority."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared/python"))
from privoke_model.artifact import load_artifact
from privoke_model.contextual_training import (prepare_training_policy_artifact, LEGACY_OBJECTIVE,
    CLASS_BALANCED_OBJECTIVE, TRAIN_DIAGNOSTICS_POLICY, PROCESS_OBJECTIVES)
from privoke_model.contextual_training import BACKTRACKING_POLICY, prepare_training_backtracking_artifact
from privoke_model.fingerprint import parameter_fingerprint


def prepare(source, *, objective, diagnostics, protocol_bytes, backtracking=None, optimizer=None,
            window_manifest_sha256=None,component_manifest_sha256=None):
    """Bind actual model bytes, policy, source code and caller-frozen protocol/settings."""
    artifact = load_artifact(source)
    if "contextual_training_optimizer" in artifact.get("metadata", {}):
        raise ValueError("Controlled preparation requires absent optimizer metadata.")
    prepared = prepare_training_policy_artifact(artifact, objective=objective, diagnostics=diagnostics)
    if optimizer is not None:
        from privoke_model.full_adam import POLICY, prepare_artifact
        from privoke_model import window_training as window
        if optimizer not in (POLICY,window.POLICY) or backtracking is not None or diagnostics is not None:
            raise ValueError("Fixed FULL Adam rejects diagnostics/backtracking mixtures.")
        prepared = (window.prepare_artifact(prepared,window_manifest_sha256,component_manifest_sha256)
                    if optimizer==window.POLICY else prepare_artifact(prepared))
    if optimizer!="full_projected_adam64_window_checkpoint_v1" and (window_manifest_sha256 or component_manifest_sha256):
        raise ValueError("Window manifest pins require the explicit window optimizer.")
    if backtracking is not None:
        if backtracking != BACKTRACKING_POLICY:
            raise ValueError("Unsupported backtracking preparation policy.")
        preparation = {"schema": 1, "baseline_checksum": artifact["checksum"],
            "baseline_fingerprint": parameter_fingerprint({k: v["values"] for k, v in artifact["parameters"].items()},
                                                          {k: v["shape"] for k, v in artifact["parameters"].items()}),
            "protocol_sha256": hashlib.sha256(protocol_bytes).hexdigest(),
            "source_sha256": hashlib.sha256((ROOT / "shared/python/privoke_model/contextual_training.py").read_bytes()).hexdigest()}
        prepared = prepare_training_backtracking_artifact(prepared, preparation=preparation)
    tensors = artifact["parameters"]
    provenance = {"schema": 1, "fit_release": False, "objective": objective, "diagnostics": diagnostics,
        "optimizer": optimizer or "absent", "source_file_sha256": hashlib.sha256(Path(source).read_bytes()).hexdigest(),
        "baseline_artifact_checksum": artifact["checksum"], "prepared_artifact_checksum": prepared["checksum"],
        "baseline_parameter_fingerprint": parameter_fingerprint({k: v["values"] for k, v in tensors.items()},
                                                                {k: v["shape"] for k, v in tensors.items()}),
        "protocol_sha256": hashlib.sha256(protocol_bytes).hexdigest(),
        "source_sha256": hashlib.sha256((ROOT / "shared/python/privoke_model/contextual_training.py").read_bytes()).hexdigest()}
    if backtracking is not None:
        from privoke_model.contextual_training import validate_backtracking_policy
        provenance.update(backtracking_policy=backtracking, backtracking_preparation_sha256=validate_backtracking_policy(prepared["metadata"]))
    return prepared, provenance


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--objective", choices=PROCESS_OBJECTIVES, required=True)
    parser.add_argument("--diagnostics", choices=(TRAIN_DIAGNOSTICS_POLICY, "off"), required=True)
    parser.add_argument("--backtracking", choices=(BACKTRACKING_POLICY,), default=None)
    parser.add_argument("--optimizer", choices=("full_projected_adam64_v1","full_projected_adam64_window_checkpoint_v1"), default=None)
    parser.add_argument("--window-manifest-sha256")
    parser.add_argument("--component-manifest-sha256")
    parser.add_argument("--protocol", type=Path, required=True, help="Frozen dataset and effective settings/protocol binding")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.provenance.exists() or args.output.resolve() == args.provenance.resolve():
        parser.error("Preparation requires two distinct new output files.")
    prepared, provenance = prepare(args.source, objective=args.objective,
        diagnostics=None if args.diagnostics == "off" else args.diagnostics, protocol_bytes=args.protocol.read_bytes(), backtracking=args.backtracking, optimizer=args.optimizer,
        window_manifest_sha256=args.window_manifest_sha256,component_manifest_sha256=args.component_manifest_sha256)
    for path, payload in ((args.output, prepared), (args.provenance, provenance)):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, separators=(",", ":"), allow_nan=False)
            stream.write("\n")


if __name__ == "__main__":
    main()
