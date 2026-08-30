"""Shared PriVoke transformer artifact and inference implementation."""

from .artifact import (
    ARCHITECTURE_NAME,
    ModelArtifactError,
    apply_parameter_update,
    load_artifact,
    write_artifact_atomic,
)

__all__ = [
    "ARCHITECTURE_NAME",
    "ModelArtifactError",
    "ModelConfig",
    "ModelPrediction",
    "TinyTransformerModel",
    "apply_parameter_update",
    "load_artifact",
    "write_artifact_atomic",
]


def __getattr__(name: str):
    if name in {"ModelConfig", "ModelPrediction", "TinyTransformerModel"}:
        from .network import ModelConfig, ModelPrediction, TinyTransformerModel

        return {
            "ModelConfig": ModelConfig,
            "ModelPrediction": ModelPrediction,
            "TinyTransformerModel": TinyTransformerModel,
        }[name]
    raise AttributeError(name)
