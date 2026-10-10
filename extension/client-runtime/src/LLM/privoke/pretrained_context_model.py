"""Semantic findings from one immutable experimental pretrained-head snapshot."""
from types import MappingProxyType

from privoke_model.pretrained_context import (
    validate_pretrained_release_identity, validate_pretrained_stream, validate_pretrained_parameters,
)

from ...pretrained_context import FrozenPretrainedEncoder, PretrainedContextModel
from .parameter_stream import ParameterSnapshot
from .streamed_model import StreamedTransformerPrivacyModel


class StreamedPretrainedContextModel(StreamedTransformerPrivacyModel):
    """Reuse the semantic finding contract while replacing only model execution."""

    def __init__(self, snapshot: ParameterSnapshot, encoder=None):
        config = validate_pretrained_stream(snapshot.model_id, snapshot.metadata)
        validate_pretrained_release_identity(snapshot.version, snapshot.generated_at_unix)
        validate_pretrained_parameters(snapshot.parameters, snapshot.shapes, {name: False for name in snapshot.parameters})
        self.snapshot = ParameterSnapshot(
            snapshot.model_id, snapshot.version, snapshot.generated_at_unix,
            MappingProxyType({name: tuple(values) for name, values in snapshot.parameters.items()}),
            MappingProxyType({name: tuple(shape) for name, shape in snapshot.shapes.items()}),
            MappingProxyType(dict(snapshot.metadata)),
        )
        self.model = PretrainedContextModel(config, self.snapshot.parameters, self.snapshot.shapes,
                                            encoder if encoder is not None else FrozenPretrainedEncoder())

    def classify(self, text):
        # The pipeline owns normalization and original-offset recovery.
        results = super().classify(text)
        for result in results:
            result.metadata["classifier"] = "privoke_pretrained_context"
            result.metadata["backbone_sha256"] = self.model.config["backbone_sha256"]
            result.metadata["tokenizer_sha256"] = self.model.config["tokenizer_sha256"]
        return results
