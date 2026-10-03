import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from grpc_runtime_client import handle, runtime_pb2


class BridgeLayerTests(unittest.TestCase):
    def test_ablations_send_exact_requested_layers(self):
        layers = {
            "regex": [runtime_pb2.DETECTION_LAYER_REGEX],
            "ner": [runtime_pb2.DETECTION_LAYER_NER],
            "semantic": [runtime_pb2.DETECTION_LAYER_SEMANTIC],
            "regex-ner": [runtime_pb2.DETECTION_LAYER_REGEX, runtime_pb2.DETECTION_LAYER_NER],
        }
        for name, expected in layers.items():
            stub = MagicMock()
            stub.AnalyzePrompt.return_value = SimpleNamespace(
                error="", action="ALLOW", masked_text="", elapsed_ms=1.0,
                evidence=SimpleNamespace(has_confidence=False), layers=[],
                classification=SimpleNamespace(sensitivity="S0", visibility="PU", categories=[]),
            )
            handle(stub, {"operation": "analyze", "text": "A general question", "layer": name})
            request = stub.AnalyzePrompt.call_args.args[0]
            self.assertEqual(list(request.layers), expected)
