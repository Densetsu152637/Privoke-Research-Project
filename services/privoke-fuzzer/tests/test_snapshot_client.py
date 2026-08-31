from __future__ import annotations

import sys
import unittest
from pathlib import Path

SERVICE_ROOT = Path(__file__).resolve().parents[1]
for path in (SERVICE_ROOT / "src", SERVICE_ROOT / "generated"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from privoke.v1 import parameters_pb2
from snapshot_client import ModelSnapshotUnavailable, assemble_parameter_stream


def parameter_chunk(index: int, offset: int, values: list[float]):
    return parameters_pb2.ModelParameterChunk(
        model_id="privoke-baseline",
        version="v1",
        generated_at_unix=1,
        parameter=parameters_pb2.ParameterChunk(
            name="head.bias",
            shape=[4],
            value_offset=offset,
            values=values,
        ),
        chunk_index=index,
        total_chunks=2,
    )


class SnapshotAssemblyTests(unittest.TestCase):
    def test_reassembles_contiguous_parameter_chunks(self) -> None:
        snapshot = assemble_parameter_stream(
            [parameter_chunk(0, 0, [0.1, 0.2]), parameter_chunk(1, 2, [0.3, 0.4])]
        )

        self.assertEqual(snapshot.model_id, "privoke-baseline")
        self.assertEqual(list(snapshot.parameters[0].shape), [4])
        self.assertEqual(len(snapshot.parameters[0].values), 4)

    def test_rejects_discontinuous_parameter_chunks(self) -> None:
        chunks = [
            parameter_chunk(0, 0, [0.1, 0.2]),
            parameter_chunk(1, 3, [0.3, 0.4]),
        ]

        with self.assertRaisesRegex(ModelSnapshotUnavailable, "discontinuous"):
            assemble_parameter_stream(chunks)


if __name__ == "__main__":
    unittest.main()
