import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from privoke_model.fingerprint import parameter_fingerprint


class ParameterFingerprintTests(unittest.TestCase):
    def test_numeric_boundaries_cannot_collide(self):
        self.assertNotEqual(parameter_fingerprint({"tensor": [1.0, 23.0]}), parameter_fingerprint({"tensor": [1.02, 3.0]}))
        self.assertNotEqual(parameter_fingerprint({"tensor": [1.0, 23.0]}, {"tensor": [2]}), parameter_fingerprint({"tensor": [1.02, 3.0]}, {"tensor": [2]}))

    def test_tensor_boundaries_and_shapes_are_part_of_identity(self):
        self.assertNotEqual(parameter_fingerprint({"a": [1], "b": [2]}), parameter_fingerprint({"a": [1, 2]}))
        self.assertNotEqual(parameter_fingerprint({"a": [1, 2]}, {"a": [2]}), parameter_fingerprint({"a": [1, 2]}, {"a": [1, 2]}))

    def test_mapping_order_is_irrelevant_and_values_are_not_mutated(self):
        values = {"b": [3.0], "a": [1.0, 2.0]}
        self.assertEqual(parameter_fingerprint(values), parameter_fingerprint({"a": [1, 2], "b": [3]}))
        self.assertEqual(values, {"b": [3.0], "a": [1.0, 2.0]})
        self.assertEqual(len(parameter_fingerprint(values)), 64)

    def test_non_finite_values_are_rejected(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ValueError):
                parameter_fingerprint({"a": [value]})
