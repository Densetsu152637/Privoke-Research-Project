"""Synthetic BC01 source freezing and permanent-family exclusion."""
import copy
import unittest
from unittest.mock import patch

import test_benign_coverage
from prompt_generation import train_window
from privoke_model import window_training as w


class TrainWindowTests(test_benign_coverage.BenignCoverageTests):
    def test_freeze_all_families_actual_wire_rows_and_source_replay(self):
        value=train_window.prepare_window(self.dataset,self.release,42)
        self.assertEqual(value,train_window.prepare_window(self.dataset,self.release,42))
        self.assertEqual(len(value["blocks"]),8)
        examples,guard=train_window.examples(value)
        self.assertEqual((len(examples),len(guard)),(512,16))
        w.validate_request(value,examples,guard)
        self.assertEqual(value["provenance"]["taxonomy_families"],20)
        self.assertLess(value["provenance"]["unique_source_ids"],512)
        train_window.validate_sources(value,self.dataset,self.release)
        tampered=copy.deepcopy(value);tampered["blocks"][0]["rows"][0]["packed"]^=1
        with self.assertRaises(ValueError):train_window.validate_sources(tampered,self.dataset,self.release)
        tampered=copy.deepcopy(value);tampered["guard"][0]["group"]=value["blocks"][0]["rows"][0]["group"]
        with self.assertRaises(ValueError):w.validate_window(tampered)

    def test_bounded_search_fails_closed_when_family_coverage_unavailable(self):
        with patch.object(w,"derived_seed",return_value=42),patch.object(train_window.benign,"generate_partition",wraps=train_window.benign.generate_partition) as generate:
            with self.assertRaises(ValueError):train_window.prepare_window(self.dataset,self.release,42)
            self.assertEqual(generate.call_count,64)


if __name__=="__main__":unittest.main()
