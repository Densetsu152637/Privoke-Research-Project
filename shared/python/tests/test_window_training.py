"""Synthetic policy arithmetic and independent component predicates."""
import copy
import unittest

from privoke_model import window_training as w
from privoke_model.contextual_training import training_admission_metadata,parse_training_admission_metadata
from privoke_contracts.classification import initialise_unpacked,Sensitivity,Visibility,Category


def packed(s=Sensitivity.S3,v=Visibility.P3,c=(Category.HEALTH,)):
    return initialise_unpacked(s,v,c).pack()


class WindowContractTests(unittest.TestCase):
    def test_epoch_schedule_is_reproducible_permutation_and_seed_sensitive(self):
        a=w.schedule(42)
        self.assertEqual(len(a),64)
        for start in range(0,64,8):
            self.assertEqual(sorted(a[start:start+8]),list(range(8)))
        self.assertEqual(a,w.schedule(42));self.assertNotEqual(a,w.schedule(43))

    def test_each_discrete_component_independently_prevents_compensation(self):
        original=packed()
        for candidate,component in ((packed(Sensitivity.S0,c=()),"sensitivity"),(packed(Sensitivity.S2),"severity"),
            (packed(c=()),"category"),(packed(v=Visibility.P4),"visibility"),(original,"action")):
            confidence=.1 if component=="action" else .9
            predicates=w.component_predicates(original,original,.9,candidate,confidence)
            self.assertFalse(predicates[component],component)
        # Retain gold-correct negative category decisions, too.
        self.assertFalse(w.component_predicates(original,original,.9,packed(c=(Category.HEALTH,Category.IDENTITY)),.9)["category"])

    def test_rank_requires_sensitive_progress_and_all_components_nonregression(self):
        counts={"all_joint":10,"sensitive_joint":5,"clean_joint":5,"sensitive_recall":8,"clean_specificity":8,
            **{p+c:8 for p in ("sensitive_","clean_") for c in w.COMPONENTS}}
        base={"step":0,"counts":counts,"violations":0,"loss":10.}
        clean={**base,"step":8,"counts":{**counts,"all_joint":11,"clean_joint":6},"loss":1.}
        self.assertEqual(w.select([base,clean]),base)
        good={**base,"step":16,"counts":{**counts,"sensitive_category":9},"loss":9.}
        terminal={**good,"step":64,"counts":{**good["counts"],"sensitive_visibility":7}}
        self.assertEqual(w.select([base,clean,good,terminal]),good)
        self.assertEqual(w.select([base,{**good,"violations":1}]),base)
        self.assertEqual(w.select([base,good,{**good,"step":24}]),good)

    def test_schema5_exact_admission_and_orphan_pins(self):
        metadata={"expected_contextual_training_optimizer":w.POLICY,"expected_contextual_training_objective":w.OBJECTIVE,
            "expected_contextual_candidate_eligibility":w.ELIGIBILITY,"expected_contextual_training_scope":"full_encoder",
            "expected_"+w.CONFIG_KEY:w.canonical(w.CONFIG),"expected_"+w.WINDOW_KEY:"a"*64,"expected_"+w.REFERENCE_KEY:"b"*64}
        admission=w.expectations(metadata)
        header=training_admission_metadata(admission)
        self.assertEqual(parse_training_admission_metadata(header),admission)
        bad=copy.deepcopy(metadata);bad["expected_"+w.CONFIG_KEY]=w.canonical({**w.CONFIG,"margin_cap":2.})
        with self.assertRaises(ValueError):w.expectations(bad)
        with self.assertRaises(ValueError):w.expectations({"expected_"+w.WINDOW_KEY:"a"*64})


if __name__=="__main__":unittest.main()
