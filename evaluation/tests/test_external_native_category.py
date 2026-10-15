import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from types import SimpleNamespace
from privoke_eval.external_native_category import select_components, confusion, category_conflicts

class NativeCategoryTests(unittest.TestCase):
    def test_global_component_allocation_and_determinism(self):
        components = [SimpleNamespace(component_id="mixed", member_uids=(1,2), exclusion_reasons=()),
                      SimpleNamespace(component_id="positive", member_uids=(3,), exclusion_reasons=())]
        args = (components, {1:"hard_negative",2:"positive",3:"positive"}, {1,2,3}, {"hard_negative":1,"positive":1})
        rows, _ = select_components(*args)
        self.assertEqual([r["uid"] for r in rows], [1,3])
        self.assertEqual(select_components(*args)[0], rows)
    def test_quota_fails_instead_of_reusing_component(self):
        components = [SimpleNamespace(component_id="mixed", member_uids=(1,2), exclusion_reasons=())]
        with self.assertRaisesRegex(ValueError, "quota unavailable"):
            select_components(components,{1:"hard_negative",2:"positive"},{1,2},{"hard_negative":1,"positive":1})
    def test_errors_remain_in_class_denominators(self):
        result = confusion([{"source_positive":True,"predicted":True},{"source_positive":True,"predicted":None},
                            {"source_positive":False,"predicted":None},{"source_positive":False,"predicted":False}])
        self.assertEqual(result["recall"], .5)
        self.assertEqual(result["specificity"], .5)
        self.assertEqual(result["complete_case_recall"], 1)
        self.assertEqual(result["errors_negative"], 1)
    def test_native_conflict_after_normalization(self):
        components=[SimpleNamespace(component_id="mixed",member_uids=(1,2))]
        result=category_conflicts(components,{1:"positive",2:"negative"},{1:{"llm_input":" X "},2:{"llm_input":"x"}},lambda s:s.strip().lower())
        self.assertEqual(result,{"mixed"})

if __name__ == "__main__":
    unittest.main()
