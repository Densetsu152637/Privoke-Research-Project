"""No-model preparation and strict objective-specific wire contracts."""
import copy,json,unittest
import test_contextual_training as prior
from privoke_model.contextual_training import *
from privoke_model.artifact import ModelArtifactError

NEW=CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE
class SumMarginContractTests(unittest.TestCase):
    def test_preparation_and_canonical_null_objective_header(self):
        base=prepare_full_encoder_artifact(prior.ContextualTrainingContractTests().original(),version='sm01',generated_at_unix=1,source_revision='a'*40)
        prepared=prepare_training_policy_artifact(base,objective=NEW)
        self.assertEqual(prepared['parameters'],base['parameters'])
        self.assertEqual(prepared['version'],base['version'])
        self.assertNotEqual(prepared['checksum'],base['checksum'])
        self.assertEqual(prepare_training_objective_artifact(prepared),prepare_training_objective_artifact(base))
        expected=training_policy_expectations({'expected_contextual_training_objective':NEW})
        self.assertIn('expected_diagnostics_policy',expected);self.assertIsNone(expected['expected_diagnostics_policy'])
        header=training_admission_metadata(expected)
        self.assertEqual(json.loads(header[0][1]),{'schema':2,'expected_objective':NEW,'expected_diagnostics_policy':None})
        self.assertEqual(parse_training_admission_metadata(header),expected)
        for mutate in [lambda d:d.pop('expected_diagnostics_policy'),lambda d:d.update(expected_objective=LEGACY_OBJECTIVE),
                       lambda d:d.update(expected_backtracking_policy=BACKTRACKING_POLICY),lambda d:d.update(schema=True),
                       lambda d:d.update(expected_diagnostics_policy='off')]:
            wrong=json.loads(header[0][1]);mutate(wrong)
            with self.assertRaises(ValueError):parse_training_admission_metadata(((BACKTRACKING_HEADER,json.dumps(wrong)),))
        with self.assertRaises(ValueError):parse_training_admission_metadata((header[0],header[0]))
        with self.assertRaises(ModelArtifactError):prepare_training_optimizer_artifact(prepared,LOCAL_SGD_1)

    def test_five_component_diagnostic_schema_is_objective_specific(self):
        record={'schema':2,'objective':NEW,'fingerprints':['a'*64,'b'*64],
            'phases':[['base_training','semantic','ok',2],['candidate_training','semantic','ok',2]],'counts':[2,1,1],
            'loss_columns':list(SUM_MARGIN_LOSS_COLUMNS),'loss':[[1,2,3,4,10]]*2,
            'accuracy_columns':list(DIAGNOSTIC_ACCURACY_COLUMNS),'accuracy':[[1]*6]*2,
            'update_columns':list(DIAGNOSTIC_UPDATE_COLUMNS),'update':[6,0,.01,.01]}
        def validate(d,obj=NEW):return validate_training_diagnostics(json.dumps(d),objective=obj,examples=2,base_fingerprint='a'*64,candidate_fingerprint='b'*64)
        validate(record)
        for key,value in [('schema',1),('loss_columns',list(DIAGNOSTIC_LOSS_COLUMNS)),('loss',[[1,2,3,6]]*2),('loss',[[1,2,3,4,6]]*2),('loss',[[1e308]*5]*2)]:
            wrong=copy.deepcopy(record);wrong[key]=value
            with self.assertRaises(ValueError):validate(wrong)
        with self.assertRaises(ValueError):validate(record,CLASS_BALANCED_OBJECTIVE)

    def test_backtracking_schema_two_has_explicit_five_columns_and_bounded_five_trials(self):
        header={'schema':2,'policy':BACKTRACKING_POLICY,'objective':NEW,'base':['a'*64,[1,2,3,4,10]],
            'raw':['b'*64,'c'*64,6,1.,1.],'selected':None,'gradient_fits':1,'loss_columns':list(SUM_MARGIN_LOSS_COLUMNS)}
        rows=[[.003*s,[1,2,3,4,10],0,.01,.01,'d'*64,'e'*64,'ok',64,True,64] for s in BACKTRACKING_SCALES]
        metadata={BACKTRACKING_TRACE_KEY:json.dumps(header,separators=(',',':')),BACKTRACKING_TRIALS_KEY:json.dumps(rows,separators=(',',':')),
            EXECUTED_OBJECTIVE_KEY:NEW,'base_parameter_fingerprint':'a'*64,'trained_parameter_inventory_fingerprint':'c'*64}
        validate_backtracking_trace(metadata,examples=64,requested_rate=.003,rejected=True)
        self.assertTrue(all(len(v.encode())<=2048 for v in metadata.values()))
        for mutate in [lambda h:h.update(schema=1),lambda h:h.pop('loss_columns'),lambda h:h.update(objective=CLASS_BALANCED_OBJECTIVE)]:
            wrong=copy.deepcopy(header);mutate(wrong);meta={**metadata,BACKTRACKING_TRACE_KEY:json.dumps(wrong)}
            with self.assertRaises(ValueError):validate_backtracking_trace(meta,examples=64,requested_rate=.003,rejected=True)
