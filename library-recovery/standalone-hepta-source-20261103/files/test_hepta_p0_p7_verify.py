import copy
import importlib.util
import json
import unittest
from pathlib import Path

SOURCE=Path(__file__).with_name('hepta_p0_p7_verify.py')
spec=importlib.util.spec_from_file_location('p0p7_verify', SOURCE)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
DATA=json.loads(Path(__file__).with_name('HEPTA_P0_P7_BLOCKERS_20261023.json').read_text())

class LedgerTests(unittest.TestCase):
    def test_actual_ledger_is_honest_blocked(self):
        result=module.validate(DATA)
        self.assertEqual(result['structural_check'],'PASS')
        self.assertFalse(result['all_blockers_closed'])
        self.assertEqual(len(result['stages']),8)
        self.assertGreater(result['open_blockers'],20)
    def test_global_false_close_is_rejected(self):
        x=copy.deepcopy(DATA);x['all_blockers_closed']=True
        with self.assertRaisesRegex(ValueError,'global closure'):
            module.validate(x)
    def test_stage_false_close_is_rejected(self):
        x=copy.deepcopy(DATA);x['stages'][1]['status']='CLOSED'
        with self.assertRaisesRegex(ValueError,'premature'):
            module.validate(x)
    def test_missing_evidence_cannot_close(self):
        x=copy.deepcopy(DATA);x['stages'][0]['blockers'][0]['status']='CLOSED'
        with self.assertRaisesRegex(ValueError,'evidence pair'):
            module.validate(x)
    def test_stale_cross_source_proofs_cannot_close(self):
        x=copy.deepcopy(DATA);b=x['stages'][0]['blockers'][0]
        b['status']='CLOSED'
        b['closure_attestations']=[
            {'source_sha':'a'*40,'artifact_sha256':'c'*64,'role':'execution','auditor':'host-A'},
            {'source_sha':'b'*40,'artifact_sha256':'d'*64,'role':'independent_evaluation','auditor':'host-B'}]
        with self.assertRaisesRegex(ValueError,'unpaired'):
            module.validate(x)
    def test_duplicate_blocker(self):
        x=copy.deepcopy(DATA);x['stages'][0]['blockers'].append(copy.deepcopy(x['stages'][0]['blockers'][0]))
        with self.assertRaisesRegex(ValueError,'duplicate'):
            module.validate(x)
    def test_broken_dependency_order(self):
        x=copy.deepcopy(DATA);x['stages'][4]['depends_on']=['P1']
        with self.assertRaisesRegex(ValueError,'dependency'):
            module.validate(x)
    def test_non_authorized_state_stays_denied(self):
        x=copy.deepcopy(DATA);x['authority']='ALLOW_ALL'
        with self.assertRaisesRegex(ValueError,'authority'):
            module.validate(x)
    def test_missing_closure_condition(self):
        x=copy.deepcopy(DATA);x['stages'][2]['blockers'][1]['closure_test']=''
        with self.assertRaisesRegex(ValueError,'closure'):
            module.validate(x)
    def test_source_reference_must_be_trusted_url(self):
        x=copy.deepcopy(DATA);x['stages'][4]['blockers'][0]['source_refs']=['file:///tmp/self-certified']
        with self.assertRaisesRegex(ValueError,'source reference'):
            module.validate(x)

if __name__=='__main__':
    unittest.main()
