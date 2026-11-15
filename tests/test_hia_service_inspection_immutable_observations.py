"""Regression controls for immutable original observation and late-event custody."""
from __future__ import annotations
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from tools.observe_hia_service_inspection_immutable_originals import frozen_record, late_observation
from tools.qualify_hia_service_inspection_finite import validate_original_group


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),
                      ensure_ascii=True,allow_nan=False).encode()


class ImmutableInspectionObservationTests(unittest.TestCase):
    def test_late_mutation_never_reencodes_the_original_equality_operands(self):
        first={'case_id':'immutable','trace':[{'operation':'body'}],'error':{'name':'store'}}
        second=json.loads(canonical(first))
        first_bytes,second_bytes=canonical(first),canonical(second)
        first['trace'].append({'operation':'receiver.release'})
        record=frozen_record('immutable',first_bytes,second_bytes,canonical)
        self.assertTrue(record.endswith(b'\n'))
        saved=json.loads(record)
        self.assertIs(saved['canonical_equal'],True)
        self.assertEqual(canonical(saved['first']),first_bytes)
        self.assertEqual(canonical(saved['second']),second_bytes)
        self.assertNotEqual(canonical(first),first_bytes)
        self.assertEqual(saved['first']['error'],{'name':'store'})
        other=canonical({**second,'error':{'name':None}})
        self.assertIs(json.loads(frozen_record('immutable',first_bytes,other,canonical))['canonical_equal'],False)

    def test_late_record_preserves_complete_suffix_and_refuses_nonappend_changes(self):
        initial={'case_id':'late','trace':[{'operation':'body','sequence':1}],
                 'error':{'name':'store'},'mode':1}
        frozen=canonical(initial)
        live=json.loads(frozen);live['trace'].append({'operation':'receiver.release'})
        captured=late_observation(frozen,live,canonical)
        self.assertEqual(captured['status'],'PASS')
        self.assertEqual(captured['later_complete'],live)
        self.assertEqual(captured['late_suffix'],[{'operation':'receiver.release'}])
        self.assertEqual(captured['capture_sha256'],sha256(frozen).hexdigest())
        for altered in ({**live,'trace':[{'operation':'replacement'}]},
                        {**live,'error':{'name':None}},
                        {**live,'mode':True}, {**live,'mode':1.0},
                        {**live,'trace':[{'operation':'body','sequence':True}]},
                        {**live,'trace':[{'operation':'body','sequence':1.0}]}):
            with self.subTest(altered=altered):
                self.assertEqual(late_observation(frozen,altered,canonical)['status'],'HOLD')

    def test_admission_refuses_the_legacy_true_flag_with_changed_stored_first(self):
        first={'case_id':'complete','trace':[{'operation':'body'}],'error':None}
        raw=canonical(first)
        later=json.loads(raw);later['trace'].append({'operation':'receiver.release'})
        audit=late_observation(raw,later,canonical)
        row=frozen_record('complete',raw,raw,canonical)
        late=canonical({'case_id':'complete','first':audit,'second':audit,
                        'phase':'before_existing_observation_reference_release'})+b'\n'
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary)
            (directory/'base.jsonl').write_bytes(row)
            (directory/'base-late-observations.jsonl').write_bytes(late)
            file_pins={name:{'bytes':len(data),'sha256':sha256(data).hexdigest()}
                       for name,data in [('base.jsonl',row),('base-late-observations.jsonl',late)]}
            validate_original_group(directory,'base',[{'id':'complete'}],file_pins=file_pins)
            changed_pins={**file_pins,'base.jsonl':{**file_pins['base.jsonl'],'sha256':'0'*64}}
            with self.assertRaisesRegex(ValueError,'actual consumed'):
                validate_original_group(directory,'base',[{'id':'complete'}],file_pins=changed_pins)
            corrupted=json.loads(row);corrupted['first']=later
            self.assertIs(corrupted['canonical_equal'],True)
            (directory/'base.jsonl').write_bytes(canonical(corrupted)+b'\n')
            with self.assertRaisesRegex(ValueError,'immutable equality'):
                validate_original_group(directory,'base',[{'id':'complete'}],file_pins=file_pins)
            (directory/'base.jsonl').write_bytes(row)
            damaged=json.loads(late);damaged['first']['later_complete']['trace'][0]={'operation':'changed'}
            (directory/'base-late-observations.jsonl').write_bytes(canonical(damaged)+b'\n')
            with self.assertRaisesRegex(ValueError,'late evidence'):
                validate_original_group(directory,'base',[{'id':'complete'}],file_pins=file_pins)


if __name__=='__main__':
    unittest.main()
