"""Full source validation and fixed eleven-marker controls; no Lean execution."""
from dataclasses import replace
from functools import lru_cache
import unittest
from unittest.mock import patch
from tools import core_seven_certificate_sources as seven
from tools import core_seven_part04_diagnostic_sources as diag

@lru_cache(maxsize=1)
def fixture():
    prepared = seven.original.build_inputs()
    proposal = seven.build_sources(prepared)
    return prepared, proposal, diag.build_diagnostic_sources(prepared, proposal)

class SevenPart04SourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared, cls.proposal, cls.diagnostic = fixture()

    def validate(self, candidate):
        # Full original, inverse and seven-source gates ran on fixture. Marker
        # adversaries alter only derivative; do not repeat expensive oracle.
        with patch.object(seven, 'validate_sources') as gate:
            value = diag.validate_diagnostic_sources(self.prepared, self.proposal, candidate)
            gate.assert_called_once_with(self.prepared, self.proposal)
            return value

    def changed(self, manifest=None, source=None):
        stages = self.diagnostic.stages
        if source is not None: stages = stages[:5] + (replace(stages[5],source=source),)
        return diag.DiagnosticSources(stages, diag.encode(self.diagnostic.manifest if manifest is None else manifest))

    def reject(self, candidate):
        with self.assertRaises((ValueError, TypeError, KeyError)): self.validate(candidate)

    def test_actual_frozen_source_inventory_and_retention(self):
        self.validate(self.diagnostic)
        m = self.diagnostic.manifest
        self.assertEqual(tuple(len(s.expected_theorems) for s in self.diagnostic.stages),(56,547,271,54,1164,1298))
        self.assertEqual(m['retained_total_source_bytes'],6144549)
        self.assertEqual(m['diagnostic_target_source_bytes'],551195)
        self.assertEqual(len(m['retained_paths']),23)
        self.assertEqual(m['retained_paths']['seven/CertPart04.lean']['sha256'],
                         self.proposal.stages[5].source_sha256)
        for stage in self.diagnostic.stages:
            path = stage.module_name.replace('.', '/') + '.lean'
            self.assertEqual(m['retained_paths'][path]['sha256'], stage.source_sha256)
        self.assertEqual([r['original_offset'] for r in m['markers']],[65,102701,104333,112569,112729,113075,243492,243951,484546,484578,550810])
        self.assertEqual([r['instrumented_offset'] for r in m['markers']],[offset+35*i for i,offset in enumerate([65,102701,104333,112569,112729,113075,243492,243951,484546,484578,550810])])
        self.assertEqual([len(r['text'].encode()) for r in m['markers']],[35]*11)
        self.assertEqual(diag.strip_markers(self.diagnostic.stages[5].source,m),self.proposal.stages[5].source.encode())
        self.assertEqual(m['not_scheduled_stage_names'],list(seven.NAMES[6:]))
        self.assertLessEqual(len(self.diagnostic.manifest_json.encode()),32768)
        self.assertTrue(all(x['status']=='unproved' for x in m['obligations']))
        self.assertEqual(len(m['obligations']),12)
        self.assertFalse(m['acceptance_eligible'])
        self.assertEqual(len(self.prepared['binding_inputs']), 5)
        self.assertEqual(len(self.proposal.manifest['expected_targets']), 66)
        self.assertEqual(len(self.proposal.manifest['historical_negatives']), 10)
        self.assertEqual(m['original_target_source_bytes'], 550810)
        self.assertEqual(m['original_target_source_sha256'],
                         'a4fdf6b42713f4ff028ec7f2febbfcd1e5e3eb862a86d897b31c8375295140a7')

    def test_rehashed_marker_fields_and_neighbors(self):
        for field,value in [('id','HIA_DIAG_v1_P04_000'),('text','#eval 1\n'),('sha256','0'*64),
                            ('original_offset',True),('instrumented_offset',True),('anchors',['after:linearBytes']),
                            ('previous_command',None),('next_command',None),('extra',1)]:
            m=self.diagnostic.manifest;m['markers'][1][field]=value
            self.reject(self.changed(manifest=m))
        for mode in ('drop','duplicate','reverse'):
            m=self.diagnostic.manifest
            if mode=='drop':m['markers'].pop()
            if mode=='duplicate':m['markers'][1]=m['markers'][0]
            if mode=='reverse':m['markers'].reverse()
            self.reject(self.changed(manifest=m))

    def test_rehashed_manifest_and_bytes(self):
        for key,value in [('marker_count',True),('maximum_processes',5),('target','CertPart04'),
                          ('protocol','compositional-byte-facts-prefix-diagnostic-v1'),('retained_total_source_bytes',0),
                          ('acceptance_eligible',True),('extra',1)]:
            m=self.diagnostic.manifest;m[key]=value;self.reject(self.changed(manifest=m))
        for source in (self.diagnostic.stages[5].source+'#check "unknown"\n',
                       self.diagnostic.stages[5].source.replace('\n','\r\n'),
                       self.diagnostic.stages[5].source.replace('parallel_r113','parallel_r_bad',1)):
            self.reject(self.changed(source=source))
        for serialized in (self.diagnostic.manifest_json+' ', '{"schema":"fake",'+self.diagnostic.manifest_json[1:]):
            self.reject(replace(self.diagnostic,manifest_json=serialized))

    def test_whole_source_gate_mandatory_before_marker_derivation(self):
        for call in (lambda:diag.build_diagnostic_sources(self.prepared,self.proposal),
                     lambda:diag.validate_diagnostic_sources(self.prepared,self.proposal,self.diagnostic)):
            with patch.object(seven,'validate_sources',side_effect=ValueError('full inverse failed')) as gate:
                with self.assertRaisesRegex(ValueError,'full inverse failed'):call()
                gate.assert_called_once_with(self.prepared,self.proposal)

    def test_caps_and_actual_extra_copies(self):
        for cap in ('MAX_MANIFEST','MAX_SOURCE','MAX_TOTAL_SOURCE'):
            with patch.object(diag,cap,1),self.assertRaises(ValueError):diag._derive(self.prepared,self.proposal)
        with self.assertRaises(ValueError):seven.validate_retention(self.proposal,tuple(s.source for s in seven.invert_sources(self.prepared,self.proposal)))

    def test_old_builders_reject_new_and_reverse(self):
        from tools import core_byte_facts_diagnostic_sources as byte_diag
        from tools import core_seven_certificate_diagnostic_sources as four_diag
        for old in (byte_diag, four_diag):
            with self.assertRaises(ValueError):
                old.strip_markers(self.diagnostic.stages[5].source, self.diagnostic.manifest)
            m = self.diagnostic.manifest
            m['protocol'] = old.PROTOCOL
            with self.assertRaises(ValueError):
                diag.strip_markers(self.diagnostic.stages[5].source, m)

    def test_first_and_final_boundaries_are_not_moveable(self):
        # Marker zero is before the first declaration; the final marker is
        # after the final print, never proof of completion or serialization.
        m = self.diagnostic.manifest
        self.assertEqual(m['markers'][0]['next_command']['name'], 'parallel_r113')
        self.assertEqual(m['markers'][-1]['previous_command']['kind'], 'print')
        self.assertIsNone(m['markers'][-1]['next_command'])
        for index in (0, 9, 10):
            for key in ('original_offset', 'instrumented_offset'):
                for delta in (-1, 1):
                    m = self.diagnostic.manifest
                    m['markers'][index][key] += delta
                    self.reject(self.changed(manifest=m))
            for key in ('previous_command', 'next_command', 'anchors'):
                m = self.diagnostic.manifest
                m['markers'][index][key] = m['markers'][1][key]
                self.reject(self.changed(manifest=m))

    def test_independent_inverse_rejects_relocated_marker_intervals(self):
        original = self.proposal.stages[5].source.encode()
        for index in (0, 9, 10):
            m = self.diagnostic.manifest
            m['markers'][index]['original_offset'] -= 1
            m['markers'][index]['instrumented_offset'] -= 1
            chunks, cursor = [], 0
            for marker in m['markers']:
                offset = marker['original_offset']
                chunks.extend((original[cursor:offset], marker['text'].encode()))
                cursor = offset
            chunks.append(original[cursor:])
            source = b''.join(chunks).decode()
            # Interval-only inversion still restores the original; independent
            # anchor reconstruction must reject this self-consistent relocation.
            self.assertEqual(diag.strip_markers(source, m), original)
            candidate = self.changed(manifest=m, source=source)
            with patch.object(diag, 'TARGET_SOURCE_SHA256', diag.digest(source.encode())):
                self.reject(candidate)

    def test_first_five_parents_and_schedule_are_exact(self):
        self.assertEqual(self.diagnostic.stages[:5], self.proposal.stages[:5])
        self.assertEqual(self.diagnostic.manifest['maximum_processes'], 6)
        self.assertEqual(len(self.diagnostic.stages), 6)
        for index in range(5):
            stages = list(self.diagnostic.stages)
            stages[index] = replace(stages[index], source=stages[index].source + '\n')
            self.reject(replace(self.diagnostic, stages=tuple(stages)))
        self.reject(replace(self.diagnostic, stages=self.diagnostic.stages + self.proposal.stages[6:7]))
        for flag, value in diag.DENY.items():
            self.assertEqual(self.diagnostic.manifest[flag], value)

if __name__ == '__main__':
    unittest.main()
