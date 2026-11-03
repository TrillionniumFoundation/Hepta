"""Pure source-marker controls; no Lean process or acceptance claim."""
from dataclasses import replace
import unittest
from unittest.mock import patch

from tools import core_byte_facts_sources as facts
from tools import core_byte_facts_diagnostic_sources as diag
from tools import core_syntax_partition_diagnostic_sources as previous
from tools import core_syntax_partition_sources as original


class ByteFactsDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = original.build_inputs()
        cls.proposal = facts.build_sources(cls.prepared)
        cls.diagnostic = diag.build_diagnostic_sources(cls.prepared, cls.proposal)

    def validate(self, candidate):
        # Both inputs were fully authenticated in the fixture. Bypass only that
        # expensive repeated gate for marker-specific adversarial tests.
        def authenticated(prepared, proposal):
            self.assertIs(prepared, self.prepared)
            self.assertIs(proposal, self.proposal)
        with patch.object(facts, 'validate_sources', side_effect=authenticated):
            return diag.validate_diagnostic_sources(self.prepared, self.proposal, candidate)

    def changed(self, source=None, manifest=None, stages=None):
        stages = list(self.diagnostic.stages if stages is None else stages)
        if source is not None:
            stages[3] = replace(stages[3], source=source)
        return diag.DiagnosticSources(tuple(stages), diag.encode(
            self.diagnostic.manifest if manifest is None else manifest))

    def reject(self, candidate):
        with self.assertRaises((ValueError, TypeError, KeyError)):
            self.validate(candidate)

    def test_complete_inventory_budget_and_protocol(self):
        stats = self.validate(self.diagnostic)
        m = self.diagnostic.manifest
        self.assertFalse(stats['acceptance_eligible'])
        self.assertEqual(stats['authority'], 'DENY_ALL')
        self.assertEqual(tuple(s.name for s in self.diagnostic.stages), diag.SCHEDULED)
        self.assertEqual(tuple(len(s.expected_theorems) for s in self.diagnostic.stages), (56,35,703,1298))
        self.assertEqual(self.diagnostic.stages[:3], self.proposal.stages[:3])
        self.assertEqual(m['maximum_processes'], 4)
        self.assertLessEqual(m['marker_count'], 24)
        self.assertEqual(m['candidate_site_count'], 24)
        self.assertLessEqual(len(self.diagnostic.manifest_json.encode()), 32768)
        self.assertEqual(m['original_total_source_bytes'], sum(s.source_bytes for s in self.prepared['stages']))
        self.assertEqual(m['transformed_total_source_bytes'], sum(s.source_bytes for s in self.proposal.stages))
        self.assertEqual(m['retained_total_source_bytes'], m['original_total_source_bytes'] +
                         m['transformed_total_source_bytes'] + self.diagnostic.stages[3].source_bytes)
        self.assertLessEqual(m['retained_total_source_bytes'], 8*1024*1024)
        self.assertLessEqual(max(s.source_bytes for s in self.diagnostic.stages), 2*1024*1024)
        self.assertEqual(m['transformation_manifest_sha256'], self.proposal.manifest_sha256)
        self.assertEqual(m['original_manifest_sha256'], self.prepared['manifest_sha256'])
        self.assertEqual(len(m['obligations']), 12)
        self.assertTrue(all(o['status'] == 'unproved' for o in m['obligations']))
        for k,v in facts.DENY.items(): self.assertEqual(m[k],v)

    def test_two_independent_inverse_layers(self):
        stripped = diag.strip_markers(self.diagnostic.stages[3].source, self.diagnostic.manifest)
        self.assertEqual(stripped, self.proposal.stages[3].source.encode())
        restored = facts.inverse_source(stripped.decode(), self.prepared['stages'][3].source,
                                        self.proposal.manifest['edits']['CertPart02'])
        self.assertEqual(restored, self.prepared['stages'][3].source.encode())

    def test_named_anchors_and_complete_command_boundaries(self):
        m = self.diagnostic.manifest
        labels = {a for marker in m['markers'] for a in marker['anchors']}
        for ordinal in (0,63,127,255,383,511,594):
            for side in ('before','after'):
                self.assertIn(side + '_linear_bf%04d' % ordinal, labels)
        for name in ('bounds','serialized','parsed','length','byte_range','transport'):
            self.assertIn('after_linear_'+name, labels)
        source = self.proposal.stages[3].source.encode()
        for index, marker in enumerate(m['markers']):
            self.assertEqual(marker['id'], 'HIA_DIAG_v1_P02_%03d' % index)
            offset = marker['original_offset']
            self.assertTrue(offset == len(source) or not source[offset:offset+1] == b' ')
            if marker['previous_command']:
                self.assertEqual(marker['previous_command']['end'], offset)
            if marker['next_command']:
                self.assertEqual(marker['next_command']['start'], offset)

    def test_tamper_marker_interval_text_id_hash_and_offsets(self):
        for key,value in (('id','HIA_DIAG_v1_P02_099'), ('text','#eval 1\n'),
                          ('sha256','0'*64), ('instrumented_offset',True),
                          ('original_offset',0)):
            m = self.diagnostic.manifest
            m['markers'][0][key] = value
            self.reject(self.changed(manifest=m))
        source = self.diagnostic.stages[3].source
        self.reject(self.changed(source=source.replace('HIA_DIAG_v1_P02_000','HIA_DIAG_v1_P02_001',1)))
        self.reject(self.changed(source=source + '#check "HIA_DIAG_v1_P02_023"\n'))

    def test_reordered_missing_duplicate_and_extra_markers(self):
        for mode in ('missing','duplicate','reverse','extra'):
            m = self.diagnostic.manifest
            if mode == 'missing': m['markers'].pop()
            if mode == 'duplicate': m['markers'][1] = dict(m['markers'][0])
            if mode == 'reverse': m['markers'].reverse()
            if mode == 'extra': m['markers'][0]['extra'] = True
            self.reject(self.changed(manifest=m))

    def test_rehashed_marker_anchor_cannot_claim_completion_or_different_boundary(self):
        for key,value in (('anchors',['linear_length_completed']), ('previous_command',None),
                          ('next_command',{'kind':'theorem','name':'linear_length','start':0,'end':1})):
            m = self.diagnostic.manifest
            m['markers'][2][key] = value
            self.assertEqual(diag.strip_markers(self.diagnostic.stages[3].source,m),
                             self.proposal.stages[3].source.encode())
            self.reject(self.changed(manifest=m))

    def test_parent_inventory_root_proof_and_stage_count_changes_rejected(self):
        for index in (0,1,2):
            ss = list(self.diagnostic.stages)
            ss[index] = replace(ss[index], source=ss[index].source+'\n')
            self.reject(self.changed(stages=ss))
        ss = list(self.diagnostic.stages)
        ss[3] = replace(ss[3], expected_theorems=ss[3].expected_theorems-{'HiaCoreSyntaxSlice.linear_bf0594'})
        self.reject(self.changed(stages=ss))
        self.reject(self.changed(stages=self.diagnostic.stages[:3]))
        self.reject(self.changed(source=self.diagnostic.stages[3].source.replace(
            'rw [(linear_bf0594).1]', 'rw [(linear_bf0593).1]',1)))

    def test_metadata_and_resource_claims_fail_closed(self):
        for key,value in (('maximum_processes',5),('acceptance_eligible',True),('authority','ALLOW'),
                          ('retained_total_source_bytes',0),('marker_count',True),
                          ('transformation_manifest_sha256','0'*64),('extra',1)):
            m = self.diagnostic.manifest; m[key] = value
            self.reject(self.changed(manifest=m))
        with patch.object(diag,'MAX_MANIFEST',1),self.assertRaises(ValueError):
            diag._derive(self.prepared,self.proposal)
        with patch.object(diag,'MAX_TOTAL_SOURCE',1),self.assertRaises(ValueError):
            diag._derive(self.prepared,self.proposal)
        with patch.object(diag,'MAX_SOURCE',1),self.assertRaises(ValueError):
            diag._derive(self.prepared,self.proposal)

    def test_old_and_new_protocols_mutually_reject(self):
        old = previous._derive(self.prepared)
        self.reject(old)
        with patch.object(previous,'_validate_original',return_value=None),self.assertRaises(ValueError):
            previous.validate_diagnostic_sources(self.prepared,self.diagnostic)
        m = self.diagnostic.manifest; m['protocol'] = previous.PROTOCOL
        self.reject(self.changed(manifest=m))
        with self.assertRaises(ValueError): diag.strip_markers(old.stages[3].source, old.manifest)

    def test_faulty_marker_emitter_cannot_authorize_nonreporting_command(self):
        def faulty(index):
            return 'HIA_DIAG_v1_P02_%03d' % index, '#eval 1\n'
        with patch.object(diag, '_marker', side_effect=faulty):
            candidate = diag._derive(self.prepared, self.proposal)
            self.reject(candidate)

    def test_source_proposal_validation_is_mandatory_before_derivation_or_marker_validation(self):
        for call in (lambda: diag.build_diagnostic_sources(self.prepared,self.proposal),
                     lambda: diag.validate_diagnostic_sources(self.prepared,self.proposal,self.diagnostic)):
            with patch.object(facts,'validate_sources',side_effect=ValueError('original gate')) as gate:
                with self.assertRaisesRegex(ValueError,'original gate'): call()
                gate.assert_called_once_with(self.prepared,self.proposal)


if __name__ == '__main__':
    unittest.main()
