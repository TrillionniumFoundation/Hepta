"""Closed Part03 source/inverse controls. No Lean or real compiler invocation."""
from dataclasses import replace
from functools import lru_cache
import unittest
from unittest.mock import patch
from tools import core_seven_certificate_sources as seven
from tools import core_seven_parallel_relocation_sources as relocation
from tools import core_seven_relocated_part03_sources as d

@lru_cache(maxsize=1)
def fixture():
    prepared = seven.original.build_inputs()
    previous = seven.build_sources(prepared)
    stages = relocation._derive_stages(previous)
    proposal = relocation.ParallelRelocationSources(prepared['stages'], stages,
        relocation.encode(relocation._manifest(prepared, previous, stages)))
    return prepared, previous, proposal, d.build_diagnostic_sources(prepared, previous, proposal)

class Part03SourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared, cls.previous, cls.proposal, cls.diag = fixture()

    def candidate(self, manifest=None, source=None):
        stages = self.diag.stages
        if source is not None: stages = stages[:4] + (replace(stages[4], source=source),)
        return d.RelocatedPart03DiagnosticSources(stages, d.encode(self.diag.manifest if manifest is None else manifest))

    def reject(self, candidate):
        # The genuine builder above runs the full original/inverse gates once.
        # These adversaries exercise only the new closed derivative grammar.
        with patch.object(relocation, 'validate_sources'), self.assertRaises((ValueError, TypeError, KeyError)):
            d.validate_diagnostic_sources(self.prepared,self.previous,self.proposal,candidate)

    def test_fixed_source_and_complete_inputs(self):
        self.assertEqual([len(s.expected_theorems) for s in self.diag.stages], [56,547,271,54,1655])
        self.assertEqual(len(self.prepared['binding_inputs']),5)
        self.assertEqual(len(self.previous.manifest['expected_targets']),66)
        self.assertEqual(len(self.previous.manifest['historical_negatives']),10)
        self.assertEqual(d.strip_markers(self.diag.stages[4].source,self.diag.manifest),self.proposal.stages[4].source.encode())
        self.assertEqual(self.diag.stages[4].source_bytes,612761)
        self.assertEqual(self.diag.stages[4].source_sha256,d.TARGET_SOURCE_SHA256)
        self.assertEqual(len(self.diag.manifest_json.encode()),6616)

    def test_exact_retained_paths(self):
        sources=d.retained_sources(self.prepared,self.proposal,self.diag.stages)
        self.assertEqual(len(sources),23)
        self.assertEqual(sum(len(s.encode()) for s in sources.values()),6206115)
        self.assertEqual(sources['relocated/CertPart03.lean'],self.proposal.stages[4].source)
        self.assertEqual(sources['HiaSyntaxResearch/CertPart03.lean'],self.diag.stages[4].source)
        self.assertNotIn('HiaSyntaxResearch/CertPart04.lean',sources)
        self.assertTrue(all(len(s.encode())<=2097152 for s in sources.values()))

    def test_closed_nonacceptance_flags(self):
        m=self.diag.manifest
        for key in ('acceptance_eligible','kernel_core_syntax_connection_checked','actual_core_bridge_proved',
                    'python_exporter_refinement_proved','body_prefix_refinement_proved','all_edge_transfer_proved'):
            self.assertIs(m[key],False)
            bad=self.diag.manifest;bad[key]=True;self.reject(self.candidate(manifest=bad))
        self.assertEqual(m['authority'],dict(seven.facts.DENY))
        self.assertEqual(len(m['obligations']),12)
        self.assertTrue(all(x['status']=='unproved' for x in m['obligations']))

    def test_marker_keys_and_types(self):
        for key,value in [('id','HIA_SEVEN_DIAG_v1_P04_001'),('text','#eval 1\n'),('sha256','0'*64),
                          ('original_offset',True),('instrumented_offset',True),('anchor','unknown'),
                          ('previous_command',None),('next_command',None),('extra',0)]:
            m=self.diag.manifest;m['markers'][1][key]=value;self.reject(self.candidate(manifest=m))

    def test_marker_order_and_cardinality(self):
        for mode in ('drop','duplicate','reverse','extra'):
            m=self.diag.manifest
            if mode=='drop':m['markers'].pop()
            elif mode=='duplicate':m['markers'][1]=m['markers'][0]
            elif mode=='reverse':m['markers'].reverse()
            else:m['markers'].append(m['markers'][-1])
            self.reject(self.candidate(manifest=m))

    def test_neighborhood_bool_offsets_rejected(self):
        m=self.diag.manifest;m['markers'][0]['previous_command']['start']=True
        self.reject(self.candidate(manifest=m))

    def test_marker_relocation_rejected_even_rehashed(self):
        m=self.diag.manifest;raw=self.proposal.stages[4].source.encode()
        m['markers'][1]['original_offset']=334;m['markers'][1]['instrumented_offset']=369
        chunks=[];cursor=0
        for marker in m['markers']:
            offset=marker['original_offset'];chunks.extend((raw[cursor:offset],marker['text'].encode()));cursor=offset
        chunks.append(raw[cursor:]);changed=b''.join(chunks).decode()
        m['marked']={'bytes':len(changed.encode()),'sha256':d.digest(changed.encode())}
        self.reject(self.candidate(manifest=m,source=changed))

    def test_manifest_fields_closed(self):
        for key,value in [('schema','old'),('protocol','old'),('maximum_processes',6),('marker_count',True),
                          ('source_only',False),('target','CertPart03'),('subject_count',1654),
                          ('original_manifest_sha256','0'*64),('previous_seven_manifest_sha256','0'*64),
                          ('relocation_manifest_sha256','0'*64),('source_file_map_sha256','0'*64),('extra',1)]:
            m=self.diag.manifest;m[key]=value;self.reject(self.candidate(manifest=m))

    def test_manifest_canonical_duplicate_trailing_rejected(self):
        for raw in (self.diag.manifest_json+' ',self.diag.manifest_json.rstrip(),
                    '{"schema":"fake",'+self.diag.manifest_json[1:]):
            self.reject(replace(self.diag,manifest_json=raw))

    def test_source_byte_mutations_rejected(self):
        source=self.diag.stages[4].source
        for changed in (source+'\n',source.replace('\n','\r\n'),source.replace('linearRaw','linearBad',1),
                        source.replace('#check','--check',1),source+'#check "foreign"\n'):
            self.reject(self.candidate(source=changed))

    def test_exact_five_stage_type_and_schedule(self):
        self.assertEqual(self.diag.stages[:4],self.proposal.stages[:4])
        for stages in (list(self.diag.stages),self.diag.stages[:-1],self.diag.stages+self.proposal.stages[5:6],self.diag.stages[::-1]):
            self.reject(replace(self.diag,stages=stages))
        class Subtype(d.RelocatedPart03DiagnosticSources):pass
        self.reject(Subtype(self.diag.stages,self.diag.manifest_json))

    def test_parent_and_target_metadata_unchanged(self):
        for i in range(4):
            stages=list(self.diag.stages);stages[i]=replace(stages[i],source=stages[i].source+'\n')
            self.reject(replace(self.diag,stages=tuple(stages)))
        stages=self.diag.stages[:4]+(replace(self.diag.stages[4],name='Foreign'),)
        self.reject(replace(self.diag,stages=stages))

    def test_complete_recovered_gate_is_mandatory(self):
        with patch.object(relocation,'validate_sources',side_effect=ValueError('mandatory oracle')) as gate:
            with self.assertRaisesRegex(ValueError,'mandatory oracle'):
                d.validate_diagnostic_sources(self.prepared,self.previous,self.proposal,self.diag)
            gate.assert_called_once()
            recovered=gate.call_args.args[2]
            self.assertEqual(recovered.stages,self.proposal.stages)
            self.assertIsNot(recovered,self.proposal)
            self.assertEqual(gate.call_args.args[3],(self.diag.stages[4].source,))

    def test_old_protocols_rejected_both_directions(self):
        from tools import core_seven_relocation_diagnostic_sources as old
        from tools import core_seven_part04_diagnostic_sources as part04
        for module in (old,part04):
            with self.assertRaises(ValueError):module.strip_markers(self.diag.stages[4].source,self.diag.manifest)
            m=self.diag.manifest;m['protocol']=module.PROTOCOL
            self.reject(self.candidate(manifest=m))
        self.reject(self.proposal)

    def test_endpoints_and_inventory_markers_fixed(self):
        markers=self.diag.manifest['markers']
        self.assertEqual(tuple(m['original_offset'] for m in markers),d.OFFSETS)
        self.assertEqual(markers[0]['next_command']['name'],'linearRaw')
        self.assertEqual(markers[9]['previous_command']['name'],'HiaCoreSyntaxSlice.parallel_bf0226')
        self.assertIsNone(markers[-1]['next_command'])
        self.assertTrue(all(len(m['text'].encode())==35 for m in markers))

if __name__=='__main__':unittest.main()
