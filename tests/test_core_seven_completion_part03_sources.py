"""Closed Part03 source/inverse controls. No Lean or real compiler invocation."""
from dataclasses import replace
from functools import lru_cache
import unittest
from unittest.mock import patch
from tools import core_seven_certificate_sources as seven
from tools import core_seven_parallel_relocation_sources as relocation
from tools import core_seven_completion_part03_sources as d

@lru_cache(maxsize=1)
def fixture():
    prepared = seven.original.build_inputs()
    from tools import core_seven_completion_part03_plan as plan
    previous = plan._previous_scaffolding(prepared)
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
        return d.CompletionPart03DiagnosticSources(stages, d.encode(self.diag.manifest if manifest is None else manifest))

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
        self.assertEqual(self.diag.stages[4].source_bytes,612821)
        self.assertEqual(self.diag.stages[4].source_sha256,d.TARGET_SOURCE_SHA256)
        self.assertEqual(len(self.diag.manifest_json.encode()),7444)

    def test_exact_retained_paths(self):
        sources=d.retained_sources(self.prepared,self.proposal,self.diag.stages)
        self.assertEqual(len(sources),23)
        self.assertEqual(sum(len(s.encode()) for s in sources.values()),6206175)
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
                        source.replace('#check','--check',1), source.replace(d.SENTINEL_TEXT,'',1),
                        source.replace(d.SENTINEL_TEXT,d.SENTINEL_TEXT*2,1), source.replace('True.intro','False.elim'),source+'#check "foreign"\n'):
            self.reject(self.candidate(source=changed))

    def test_exact_five_stage_type_and_schedule(self):
        self.assertEqual(self.diag.stages[:4],self.proposal.stages[:4])
        for stages in (list(self.diag.stages),self.diag.stages[:-1],self.diag.stages+self.proposal.stages[5:6],self.diag.stages[::-1]):
            self.reject(replace(self.diag,stages=stages))
        class Subtype(d.CompletionPart03DiagnosticSources):pass
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
            self.assertEqual(gate.call_args.kwargs['retained_copies'],(self.diag.stages[4].source,))

    def test_old_protocols_rejected_both_directions(self):
        from tools import core_seven_relocation_diagnostic_sources as old
        from tools import core_seven_part04_diagnostic_sources as part04
        for module in (old,part04):
            with self.assertRaises(ValueError):module.strip_markers(self.diag.stages[4].source,self.diag.manifest)
            m=self.diag.manifest;m['protocol']=module.PROTOCOL
            self.reject(self.candidate(manifest=m))
        self.reject(self.proposal)

    def test_static_headroom_and_identity_closed(self):
        from tools import core_seven_completion_part03_plan as plan
        identity=dict(**plan.common('f'*64),commit_sha='f'*40,tree_sha='f'*40,
            lean_binary_sha256='f'*64,sources={n:'f'*64 for n in plan.source_paths()},
            support={n:'f'*64 for n in plan.support_paths()})
        value=plan._derive_plan(identity['run_id'],identity,'/tmp/lean/bin/lean','/tmp/diagnostic',
            self.prepared,self.proposal,self.diag)
        ledger=plan.static_sizing(identity,value,self.prepared,self.proposal,self.diag)
        self.assertEqual(len(plan.source_paths()),255)
        self.assertEqual(set(plan.source_paths())-set(plan.previous_protocol.source_paths()),set(plan.ADDITIONS))
        self.assertFalse(any('linear_part03' in n or 'linear_rebalance' in n for n in plan.source_paths()))
        self.assertEqual(ledger['metadata_delta_bound'],3268)
        self.assertEqual(ledger['metadata_bound'],214641)
        self.assertEqual(ledger['source_delta'],60)
        self.assertEqual(ledger['nominal_output_delta'],80)
        self.assertEqual(ledger['event_stream_bound'],8090)
        with patch.object(plan,'METADATA_RESERVE',214640), self.assertRaisesRegex(ValueError,'headroom'):
            plan.static_sizing(identity,value,self.prepared,self.proposal,self.diag)

    def test_inverse_restores_actual_old_marked_bytes(self):
        from tools import core_seven_relocated_part03_sources as old
        raw = d.strip_completion(self.diag.stages[4].source, self.diag.manifest)
        self.assertEqual(len(raw), old.TARGET_SOURCE_BYTES)
        self.assertEqual(d.digest(raw), old.TARGET_SOURCE_SHA256)
        self.assertEqual(raw, old._derive(self.prepared,self.previous,self.proposal).stages[4].source.encode())

    def test_sentinel_record_closed(self):
        for key,value in [('subject','False.elim'),('bytes',True),('instrumented_offset',0),
                          ('text','#print axioms False.elim\n'),('sha256','0'*64),('extra',0)]:
            m=self.diag.manifest;m['sentinel'][key]=value;self.reject(self.candidate(manifest=m))

    def test_exact_stage_container_types(self):
        for key,value in [('expected_theorems',set(self.diag.stages[4].expected_theorems)),
                          ('parents',list(self.diag.stages[4].parents))]:
            bad=self.diag.stages[:4]+(replace(self.diag.stages[4],**{key:value}),)
            self.reject(replace(self.diag,stages=bad))

    def test_old_original_protocol_rejected(self):
        from tools import core_seven_relocated_part03_sources as old
        old_diag=old._derive(self.prepared,self.previous,self.proposal)
        self.reject(old_diag)
        with self.assertRaises(ValueError):old.strip_markers(self.diag.stages[4].source,self.diag.manifest)
        with self.assertRaises(ValueError):d.strip_markers(old_diag.stages[4].source,old_diag.manifest)

    def test_endpoints_and_inventory_markers_fixed(self):
        markers=self.diag.manifest['markers']
        self.assertEqual(tuple(m['original_offset'] for m in markers),d.OFFSETS)
        self.assertEqual(tuple(m['instrumented_offset'] for m in markers),d.MARKER_OFFSETS)
        self.assertEqual(tuple(m['id'] for m in markers),d.MARKER_IDS)
        self.assertEqual(markers[0]['next_command']['name'],'linearRaw')
        self.assertEqual(markers[9]['previous_command']['name'],'True.intro')
        self.assertEqual(markers[10]['previous_command']['name'],'HiaCoreSyntaxSlice.parallel_bf0226')
        self.assertIsNone(markers[-1]['next_command'])
        self.assertTrue(all(len(m['text'].encode())==35 for m in markers))
        source=self.diag.stages[4].source.encode()
        self.assertEqual(source[d.SENTINEL_OFFSET:d.MARKER_OFFSETS[9]],d.SENTINEL_TEXT.encode())
        self.assertEqual(source.count(d.SENTINEL_TEXT.encode()),1)

if __name__=='__main__':unittest.main()
