"""Full source validation and fixed four-marker controls; no Lean execution."""
from dataclasses import replace
from functools import lru_cache
import unittest
from unittest.mock import patch
from tools import core_seven_certificate_sources as seven
from tools import core_seven_certificate_diagnostic_sources as diag
from tools import core_syntax_diagnostic_capture as collector

@lru_cache(maxsize=1)
def fixture():
    prepared = seven.original.build_inputs()
    proposal = seven.build_sources(prepared)
    return prepared, proposal, diag.build_diagnostic_sources(prepared, proposal)

class SevenDiagnosticSourceTests(unittest.TestCase):
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
        if source is not None: stages = stages[:3] + (replace(stages[3],source=source),)
        return diag.DiagnosticSources(stages, diag.encode(self.diagnostic.manifest if manifest is None else manifest))

    def reject(self, candidate):
        with self.assertRaises((ValueError, TypeError, KeyError)): self.validate(candidate)

    def test_actual_frozen_source_inventory_and_retention(self):
        self.validate(self.diagnostic)
        m = self.diagnostic.manifest
        self.assertEqual(tuple(len(s.expected_theorems) for s in self.diagnostic.stages),(56,547,271,54))
        self.assertEqual(m['retained_total_source_bytes'],5615437)
        self.assertEqual(m['diagnostic_target_source_bytes'],22083)
        self.assertEqual(len(m['retained_paths']),23)
        self.assertEqual([r['original_offset'] for r in m['markers']],[65,10206,11746,19464])
        self.assertEqual([r['instrumented_offset'] for r in m['markers']],[65,10241,11816,19569])
        self.assertEqual([len(r['text'].encode()) for r in m['markers']],[35]*4)
        self.assertEqual(diag.strip_markers(self.diagnostic.stages[3].source,m),self.proposal.stages[3].source.encode())
        self.assertEqual(m['not_scheduled_stage_names'],list(seven.NAMES[4:]))
        self.assertLessEqual(len(self.diagnostic.manifest_json.encode()),32768)
        self.assertTrue(all(x['status']=='unproved' for x in m['obligations']))
        self.assertEqual(len(m['obligations']),12)
        self.assertFalse(m['acceptance_eligible'])

    def test_rehashed_marker_fields_and_neighbors(self):
        for field,value in [('id','HIA_DIAG_v1_P02_000'),('text','#eval 1\n'),('sha256','0'*64),
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
        for key,value in [('marker_count',True),('maximum_processes',5),('target','CertPart02'),
                          ('protocol','compositional-byte-facts-prefix-diagnostic-v1'),('retained_total_source_bytes',0),
                          ('acceptance_eligible',True),('extra',1)]:
            m=self.diagnostic.manifest;m[key]=value;self.reject(self.changed(manifest=m))
        for source in (self.diagnostic.stages[3].source+'#check "unknown"\n',
                       self.diagnostic.stages[3].source.replace('\n','\r\n'),
                       self.diagnostic.stages[3].source.replace('linear_k3_0','linear_k3_bad',1)):
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
        from tools import core_byte_facts_diagnostic_sources as old
        with self.assertRaises(ValueError):old.strip_markers(self.diagnostic.stages[3].source,self.diagnostic.manifest)
        m=self.diagnostic.manifest;m['protocol']=old.PROTOCOL
        with self.assertRaises(ValueError):diag.strip_markers(self.diagnostic.stages[3].source,m)

class SevenMarkerObserverTests(unittest.TestCase):
    def markers(self,prefix='HIA_SEVEN_DIAG_v1_P02_',count=4):
        return [dict(id=prefix+'%03d'%i,original_offset=i,instrumented_offset=i) for i in range(count)]

    def test_cross_mode_plans_and_raw_records(self):
        modes=(('LinearTransport','HIA_DIAG_v1_LIN_'),('CertPart02','HIA_DIAG_v1_P02_'),('SevenCertificatePart02','HIA_SEVEN_DIAG_v1_P02_'))
        for target,prefix in modes:
            for other,foreign in modes:
                if target==other:continue
                with self.assertRaises(ValueError):collector.MarkerObserver(self.markers(foreign),target=target)
                obs=collector.MarkerObserver(self.markers(prefix),target=target)
                raw=('"'+foreign+'000" : String\n').encode()
                if target=='SevenCertificatePart02':
                    with self.assertRaises(ValueError):obs('stdout',raw,0,0)
                else:self.assertEqual(obs('stdout',raw,0,0),[])
                self.assertEqual(obs('stderr',raw,0,0),[])

    def test_split_exact_records_and_reordered_duplicates(self):
        markers=self.markers();raw=b''.join(('"'+m['id']+'" : String\n').encode() for m in markers)
        for cut in range(len(raw)+1):
            obs=collector.MarkerObserver(markers,target='SevenCertificatePart02')
            events=obs('stdout',raw[:cut],0,0)+obs('stdout',raw[cut:],cut,1)
            self.assertEqual([e['id'] for e in events],[m['id'] for m in markers])
        for index in (1,3):
            obs=collector.MarkerObserver(markers,target='SevenCertificatePart02')
            with self.assertRaises(ValueError):obs('stdout',('"'+markers[index]['id']+'" : String\n').encode(),0,0)
        obs=collector.MarkerObserver(markers,target='SevenCertificatePart02')
        self.assertEqual(obs('stdout',b'warning ordinary diagnostic text\n"HIA_SEVEN_DIAG_v1_P02_000" : String',0,0),[])


class SevenCaptureTests(unittest.TestCase):
    def capture(self, script, markers=(), setup=None, overrides=()):
        from tests.test_core_syntax_diagnostic_capture import DiagnosticCaptureTests
        raw=b'{"diagnostic_only":true}\n'
        reference=dict(path='SevenCertificatePart02.started.json',sha256=diag.digest(raw))
        original=collector.capture_result
        def invoke(*args,**kwargs):
            kwargs['safe_root'].write(reference['path'],raw)
            return original(*args,**kwargs,started_reference=reference)
        with patch.object(collector,'capture_result',side_effect=invoke):
            return DiagnosticCaptureTests().run_child(script,markers=markers,target='SevenCertificatePart02',
                                                       setup=setup,overrides=overrides)

    def test_actual_setup_start_and_54_print_serialization(self):
        import json
        _,_,diagnostic=fixture()
        markers=diagnostic.manifest['markers']
        result,files,_=self.capture('import time;time.sleep(10)',markers,
                                  overrides=(('PROCESS_SECONDS',.1),))
        rows=[json.loads(line) for line in files['SevenCertificatePart02.events.jsonl'].splitlines()]
        start=rows[0]
        self.assertEqual(start['kind'],'start')
        self.assertFalse(start['process']['process_started'])
        self.assertEqual(start['process']['started_reference'],rows[-1]['process']['started_reference'])
        # Serialize the actual production start with timeout restored, and
        # representative bounded workflow paths, no artificial fixed allowance.
        process=start['process'];process['timeout_seconds']=60
        root='/tmp/hepta-seven-first-four-diagnostic';exe='/opt/lean/bin/lean'
        process.update(argv=[exe,'--root='+root,'-o',root+'/HiaSyntaxResearch/CertPart02.olean',
                             root+'/HiaSyntaxResearch/CertPart02.lean'],cwd=root,search_path=root,sysroot='/opt/lean',
                       manifest_reference=dict(path='diagnostic-manifest.json',sha256='a'*64))
        used=len(collector._record_bytes(start));initial=used
        observer=collector.MarkerObserver(markers,target='SevenCertificatePart02')
        offset=0
        lines=[('"'+m['id']+'" : String\n').encode() for m in markers]
        lines += [("'"+name+"' does not depend on any axioms\n").encode() for name in sorted(diagnostic.stages[3].expected_theorems)]
        for raw in lines:
            receive=dict(kind='receive',stream='stdout',offset=offset,bytes=len(raw),received_seconds=60.999999)
            used+=len(collector._record_bytes(receive))
            for event in observer('stdout',raw,offset,60.999999):
                used+=len(collector._record_bytes(dict(kind='marker',event=event,received_seconds=60.999999)))
            offset+=len(raw)
        self.assertLessEqual(used,8192)
        self.assertLessEqual(len(files['SevenCertificatePart02.events.jsonl']),12288)
        self.assertEqual(collector.INTERNAL_METADATA_LIMIT-collector.TERMINAL_RESERVE,8192)
        print('seven capture serialization: actual start=%d, full54+four trace=%d, live cap=8192'%(initial,used))

    def test_fragmentation_metadata_overflow_is_closed(self):
        result,files,_=self.capture('import os,time\nfor i in range(200):\n os.write(1,b"inert theorem line\\n");time.sleep(.002)')
        self.assertEqual(result['status'],'diagnostic_output_limit')
        self.assertTrue(result['output_truncated'])
        self.assertIn('metadata budget',result['error'])
        self.assertGreater(sum(result['observed_bytes'].values()),result['raw_written_bytes'])
        self.assertTrue(result['terminal_record_persisted'])

    def test_foreign_marker_fails_before_persisting_read(self):
        result,files,_=self.capture('import os,time;os.write(1,b\'"HIA_DIAG_v1_P02_000" : String\\n\');time.sleep(10)')
        self.assertEqual(result['status'],'diagnostic_infrastructure_failed')
        self.assertEqual(files['SevenCertificatePart02.stdout'],b'')
        self.assertEqual(result['marker_count'],0)

    def test_spawn_failure_has_setup_start_but_zero_actual_launch(self):
        import json
        def setup(root,stack):
            stack.enter_context(patch.object(collector.subprocess,'Popen',side_effect=OSError('fake spawn refusal')))
        result,files,launches=self.capture('raise Exception("never")',setup=setup)
        rows=[json.loads(x) for x in files['SevenCertificatePart02.events.jsonl'].splitlines()]
        self.assertEqual([r['kind'] for r in rows],['start','terminal'])
        self.assertTrue(all(r['process']['process_started'] is False for r in rows))
        self.assertEqual(launches,[])
        self.assertFalse(result['process_started'])

if __name__=='__main__':unittest.main()
