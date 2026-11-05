"""Fresh six-process fake-child execution and hostile frozen evidence tests."""
from contextlib import ExitStack
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from tests.test_core_seven_relocation_sources import fixture
from tests.test_core_syntax_diagnostic_capture import PLATFORM
from tools import diagnose_core_seven_relocation as runner
from tools import core_seven_certificate_sources as seven
from tools import core_seven_relocation_diagnostic_sources as diag
from tools import core_seven_part04_capture as collector
from tools import check_core_syntax_staged as base

class Part04RunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.prepared,cls.previous,cls.proposal,cls.diagnostic=fixture()

    def exercise(self,behavior='success',inspect=None,full=False):
        with tempfile.TemporaryDirectory() as folder,ExitStack() as stack:
            stack.enter_context(patch.object(runner,'_git_baseline',return_value=dict(head='a'*40,tree='b'*40)))
            home=Path(folder);exe=home/'pinned/bin/lean';exe.parent.mkdir(parents=True)
            exe.write_bytes(b'fake executable never launched');(home/'pinned/lib/lean').mkdir(parents=True)
            identity=runner.source_identity()
            support={}
            for name in ('lib/lean/Init.olean','lib/lean/Lean/Elab/Tactic/Omega.olean'):
                support_file=exe.parent.parent/name;support_file.parent.mkdir(parents=True,exist_ok=True)
                support_file.write_bytes(('fake support '+name).encode());support[name]=base.digest(support_file.read_bytes())
            calls=[]
            if behavior=='late_prelaunch':
                original_check=runner._ExternalSnapshot.check
                original_clock=time.monotonic
                late=[False]
                def checked(obj):
                    original_check(obj)
                    if (home/'out'/runner.TARGET_STARTED).exists():late[0]=True
                stack.enter_context(patch.object(runner._ExternalSnapshot,'check',checked))
                stack.enter_context(patch.object(runner.time,'monotonic',side_effect=lambda:original_clock()+(541 if late[0] else 0)))
            def invoke(executable,source,output,root):
                stage=next(s for s in self.diagnostic.stages if s.name==source.stem);calls.append(stage.name)
                out=''.join("'"+n+"' does not depend on any axioms\n" for n in seven._qualified_prints(stage.source))
                if stage.name=='CertPart01':
                    if behavior=='missing':out=out.split('\n',1)[1]
                    if behavior=='extra':out+="'extra' does not depend on any axioms\n"
                    if behavior=='sorry':out=out.replace('does not depend on any axioms','depends on axioms: [sorryAx]',1)
                    if behavior.startswith('mutate:'):(root/behavior[7:]).write_bytes(b'changed')
                    replacement={'replace_binary':exe,'replace_support':exe.parent.parent/'lib/lean/Init.olean',
                                 'replace_parent':root/'Baseline.stdout'}.get(behavior)
                    if replacement:
                        temp=replacement.with_suffix('.replacement');temp.write_bytes(replacement.read_bytes());os.replace(temp,replacement)
                if stage.name=='CertPart03' and behavior in ('parent_list','parent_string','parent_bool'):
                    return {'parent_list': [], 'parent_string': 'malformed', 'parent_bool': False}[behavior]
                if behavior=='parent_spawn' and stage.name=='CertPart01':
                    return dict(**runner._command(executable,root,stage),returncode=None,timed_out=False,incomplete=True,
                                output_truncated=False,elapsed_seconds=.1,error_type='OSError',stdout='',stderr='')
                if behavior!='no_output' or stage.name!='CertPart01':output.write_bytes(('fake '+stage.name).encode())
                result=dict(**runner._command(executable,root,stage),returncode=1 if behavior=='parent_exit' and stage.name=='CertPart01' else 0,
                            timed_out=behavior=='parent_timeout' and stage.name=='CertPart01',incomplete=False,
                            output_truncated=False,elapsed_seconds=.1,stdout=out,stderr='')
                if stage.name=='CertPart03' and behavior=='part03_timeout':
                    result.update(returncode=None,timed_out=True,incomplete=True,error_type='TimeoutExpired',elapsed_seconds=60.12345678,stdout='partial parent output',stderr='partial error')
                if stage.name=='CertPart03' and behavior=='parent_raw_cap':
                    result.update(returncode=1,stdout='x'*base.MAX_DIAGNOSTIC,stderr='')
                if stage.name=='CertPart03' and behavior=='parent_uncertain':raise OSError('uncertain launch')
                if behavior=='parent_malformed' and stage.name=='CertPart01':result['returncode']=True
                if result['timed_out'] and behavior!='part03_timeout':result.update(returncode=None,incomplete=True,error_type='TimeoutExpired',elapsed_seconds=60.1)
                return result
            def capture(executable,source,output,root,**kwargs):
                if behavior=='uncertain':raise RuntimeError('uncertain launch')
                calls.append('CertPart04')
                lines=[('"'+m['id']+'" : String\n') for m in self.diagnostic.manifest['markers']]
                names=seven._qualified_prints(self.diagnostic.stages[5].source)
                if behavior=='target_missing':names=names[1:]
                out=''.join(lines)+''.join("'"+n+"' does not depend on any axioms\n" for n in names)
                if behavior=='target_extra':out+="'extra' does not depend on any axioms\n"
                if behavior=='target_sorry':out=out.replace('does not depend on any axioms','depends on axioms: [sorryAx]',1)
                script='import os,pathlib,time\npathlib.Path(%r).write_bytes(b"untrusted fake target")\nos.write(1,%r)\ntime.sleep(.03)\n'%(str(output),out.encode())
                if behavior=='fifth':script+='pathlib.Path(%r).write_bytes(b"forbidden fifth module")\n'%str(root/'HiaSyntaxResearch/CertPart05.olean')
                if behavior=='target_timeout':script+='time.sleep(10)\n'
                if behavior=='target_limit':script='import os,time\nfor i in range(200):\n os.write(1,b"inert theorem line\\n");time.sleep(.002)\n'
                if behavior=='target_exit':script+='raise SystemExit(1)\n'
                real=subprocess.Popen
                def popen(argv,**options):
                    if behavior=='spawn':raise OSError('fake spawn refused')
                    return real([sys.executable,'-c',script],**options)
                with ExitStack() as capture_stack:
                    capture_stack.enter_context(patch.object(collector.subprocess,'Popen',side_effect=popen))
                    capture_stack.enter_context(patch.object(collector,'platform_observation',return_value=PLATFORM))
                    if behavior=='target_timeout':
                        origin=time.monotonic()
                        capture_stack.enter_context(patch.object(collector,'time',SimpleNamespace(monotonic=lambda:origin+(time.monotonic()-origin)*100)))
                    captured=collector.capture_result(executable,source,output,root,**kwargs)
                if behavior=='malformed_terminal':
                    event_path=root/runner.CAPTURE_FILES[2]
                    event_path.write_bytes(b''.join(event_path.read_bytes().splitlines(keepends=True)[:-1])+b'{"kind":"terminal"}\n')
                if behavior=='collector_files_forged':captured['files'][runner.CAPTURE_FILES[0]]['sha256']='0'*64
                return captured
            # Source fixture already passed unchanged full original/inverse gates.
            if not full:
                for obj,name in ((base,'validate_plan'),(seven,'validate_sources'),(diag,'validate_diagnostic_sources')):
                    stack.enter_context(patch.object(obj,name))
            report=runner.execute_diagnostic(exe,home/'out',self.prepared,self.previous,self.proposal,self.diagnostic,
                 identity,support,lambda:identity,lambda _:support,base.digest(exe.read_bytes()),run_process=invoke,capture=capture)
            self.assertLessEqual(len(calls),6);self.assertLessEqual(report['invocations'],6)
            self.assertFalse((home/'out/CertPart04.finished.json').exists())
            self.assertEqual(report['authority'],'DENY_ALL')
            stack.close()
            with patch.object(runner,'_git_baseline',return_value=dict(head='a'*40,tree='b'*40)):
                if inspect:inspect(home/'out',report,identity,support)
            return report,calls

    def test_each_whole_source_gate_precedes_output_and_launch(self):
        for gate in ('markers',):
            with tempfile.TemporaryDirectory() as folder,ExitStack() as stack:
                out=Path(folder)/'must-not-exist'
                for label,obj,name in (('original',base,'validate_plan'),('seven',seven,'validate_sources'),
                                       ('markers',diag,'validate_diagnostic_sources')):
                    stack.enter_context(patch.object(obj,name,side_effect=ValueError('blocked '+gate) if label==gate else None))
                with self.assertRaisesRegex(ValueError,'blocked '+gate):
                    runner.execute_diagnostic(Path(folder)/'nonexistent',out,self.prepared,self.previous,self.proposal,self.diagnostic,
                                              {},{},lambda:{},lambda _: {},'0'*64,
                                              run_process=lambda *a: self.fail('launched before source gate'))
                self.assertFalse(out.exists())

    def test_expensive_prelaunch_checks_cannot_cross_launch_deadline(self):
        report,calls=self.exercise('late_prelaunch')
        self.assertEqual(calls,list(runner.DIAGNOSTIC_NAMES[:5]))
        self.assertEqual(report['invocations'],5)
        self.assertEqual(report['status'],'diagnostic_failed')
        self.assertFalse(report['evidence_complete'])

    def test_success_exactly_six_never_admits_target(self):
        report,calls=self.exercise()
        self.assertEqual(calls,list(runner.DIAGNOSTIC_NAMES))
        self.assertEqual(report['status'],'diagnostic_completed',report)
        self.assertTrue(report['evidence_complete'],report)
        self.assertNotIn('olean',report['stages'][-1])
        self.assertEqual(len(report['not_scheduled']),5)

    def test_parent_failures_have_failed_receipt_no_target(self):
        for behavior in ('parent_exit','parent_timeout','missing','extra','sorry','no_output'):
            with self.subTest(behavior=behavior):
                report,calls=self.exercise(behavior)
                self.assertEqual(calls,list(runner.DIAGNOSTIC_NAMES[:3]))
                self.assertEqual(report['status'],'diagnostic_failed')
                self.assertEqual(report['stages'][-1]['status'],'failed')

    def test_target_bad_inventory_never_success(self):
        for behavior in ('target_missing','target_extra','target_sorry'):
            with self.subTest(behavior=behavior):
                report,calls=self.exercise(behavior)
                self.assertEqual(report['status'],'diagnostic_failed',report)
                self.assertEqual(len(calls),6)

    def test_preserves_frozen_mutation_and_incomplete_closure(self):
        for name in ('RUN.json','IDENTITY.json','Baseline.finished.json','HiaSyntaxResearch/Baseline.olean',
                     'HiaSyntaxResearch/SyntaxData.lean'):
            with self.subTest(name=name):
                report,calls=self.exercise('mutate:'+name)
                self.assertEqual(len(calls),3)
                self.assertFalse(report['evidence_complete'])
                self.assertEqual(report['status'],'diagnostic_failed')

    def test_spawn_refusal_and_uncertain_count(self):
        report,_=self.exercise('spawn')
        self.assertEqual(report['invocations'],5)
        self.assertTrue(report['invocation_count_exact'])
        report,_=self.exercise('uncertain')
        self.assertEqual(report['invocations'],6)
        self.assertFalse(report['invocation_count_exact'])

    def replay(self,path,identity,support,full=False,after_sources=None):
        def known_sources(snapshot,frozen,identities):
            # Source semantics have their own full-validation controls. Here
            # pin all source/manifests to the fully validated immutable fixture
            # so adversarial receipt tests do not repeat source generation.
            for name,text in diag.retained_sources(self.prepared,self.proposal,self.diagnostic.stages).items():
                self.assertEqual(snapshot.read(name),text.encode())
            for name,text in (('original-manifest.json',self.prepared['manifest_json']),
                              ('oldseven-manifest.json',self.previous.manifest_json),
                              ('relocation-manifest.json',self.proposal.manifest_json),
                              ('diagnostic-manifest.json',self.diagnostic.manifest_json)):
                self.assertEqual(snapshot.read(name),text.encode())
            if after_sources:after_sources()
            return self.prepared,self.proposal,self.diagnostic
        from contextlib import nullcontext
        with (nullcontext() if full else patch.object(runner,'_reconstruct',side_effect=known_sources)):
            return runner.verify_evidence(path,source_reader=lambda:identity,support_reader=lambda _:support)

    def test_success_replays_and_measures_full_capture_and_display(self):
        def inspect(path,report,identity,support):
            verified=self.replay(path,identity,support)
            self.assertEqual(verified['validated_parent_count'],5)
            self.assertTrue(verified['validated_markers'])
            events=(path/runner.CAPTURE_FILES[2]).read_bytes()
            result=(path/'RESULT.json').read_bytes()
            live=len(events)+len(result)
            display=sum(len(n.encode())+2+len(raw) for n,raw in verified['display'])
            durable=sum(p.stat().st_size for p in path.rglob('*') if p.is_file() and p.suffix not in ('.lean','.olean'))
            self.assertLessEqual(live,collector.METADATA_LIMIT)
            self.assertLessEqual(display+durable,base.MAX_DIAGNOSTIC)
            print('seven full fake run: events=%d result=%d live=%d durable=%d display=%d combined=%d'%
                  (len(events),len(result),live,durable,display,durable+display))
        self.exercise(inspect=inspect)

    def test_complete_failure_replay_and_spawn_semantics(self):
        for behavior in ('parent_exit','parent_timeout','missing','no_output','spawn','target_missing','target_sorry','target_timeout','target_limit'):
            def inspect(path,report,identity,support):
                verified=self.replay(path,identity,support)
                self.assertEqual(verified['validated_markers'],behavior=='target_timeout')
                self.assertLessEqual(verified['validated_parent_count'],5)
            with self.subTest(behavior=behavior):self.exercise(behavior,inspect)

    def test_rehashed_result_receipt_and_start_tampering(self):
        def inspect(path,report,identity,support):
            originals={p.relative_to(path).as_posix():p.read_bytes() for p in path.rglob('*') if p.is_file()}
            def restore():
                for name,raw in originals.items():(path/name).write_bytes(raw)
            def rehash(name,value):
                (path/name).write_bytes(runner._encoded(value))
                if name=='RESULT.json':return
                evidence=json.loads((path/'EVIDENCE.json').read_bytes())
                evidence['sha256'][name]=base.digest((path/name).read_bytes())
                (path/'EVIDENCE.json').write_bytes(runner._encoded(evidence))
                result=json.loads((path/'RESULT.json').read_bytes())
                result['evidence_sha256']=base.digest((path/'EVIDENCE.json').read_bytes())
                (path/'RESULT.json').write_bytes(runner._encoded(result))
            attacks=[('RESULT.json','invocations',5),('RESULT.json','invocations',True),
                     ('RESULT.json','acceptance_eligible',True),
                     ('RESULT.json','closure_failed',True),('RESULT.json','closure_failed',None),
                     ('RESULT.json','closure_failed',0),('RESULT.json','target_outcome_uncertain',True),
                     ('RESULT.json','target_outcome_uncertain',None),('RESULT.json','target_outcome_uncertain',0),('RESULT.json','run_sha256','0'*64),
                     ('RESULT.json','identity_sha256','0'*64),('RESULT.json','relocation_manifest_sha256','0'*64),('RESULT.json','extra',1),
                     (runner.TARGET_STARTED,'parents',{}),(runner.TARGET_STARTED,'source_sha256','0'*64),
                     ('CertPart01.finished.json','parents',{}),('Baseline.finished.json','status','failed'),
                     (runner.TARGET_INVENTORY,'diagnostic_only',False)]
            for name,key,value in attacks:
                with self.subTest(name=name,key=key):
                    restore();obj=json.loads((path/name).read_bytes());obj[key]=value;rehash(name,obj)
                    with self.assertRaises((ValueError,KeyError,AssertionError)):self.replay(path,identity,support)
            # Rewrite every outer hash/accounting after hostile capture edits:
            # a changed digest alone is not the reason these cases must fail.
            for mutation in ('bool_time','offset_hole','unknown_event','foreign_start','bool_pid','cleanup_error','leader_error','bool_signal','partial_namespace','decreasing_time','trace_protocol','receive_record'):
                with self.subTest(capture=mutation):
                    restore()
                    result=json.loads((path/'RESULT.json').read_bytes())
                    process=result['stages'][5]['process']
                    rows=[json.loads(x) for x in (path/runner.CAPTURE_FILES[2]).read_bytes().splitlines()]
                    receive=next(row for row in rows if row['kind']=='marker')
                    if mutation=='bool_time':receive['received_seconds']=True
                    if mutation=='offset_hole':receive['event']['byte_offset']=1
                    if mutation=='unknown_event':rows.insert(1,dict(kind='unrecognized'))
                    if mutation=='decreasing_time':
                        markers=[r for r in rows if r['kind']=='marker'];markers[0]['received_seconds']=markers[0]['event']['received_seconds']=0.02;markers[1]['received_seconds']=markers[1]['event']['received_seconds']=0.01
                    if mutation=='trace_protocol':
                        process['trace']='other';rows[-1]['process']['trace']='other';rows[0]['process']['trace']='other'
                    if mutation=='receive_record':rows.insert(1,dict(kind='receive',stream='stdout',offset=0,bytes=1,received_seconds=0))
                    if mutation=='foreign_start':rows[0]['process']['started_reference']['sha256']='0'*64
                    if mutation=='bool_pid':
                        process['pid']=True;rows[-1]['process']['pid']=True
                    if mutation in ('cleanup_error','leader_error'):
                        key='group_cleanup_error' if mutation=='cleanup_error' else 'leader_cleanup_error'
                        process[key]='forged cleanup failure';rows[-1]['process'][key]=process[key]
                    if mutation=='bool_signal':
                        process['returncode']=-1;process['signal']=True
                        rows[-1]['process']['returncode']=-1;rows[-1]['process']['signal']=True
                    if mutation=='partial_namespace':
                        raw_name=runner.CAPTURE_FILES[0]
                        raw=(path/raw_name).read_bytes()+b'"HIA_'
                        (path/raw_name).write_bytes(raw)
                        item=dict(path=raw_name,bytes=len(raw),sha256=base.digest(raw))
                        process['raw_files'][raw_name]=item
                        process['observed_bytes']['stdout']=len(raw)
                        process['raw_written_bytes']+=5
                        rows[-1]['process']['raw_files'][raw_name]=item
                        rows[-1]['process']['observed_bytes']['stdout']=len(raw)
                        rows[-1]['accounting_before_terminal']['raw_written_bytes']+=5
                    prefix=b''.join(runner._encoded(row) for row in rows[:-1])
                    rows[-1]['accounting_before_terminal']['metadata_written_bytes']=len(prefix)
                    event_bytes=prefix+runner._encoded(rows[-1]);(path/runner.CAPTURE_FILES[2]).write_bytes(event_bytes)
                    item=dict(path=runner.CAPTURE_FILES[2],sha256=base.digest(event_bytes),bytes=len(event_bytes))
                    process['compact_receipt_reference']=item
                    process['metadata_written_bytes']=len(event_bytes)
                    process['metadata_remaining_bytes']=collector.METADATA_LIMIT-len(event_bytes)
                    evidence=json.loads((path/'EVIDENCE.json').read_bytes())
                    evidence['sha256'][runner.CAPTURE_FILES[2]]=base.digest(event_bytes)
                    if mutation=='partial_namespace':evidence['sha256'][runner.CAPTURE_FILES[0]]=base.digest((path/runner.CAPTURE_FILES[0]).read_bytes())
                    (path/'EVIDENCE.json').write_bytes(runner._encoded(evidence))
                    result['evidence_sha256']=base.digest((path/'EVIDENCE.json').read_bytes())
                    (path/'RESULT.json').write_bytes(runner._encoded(result))
                    with self.assertRaises((ValueError,KeyError,AssertionError)):self.replay(path,identity,support)
            restore()
            # Removal is not rescued by recomputing the outer containers.
            (path/runner.TARGET_STARTED).unlink()
            evidence=json.loads((path/'EVIDENCE.json').read_bytes());del evidence['sha256'][runner.TARGET_STARTED]
            (path/'EVIDENCE.json').write_bytes(runner._encoded(evidence))
            result=json.loads((path/'RESULT.json').read_bytes());result['evidence_sha256']=base.digest((path/'EVIDENCE.json').read_bytes())
            (path/'RESULT.json').write_bytes(runner._encoded(result))
            with self.assertRaises((ValueError,KeyError)):self.replay(path,identity,support)
        self.exercise(inspect=inspect)

    def test_same_byte_inode_replacement_stops_before_target(self):
        for behavior in ('replace_binary','replace_support','replace_parent'):
            with self.subTest(behavior=behavior):
                report,calls=self.exercise(behavior)
                self.assertEqual(len(calls),3)
                self.assertFalse(report['evidence_complete'])

    def test_seventh_output_is_not_frozen_as_valid_failure(self):
        report,calls=self.exercise('fifth')
        self.assertEqual(len(calls),6)
        self.assertFalse(report['evidence_complete'])

    def test_mid_replay_mutation_suppresses_all_presentation(self):
        def inspect(path,report,identity,support):
            def mutate():
                original=path/'Baseline.stdout';replacement=path/'replacement.tmp'
                replacement.write_bytes(original.read_bytes());os.replace(replacement,original)
            real_verify=runner.verify_evidence
            def verify(_):
                with patch.object(runner,'verify_evidence',real_verify):
                    return self.replay(path,identity,support,after_sources=mutate)
            stream=io.BytesIO()
            class Stdout:buffer=stream
            with patch.object(runner,'verify_evidence',side_effect=verify),patch('sys.stdout',Stdout()):
                with self.assertRaises(ValueError):runner.print_events(path)
            self.assertEqual(stream.getvalue(),b'')
        self.exercise(inspect=inspect)

    def test_rehashed_failed_parent_launch_accounting_is_rejected(self):
        for behavior,forged_started,forged_count in (('parent_exit',False,2),('parent_spawn',True,3)):
            def inspect(path,report,identity,support):
                self.replay(path,identity,support)
                name='CertPart01.finished.json';receipt=json.loads((path/name).read_bytes())
                receipt['process_started']=forged_started;(path/name).write_bytes(runner._encoded(receipt))
                digest=base.digest((path/name).read_bytes())
                evidence=json.loads((path/'EVIDENCE.json').read_bytes());evidence['sha256'][name]=digest
                (path/'EVIDENCE.json').write_bytes(runner._encoded(evidence))
                result=json.loads((path/'RESULT.json').read_bytes())
                result['invocations']=forged_count;result['stages'][2]['receipt_sha256']=digest
                result['evidence_sha256']=base.digest((path/'EVIDENCE.json').read_bytes())
                (path/'RESULT.json').write_bytes(runner._encoded(result))
                with self.assertRaisesRegex(ValueError,'parent launch flag differs'):
                    self.replay(path,identity,support)
            with self.subTest(behavior=behavior):self.exercise(behavior,inspect)

    def test_malformed_parent_outcome_is_explicitly_incomplete(self):
        report,calls=self.exercise('parent_malformed')
        self.assertEqual(len(calls),3)
        self.assertFalse(report['evidence_complete'])
        self.assertTrue(report['closure_failed'])

    def test_malformed_persisted_terminal_is_explicitly_incomplete(self):
        report,_=self.exercise('malformed_terminal')
        self.assertFalse(report['evidence_complete'])
        self.assertTrue(report['closure_failed'])


    def test_compact_target_files_independently_verified(self):
        report,calls=self.exercise('collector_files_forged')
        self.assertEqual(len(calls),6)
        self.assertFalse(report['evidence_complete'])
        def inspect(path,report,identity,support):
            result=json.loads((path/'RESULT.json').read_bytes())
            self.assertNotIn('files',result['stages'][-1]['process'])
            for field,value in [('files',{}),('raw_files',{}),('compact_receipt_reference',{})]:
                changed=json.loads(json.dumps(result));changed['stages'][-1]['process'][field]=value
                (path/'RESULT.json').write_bytes(runner._encoded(changed))
                with self.assertRaises(ValueError):self.replay(path,identity,support)
        self.exercise(inspect=inspect)

    def test_nonnull_malformed_parent_outcomes_never_become_null_evidence(self):
        def inspect(path,report,identity,support):
            with self.assertRaises(ValueError):self.replay(path,identity,support)
        for behavior in ('parent_list','parent_string','parent_bool'):
            with self.subTest(behavior=behavior):
                report,calls=self.exercise(behavior,inspect)
                self.assertEqual(len(calls),5)
                self.assertFalse(report['evidence_complete'])
                self.assertTrue(report['closure_failed'])
                self.assertFalse(report['invocation_count_exact'])

    def test_part03_failure_raw_elapsed_and_projection_tampering(self):
        def inspect(path, report, identity, support):
            self.replay(path, identity, support)
            row=report['stages'][-1]
            self.assertEqual(row['process'],dict(process_started=True,elapsed_seconds=60.123457,
                returncode=None,timed_out=True,incomplete=True,output_truncated=False,
                retained_bytes=len(b'partial parent outputpartial error')))
            result=json.loads((path/'RESULT.json').read_bytes())
            for field,value in [('elapsed_seconds',60.123456),('retained_bytes',0),('returncode',True),('process_started',None)]:
                changed=json.loads(json.dumps(result));changed['stages'][-1]['process'][field]=value
                (path/'RESULT.json').write_bytes(runner._encoded(changed))
                with self.assertRaises(ValueError):self.replay(path,identity,support)
            (path/'RESULT.json').write_bytes(runner._encoded(result))
            (path/'CertPart03.stderr').write_bytes(b'forged error')
            with self.assertRaises(ValueError):self.replay(path,identity,support)
        report,calls=self.exercise('part03_timeout',inspect)
        self.assertEqual(calls,list(runner.DIAGNOSTIC_NAMES[:5]))
        self.assertEqual(report['invocations'],5)
        self.assertTrue(report['evidence_complete'])

    def test_part03_unknown_and_aggregate_overflow_refuse_completion(self):
        report,calls=self.exercise('parent_uncertain')
        self.assertEqual(len(calls),5)
        self.assertFalse(report['invocation_count_exact'])
        self.assertIsNone(report['stages'][-1]['process']['process_started'])
        def inspect(path,report,identity,support):
            self.assertEqual((path/'CertPart03.stdout').stat().st_size,base.MAX_DIAGNOSTIC)
            with self.assertRaises(ValueError):self.replay(path,identity,support)
        report,calls=self.exercise('parent_raw_cap',inspect)
        self.assertEqual(len(calls),5)
        self.assertFalse(report['evidence_complete'])
        self.assertTrue(report['closure_failed'])

    def test_exact_relocated_inventory_and_old_protocol_rejected(self):
        self.assertEqual(len(seven._qualified_prints(self.diagnostic.stages[5].source)),807)
        self.assertEqual(len(seven._qualified_prints(self.previous.stages[5].source)),1298)
        def inspect(path,report,identity,support):
            result=json.loads((path/'RESULT.json').read_bytes())
            result['protocol']='seven-certificate-first-six-diagnostic-v1'
            (path/'RESULT.json').write_bytes(runner._encoded(result))
            with self.assertRaises(ValueError):self.replay(path,identity,support)
        self.exercise(inspect=inspect)

    def test_full_inverse_replay_integration(self):
        def inspect(path,report,identity,support):
            verified=self.replay(path,identity,support,full=True)
            self.assertEqual(verified['validated_parent_count'],5)
            self.assertTrue(verified['validated_markers'])
        self.exercise(inspect=inspect,full=True)

if __name__=='__main__':unittest.main()

class Part04ReplayGrammarTests(unittest.TestCase):
    def plan(self):
        return [dict(id='HIA_SEVEN_DIAG_v1_P04_%03d'%i,original_offset=i+65,instrumented_offset=i+65+35*i) for i in range(11)]

    def raw(self):
        return b''.join(('"'+m['id']+'" : String\n').encode() for m in self.plan())

    def test_independent_lf_parser_all_offsets_and_fragmentation(self):
        raw=self.raw()
        expected=runner._marker_lines(raw,b'',self.plan())
        self.assertEqual(len(expected),11)
        self.assertEqual([m['byte_offset'] for m in expected],[i*37 for i in range(11)])
        for cut in range(len(raw)+1):
            self.assertEqual(runner._marker_lines(raw[:cut]+raw[cut:],b'',self.plan()),expected)
        self.assertEqual(len(runner._marker_lines(raw[:37],b'',self.plan())),1)
        self.assertEqual(runner._marker_lines(b'ordinary\n',b'ordinary\n',self.plan()),[])

    def test_independent_lf_parser_rejects_foreign_partial_reordered_stderr(self):
        raw=self.raw();lines=raw.splitlines(keepends=True)
        for value in (raw+lines[-1],lines[1]+lines[0],raw[:-1],raw.replace(b'P04_',b'P02_',1),
                      raw.replace(b'HIA_SEVEN_DIAG_v1_P04_',b'HIA_DIAG_v1_LIN_',1),
                      b'prefix'+raw,raw.replace(b'\n',b'\r\n',1),raw+b'"HIA_SEVEN_DIAG_v1_P04_',raw+b'"HIA_',raw+b'"HIA_DIAG',raw+b'"HIA_SEVEN_DIAG'):
            with self.subTest(value=value[:70]),self.assertRaises(ValueError):
                runner._marker_lines(value,b'',self.plan())
        with self.assertRaises(ValueError):runner._marker_lines(raw,lines[0],self.plan())

    def test_inventory_rejects_duplicate_axioms_before_compaction(self):
        stage=SimpleNamespace(expected_theorems={'HiaCoreSyntaxSlice.t'},source='unused')
        with patch.object(seven,'_qualified_prints',return_value=('HiaCoreSyntaxSlice.t',)):
            for xs in ('propext,propext','Classical.choice,Quot.sound,propext,propext'):
                with self.assertRaises(ValueError):runner._inventory(("'HiaCoreSyntaxSlice.t' depends on axioms: ["+xs+"]\n").encode(),b'',stage)
            inv=runner._inventory(b"'HiaCoreSyntaxSlice.t' depends on axioms: [propext,Classical.choice,Quot.sound]\n",b'',stage)
            self.assertEqual(runner._compact_inventory(inv),dict(count=1,sha256=base.digest(runner._encoded(inv))))

    def test_caps_are_tighter_than_original_envelope(self):
        self.assertEqual(runner.RESULT_CAP+collector.EVENT_STREAM_LIMIT,16384)
        self.assertLessEqual(collector.START_LIMIT+11*collector.MARKER_LIMIT,8192)
        self.assertLessEqual(collector.TERMINAL_LIMIT,4096)
        self.assertEqual(runner._cap('IDENTITY.json'),114688)
        self.assertEqual(runner._cap('RESULT.json'),7968)
        self.assertEqual(runner._cap(runner.CAPTURE_FILES[2]),8416)

    def test_command_accepts_bound_paths_and_rejects_oversize(self):
        stage=SimpleNamespace(module_name='HiaSyntaxResearch.Baseline')
        got=runner._command(Path('/tmp/pinned/bin/lean'),Path('/tmp/out'),stage)
        self.assertEqual(got['timeout_seconds'],60)
        self.assertEqual(got['argv'][-1],'/tmp/out/HiaSyntaxResearch/Baseline.lean')
        with self.assertRaises(ValueError):runner._command(Path('/tmp/pinned/bin/lean'),Path('/'+'x'*128),stage)

    def test_combined_display_budget_is_independent_of_durable_cap(self):
        files={'RESULT.json':b'x'*7968,runner.CAPTURE_FILES[2]:b'x'*8416,'RUN.json':b'x'*(1048576-7968-8416)}
        runner._evidence_budget(files)
        with self.assertRaises(ValueError):runner._evidence_budget(files,[runner.CAPTURE_FILES[2],'RESULT.json'])

class RelocationNumericBoundsTests(unittest.TestCase):
    def test_parent_signed64_and_available_counter_bounds(self):
        command=runner._command(Path('/tmp/pinned/bin/lean'),Path('/tmp/out'),SimpleNamespace(module_name='HiaSyntaxResearch.Baseline'))
        process=dict(command,returncode=0,timed_out=False,incomplete=False,output_truncated=False,elapsed_seconds=.123456789)
        for value in (-2**63,2**63-1):
            runner._process(dict(process,returncode=value),command)
        for key,values in [('returncode',[True,2**63,-2**63-1]),('elapsed_seconds',[True,float('nan'),float('inf'),-1,601]),('stdout_available_bytes',[True,-1,2**63]),('stderr_available_bytes',[True,-1,2**63]),('error_type',['','a'*33,'bad error','é'])]:
            for value in values:
                with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                    runner._process(dict(process,**{key:value}),command)
        runner._process(dict(process,stdout_available_bytes=2**63-1,stderr_available_bytes=0,error_type='X'*32),command)

    def test_projection_distinguishes_null_and_known_nonlaunch(self):
        snapshot=SimpleNamespace(read=lambda _: b'abc')
        for started in (False,None):
            got=runner._parent_projection(snapshot,{},'Baseline',dict(process=None,process_started=started))
            self.assertIs(got['process_started'],started)
            self.assertTrue(all(value is None for key,value in got.items() if key!='process_started'))
        with self.assertRaises(ValueError):
            runner._parent_projection(snapshot,{},'Baseline',dict(process={},process_started=None,command={}))
