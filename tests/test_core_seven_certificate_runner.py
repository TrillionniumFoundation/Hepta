"""Fresh four-process fake-child execution and hostile frozen evidence tests."""
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
from tests.test_core_seven_certificate_diagnostic import fixture
from tests.test_core_syntax_diagnostic_capture import PLATFORM
from tools import diagnose_core_seven_certificate as runner
from tools import core_seven_certificate_sources as seven
from tools import core_seven_certificate_diagnostic_sources as diag
from tools import core_syntax_diagnostic_capture as collector
from tools import check_core_syntax_staged as base

class SevenRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.prepared,cls.proposal,cls.diagnostic=fixture()

    def exercise(self,behavior='success',inspect=None):
        with tempfile.TemporaryDirectory() as folder,ExitStack() as stack:
            home=Path(folder);exe=home/'pinned/bin/lean';exe.parent.mkdir(parents=True)
            exe.write_bytes(b'fake executable never launched');(home/'pinned/lib/lean').mkdir(parents=True)
            identity=runner.source_identity()
            support={}
            for name in ('lib/lean/Init.olean','lib/lean/Lean/Elab/Tactic/Omega.olean'):
                support_file=exe.parent.parent/name;support_file.parent.mkdir(parents=True,exist_ok=True)
                support_file.write_bytes(('fake support '+name).encode());support[name]=base.digest(support_file.read_bytes())
            calls=[]
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
                if behavior=='parent_spawn' and stage.name=='CertPart01':
                    return dict(**runner._command(executable,root,stage),returncode=None,timed_out=False,incomplete=True,
                                output_truncated=False,elapsed_seconds=.1,error_type='OSError',stdout='',stderr='')
                if behavior!='no_output' or stage.name!='CertPart01':output.write_bytes(('fake '+stage.name).encode())
                result=dict(**runner._command(executable,root,stage),returncode=1 if behavior=='parent_exit' and stage.name=='CertPart01' else 0,
                            timed_out=behavior=='parent_timeout' and stage.name=='CertPart01',incomplete=False,
                            output_truncated=False,elapsed_seconds=.1,stdout=out,stderr='')
                if behavior=='parent_malformed' and stage.name=='CertPart01':result['returncode']=True
                if result['timed_out']:result.update(returncode=None,incomplete=True,error_type='TimeoutExpired',elapsed_seconds=60.1)
                return result
            def capture(executable,source,output,root,**kwargs):
                if behavior=='uncertain':raise RuntimeError('uncertain launch')
                calls.append('CertPart02')
                lines=[('"'+m['id']+'" : String\n') for m in self.diagnostic.manifest['markers']]
                names=seven._qualified_prints(self.diagnostic.stages[3].source)
                if behavior=='target_missing':names=names[1:]
                out=''.join(lines)+''.join("'"+n+"' does not depend on any axioms\n" for n in names)
                if behavior=='target_extra':out+="'extra' does not depend on any axioms\n"
                if behavior=='target_sorry':out=out.replace('does not depend on any axioms','depends on axioms: [sorryAx]',1)
                script='import os,pathlib,time\npathlib.Path(%r).write_bytes(b"untrusted fake target")\nos.write(1,%r)\ntime.sleep(.03)\n'%(str(output),out.encode())
                if behavior=='fifth':script+='pathlib.Path(%r).write_bytes(b"forbidden fifth module")\n'%str(root/'HiaSyntaxResearch/CertPart03.olean')
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
                return captured
            # Source fixture already passed unchanged full original/inverse gates.
            for obj,name in ((base,'validate_plan'),(seven,'validate_sources'),(diag,'validate_diagnostic_sources')):
                stack.enter_context(patch.object(obj,name))
            report=runner.execute_diagnostic(exe,home/'out',self.prepared,self.proposal,self.diagnostic,
                 identity,support,lambda:identity,lambda _:support,base.digest(exe.read_bytes()),run_process=invoke,capture=capture)
            self.assertLessEqual(len(calls),4);self.assertLessEqual(report['invocations'],4)
            self.assertFalse((home/'out/CertPart02.finished.json').exists())
            self.assertEqual(report['authority'],'DENY_ALL')
            stack.close()
            if inspect:inspect(home/'out',report,identity,support)
            return report,calls

    def test_each_whole_source_gate_precedes_output_and_launch(self):
        for gate in ('original','seven','markers'):
            with tempfile.TemporaryDirectory() as folder,ExitStack() as stack:
                out=Path(folder)/'must-not-exist'
                for label,obj,name in (('original',base,'validate_plan'),('seven',seven,'validate_sources'),
                                       ('markers',diag,'validate_diagnostic_sources')):
                    stack.enter_context(patch.object(obj,name,side_effect=ValueError('blocked '+gate) if label==gate else None))
                with self.assertRaisesRegex(ValueError,'blocked '+gate):
                    runner.execute_diagnostic(Path(folder)/'nonexistent',out,self.prepared,self.proposal,self.diagnostic,
                                              {},{},lambda:{},lambda _: {},'0'*64,
                                              run_process=lambda *a: self.fail('launched before source gate'))
                self.assertFalse(out.exists())

    def test_success_exactly_four_never_admits_target(self):
        report,calls=self.exercise()
        self.assertEqual(calls,list(runner.DIAGNOSTIC_NAMES))
        self.assertEqual(report['status'],'diagnostic_completed',report)
        self.assertTrue(report['evidence_complete'],report)
        self.assertNotIn('olean',report['stages'][-1])
        self.assertEqual(len(report['not_scheduled']),7)

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
                self.assertEqual(len(calls),4)

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
        self.assertEqual(report['invocations'],3)
        self.assertTrue(report['invocation_count_exact'])
        report,_=self.exercise('uncertain')
        self.assertEqual(report['invocations'],4)
        self.assertFalse(report['invocation_count_exact'])

    def replay(self,path,identity,support,full=False,after_sources=None):
        def known_sources(snapshot,frozen,identities):
            # Source semantics have their own full-validation controls. Here
            # pin all source/manifests to the fully validated immutable fixture
            # so adversarial receipt tests do not repeat source generation.
            for name,text in diag.retained_sources(self.prepared,self.proposal,self.diagnostic.stages).items():
                self.assertEqual(snapshot.read(name),text.encode())
            for name,text in (('original-manifest.json',self.prepared['manifest_json']),
                              ('seven-manifest.json',self.proposal.manifest_json),
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
            self.assertEqual(verified['validated_parent_count'],3)
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
                self.assertLessEqual(verified['validated_parent_count'],3)
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
                     ('RESULT.json','acceptance_eligible',True),('RESULT.json','extra',1),
                     (runner.TARGET_STARTED,'parents',{}),(runner.TARGET_STARTED,'source_sha256','0'*64),
                     ('CertPart01.finished.json','parents',{}),('Baseline.finished.json','status','failed'),
                     (runner.TARGET_INVENTORY,'diagnostic_only',False)]
            for name,key,value in attacks:
                with self.subTest(name=name,key=key):
                    restore();obj=json.loads((path/name).read_bytes());obj[key]=value;rehash(name,obj)
                    with self.assertRaises((ValueError,KeyError,AssertionError)):self.replay(path,identity,support)
            # Rewrite every outer hash/accounting after hostile capture edits:
            # a changed digest alone is not the reason these cases must fail.
            for mutation in ('bool_time','offset_hole','unknown_event','foreign_start','bool_pid','cleanup_error','leader_error','bool_signal'):
                with self.subTest(capture=mutation):
                    restore()
                    result=json.loads((path/'RESULT.json').read_bytes())
                    process=result['stages'][3]['process']
                    rows=[json.loads(x) for x in (path/runner.CAPTURE_FILES[2]).read_bytes().splitlines()]
                    receive=next(row for row in rows if row['kind']=='receive')
                    if mutation=='bool_time':receive['received_seconds']=True
                    if mutation=='offset_hole':receive['offset']=1
                    if mutation=='unknown_event':rows.insert(1,dict(kind='unrecognized'))
                    if mutation=='foreign_start':rows[0]['process']['started_reference']['sha256']='0'*64
                    if mutation=='bool_pid':
                        process['pid']=True;rows[-1]['process']['pid']=True
                    if mutation in ('cleanup_error','leader_error'):
                        key='group_cleanup_error' if mutation=='cleanup_error' else 'leader_cleanup_error'
                        process[key]='forged cleanup failure';rows[-1]['process'][key]=process[key]
                    if mutation=='bool_signal':
                        process['returncode']=-1;process['signal']=True
                        rows[-1]['process']['returncode']=-1;rows[-1]['process']['signal']=True
                    prefix=b''.join(runner._encoded(row) for row in rows[:-1])
                    rows[-1]['accounting_before_terminal']['metadata_written_bytes']=len(prefix)
                    event_bytes=prefix+runner._encoded(rows[-1]);(path/runner.CAPTURE_FILES[2]).write_bytes(event_bytes)
                    item=dict(path=runner.CAPTURE_FILES[2],sha256=base.digest(event_bytes),bytes=len(event_bytes))
                    process['files'][runner.CAPTURE_FILES[2]]=item;process['compact_receipt_reference']=item
                    process['metadata_written_bytes']=len(event_bytes)
                    process['metadata_remaining_bytes']=collector.METADATA_LIMIT-len(event_bytes)
                    evidence=json.loads((path/'EVIDENCE.json').read_bytes())
                    evidence['sha256'][runner.CAPTURE_FILES[2]]=base.digest(event_bytes)
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

    def test_fifth_output_is_not_frozen_as_valid_failure(self):
        report,calls=self.exercise('fifth')
        self.assertEqual(len(calls),4)
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

    def test_full_inverse_replay_integration(self):
        def inspect(path,report,identity,support):
            verified=self.replay(path,identity,support,full=True)
            self.assertEqual(verified['validated_parent_count'],3)
            self.assertTrue(verified['validated_markers'])
        self.exercise(inspect=inspect)

if __name__=='__main__':unittest.main()
