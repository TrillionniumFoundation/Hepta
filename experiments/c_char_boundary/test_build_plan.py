"""Actual native orchestration and failure controls; no production CLI changes."""
from dataclasses import replace
from pathlib import Path
import sys
import json
import shlex
import tempfile
import time
import unittest
from unittest.mock import patch

from hepta.ast import HeptaError
from hepta.clang_capture import CaptureRejected,run_bounded
from . import test_prototype as fixtures
from . import build_plan as plan
from .prototype import Prepared,Rejected


@unittest.skipUnless(fixtures.CC,'GCC required')
class BuildPlanTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.CharPrototypeTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.entry,_=self.fixture.fixture()
        self.request=plan.Request(str(self.entry),'check',cc=fixtures.CC)

    def test_invalid_combinations_reject_before_load_or_probe(self):
        changes=[{'command':v} for v in ['emit','header','inspect','patch']]
        changes += [{'backend':'rust'},{'crate_type':'obj'},{'crate_type':'staticlib'},
                    {'crate_type':'cdylib'},{'crate_type':'rlib'}, {'profile':'other'},
                    {'target':'x86_64-linux-gnu'},{'no_std':True},{'frontend_only':True},
                    {'source_overrides':{}},{'link_args':('-funsigned-char',)},
                    {'debug':True},{'c_opt':'unroll'},{'char_mode':'unknown'},
                    {'command':'build'}, {'command':'build','output':''}, {'entry':''},
                    {'cc':None}, {'entry':Path('main.hepta')}, {'target':''},
                    {'output':str(self.fixture.root/'unexpected')}]
        with patch.object(plan,'load_project') as loader,patch.object(plan,'PrivateImporter') as probe:
            for change in changes:
                with self.subTest(change=change),self.assertRaises(Rejected):
                    plan.execute(replace(self.request,**change))
            loader.assert_not_called();probe.assert_not_called()

    def test_check_and_build_never_execute_user_program(self):
        self.entry.write_text(self.entry.read_text().replace('==2','==99'))
        checked=plan.execute(self.request)
        self.assertTrue(checked['ok']);self.assertFalse(checked['user_program_executed'])
        output=self.fixture.root/'out'
        built=plan.execute(replace(self.request,command='build',output=str(output)))
        self.assertTrue(built['ok']);self.assertFalse(built['user_program_executed'])
        self.assertEqual(plan.digest(output.read_bytes()),built['artifact_sha256'])
        # The exact artifact demonstrably aborts when actually executed.
        result=run_bounded([str(output)],timeout=5,stdout_limit=1000,stderr_limit=1000)
        self.assertNotEqual(result.returncode,0)

    def test_run_executes_once_and_preserves_stdout_and_exit(self):
        entry,_=self.fixture.fixture('int puts(const char *s);',
            'let bytes:[@CHAR@;3]=[65,66,0]; unsafe {let n=native::puts(ptr_read(read bytes)); assert(n>=0);}')
        request=replace(self.request,entry=str(entry),command='run')
        result=plan.execute(request)
        self.assertTrue(result['user_program_executed']);self.assertEqual(result['stdout'],'AB\n')
        self.assertEqual(result['returncode'],0)
        self.entry.write_text(self.entry.read_text().replace('assert(n>=0)','assert(false)'))
        result=plan.execute(request)
        self.assertFalse(result['ok']);self.assertNotEqual(result['returncode'],0)

    def test_locked_policy_fails_before_native_probe(self):
        with patch.object(plan,'PrivateImporter') as probe,self.assertRaises(HeptaError):
            plan.execute(replace(self.request,locked=True))
        probe.assert_not_called()

    def test_manual_extern_and_export_origins_refused(self):
        original=self.entry.read_text()
        for added in ['extern "C" fn getpid()->i32 effects {ffi};',
                      'export "C" fn visible()->i64 effects {} {return 1;}']:
            self.entry.write_text(original+added)
            with patch.object(plan,'PrivateImporter') as probe,self.assertRaises(Rejected):
                plan.execute(self.request)
            probe.assert_not_called()

    def test_output_cannot_replace_header_sidecar_or_sources(self):
        for output in [self.entry,self.fixture.root/'native.hepta',self.fixture.sidecar,self.fixture.root/'api.h']:
            original=output.read_bytes()
            with patch.object(plan,'PrivateImporter') as probe,self.assertRaises(Rejected):
                plan.execute(replace(self.request,command='build',output=str(output)))
            probe.assert_not_called();self.assertEqual(output.read_bytes(),original)

    def test_final_link_failure_keeps_existing_output_and_cleans_context(self):
        entry,_=self.fixture.fixture('char definitely_absent_char_symbol(char x);',
                                    'unsafe {let x=native::definitely_absent_char_symbol(1);}')
        output=self.fixture.root/'out';output.write_bytes(b'previous artifact')
        directories=[]
        class RecordingPrepared(Prepared):
            def _prepare(self,*args):
                directories.append(self.directory)
                return super()._prepare(*args)
        with patch.object(plan,'Prepared',RecordingPrepared),self.assertRaises(Rejected):
            plan.execute(replace(self.request,entry=str(entry),command='build',output=str(output)))
        self.assertEqual(output.read_bytes(),b'previous artifact')
        self.assertTrue(directories);self.assertTrue(all(not p.exists() for p in directories))
        self.assertEqual(list(self.fixture.root.glob('.char-plan-*')),[])

    def test_second_request_is_fresh_and_observes_new_source(self):
        request=replace(self.request,command='run')
        first=plan.execute(request)
        self.entry.write_text(self.entry.read_text().replace('==2','==99'))
        second=plan.execute(request)
        self.assertNotEqual(first['request_id'],second['request_id'])
        self.assertTrue(first['ok']);self.assertFalse(second['ok'])
        self.assertNotEqual(first['receipt']['context_source_sha256'],second['receipt']['context_source_sha256'])

    def test_mutation_after_preparation_refuses_publication(self):
        output=self.fixture.root/'out';output.write_bytes(b'old')
        original=Prepared.compile
        def mutate(prepared,**options):
            self.entry.write_text(self.entry.read_text()+'\n')
            return original(prepared,**options)
        with patch.object(Prepared,'compile',mutate),self.assertRaises(Rejected):
            plan.execute(replace(self.request,command='build',output=str(output)))
        self.assertEqual(output.read_bytes(),b'old')
        self.assertTrue(plan.execute(self.request)['ok'])

    def test_whole_deadline_not_reset_between_native_calls(self):
        budget=plan.Budget(seconds=.8)
        deadline=budget.deadline
        budget.capture([sys.executable,'-c','import time;time.sleep(.3)'])
        self.assertEqual(budget.deadline,deadline)
        started=time.monotonic()
        with self.assertRaises((CaptureRejected,Rejected)):
            budget.capture([sys.executable,'-c','import time;time.sleep(2)'])
        self.assertLess(time.monotonic()-started,1.5)
        self.assertEqual(budget.deadline,deadline)
        with self.assertRaises(Rejected):budget.capture([sys.executable,'-c','pass'])

    def test_aggregate_output_quota_spans_native_calls(self):
        budget=plan.Budget(output_bytes=100)
        budget.capture([sys.executable,'-c','print("x"*59)'])
        with self.assertRaises(CaptureRejected):
            budget.capture([sys.executable,'-c','print("x"*59)'])
        self.assertTrue(budget.closed)

    def test_native_call_count_is_bounded(self):
        budget=plan.Budget(calls=1)
        budget.capture([sys.executable,'-c','pass'])
        with self.assertRaises(Rejected):budget.capture([sys.executable,'-c','pass'])

    def test_expired_request_does_not_probe(self):
        original=plan.load_project
        def slow(*args,**kwargs):
            value=original(*args,**kwargs);time.sleep(.03);return value
        with patch.object(plan,'load_project',slow),patch.object(plan,'PrivateImporter') as probe:
            with self.assertRaises(Rejected):plan.execute(self.request,seconds=.01)
            probe.assert_not_called()

    def test_importer_module_is_private_and_removed_after_request(self):
        old=plan.c_import._native_process
        before={name for name in sys.modules if name.startswith('hepta._char_plan_')}
        plan.execute(self.request)
        self.assertIs(plan.c_import._native_process,old)
        self.assertEqual(before,{name for name in sys.modules if name.startswith('hepta._char_plan_')})

    def test_actual_run_timeout_cleans_private_inputs(self):
        entry,_=self.fixture.fixture(body='while true {}')
        directories=[]
        class RecordingPrepared(Prepared):
            def _prepare(self,*args):
                directories.append(self.directory)
                return super()._prepare(*args)
        with patch.object(plan,'Prepared',RecordingPrepared),self.assertRaises(CaptureRejected) as error:
            plan.execute(replace(self.request,entry=str(entry),command='run'),seconds=2)
        self.assertEqual(error.exception.code,'E_CAPTURE_TIMEOUT')
        self.assertTrue(directories);self.assertTrue(all(not p.exists() for p in directories))

    def test_actual_program_output_quota_is_enforced(self):
        entry,_=self.fixture.fixture('int puts(const char *s);',
            'let bytes:[@CHAR@;3]=[65,66,0]; while true { unsafe {let n=native::puts(ptr_read(read bytes));} }')
        with self.assertRaises(CaptureRejected) as error:
            plan.execute(replace(self.request,entry=str(entry),command='run'),output_bytes=30_000)
        self.assertEqual(error.exception.code,'E_CAPTURE_OUTPUT_SIZE')

    def test_import_alias_preserves_origin_and_execution(self):
        self.entry.write_text(self.entry.read_text().replace('import native;','import native as n;').replace('native::','n::'))
        self.assertTrue(plan.execute(replace(self.request,command='run'))['ok'])

    def test_external_header_and_symlink_output_are_protected(self):
        with tempfile.TemporaryDirectory() as outside:
            header=Path(outside)/'external.h'
            original=(self.fixture.root/'api.h').read_bytes();header.write_bytes(original)
            metadata=json.loads(self.fixture.sidecar.read_text());metadata['header']=str(header)
            self.fixture.sidecar.write_text(json.dumps(metadata))
            alias=self.fixture.root/'output-link';alias.symlink_to(header)
            for output in [header,alias]:
                with self.assertRaises(Rejected):
                    plan.execute(replace(self.request,command='build',output=str(output)))
                self.assertEqual(header.read_bytes(),original)

    def test_output_cannot_replace_implicit_native_dependency(self):
        dependency=self.fixture.root/'forced.h'
        original=b'/* stable implicit compiler input */\n';dependency.write_bytes(original)
        wrapper=self.fixture.root/'gcc-wrapper'
        wrapper.write_text('#!/bin/sh\nexec '+shlex.quote(fixtures.CC)+' -include '+shlex.quote(str(dependency))+' "$@"\n')
        wrapper.chmod(0o700)
        with self.assertRaisesRegex(Rejected,'observed native dependency'):
            plan.execute(replace(self.request,command='build',cc=str(wrapper),output=str(dependency)))
        self.assertEqual(dependency.read_bytes(),original)
        self.assertEqual(list(self.fixture.root.glob('.char-plan-*')),[])

    def test_native_dependency_mutation_after_compile_keeps_old_output(self):
        dependency=self.fixture.root/'forced.h';dependency.write_text('/* original */\n')
        wrapper=self.fixture.root/'gcc-wrapper'
        wrapper.write_text('#!/bin/sh\nexec '+shlex.quote(fixtures.CC)+' -include '+shlex.quote(str(dependency))+' "$@"\n')
        wrapper.chmod(0o700)
        output=self.fixture.root/'out';output.write_bytes(b'old artifact')
        original=Prepared.compile
        def mutate(prepared,**options):
            artifact,receipt=original(prepared,**options)
            self.assertIn(str(dependency),receipt['dependencies_observed_after_compile'])
            dependency.write_text('/* changed after native compilation */\n')
            return artifact,receipt
        with patch.object(Prepared,'compile',mutate),self.assertRaisesRegex(Rejected,'dependency changed'):
            plan.execute(replace(self.request,command='build',cc=str(wrapper),output=str(output)))
        self.assertEqual(output.read_bytes(),b'old artifact')
        self.assertEqual(list(self.fixture.root.glob('.char-plan-*')),[])
