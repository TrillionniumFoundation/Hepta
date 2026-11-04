"""Real GCC importer/compile/link controls; no compiler/read mocking."""
from dataclasses import replace
from pathlib import Path
import shlex
import tempfile
import unittest
from experiments.c_char_boundary import test_prototype as fixtures
CC=fixtures.CC
from experiments.c_char_boundary.prototype import run
from experiments.c_char_boundary.build_plan import Request
from experiments.request_load.build_plan import execute as old_execute
from experiments.request_load.context import Limits as OldLimits, Rejected
from hepta.packages import write_lock
from hepta.ast import HeptaError
from .build_plan import execute
from .context import Context, Limits
from .prepared import Prepared


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(CC, 'GCC is required, never skip native controls')
        self.fixture=fixtures.CharPrototypeTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.entry,_=self.fixture.fixture()
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.dependency=self.root/'forced.h';self.dependency.write_bytes(b'/* stable */\n')
        self.wrapper=self.root/'gcc-wrapper'
        self.wrapper.write_text('#!/bin/sh\nexec '+shlex.quote(CC)+' -include '+shlex.quote(str(self.dependency))+' "$@"\n')
        self.wrapper.chmod(0o755)
        self.output=self.root/'result';self.output.write_bytes(b'old artifact')
        self.request=Request(str(self.entry),'build',cc=str(self.wrapper),output=str(self.output))

    def lock(self):
        (self.fixture.root/'hepta.toml').write_text('[package]\nname="example"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')
        write_lock(self.fixture.root)
        self.request=replace(self.request,locked=True)

    def test_real_locked_build_and_dependency_receipt(self):
        self.lock();result=execute(self.request)
        self.assertTrue(result['ok']);self.assertFalse(result['user_program_executed'])
        self.assertIn(str(self.dependency),result['receipt']['dependencies_observed_after_compile'])
        self.assertNotEqual(self.output.read_bytes(),b'old artifact')
        self.assertFalse(result['receipt']['atomic_system_snapshot'])
        self.assertFalse(result['foreign_binary_authenticated'])

    def test_old_route_accepts_large_dependency_new_route_refuses_before_publication(self):
        self.lock();self.dependency.write_bytes(b'/*'+b'x'*2_000_000+b'*/\n')
        old=old_execute(self.request,limits=OldLimits(total_bytes=1_000_000))
        self.assertTrue(old['ok'])
        artifact=self.output.read_bytes()
        with self.assertRaises(Rejected):execute(self.request,limits=Limits(total_bytes=1_000_000))
        self.assertEqual(self.output.read_bytes(),artifact)

    def test_dependency_role_cap_rejects_real_forced_include(self):
        self.dependency.write_bytes(b'/*'+b'x'*200_000+b'*/\n')
        with self.assertRaises(Rejected):execute(self.request,limits=Limits(native_dependency=100_000))
        self.assertEqual(self.output.read_bytes(),b'old artifact')

    def test_actual_check_and_run(self):
        checked=execute(replace(self.request,command='check',output=None))
        self.assertTrue(checked['ok']);self.assertFalse(checked['user_program_executed'])
        ran=execute(replace(self.request,command='run',output=None))
        self.assertTrue(ran['ok']);self.assertTrue(ran['user_program_executed']);self.assertEqual(ran['returncode'],0)

    def test_malformed_missing_stale_locks_preserve_diagnostics(self):
        self.lock();lock=self.fixture.root/'Hepta.lock';original=lock.read_bytes()
        for value,code in ((b'{','E_LOCK_INVALID'),(None,'E_LOCK_MISSING'),(b'{}','E_LOCK_STALE')):
            with self.subTest(code=code):
                if value is None:lock.unlink()
                else:lock.write_bytes(value)
                with self.assertRaises(HeptaError) as caught:execute(self.request)
                self.assertEqual(caught.exception.diagnostic.code,code)
                self.assertEqual(self.output.read_bytes(),b'old artifact')
                lock.write_bytes(original)

    def test_real_two_tu_dependency_change_rejected(self):
        entry,_=self.fixture.fixture('char echo_char(char x);','unsafe {assert(native::echo_char(3)==3);}')
        changed=[]
        def runner(argv):
            if '-c' in argv and any(str(arg).endswith('unit-1.o') for arg in argv):
                self.dependency.write_bytes(b'/* changed between real TUs */\n');changed.append(True)
            return run(argv)
        context=Context()
        with Prepared(entry,cc=str(self.wrapper),_context=context,_runner=runner) as prepared:
            with self.assertRaisesRegex(Rejected,'between observations'):
                prepared.compile(native_source='char echo_char(char x){return x;}')
        self.assertTrue(changed);self.assertTrue(context.closed)

    def test_real_two_tu_stable_dependency_is_admitted(self):
        entry,_=self.fixture.fixture('char echo_char(char x);','unsafe {assert(native::echo_char(3)==3);}')
        context=Context()
        with Prepared(entry,cc=str(self.wrapper),_context=context) as prepared:
            artifact,receipt=prepared.compile(native_source='char echo_char(char x){return x;}')
            self.assertTrue(artifact.is_file());self.assertIn(str(self.dependency),receipt['dependencies_observed_after_compile'])
            duplicates=[r for r in prepared.observer._records if r.raw==str(self.dependency)]
            self.assertEqual(len(duplicates),2);prepared.observer.revalidate()

    def test_real_compiler_space_hash_dollar_dependency_names(self):
        for name in ['with space.h','with#hash.h','with$dollar.h']:
            with self.subTest(name=name):
                dependency=self.root/name;dependency.write_bytes(b'/* valid */\n')
                self.wrapper.write_text('#!/bin/sh\nexec '+shlex.quote(CC)+' -include '+shlex.quote(str(dependency))+' "$@"\n')
                if name=='with$dollar.h':
                    result=execute(self.request)
                    self.assertIn(str(dependency),result['receipt']['dependencies_observed_after_compile'])
                else:
                    before=self.output.read_bytes()
                    with self.assertRaisesRegex(Rejected,'path escape'):execute(self.request)
                    self.assertEqual(self.output.read_bytes(),before)
