"""Actual kernel execution, foreign byte ABI and legacy observation controls."""
from pathlib import Path
import platform
import shutil
import struct
import tempfile
import unittest

from tools.hia_selfhost_native_observer import frame, execute, invoke as native_invoke, independent_reference, build


@unittest.skipUnless(platform.system()=='Linux' and platform.machine().lower() in ('x86_64','amd64')
    and shutil.which('ld'), 'Linux x86-64 bootstrap required')
class NativeObserverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_selfhost import build_seed, compile_stage, SOURCE
        cls.temp = tempfile.TemporaryDirectory(prefix='hia-native-observer-')
        cls.root = Path(cls.temp.name)
        # The VM's actual packer result is established before the seed exists.
        cls.reference = independent_reference()
        seed, _ = build_seed(cls.root)
        cls.compiler, _ = compile_stage(cls.root,'B1',seed,SOURCE.read_bytes(),image_format='seed-shared')
        cls.executable, cls.build = build(cls.root,cls.compiler,cls.reference)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def call(self,name,image,source=b'',capacity=32,workspace_size=128,workspace_fill=90):
        path = self.root/(name+'.image.bin'); path.write_bytes(image)
        return native_invoke(self.root,name,self.executable,path,source,
            capacity=capacity,workspace_size=workspace_size,workspace_fill=workspace_fill)

    def test_actual_hia_emission_matches_independent_VM_every_ELF_byte(self):
        from tools.generate_hia_native_observer import reference_image
        from tools.qualify_hia_selfhost_cli import inspect_executable
        self.assertTrue(self.reference['before_B0'])
        self.assertEqual(self.executable.read_bytes(),reference_image())
        inspected=inspect_executable(self.executable.read_bytes())
        self.assertIsInstance(inspected,dict)
        self.assertFalse(self.build['whole_stack_rewritten_in_hia'])

    def test_exact_full_foreign_return_source_output_and_workspace_observations(self):
        from tools.qualify_hia_selfhost import invoke
        # Arbitrary full 64-bit return, with the ABI-status half observable.
        code=bytes.fromhex('48 b8 2a 00 00 00 ef be ad de c3')
        for n,source in enumerate((b'',b'A\0\xff'*137)):
            for capacity in (0,1,257):
                for fill in (0,90,255):
                    name='paired-'+str(n)+'-'+str(capacity)+'-'+str(fill)
                    result,output=self.call(name,code,source,capacity,1032,fill)
                    original,raw=invoke(self.root,name+'-legacy',self.root/(name+'.image.bin'),source,
                        capacity=capacity,workspace_size=1032,workspace_fill=fill)
                    for key in ('status','result_u64','abi_status','core_u32','source_unchanged',
                        'output_unchanged','workspace_header','source_sha256','output_sha256','limits'):
                        self.assertEqual(result[key],original[key],(name,key))
                    self.assertEqual(output,raw)
                    self.assertTrue(result['fresh_native_exec'])
                    self.assertFalse(result['successor_process_reuse'])

    def test_source_mutation_is_actually_observed_not_assumed(self):
        # Deliberately hostile image violates the read-only source obligation.
        result,output=self.call('mutates-source',bytes.fromhex('c6 07 61 31 c0 c3'),b'XYZ')
        self.assertFalse(result['source_unchanged'])
        self.assertTrue(result['output_unchanged'])
        self.assertEqual(output,b'\xa5'*32)

    def test_native_trap_remains_real_SIGILL_and_retained_shared_capture_path(self):
        import tools.qualify_hia_selfhost as q
        result,output=self.call('actual-UD2',b'\x0f\x0b')
        self.assertEqual((result['status'],result['returncode'],output),('child_failed',-4,b''))
        # A write before trapping is observed through actual parent-owned
        # shared memory, not inferred from the native stdout protocol.
        image=self.root/'prior-store-UD2.bin';image.write_bytes(bytes.fromhex('c6 02 63 0f 0b'))
        prior=q.NATIVE_OBSERVER
        try:
            q.NATIVE_OBSERVER=self.executable
            trapped,raw=q.invoke(self.root,'retained-shared-capture',image,b'',capacity=1,
                workspace_size=0,observe_trap_writes=True)
        finally:
            q.NATIVE_OBSERVER=prior
        self.assertEqual(trapped['returncode'],-4)
        self.assertTrue(trapped['shared_output_observation']['available'])
        self.assertEqual(raw,b'c')
        self.assertEqual(trapped['transport'],'HIA-emitted-static-ELF-observer-v2')
        legacy,old=q.invoke(self.root,'legacy-shared-capture-control',image,b'',capacity=1,
            workspace_size=0,observe_trap_writes=True)
        self.assertEqual(old,raw)
        self.assertEqual(legacy['returncode'],trapped['returncode'])

    def test_real_HIA_compiler_bytes_output_and_error_counters_equal_legacy(self):
        from tools.qualify_hia_selfhost import invoke, SAMPLE
        for n,source in enumerate((SAMPLE.read_bytes(),b'invalid')):
            name='compiler-control-'+str(n)
            actual,output=native_invoke(self.root,name,self.executable,self.compiler,source,
                capacity=1<<20,workspace_size=1<<20,workspace_fill=90)
            original,raw=invoke(self.root,name+'-legacy',self.compiler,source,workspace_fill=90)
            self.assertEqual(output,raw)
            for key in ('status','result_u64','core_u32','abi_status','source_unchanged',
                        'output_unchanged','workspace_header'):
                self.assertEqual(actual[key],original[key],(n,key))

    def test_kernel_limits_and_non_dumpable_are_real_not_receipt_constants(self):
        # Linux prlimit64(0, RLIMIT_CPU, NULL, workspace) then PR_GET_DUMPABLE.
        # Store actual results into the output before returning the syscall code.
        code=bytes.fromhex('49 89 d4 4d 89 c2 31 ff 31 f6 31 d2 b8 2e 01 00 00 0f 05'
            ' 49 8b 02 49 89 04 24 49 8b 42 08 49 89 44 24 08'
            ' bf 03 00 00 00 b8 9d 00 00 00 0f 05 c3')
        # Preserve SysV r12 across this deliberately hand-authored foreign image.
        code=b'\x41\x54'+code[:-1]+b'\x41\x5c\xc3'
        result,output=self.call('kernel-limits',code,capacity=16,workspace_size=16)
        self.assertEqual(result['core_u32'],0)
        self.assertEqual(struct.unpack('<2Q',output),(10,10))

    def test_custom_preimages_and_real_post_trap_writes_match_independent_legacy_capture(self):
        from tools.qualify_hia_selfhost import invoke
        codes=[bytes.fromhex('31 c0 c3'),bytes.fromhex('c6 02 63 31 c0 c3'),bytes.fromhex('c6 02 63 0f 0b')]
        for index,code in enumerate(codes):
            image=self.root/('custom-'+str(index)+'.bin');image.write_bytes(code)
            for initial in (b'\0',b'Z\0\xff',b'\xff'*31):
                name='custom-'+str(index)+'-'+str(len(initial))
                actual,out=native_invoke(self.root,name,self.executable,image,b'input',capacity=len(initial),
                    workspace_size=128,workspace_fill=255,output_initial=initial,observe_trap_writes=True)
                old,raw=invoke(self.root,name+'-legacy',image,b'input',capacity=len(initial),workspace_size=128,
                    workspace_fill=255,output_initial=initial,observe_trap_writes=True)
                self.assertEqual(actual['status'],old['status'])
                self.assertEqual(out,raw)
                for key in ('available','initial_sha256','observed_sha256','observed_bytes','unchanged'):
                    self.assertEqual(actual['shared_output_observation'][key],old['shared_output_observation'][key])
                if index==2:self.assertEqual(actual['returncode'],-4)
                else:self.assertEqual(actual['core_u32'],old['core_u32'])

    def test_unexpected_native_stdout_is_refused_and_exact_failure_bytes_retained(self):
        # Deliberate foreign image writes caller bytes to stdout before returning.
        code=bytes.fromhex('48 89 f2 48 89 fe bf 01 00 00 00 b8 01 00 00 00 0f 05 b8 2a 00 00 00 c3')
        result,output=self.call('unexpected-stdout',code,b'injected-prefix')
        self.assertEqual(result['status'],'protocol_failed')
        self.assertEqual(output,b'')
        raw=(self.root/'unexpected-stdout.failure-stdout.raw').read_bytes()
        self.assertTrue(raw.startswith(b'injected-prefixHIAOBR02'))
        self.assertEqual(len(raw),result['response_bytes'])

    def test_shared_extent_seals_allow_real_writes_but_not_growth_or_shrink(self):
        import fcntl,os
        from tools.hia_selfhost_native_observer import shared_output,read_capture
        with shared_output(b'ABC',True) as descriptor:
            self.assertEqual(read_capture(descriptor,3),b'ABC')
            self.assertEqual(fcntl.fcntl(descriptor,getattr(fcntl,'F_GET_SEALS',1034)) & 7,7)
            for size in (0,2,4):
                with self.assertRaises(OSError):os.ftruncate(descriptor,size)
            os.pwrite(descriptor,b'Z',1)
            self.assertEqual(read_capture(descriptor,3),b'AZC')
        with self.assertRaises(OSError):fcntl.fcntl(descriptor,fcntl.F_GETFD)

    def test_prelaunch_storage_failure_does_not_leak_shared_output_descriptor(self):
        import errno
        from unittest.mock import patch
        before=len(list(Path('/proc/self/fd').iterdir()))
        image=self.root/'storage-failure-image.bin';image.write_bytes(bytes.fromhex('31 c0 c3'))
        with patch.object(Path,'write_text',side_effect=OSError(errno.ENOSPC,'injected retained storage failure')):
            with self.assertRaises(OSError):
                native_invoke(self.root,'storage-failure',self.executable,image,b'',capacity=1,
                    workspace_size=0,workspace_fill=0,output_initial=b'X',observe_trap_writes=True)
        self.assertEqual(len(list(Path('/proc/self/fd').iterdir())),before)

    def test_bad_frames_lengths_overflow_and_arguments_fail_without_output(self):
        image=self.executable.read_bytes()
        good=frame(b'\xc3',b'',0,0,0)
        bad=[b'',good[:47],b'badMAGIC'+good[8:],good+b'\0',good[:-1]]
        for index in range(5):
            altered=bytearray(good);struct.pack_into('<Q',altered,8+index*8,2**64-1);bad.append(bytes(altered))
        for value in (0,1,2,2147483648,2**64-2):
            altered=bytearray(good);struct.pack_into('<Q',altered,48,value);bad.append(bytes(altered))
        for data in bad:
            result=execute(image,data,cwd=self.root)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(2,b'',b''))
        result=execute(image,good,cwd=self.root,arguments=('unexpected',))
        self.assertEqual((result.returncode,result.stdout),(64,b''))
        for values in ((b'',b'',0,0,0),(b'x',b'',True,0,0),(b'x',b'',0,0,256)):
            with self.assertRaises(ValueError):frame(*values)


if __name__=='__main__':
    unittest.main()
