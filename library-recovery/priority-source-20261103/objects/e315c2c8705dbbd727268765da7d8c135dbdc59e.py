import ctypes
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from hia_candidate import run,Refused
from hia_candidate.migrate_c import migrate
from hia_candidate.native import compile_and_probe
from hia_candidate.optimizer import eliminate_wrapping_add_zero
from hia_candidate.cpp_bridge import qualify_cpp

ROOT=Path(__file__).resolve().parent.parent

@unittest.skipUnless(shutil.which('clang') and shutil.which('gcc'),"real GCC/Clang required")
class NativeMigrationTests(unittest.TestCase):
    def test_clang_migration_and_two_compiler_differential(self):
        for name in ('add_zero','advanced'):
            source=ROOT/'fixtures'/'c'/f'{name}.c'
            migrated=migrate(source)
            with tempfile.TemporaryDirectory() as tmp:
                compiled=compile_and_probe(migrated.verified,output=Path(tmp)/'lowered',
                        vectors=[0,1,2,7,127,255,256,4095,65535,2**32-1],iterations=100)
                self.assertEqual(compiled['status'],'FINITE_NATIVE_DIFFERENTIAL_PASS')
                self.assertEqual(len(compiled['observations']),2)
                for compiler in ('gcc','clang'):
                    original=Path(tmp)/(compiler+'-original.so')
                    x=subprocess.run([compiler,'-std=c11','-O2','-Wall','-Wextra','-Werror',
                        '-fPIC','-shared',str(source),'-o',str(original)],capture_output=True,text=True,timeout=15)
                    self.assertEqual(x.returncode,0,x.stderr)
                    lib=ctypes.CDLL(str(original.resolve()))
                    fn=getattr(lib,migrated.verified.unpack()['function']['name'])
                    fn.argtypes=[ctypes.c_uint32];fn.restype=ctypes.c_uint32
                    for v in [0,1,3,17,255,512,2**31,2**32-1]:
                        self.assertEqual(fn(v),run(migrated.verified,[v]).results[0])

    def test_reject_unsupported_whole_c_unit(self):
        for file in ('global_reject.c','pointer_reject.c'):
            with self.assertRaises(Refused): migrate(ROOT/'fixtures'/'c'/file)

    def test_source_change_without_vacuous_proof(self):
        m=migrate(ROOT/'fixtures'/'c'/'add_zero.c')
        transform=eliminate_wrapping_add_zero(m.verified)
        self.assertIsNotNone(transform)
        self.assertNotEqual(transform.source_digest,transform.candidate_digest)
        self.assertEqual(run(transform.candidate,[567]).results,(567,))

@unittest.skipUnless(shutil.which('g++') and shutil.which('clang++'),"real C++ compilers required")
class BridgeTests(unittest.TestCase):
    def test_two_native_compilers_two_synthetic_revisions(self):
        with tempfile.TemporaryDirectory() as tmp:
            report=qualify_cpp(tmp)
            self.assertEqual(report['status'],'BOUNDED_CPP_BRIDGE_PASS')
            self.assertEqual(len(report['rows']),4)
            self.assertTrue(all(row['live_after']==0 for row in report['rows']))
            self.assertFalse(report['production_qualified'])

if __name__=='__main__': unittest.main()

@unittest.skipUnless(shutil.which('gcc') and shutil.which('clang'),'native C compilers required')
class LayoutTests(unittest.TestCase):
    def test_native_record_layout_gcc_clang(self):
        from hia_candidate.native import probe_native_layout
        with tempfile.TemporaryDirectory() as tmp:
            result=probe_native_layout(tmp)
            self.assertEqual(result['status'],'FINITE_HOST_C_LAYOUT_PASS')
            self.assertEqual(len(result['native_observed']),2)
            self.assertFalse(result['ARM64_execution'])

@unittest.skipUnless(shutil.which('clang') and shutil.which('readelf'),'cross compiler absent')
class ArmCrossObjectTests(unittest.TestCase):
    def test_real_aarch64_elf_object_not_runtime_qualification(self):
        from hia_candidate.native import cross_compile_aarch64_object
        m=migrate(ROOT/'fixtures'/'c'/'add_zero.c')
        with tempfile.TemporaryDirectory() as tmp:
            result=cross_compile_aarch64_object(m.verified,tmp)
            self.assertEqual(result['status'],'AARCH64_CROSS_OBJECT_CREATED')
            self.assertFalse(result['actual_device_execution'])
