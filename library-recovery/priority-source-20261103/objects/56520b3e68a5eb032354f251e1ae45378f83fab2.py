import ctypes
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parent

class CppBridgeTests(unittest.TestCase):
    def test_cpp_gcc_clang_true_c_abi(self):
        if not all(shutil.which(x) for x in ['gcc','g++','clang','clang++']):
            self.skipTest('requires gcc/g++ and clang/clang++')
        for cpp,cc in [('g++','gcc'),('clang++','clang')]:
            with self.subTest(cpp=cpp,cc=cc), tempfile.TemporaryDirectory() as d:
                lib=Path(d)/'libhia_cpp.so'
                build=subprocess.run([cpp,'-std=c++17','-fPIC','-shared','-O2',
                    '-Wall','-Wextra','-Werror',str(ROOT/'cpp_bridge_fixture.cpp'),'-o',str(lib)],
                    text=True,capture_output=True,timeout=20)
                self.assertEqual(build.returncode,0,build.stderr)
                app=Path(d)/'consumer'
                build=subprocess.run([cc,'-std=c11','-O2','-Wall','-Wextra','-Werror',
                    str(ROOT/'cpp_c_consumer.c'),'-L'+d,'-lhia_cpp',
                    '-Wl,-rpath,'+d,'-o',str(app)],text=True,capture_output=True,timeout=20)
                self.assertEqual(build.returncode,0,build.stderr)
                execution=subprocess.run([str(app)],capture_output=True,text=True,timeout=10)
                self.assertEqual(execution.returncode,0,(execution.returncode,execution.stderr))
                # Separate process run above is the authoritative C consumer; below is a fresh
                # in-process C ABI check with no C++ exceptions crossing the boundary.
                library=ctypes.CDLL(str(lib))
                library.hia_cpp_new.argtypes=[ctypes.c_int32];library.hia_cpp_new.restype=ctypes.c_uint64
                library.hia_cpp_delete.argtypes=[ctypes.c_uint64];library.hia_cpp_delete.restype=ctypes.c_int
                library.hia_cpp_step.argtypes=[ctypes.c_uint64,ctypes.c_int32,ctypes.POINTER(ctypes.c_int32)]
                library.hia_cpp_step.restype=ctypes.c_int
                library.hia_cpp_constructed.restype=ctypes.c_uint64
                library.hia_cpp_destroyed.restype=ctypes.c_uint64
                old=library.hia_cpp_new(42);self.assertNotEqual(old,0)
                result=ctypes.c_int32(0)
                self.assertEqual(library.hia_cpp_step(old,7,ctypes.byref(result)),0)
                self.assertEqual(result.value,49)
                self.assertEqual(library.hia_cpp_delete(old),0)
                self.assertEqual(library.hia_cpp_delete(old),1)
                new=library.hia_cpp_new(4)
                self.assertNotEqual(new,old)
                self.assertEqual(library.hia_cpp_step(old,9,ctypes.byref(result)),1)
                self.assertEqual(library.hia_cpp_delete(new),0)
                self.assertEqual(library.hia_cpp_constructed(),library.hia_cpp_destroyed())
