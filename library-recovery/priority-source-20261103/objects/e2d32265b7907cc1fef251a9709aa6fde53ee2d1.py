import ctypes
import random
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from hia_probe import (SCHEMA,UINT32,Rejected,ProgramTrap,
                       emit_native_c,emit_checked_native_c,interpret_scalar)

OPERATIONS=['int.add.checked','int.sub.checked','int.mul.checked','int.div.checked',
            'int.rem.checked','int.shl.checked','int.shr.checked']

def program(op):
    return {'schema':SCHEMA,'name':'t','params':[{'name':'a','type':'u32'},{'name':'b','type':'u32'}],
            'ops':[{'id':'v0','opcode':op,'args':['a','b']}],'result':'v0'}

class CheckedTrapTests(unittest.TestCase):
    def test_checked_trap_vectors(self):
        checks=[('int.add.checked',[UINT32,1],'overflow'),
                ('int.sub.checked',[0,1],'overflow'),
                ('int.mul.checked',[UINT32,2],'overflow'),
                ('int.div.checked',[2,0],'division_by_zero'),
                ('int.rem.checked',[2,0],'division_by_zero'),
                ('int.shl.checked',[1,32],'shift_count'),
                ('int.shr.checked',[1,32],'shift_count')]
        for op,values,expected in checks:
            with self.subTest(op=op):
                with self.assertRaises(ProgramTrap) as e:interpret_scalar(program(op),values)
                self.assertEqual(e.exception.code,expected)

    def test_checked_shift_valid_count_wraps_value(self):
        self.assertEqual(interpret_scalar(program('int.shl.checked'),[UINT32,31]),0x80000000)
        self.assertEqual(interpret_scalar(program('int.shr.checked'),[UINT32,31]),1)

    def test_no_trap_erasure_to_scalar_abi(self):
        with self.assertRaises(Rejected) as e:emit_native_c(program('int.add.checked'))
        self.assertEqual(e.exception.code,'E_ABI_TRAP')

    def test_checked_native_differential(self):
        if not shutil.which('gcc') or not shutil.which('clang'):
            self.skipTest('requires real GCC and Clang')
        rng=random.Random(20261031)
        special=[0,1,2,3,15,31,32,33,127,255,65535,0x80000000,UINT32]
        pairs=[(a,b) for a in special for b in special]
        pairs.extend((rng.randrange(UINT32+1),rng.randrange(UINT32+1)) for _ in range(200))
        for opcode in OPERATIONS:
            for compiler in ['gcc','clang']:
                with self.subTest(opcode=opcode,compiler=compiler),tempfile.TemporaryDirectory() as d:
                    src=Path(d)/'generated.c';src.write_text(emit_checked_native_c(program(opcode)))
                    lib=Path(d)/'native.so'
                    r=subprocess.run([compiler,'-std=c11','-O3','-Wall','-Wextra','-Werror',
                        '-fPIC','-shared',str(src),'-o',str(lib)],capture_output=True,text=True,timeout=20)
                    self.assertEqual(r.returncode,0,r.stderr)
                    f=ctypes.CDLL(str(lib)).hia_checked
                    f.argtypes=[ctypes.c_uint32,ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint32)]
                    f.restype=ctypes.c_int
                    self.assertEqual(f(1,2,None),4)
                    for a,b in pairs:
                        expected_code=0
                        try:expected=interpret_scalar(program(opcode),[a,b])
                        except ProgramTrap as error:
                            expected_code={'overflow':1,'division_by_zero':2,'shift_count':3}[error.code]
                        out=ctypes.c_uint32(0xDEADBEEF)
                        status=f(a,b,ctypes.byref(out))
                        self.assertEqual(status,expected_code,(opcode,compiler,a,b))
                        if expected_code==0:self.assertEqual(out.value,expected,(opcode,compiler,a,b))
                        else:self.assertEqual(out.value,0xDEADBEEF,(opcode,compiler,a,b))

if __name__=='__main__':unittest.main()
