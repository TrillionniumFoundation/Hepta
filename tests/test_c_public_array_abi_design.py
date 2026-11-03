"""Executable design controls, NOT implementation of public array-pointer ABI."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from hepta.ast import HeptaError
from hepta.backend import emit_header
from hepta.c_backend import emit_c
from hepta.checker import check
from hepta.parser import parse

SOURCE = '''
extern "C" fn foreign_sum(p:raw const [i32;3], n:usize)->i32 effects {ffi};
export "C" fn identity(p:raw mut [i32;3])->raw mut [i32;3] effects {} {return p;}
export "C" fn plane(p:raw mut [[i32;3];2])->raw mut [[i32;3];2] effects {} {return p;}
export "C" fn indirect(p:raw mut raw mut [i32;3])->raw mut raw mut [i32;3] effects {} {return p;}
'''

class PublicArrayAbiDesignTests(unittest.TestCase):
    def test_frontend_accepts_but_c_backend_still_refuses(self):
        sources = [
            SOURCE,
            'extern "C" fn nested(p:raw const [[i32;3];2])->i32 effects {ffi};',
            'extern "C" fn returned()->raw mut [i32;3] effects {ffi};',
        ]
        for source in sources:
            with self.subTest(source=source):
                p = parse(source)
                c = check(p)
                self.assertTrue(c.ok, c.diagnostics)
                with self.assertRaises(HeptaError) as error:
                    emit_c(p, c, crate_type='staticlib')
                self.assertEqual(error.exception.diagnostic.code, 'E_C_BACKEND_SUBSET')
                self.assertIn('public declarator', str(error.exception))

    @unittest.skipUnless(shutil.which('gcc'), 'native GCC required')
    def test_real_header_callers_preserve_pointer_identity_and_stride(self):
        # C stand-in supplies the intended contract, not a Hepta backend pass.
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d/'abi.h').write_text(emit_header(parse(SOURCE)))
            (d/'callee.c').write_text('''#include "abi.h"
int32_t foreign_sum(const int32_t (*p)[3], size_t n) {
 int32_t total=0; for(size_t i=0;i<n;i++) for(size_t j=0;j<3;j++) total+=p[i][j]; return total;
}
int32_t (*identity(int32_t (*p)[3]))[3] {return p;}
int32_t (*plane(int32_t (*p)[2][3]))[2][3] {return p;}
int32_t (**indirect(int32_t (**p)[3]))[3] {return p;}
''')
            (d/'caller.c').write_text('''#include "abi.h"
#include <assert.h>
int main(void) {
 int32_t rows[2][3]={{1,2,3},{4,5,6}}; int32_t (*p)[3]=rows;
 assert(identity(p)==p); identity(p)[1][2]=17; assert(rows[1][2]==17);
 assert(foreign_sum((const int32_t (*)[3])p,2)==32);
 assert(indirect(&p)==&p); *indirect(&p)=rows+1; assert(p==rows+1);
 int32_t planes[2][2][3]={{{1,2,3},{4,5,6}},{{7,8,9},{10,11,12}}};
 assert(plane(planes)==planes); plane(planes)[1][1][2]=99; assert(planes[1][1][2]==99);
 return 0;
}
''')
            for opt in ('0','3'):
                result=subprocess.run(['gcc','-std=c11','-pedantic-errors','-Wall','-Wextra','-Werror','-O'+opt,'-fstrict-aliasing','-fsanitize=undefined','-fno-sanitize-recover=all',str(d/'caller.c'),str(d/'callee.c'),'-o',str(d/'run')],capture_output=True,text=True,timeout=60)
                self.assertEqual(result.returncode,0,result.stderr)
                result=subprocess.run([str(d/'run')],capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertNotIn('runtime error:',result.stderr)

    @unittest.skipUnless(shutil.which('gcc'), 'native GCC required')
    def test_equal_layout_wrapper_is_not_header_compatible(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)
            (d/'abi.h').write_text(emit_header(parse(SOURCE)))
            (d/'wrong.c').write_text('''#include "abi.h"
typedef struct {int32_t data[3];} PrivateRow;
_Static_assert(sizeof(PrivateRow)==sizeof(int32_t[3]), "same size");
_Static_assert(_Alignof(PrivateRow)==_Alignof(int32_t[3]), "same alignment");
PrivateRow *identity(PrivateRow *p) {return p;}
''')
            result=subprocess.run(['gcc','-std=c11','-Werror','-c',str(d/'wrong.c'),'-o',str(d/'wrong.o')],capture_output=True,text=True,timeout=60)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('conflicting types',result.stderr)
            self.assertIn('identity',result.stderr)

if __name__ == '__main__':
    unittest.main()
