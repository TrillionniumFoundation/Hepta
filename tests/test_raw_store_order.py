"""Characterize raw-store operand order before changing either backend."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.backend import compile_rust, emit_rust
from hepta.c_backend import emit_c
from hepta.checker import check
from hepta.parser import parse

CC = os.environ.get('CC') or shutil.which('gcc')
RUSTC = os.environ.get('RUSTC') or shutil.which('rustc')
HELPER = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
static int64_t cells[2] = {0,0};
static size_t selected = 0;
static void event(char c) {
    putchar(c); fflush(stdout);
    const char *failure = getenv("HEPTA_STORE_FAIL");
    if (failure && failure[0] == c) abort();
}
int64_t *destination(void) { event('P'); return cells + selected; }
size_t offset(void) { event('I'); return 0; }
int64_t payload(void) { event('V'); selected = 1; return 42; }
void finish(void) { event('A'); printf(":%lld:%lld\n", (long long)cells[0], (long long)cells[1]); }
'''
IMPORTS = '''extern "C" fn destination() -> raw mut i64 effects {ffi};
extern "C" fn offset() -> usize effects {ffi};
extern "C" fn payload() -> i64 effects {ffi};
extern "C" fn finish() -> Unit effects {ffi};
'''


def source(operation):
    return IMPORTS + f'''fn main() -> Unit effects {{ffi,unsafe,write,io}} {{
        unsafe {{ {operation}(destination(), offset(), payload()); finish(); }}
    }}'''


def frontend(text):
    p = parse(text)
    checked = check(p)
    if not checked.ok:
        raise AssertionError([d.to_dict() for d in checked.diagnostics])
    return p, checked


@unittest.skipUnless(CC and sys.platform == 'linux', 'Linux GCC required')
class RawStoreOrderTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='hepta-store-order-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.helper = self.root/'helper.c'
        self.helper.write_text(HELPER)

    def execute(self, exe, expected, failure=None):
        env = os.environ.copy()
        env.pop('HEPTA_STORE_FAIL', None)
        if failure:
            env['HEPTA_STORE_FAIL'] = failure
        r = subprocess.run([str(exe)], env=env, capture_output=True, timeout=10)
        self.assertEqual(r.returncode, -signal.SIGABRT if failure else 0, r.stderr)
        self.assertEqual(r.stdout, expected.encode())
        self.assertNotIn(b'runtime error:', r.stderr)

    def rust(self, operation, optimize):
        obj = self.root/'helper.o'
        r = subprocess.run([CC, '-std=c11', '-c', str(self.helper), '-o', str(obj)], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        p, c = frontend(source(operation))
        exe = self.root/'rust'
        r = compile_rust(emit_rust(p,c,crate_type='bin'),rustc=RUSTC,
                         crate_type='bin',output=exe,optimize=optimize,link_args=[str(obj)])
        self.assertTrue(r['ok'], r['diagnostics'])
        return exe

    def test_current_c_boundary_still_rejects_effectful_store_operands(self):
        for operation in ['store','volatile_store']:
            p, c = frontend(source(operation))
            with self.assertRaises(HeptaError) as caught:
                emit_c(p,c)
            self.assertEqual(caught.exception.diagnostic.code, 'E_C_BACKEND_EVALUATION')

    def test_trace_harness_distinguishes_call_order_without_invalid_memory(self):
        # Explicit sequencing is the language call-order oracle. Both cells
        # remain valid and aligned even if payload changes the selected cell.
        text = HELPER + '\nint main(void) { int64_t *p=destination(); size_t i=offset(); int64_t v=payload(); p[i]=v; finish(); }\n'
        path = self.root/'oracle.c'; path.write_text(text)
        for opt in ['-O0','-O3']:
            exe = self.root/'oracle'
            r = subprocess.run([CC, '-std=c11',opt,'-fsanitize=undefined','-fno-sanitize-recover=all',str(path),'-o',str(exe)],capture_output=True,text=True,timeout=30)
            self.assertEqual(r.returncode,0,r.stderr)
            self.execute(exe,'PIVA:42:0\n')
            for failure, expected in [('P','P'),('I','PI'),('V','PIV')]:
                self.execute(exe,expected,failure)

    @unittest.skipUnless(RUSTC and Path(RUSTC).is_file(), 'actual Rust required')
    def test_baseline_rust_store_evaluates_value_before_pointer_and_index(self):
        # This intentionally records the existing defect, not desired behavior.
        for opt in [False,True]:
            exe = self.rust('store',opt)
            self.execute(exe,'VPIA:0:42\n')
            for failure, expected in [('P','VP'),('I','VPI'),('V','V')]:
                self.execute(exe,expected,failure)

    @unittest.skipUnless(RUSTC and Path(RUSTC).is_file(), 'actual Rust required')
    def test_baseline_rust_volatile_store_preserves_call_order(self):
        for opt in [False,True]:
            exe = self.rust('volatile_store',opt)
            self.execute(exe,'PIVA:42:0\n')
            for failure, expected in [('P','P'),('I','PI'),('V','PIV')]:
                self.execute(exe,expected,failure)
