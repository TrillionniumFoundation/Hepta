"""Raw store calls preserve left-to-right effects and abort boundaries."""
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
from hepta.c_backend import compile_c, emit_c
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

    def rust_source(self, text, optimize):
        obj = self.root/'helper.o'
        r = subprocess.run([CC, '-std=c11', '-c', str(self.helper), '-o', str(obj)], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        p, c = frontend(text)
        exe = self.root/'rust'
        r = compile_rust(emit_rust(p,c,crate_type='bin'),rustc=RUSTC,
                         crate_type='bin',output=exe,optimize=optimize,link_args=[str(obj)])
        self.assertTrue(r['ok'], r['diagnostics'])
        return exe

    def native_c(self, text, optimize):
        p, c = frontend(text)
        exe = self.root/'native'
        r = compile_c(emit_c(p,c),output=exe,optimize=optimize,sanitize=True,
                      link_args=[str(self.helper)])
        self.assertTrue(r['ok'],r['diagnostics'])
        return exe

    def test_c_store_and_volatile_store_preserve_call_order(self):
        for operation in ['store','volatile_store']:
            for optimize in [False,True]:
                exe = self.native_c(source(operation),optimize)
                self.execute(exe,'PIVA:42:0\n')
                for failure, expected in [('P','P'),('I','PI'),('V','PIV')]:
                    self.execute(exe,expected,failure)

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
    def test_rust_store_preserves_call_order(self):
        for opt in [False,True]:
            exe = self.rust_source(source('store'),opt)
            self.execute(exe,'PIVA:42:0\n')
            for failure, expected in [('P','P'),('I','PI'),('V','PIV')]:
                self.execute(exe,expected,failure)

    @unittest.skipUnless(RUSTC and Path(RUSTC).is_file(), 'actual Rust required')
    def test_rust_volatile_store_preserves_call_order(self):
        for opt in [False,True]:
            exe = self.rust_source(source('volatile_store'),opt)
            self.execute(exe,'PIVA:42:0\n')
            for failure, expected in [('P','P'),('I','PI'),('V','PIV')]:
                self.execute(exe,expected,failure)

    def nested(self, rust=False):
        text = IMPORTS + """
        fn nested_value() -> i64 effects {ffi,unsafe,write} {
            unsafe { store(destination(),offset(),payload()); } return 7;
        }
        fn main() -> Unit effects {ffi,unsafe,write} {
            unsafe { store(destination(),offset(),nested_value()); finish(); }
        }
        """
        for opt in [False, True]:
            exe = self.rust_source(text,opt) if rust else self.native_c(text,opt)
            self.execute(exe,'PIPIVA:7:0\n')

    def test_nested_store_c_uses_separate_operand_temporaries(self):
        self.nested()

    @unittest.skipUnless(RUSTC and Path(RUSTC).is_file(), 'actual Rust required')
    def test_nested_store_rust_uses_separate_operand_temporaries(self):
        self.nested(rust=True)

    def conditional(self, rust=False):
        for condition, expected in [('false && perform()', 'A:0:0\n'),
                                    ('true || perform()', 'A:0:0\n'),
                                    ('true && perform()', 'PIVA:42:0\n'),
                                    ('false || perform()', 'PIVA:42:0\n')]:
            text = IMPORTS + f"""
            fn perform() -> bool effects {{ffi,unsafe,write}} {{
                unsafe {{ store(destination(),offset(),payload()); }} return true;
            }}
            fn main() -> Unit effects {{ffi,unsafe,write}} {{
                unsafe {{ if {condition} {{ }} finish(); }}
            }}
            """
            for opt in [False,True]:
                exe = self.rust_source(text,opt) if rust else self.native_c(text,opt)
                self.execute(exe,expected)

    def test_c_stores_remain_inside_short_circuit_branches(self):
        self.conditional()

    @unittest.skipUnless(RUSTC and Path(RUSTC).is_file(), 'actual Rust required')
    def test_rust_stores_remain_inside_short_circuit_branches(self):
        self.conditional(rust=True)

    def test_unrelated_unsafe_and_index_rejections_remain(self):
        no_unsafe = 'fn main() -> Unit effects {write} {let mut a:[i64;1]=[0]; store(ptr_mut(mut a),0,1);}'
        const_store = 'fn main() -> Unit effects {unsafe,write} {let a:[i64;1]=[0]; unsafe {store(ptr_read(read a),0,1);}}'
        float_volatile = 'fn main() -> Unit effects {unsafe,write,io} {let mut a:[f64;1]=[0.0]; unsafe {volatile_store(ptr_mut(mut a),0,1.0);}}'
        for text, code in [(no_unsafe,'E_UNSAFE_REQUIRED'),(const_store,'E_READ_ONLY'),(float_volatile,'E_VOLATILE_TYPE')]:
            c = check(parse(text))
            self.assertFalse(c.ok)
            self.assertIn(code, {d.code for d in c.diagnostics})
        text = 'extern "C" fn next_index() -> usize effects {ffi}; fn main()->Unit effects {ffi,unsafe,panic} {let a:[i64;1]=[2]; unsafe {let v=a[next_index()];}}'
        p,c = frontend(text)
        with self.assertRaises(HeptaError) as caught:
            emit_c(p,c)
        self.assertEqual(caught.exception.diagnostic.code,'E_C_BACKEND_EVALUATION')

    def hepta_panic(self, rust=False):
        for target, returns, call, expected in [('pointer','raw mut i64','destination()','P'),
                                                ('index','usize','offset()','PI'),
                                                ('value','i64','payload()','PIV')]:
            args = ['destination()','offset()','payload()']
            args[['pointer','index','value'].index(target)] = 'fail_operand()'
            text = IMPORTS + f'''
            fn fail_operand() -> {returns} effects {{ffi,unsafe,panic}} {{
                unsafe {{ let observed={call}; assert(false); return observed; }}
            }}
            fn main()->Unit effects {{ffi,unsafe,panic,write}} {{
                unsafe {{store({','.join(args)});finish();}}
            }}
            '''
            for opt in [False,True]:
                exe = self.rust_source(text,opt) if rust else self.native_c(text,opt)
                # Any nonmatching marker leaves the foreign helper running;
                # the abort must come from the Hepta assert(false) itself.
                self.execute(exe,expected,failure='X')

    def test_c_hepta_operand_panics_stop_later_operands(self):
        self.hepta_panic()

    @unittest.skipUnless(RUSTC and Path(RUSTC).is_file(), 'actual Rust required')
    def test_rust_hepta_operand_panics_stop_later_operands(self):
        self.hepta_panic(rust=True)

    def index_snapshot(self, rust=False):
        text = IMPORTS + '''
        fn change(index:mut usize)->i64 effects {write,ffi,unsafe} {
            index=1; unsafe {return payload();}
        }
        fn main()->Unit effects {ffi,unsafe,write,panic} {
            let mut index:usize=0;
            unsafe {store(destination(),index,change(mut index));finish();}
            assert(index==1);
        }
        '''
        for opt in [False,True]:
            exe = self.rust_source(text,opt) if rust else self.native_c(text,opt)
            self.execute(exe,'PVA:42:0\n')

    def test_c_plain_index_is_snapshotted_before_value_mutates_it(self):
        self.index_snapshot()

    @unittest.skipUnless(RUSTC and Path(RUSTC).is_file(), 'actual Rust required')
    def test_rust_plain_index_is_snapshotted_before_value_mutates_it(self):
        self.index_snapshot(rust=True)
