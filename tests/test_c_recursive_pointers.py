"""Recursive raw-pointer records use finite layouts and real external callers."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.backend import emit_header, emit_rust
from hepta.c_backend import emit_c
from hepta.checker import check
from hepta.parser import parse

CC = os.environ.get('CC') or shutil.which('gcc')
RUSTC = os.environ.get('RUSTC') or shutil.which('rustc')
SOURCE = '''
repr(C) struct Node { next: raw mut Node, value: i64 }
repr(C) struct Left { right: raw const Right, value: i64 }
repr(C) struct Right { left: raw mut Left, value: i64 }
extern "C" fn host_node(n: Node) -> i64 effects { ffi };
export "C" fn sum(p: raw const Node, count: usize) -> i64 effects { unsafe, panic } {
    let mut current: raw const Node = p;
    let mut total: i64 = 0;
    for i in 0..count {
        unsafe { let node: Node = load(current, 0); total = total + node.value;
                 current = node.next as raw const Node; }
    }
    return total;
}
export "C" fn update(p: raw mut Node, value: i64) -> i64 effects { unsafe, ffi, write } {
    unsafe { let node: Node = load(p, 0);
        let replacement: Node = Node { next: node.next, value: value };
        store(p, 0, replacement); return host_node(replacement); }
}
export "C" fn identity(n: Node) -> Node effects {} { return n; }
export "C" fn mutual(p: raw const Left) -> i64 effects { unsafe, panic } {
    unsafe { let a: Left = load(p, 0); let b: Right = load(a.right, 0);
        let again: Left = load(b.left, 0); return a.value + b.value + again.value; }
}
'''
HARNESS = '''
#include "api.h"
#include <assert.h>
#include <stddef.h>
_Static_assert(sizeof(hepta_Node) == 16, "qualified 64-bit Node ABI");
_Static_assert(offsetof(hepta_Node, value) == 8, "Node field offset");
_Static_assert(_Alignof(hepta_Node) == _Alignof(void *), "Node alignment");
int64_t host_node(hepta_Node n) { return n.value + (n.next ? n.next->value : 0); }
int main(void) {
    hepta_Node tail = {NULL, 17}, head = {&tail, 5};
    assert(sum(&head, 2) == 22);
    assert(update(&head, 9) == 26 && head.value == 9 && head.next == &tail);
    hepta_Node copy = identity(head);
    assert(copy.value == 9 && copy.next == &tail && sum(&copy, 2) == 26);
    hepta_Left left; hepta_Right right;
    left.right = &right; left.value = 3; right.left = &left; right.value = 8;
    assert(mutual(&left) == 14);
    return 0;
}
'''


def frontend(source):
    program = parse(source)
    checked = check(program)
    if not checked.ok:
        raise AssertionError([d.to_dict() for d in checked.diagnostics])
    return program, checked


@unittest.skipUnless(CC, 'native GCC required')
class CRecursivePointerTests(unittest.TestCase):
    def compile_run(self, source, harness=None):
        p, c = frontend(source)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'source.c').write_text(emit_c(p, c, crate_type='staticlib' if harness else 'bin'))
            paths = [str(root / 'source.c')]
            if harness:
                (root / 'api.h').write_text(emit_header(p))
                (root / 'caller.c').write_text(harness)
                paths.append(str(root / 'caller.c'))
            for opt in ('-O0', '-O3'):
                exe = root / 'native'
                result = subprocess.run([CC, '-std=c11', opt, '-flto', '-Werror=lto-type-mismatch',
                    '-Werror=incompatible-pointer-types', '-fsanitize=undefined', '-fno-sanitize-recover=all',
                    *paths, '-lm', '-o', str(exe)], capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertNotIn('runtime error:', run.stderr)

    def test_external_self_and_mutual_records_pointer_and_value_abi(self):
        self.compile_run(SOURCE, HARNESS)

    def test_pointer_broken_mixed_value_dependency_and_declaration_order(self):
        for declarations in (
            'struct A { b: raw const B } struct B { a: A, value: i64 }',
            'struct B { a: A, value: i64 } struct A { b: raw const B }'):
            self.compile_run(declarations + ' fn main() -> Unit effects {} {}')

    def test_generic_recursive_pointers_and_internal_names(self):
        self.compile_run('''struct Node<T> { next: raw const Node<T>, value: T }
            struct __hepta_cb_aggregate_0 { value: i64 }
            fn accept(p: raw const Node<i64>, q: raw const Node<u8>) -> Unit effects {} {}
            fn main() -> Unit effects {} {}''')

    def test_indirect_pointer_aliases_and_constness(self):
        self.compile_run('enum Link { End, Next(raw const Link) } fn main() -> Unit effects {} {}')
        self.compile_run('''struct Node { next: raw const raw mut Node, value: i64 }
            fn main() -> Unit effects {} {}''')
        bad = 'repr(C) struct Node { next: raw const Node } fn write(p: raw const Node, n: Node) -> Unit effects { unsafe } { unsafe { store(p,0,n); } }'
        self.assertFalse(check(parse(bad)).ok)

    def test_by_value_cycles_still_rejected(self):
        for source in ('struct A { a: A }', 'struct A { b: B } struct B { a: A }',
                       'struct A { entries: [A; 2] }'):
            checked = check(parse(source))
            self.assertIn('E_RECURSIVE_LAYOUT', [d.code for d in checked.diagnostics])

    def test_expanding_generic_pointer_chain_is_bounded(self):
        p, c = frontend('struct Node<T> { next: raw const Node<[T; 2]> } '
                        'fn accept(p: raw const Node<i64>) -> Unit effects {} {} '
                        'fn main() -> Unit effects {} {}')
        with self.assertRaises(HeptaError) as caught:
            emit_c(p, c)
        self.assertEqual(caught.exception.diagnostic.code, 'E_C_SPECIALIZATION_LIMIT')

    @unittest.skipUnless(RUSTC, 'Rust reference compiler unavailable')
    def test_external_caller_against_real_rust_reference(self):
        p, c = frontend(SOURCE)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'api.h').write_text(emit_header(p))
            (root / 'caller.c').write_text(HARNESS)
            (root / 'source.rs').write_text(emit_rust(p, c, crate_type='staticlib'))
            archive = root / 'reference.a'
            result = subprocess.run([RUSTC, '--edition=2021', '--crate-type=staticlib',
                str(root / 'source.rs'), '-o', str(archive)], capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            exe = root / 'native'
            result = subprocess.run([CC, str(root / 'caller.c'), str(archive), '-ldl', '-lpthread', '-lm',
                '-o', str(exe)], capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
