"""Checked source partial restoration reaches the real executable authority."""
from __future__ import annotations

from copy import deepcopy
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.checker import check
from hepta.hia_heap_bound import qualify_live_heap_budget
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap, execute_program
from hepta.hia_program_source import HIAProgramSourceRejected, lower_program, lower_source
from hepta.hia_schema import SCHEMA_V8
from hepta.hia_static_budget import HIAStaticBudgetRejected, analyze_static_budget, qualify_vm_call_depth
from hepta.parser import parse
from hepta.resource_ir import verify_resource_ir
from hepta.resource_lowering import lower_resource_ir

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'examples/hia_program/source_partial_restore.hepta').read_text()
RETURNED_SOURCE = (ROOT / 'examples/hia_program/source_partial_returned_calls.hepta').read_text()
# cancel, allocation failure, result, allocations/frees, peak payload, attempts.
# These expectations follow the fixture's two initial owners and explicit paths.
RETURNED_CASES = ((False, None, 65, 3, 14, 3),
                  (True, None, 17, 2, 8, 2),
                  (False, 3, 18, 2, 8, 3))
CLANG = os.environ.get('CLANG') or shutil.which('clang')
DECL = 'struct Pair{left:Buffer<u8>,right:Buffer<u8>,tag:u64}'
INIT = 'let mut p=Pair{left:buffer(3),right:buffer(5),tag:7};'

RESTORE_OBSERVER = r'''
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
void *__real_malloc(size_t); void *__real_calloc(size_t,size_t); void __real_free(void *);
static void *addresses[8]; static size_t sizes[8];
static size_t attempts, allocations, frees, live_bytes, peak_bytes, fail_at;
static void *remember(void *p,size_t n){
    if(!p)return p; size_t i=0;while(i<8&&addresses[i])i++;if(i==8)exit(81);
    addresses[i]=p;sizes[i]=n;allocations++;live_bytes+=n;
    if(live_bytes>peak_bytes)peak_bytes=live_bytes;return p;
}
void *__wrap_malloc(size_t n){
    attempts++;if(attempts==fail_at)return NULL;return remember(__real_malloc(n),n);
}
void *__wrap_calloc(size_t n,size_t w){
    attempts++;if(attempts==fail_at)return NULL;return remember(__real_calloc(n,w),n*w);
}
void __wrap_free(void *p){
    if(!p)exit(82);size_t i=0;while(i<8&&addresses[i]!=p)i++;if(i==8)exit(83);
    frees++;live_bytes-=sizes[i];addresses[i]=NULL;__real_free(p);
}
extern size_t restore_try(void);
int main(int argc,char **argv){
    if(argc!=2)return 84;fail_at=(size_t)strtoull(argv[1],NULL,10);
    size_t value=restore_try();
    printf("{\"value\":%zu,\"attempts\":%zu,\"allocations\":%zu,\"frees\":%zu,"
           "\"live_bytes\":%zu,\"peak_bytes\":%zu}\n",value,attempts,allocations,frees,live_bytes,peak_bytes);
    return live_bytes ? 85 : 0;
}
'''


def standalone_function(name):
    """Select a real checked source function, keeping its record declarations."""
    ast = parse(SOURCE)
    ast.functions = [fn for fn in ast.functions if fn.name == name]
    return lower_program(ast)


class HIASourcePartialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.core = lower_source(SOURCE)

    def assert_clean(self, report, *, result, allocations, peak):
        self.assertEqual(report['status'], 'returned')
        self.assertEqual(report['result'], result)
        ledger = report['resources']
        self.assertEqual(ledger['allocations'], allocations)
        self.assertEqual(ledger['frees'], allocations)
        self.assertEqual(ledger['peak_bytes'], peak)
        self.assertEqual(ledger['live_bytes'], 0)
        self.assertEqual(ledger['live_owners'], 0)
        self.assertEqual(ledger['live_local_loans'], 0)
        self.assertEqual(ledger['owners_created'], ledger['owners_dropped'])

    def test_checker_independent_resource_ir_and_canonical_core_all_accept(self):
        ast = parse(SOURCE)
        checked = check(ast)
        self.assertTrue(checked.ok, [d.to_dict() for d in checked.diagnostics])
        self.assertTrue(verify_resource_ir(lower_resource_ir(ast, checked))['ok'])
        with patch('hepta.parser.parse', side_effect=AssertionError('standalone execution must not parse source')):
            canonical = verify_program(self.core.canonical_bytes)
            self.assert_clean(execute_program(canonical, 'restore', []), result=14, allocations=3, peak=14)

    def test_restore_after_explicit_field_release(self):
        self.assert_clean(execute_program(self.core, 'restore', []), result=14, allocations=3, peak=14)

    def test_fallible_restoration_consumes_success_or_empty_error_slot(self):
        self.assert_clean(execute_program(self.core, 'restore_try', []), result=14, allocations=3, peak=14)
        failed = execute_program(self.core, 'restore_try', [], allocation_fail_at=3)
        self.assert_clean(failed, result=1, allocations=2, peak=8)
        self.assertEqual(failed['resources']['allocation_attempts'], 3)
        self.assertEqual(failed['resources']['owners_created'], 3)

    def test_both_branch_initialization_states_reach_same_core_join(self):
        for flag, result in [(1, 14), (0, 9)]:
            with self.subTest(flag=flag):
                self.assert_clean(execute_program(self.core, 'branch_restore', [flag]),
                                  result=result, allocations=3, peak=result)

    def test_early_cancel_drops_only_remaining_initialized_field(self):
        self.assert_clean(execute_program(self.core, 'cancel_restore', [1]), result=33, allocations=2, peak=8)
        self.assert_clean(execute_program(self.core, 'cancel_restore', [0]), result=14, allocations=3, peak=14)

    def test_loop_restores_same_linear_state_on_each_backedge(self):
        for rounds in (0, 1, 3):
            with self.subTest(rounds=rounds):
                self.assert_clean(execute_program(self.core, 'loop_restore', [rounds]),
                                  result=8, allocations=2 + rounds, peak=8)

    def test_nested_generic_restore_preserves_preexisting_scalar_copy(self):
        self.assert_clean(execute_program(self.core, 'nested_restore', []), result=32, allocations=3, peak=14)

    def test_real_static_and_payload_analyzers_qualify_acyclic_restoration(self):
        for name in ('restore', 'restore_try', 'branch_restore', 'cancel_restore'):
            with self.subTest(name=name):
                core = standalone_function(name)
                static = analyze_static_budget(core, max_allocator_interactions=6, max_vm_ticks=50,
                                               max_call_depth=1, max_live_heap_bytes=14)
                heap = qualify_live_heap_budget(core, max_live_heap_bytes=14)
                self.assertEqual(static['core_sha256'], core.sha256)
                self.assertEqual(heap['peak_bounds'], {name: 14})
                self.assertFalse(heap['claims']['process_rss_bounded'])

    def test_loop_frame_bound_does_not_promise_tick_termination(self):
        core = standalone_function('loop_restore')
        frames = qualify_vm_call_depth(core, max_call_depth=1)
        self.assertEqual(frames['functions'], [{'function': 'loop_restore', 'max_call_depth': 1}])
        with self.assertRaisesRegex(HIAStaticBudgetRejected, 'E_HIA_BUDGET_UNBOUNDED'):
            analyze_static_budget(core)

    def test_restoration_can_transfer_a_disjoint_remaining_field(self):
        source = (DECL + 'fn transfer()->usize effects{alloc,block,panic}{' + INIT
                  + 'release(move p.left);p.left=move p.right;'
                    'let n=len(p.left);release(move p.left);return n;}')
        self.assert_clean(execute_program(lower_source(source), 'transfer', []),
                          result=5, allocations=2, peak=8)

    def test_every_normal_prefix_retains_actual_stopped_ledger(self):
        full = execute_program(self.core, 'restore', [])
        for limit in range(1, full['steps']):
            with self.subTest(limit=limit):
                with self.assertRaises(HIAProgramBudgetExceeded) as stopped:
                    execute_program(self.core, 'restore', [], max_steps=limit)
                report = stopped.exception.report
                self.assertEqual(report['steps'], limit + 1)
                ledger = report['resources']
                self.assertEqual(ledger['owners_created'] - ledger['owners_dropped'], ledger['live_owners'])
                self.assertLessEqual(ledger['peak_bytes'], 14)
        with self.assertRaises(HIAProgramTrap) as trapped:
            execute_program(self.core, 'restore', [], allocation_fail_at=3)
        self.assertEqual(trapped.exception.report['resources']['live_bytes'], 5)
        self.assertEqual(trapped.exception.report['resources']['live_owners'], 1)

    def test_invalid_partial_source_combinations_reject_freshly(self):
        bad = [
            (INIT + 'p.left=buffer(9);drop(move p);', 'E_LINEAR_REASSIGN'),
            (INIT + 'drop(move p);p.left=buffer(9);', 'E_USE_AFTER_MOVE'),
            (INIT + 'release(move p.left);drop(move p);', 'E_USE_AFTER_MOVE'),
            (INIT + 'release(move p.left);release(move p.left);release(move p.right);', 'E_USE_AFTER_MOVE'),
            (INIT + 'if true{release(move p.left);}else{release(move p.right);}drop(move p);', 'E_LINEAR_BRANCH'),
            (INIT + 'for i in 0..3{release(move p.left);}release(move p.right);', 'E_LINEAR_LOOP'),
            (INIT.replace('let mut', 'let') + 'release(move p.left);p.left=buffer(9);drop(move p);', 'E_LINEAR_REASSIGN'),
            (INIT + 'release(move p.left);', 'E_LINEAR_UNCONSUMED'),
        ]
        for body, code in bad:
            with self.subTest(code=code, body=body):
                source = DECL + 'fn bad()->Unit effects{alloc,block,panic}{' + body + '}'
                checked = check(parse(source))
                self.assertFalse(checked.ok)
                self.assertIn(code, [d.code for d in checked.diagnostics])
                with self.assertRaises(HIAProgramSourceRejected):
                    lower_source(source)

    def test_tampered_normalized_cleanup_and_live_loan_move_are_rejected(self):
        document = standalone_function('restore').as_dict()
        ops = document['functions'][0]['blocks'][0]['ops']
        removed = deepcopy(document)
        removed_ops = removed['functions'][0]['blocks'][0]['ops']
        del removed_ops[next(index for index, op in enumerate(removed_ops) if op['op'] == 'owner.drop')]
        with self.assertRaises(HIAProgramRejected):
            verify_program(removed)
        take_index = next(index for index, op in enumerate(ops) if op['op'] == 'owner.move')
        owner = ops[take_index]['args'][0]
        ops.insert(take_index, {'op': 'borrow.read', 'args': [owner],
                              'out': [{'name': 'forged_live_loan', 'type': 'readbuf'}], 'attrs': {}})
        with self.assertRaisesRegex(HIAProgramRejected, 'E_HIA_LOAN'):
            verify_program(document)

    @unittest.skipUnless(CLANG, 'Clang unavailable: partial-source native execution NOT qualified')
    def test_native_failure_restoration_releases_remaining_owner_and_empty_slot(self):
        from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
        core = standalone_function('restore_try')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source, object_path, executable = directory / 'observer.c', directory / 'core.o', directory / 'run'
            source.write_text(RESTORE_OBSERVER)
            compiled = compile_program_llvm(emit_program_llvm(core), program=core,
                                            output=object_path, clang=CLANG, kind='object')
            self.assertTrue(compiled['ok'], compiled)
            built = subprocess.run([CLANG, '-std=c11', '-O2', str(source), str(object_path),
                                    '-Wl,--wrap=malloc', '-Wl,--wrap=calloc', '-Wl,--wrap=free',
                                    '-o', str(executable)], capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stderr)
            for failure, value, allocations, peak in [(0, 14, 3, 14), (3, 1, 2, 8)]:
                with self.subTest(failure=failure):
                    run = subprocess.run([str(executable), str(failure)], capture_output=True, text=True, timeout=10)
                    self.assertEqual(run.returncode, 0, run.stderr)
                    self.assertEqual(json.loads(run.stdout), {
                        'value': value, 'attempts': 3, 'allocations': allocations,
                        'frees': allocations, 'live_bytes': 0, 'peak_bytes': peak})

    @unittest.skipUnless(CLANG, 'Clang unavailable: partial-source native execution NOT qualified')
    def test_native_llvm_executes_restoration_cfg_without_source(self):
        from hepta.hia_program_llvm import build_program_native
        cases = [('restore', [], [], 14), ('restore_try', [], [], 14),
                 ('branch_restore', [ctypes.c_uint8], [1], 14),
                 ('branch_restore', [ctypes.c_uint8], [0], 9),
                 ('cancel_restore', [ctypes.c_uint8], [1], 33),
                 ('cancel_restore', [ctypes.c_uint8], [0], 14),
                 ('loop_restore', [ctypes.c_size_t], [3], 8), ('nested_restore', [], [], 32)]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'restoration.so'
            with patch('hepta.parser.parse', side_effect=AssertionError('native consumer must use Core')):
                built = build_program_native(self.core.canonical_bytes, output, clang=CLANG)
            self.assertTrue(built['ok'], built)
            library = ctypes.CDLL(str(output))
            for name, types, arguments, expected in cases:
                with self.subTest(name=name, arguments=arguments):
                    function = getattr(library, name)
                    function.argtypes, function.restype = types, ctypes.c_size_t
                    self.assertEqual(function(*arguments), expected)


    @unittest.skipUnless(shutil.which('cargo'), 'Cargo unavailable: partial/returned-loan Rust parity NOT qualified')
    def test_partial_restoration_returned_calls_match_independent_rust_vm(self):
        from tests.test_hia_rust_owned_cfg import RustByteOwnerCfgParity

        # Reuse the existing raw Rust protocol and complete-ledger comparator
        # without inheriting additional discoverable tests or another runtime.
        class Parity(unittest.TestCase):
            execution_profile = 'bounded-cfg-byte-owner-loan-returns-v4'
            raw_run = RustByteOwnerCfgParity.raw_run
            parity = RustByteOwnerCfgParity.parity

        core = lower_source(RETURNED_SOURCE, core_schema=SCHEMA_V8)
        with patch('hepta.parser.parse', side_effect=AssertionError('canonical consumers must not parse source')):
            canonical = verify_program(core.canonical_bytes)
        self.assertEqual(canonical.sha256, core.sha256)
        body = canonical.as_dict()
        self.assertEqual(body['schema'], SCHEMA_V8)
        self.assertEqual(body['exports'], ['probe'])
        self.assertEqual(canonical.scalar_entrypoints, frozenset({'probe'}))
        functions = {fn['name']: fn for fn in body['functions']}
        self.assertEqual(set(functions), {'marker_word', 'view', 'edit', 'probe'})
        for name in ('view', 'edit'):
            fn = functions[name]
            self.assertEqual(fn['return_loans'], [fn['params'][0]['name']])
            self.assertNotIn('return_origins', fn)
        calls = {op['attrs']['function'] for block in functions['probe']['blocks']
                 for op in block['ops'] if op['op'] == 'call'}
        self.assertEqual(calls, {'view', 'edit'})

        RustByteOwnerCfgParity.setUpClass.__func__(Parity)
        harness = Parity()
        type(self).returned_call_rust = {
            'program_sha256': canonical.sha256, 'program': body,
            'build': Parity.build, 'executable': Parity.executable,
            'observations': Parity.observations,
        }
        for choose in (False, True):
            for cancel, failure, value, allocations, peak, attempts in RETURNED_CASES:
                with self.subTest(choose=choose, cancel=cancel, failure=failure):
                    rust = harness.parity(canonical, 'probe', [choose, cancel], fail=failure)
                    python = Parity.observations[-1]['python']
                    self.assert_clean(python, result=value, allocations=allocations, peak=peak)
                    self.assertEqual(rust['values'], [value])
                    self.assertEqual(rust['resources']['allocation_attempts'], attempts)
                    self.assertEqual(rust['resources']['loans_started'], rust['resources']['loans_ended'])
        self.assertEqual(len(Parity.observations), 6)

    @unittest.skipUnless(CLANG, 'Clang unavailable: partial/returned-loan native execution NOT qualified')
    def test_native_partial_restoration_returned_calls_use_independent_allocator_oracle(self):
        from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm

        core = lower_source(RETURNED_SOURCE, core_schema=SCHEMA_V8)
        canonical = verify_program(core.canonical_bytes)
        ir = emit_program_llvm(canonical)
        self.assertEqual(ir.exports, ('probe',))
        self.assertEqual(ir.profile, 'hepta.hia.program.llvm-linux-x86_64-parameter-loan-returns.v8')
        # Keep the same actual allocator observer. Only its declared scalar
        # entry and argv dispatch change; no source C ABI is inferred here.
        observer = RESTORE_OBSERVER.replace('extern size_t restore_try(void);',
                                            'extern size_t probe(_Bool, _Bool);')
        observer = observer.replace('if(argc!=2)', 'if(argc!=4)')
        observer = observer.replace('size_t value=restore_try();',
                                    'size_t value=probe((_Bool)strtoul(argv[2],NULL,10),'
                                    '(_Bool)strtoul(argv[3],NULL,10));')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source, object_path, executable = directory / 'observer.c', directory / 'core.o', directory / 'run'
            source.write_text(observer)
            with patch('hepta.parser.parse', side_effect=AssertionError('native compilation must use canonical Core')):
                compiled = compile_program_llvm(ir, program=canonical,
                                                output=object_path, clang=CLANG, kind='object')
            self.assertTrue(compiled['ok'], compiled)
            built = subprocess.run([CLANG, '-std=c11', '-O2', str(source), str(object_path),
                                    '-Wl,--wrap=malloc', '-Wl,--wrap=calloc', '-Wl,--wrap=free',
                                    '-o', str(executable)], capture_output=True, text=True, timeout=30)
            record = type(self).returned_call_native = {
                'program_sha256': core.sha256, 'program': core.as_dict(), 'llvm': ir.text,
                'observer_source': observer, 'object_receipt': compiled,
                'link': {'argv': built.args, 'returncode': built.returncode,
                         'stdout': built.stdout, 'stderr': built.stderr}, 'observations': [],
            }
            self.assertEqual(built.returncode, 0, built.stderr)
            retained = os.environ.get('HIA_SOURCE_PARTIAL_RETURNED_NATIVE_DIR')
            if retained:
                # Retain the exact built files for a caller collecting this
                # finite regression; later process failures cannot erase them.
                destination = Path(retained) / 'native'
                shutil.copytree(directory, destination)
                record['retained_artifacts'] = str(destination)
            for choose in (False, True):
                for cancel, failure, value, allocations, peak, attempts in RETURNED_CASES:
                    with self.subTest(choose=choose, cancel=cancel, failure=failure):
                        run = subprocess.run([str(executable), str(failure or 0),
                                              str(int(choose)), str(int(cancel))],
                                             capture_output=True, text=True, timeout=10)
                        record['observations'].append({
                            'choose': choose, 'cancel': cancel, 'allocation_fail_at': failure,
                            'process': {'argv': run.args, 'returncode': run.returncode,
                                        'stdout': run.stdout, 'stderr': run.stderr},
                        })
                        self.assertEqual(run.returncode, 0, run.stderr)
                        self.assertEqual(run.stderr, '')
                        self.assertEqual(json.loads(run.stdout), {
                            'value': value, 'attempts': attempts, 'allocations': allocations,
                            'frees': allocations, 'live_bytes': 0, 'peak_bytes': peak})


if __name__ == '__main__':
    unittest.main()
