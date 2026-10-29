"""Finite local-view source values execute through the existing HIA Core."""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.checker import check
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, execute_program
from hepta.hia_program_source import HIAProgramSourceRejected, lower_source
from hepta.hia_schema import SCHEMA, SCHEMA_V8
from hepta.parser import parse
from hepta.resource_ir import verify_resource_ir
from hepta.resource_lowering import lower_resource_ir
from tools.resource_view_cases import FRONTEND_REJECTIONS, NATIVE_REJECTIONS, SCOPED_NEIGHBOURS

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'examples/hia_program/source_local_views.hepta').read_text()
CLANG = os.environ.get('CLANG') or shutil.which('clang')
VIEW = "struct View<'a>{data:read 'a [u8],tag:u64}"
EDIT = "struct Edit<'a>{data:mut 'a [u8],tag:u64}"


def cases():
    """Source-independent arithmetic values for the declared finite corpus."""
    rows = []
    for n, byte in ((0, 0), (1, 0), (3, 19), (7, 255)):
        for early in (0, 1):
            rows.append(('shared_case', [n, byte, early], 35 + n + (byte if n and not early else 0)))
        for rounds in (0, 1, 3):
            final = (byte + rounds - 1) % 256 if n and rounds else 0
            rows.append(('mutable_case', [n, byte, rounds], rounds * (rounds + 1) // 2 + final))
        for choose in (0, 1):
            rows.append(('branch_case', [n, byte, choose],
                         17 + n + (byte if n else 0) if choose else 7 + n))
    rows.extend(('failure_case', [n], 43 + n) for n in (0, 1, 7))
    return rows


class HIASourceLocalViewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.core = lower_source(SOURCE)

    def clean(self, report, expected):
        self.assertEqual(report['status'], 'returned')
        self.assertEqual(report['result'], expected)
        resources = report['resources']
        self.assertEqual(resources['allocations'], resources['frees'])
        self.assertEqual(resources['owners_created'], resources['owners_dropped'])
        self.assertEqual(resources['loans_started'], resources['loans_ended'])
        for field in ('live_bytes', 'live_owners', 'live_local_loans'):
            self.assertEqual(resources[field], 0, field)

    def test_local_views_enter_same_core_and_preserve_shared_aliases(self):
        ast = parse(SOURCE)
        graph = lower_resource_ir(ast, check(ast))
        self.assertEqual(graph['schema'], 'hepta.resource-ir.v5')
        self.assertTrue(verify_resource_ir(graph)['ok'])
        for schema in (SCHEMA, SCHEMA_V8):
            core = lower_source(SOURCE, core_schema=schema)
            with patch('hepta.parser.parse', side_effect=AssertionError('Core consumer must not parse source')):
                canonical = verify_program(core.canonical_bytes)
                for n, byte, early in ((0, 0, 0), (3, 19, 0), (3, 19, 1)):
                    report = execute_program(canonical, 'shared_case', [n, byte, early])
                    self.clean(report, 35 + n + (byte if n and not early else 0))
            # Copying a shared record is an SSA alias, not a child reborrow.
            # Only the helper's original stored view and its actual indexed
            # byte access create capabilities within that function.
            fn = next(f for f in core.as_dict()['functions'] if f['name'] == 'shared_read')
            borrows = [op for b in fn['blocks'] for op in b['ops'] if op['op'] == 'borrow.read']
            self.assertEqual(len(borrows), 2)

    def test_mutable_views_move_drop_and_rejoin_each_loop(self):
        for entry, arguments, expected in cases():
            with self.subTest(entry=entry, arguments=arguments):
                self.clean(execute_program(self.core, entry, arguments), expected)

    def test_fallible_call_ends_local_views_on_each_return_path(self):
        for schema in (SCHEMA, SCHEMA_V8):
            core = lower_source(SOURCE, core_schema=schema)
            report = execute_program(core, 'failure_case', [7], allocation_fail_at=2)
            self.clean(report, 41)
            self.assertEqual(report['resources']['allocation_attempts'], 2)
            self.assertEqual(report['resources']['allocations'], 1)
            self.assertEqual(report['resources']['peak_bytes'], 3)
            self.clean(execute_program(core, 'shared_case', [7, 99, 0], allocation_fail_at=1), 1001)

    def test_existing_scoped_neighbours_use_canonical_core(self):
        core = lower_source(SCOPED_NEIGHBOURS)
        report = execute_program(core, 'main', [])
        self.assertEqual(report['status'], 'returned')
        self.assertEqual(report['resources']['allocations'], 2)
        self.assertEqual(report['resources']['frees'], 2)
        self.assertEqual(report['resources']['loans_started'], report['resources']['loans_ended'])

    def test_shared_alias_survives_inner_scope_and_each_early_return(self):
        source = VIEW + '''
fn inspect(data:read [u8], early:bool)->u64 effects{panic}{
    let outer=View{data:read data,tag:7};
    if true{let inner=outer;if early{return inner.tag;}assert(inner.tag==7);}
    return outer.tag+outer.data[0] as u64;
}
fn probe(early:bool)->u64 effects{alloc,block,panic}{
    let data=buffer(1);let answer=inspect(read data,early);drop(move data);return answer;
}'''
        core = lower_source(source)
        for early in (False, True):
            self.clean(execute_program(core, 'probe', [early]), 7)

    def test_view_ledger_at_every_prefix_does_not_invent_abort_cleanup(self):
        report = execute_program(self.core, 'mutable_case', [2, 91, 1])
        saw_stopped_live_loan = False
        for limit in range(1, report['steps']):
            with self.assertRaises(HIAProgramBudgetExceeded) as caught:
                execute_program(self.core, 'mutable_case', [2, 91, 1], max_steps=limit)
            ledger = caught.exception.report['resources']
            self.assertEqual(ledger['owners_created'] - ledger['owners_dropped'], ledger['live_owners'])
            self.assertEqual(ledger['loans_started'] - ledger['loans_ended'], ledger['live_local_loans'])
            saw_stopped_live_loan |= ledger['live_local_loans'] > 0
        self.assertTrue(saw_stopped_live_loan)

    def test_existing_invalid_aliases_and_escaping_storage_still_reject(self):
        for label, (source, _) in {**NATIVE_REJECTIONS, **FRONTEND_REJECTIONS}.items():
            for schema in (SCHEMA, SCHEMA_V8):
                with self.subTest(label=label, schema=schema), self.assertRaises(HIAProgramSourceRejected):
                    lower_source(source, core_schema=schema)
        excluded = {
            'view_return': VIEW + "fn f<'a>(b:read 'a [u8])->View<'a> effects{}{return View{data:read b,tag:7};}",
            'view_parameter': VIEW + "fn f<'a>(v:View<'a>)->u64 effects{}{return v.tag;}",
            'nested_view': VIEW + "struct Nest<'a>{v:View<'a>} fn f()->Unit effects{}{}",
            'two_loans': "struct Pair<'a>{a:read 'a [u8],b:read 'a [u8]} fn f()->Unit effects{}{}",
            'five_labels': "struct Many<'a>{data:read 'a [u8],a:u8,b:u8,c:u8,d:u8,e:u8} fn f()->Unit effects{}{}",
            'unused_float_label': "struct Float<'a>{data:read 'a [u8],label:f64} fn f()->Unit effects{}{}",
            'unused_wide_label': "struct Wide<'a>{data:read 'a [u8],label:u128} fn f()->Unit effects{}{}",
            'stored_returned_call': VIEW + '''fn view(b:read [u8])->read [u8] from b effects{}{return read b;}
                fn f(b:read [u8])->u64 effects{}{let v=View{data:view(read b),tag:7};return v.tag;}''',
            'standalone_stored_return': '''fn view(b:read [u8])->read [u8] from b effects{}{return read b;}
                fn f()->Unit effects{alloc,block,panic}{let b=buffer(1);let held=view(read b);drop(move b);assert(held[0]==0);}''',
            'mutable_missing_drop': EDIT + "fn f(b:mut [u8])->Unit effects{}{let v=Edit{data:mut b,tag:7};}",
            'view_shadow': VIEW + "fn f(b:read [u8])->u64 effects{}{let v=View{data:read b,tag:7};let v=v;return v.tag;}",
        }
        for label, source in excluded.items():
            with self.subTest(label=label), self.assertRaises((HIAProgramSourceRejected, ValueError)):
                lower_source(source, core_schema=SCHEMA_V8)

    def test_removed_loan_end_rejected_by_canonical_core(self):
        source = VIEW + "fn f(b:read [u8])->u64 effects{}{let view=View{data:read b,tag:7};return view.tag;}"
        document = lower_source(source).as_dict()
        ops = document['functions'][0]['blocks'][0]['ops']
        end = next(index for index, op in enumerate(ops) if op['op'] == 'loan.end')
        del ops[end]
        with self.assertRaises(HIAProgramRejected):
            verify_program(document)


@unittest.skipUnless(shutil.which('cargo'), 'Cargo unavailable: local-view Rust execution NOT qualified')
class HIASourceLocalViewRust(unittest.TestCase):
    observations = []

    def test_actual_rust_machine_matches_values_loans_failures_and_every_step(self):
        from tests.test_hia_rust_owned_cfg import RustByteOwnerCfgParity

        class Parity(unittest.TestCase):
            raw_run = RustByteOwnerCfgParity.raw_run
            parity = RustByteOwnerCfgParity.parity

        RustByteOwnerCfgParity.setUpClass.__func__(Parity)
        harness = Parity()
        type(self).build = Parity.build
        type(self).observations = Parity.observations
        type(self).programs = Parity.sources
        for schema, profile in ((SCHEMA, 'bounded-cfg-byte-owner-bulk-v3'),
                                (SCHEMA_V8, 'bounded-cfg-byte-owner-loan-returns-v4')):
            core = lower_source(SOURCE, core_schema=schema)
            harness.execution_profile = profile
            for entry, arguments, expected in cases():
                with self.subTest(schema=schema, entry=entry, arguments=arguments):
                    report = harness.parity(core, entry, arguments)
                    self.assertEqual(report['values'], [expected])
            harness.parity(core, 'failure_case', [7], fail=2)
            harness.parity(core, 'shared_case', [7, 99, 0], fail=1)
            for heap in (1, 3):
                harness.parity(core, 'failure_case', [7], heap=heap)
            completed = harness.parity(core, 'mutable_case', [2, 91, 1])
            for limit in range(1, completed['steps'] + 1):
                harness.parity(core, 'mutable_case', [2, 91, 1], steps=limit)


@unittest.skipUnless(CLANG, 'Clang unavailable: local-view native execution NOT qualified')
class HIASourceLocalViewNative(unittest.TestCase):
    records = []

    def test_source_rust_and_canonical_llvm_execute_same_finite_inputs(self):
        from hepta.backend import compile_rust, emit_rust
        from hepta.hia_program_llvm import build_program_native
        if not shutil.which('rustc'):
            self.skipTest('rustc unavailable: source-reference differential NOT qualified')
        ast = parse(SOURCE)
        generated = emit_rust(ast, check(ast), crate_type='cdylib')
        type(self).records = []
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rust_path = directory / 'source.so'
            rust_receipt = compile_rust(generated, crate_type='cdylib', output=rust_path, linker=CLANG)
            self.assertTrue(rust_receipt['ok'], rust_receipt)
            rust_library = ctypes.CDLL(str(rust_path))
            for schema in (SCHEMA, SCHEMA_V8):
                core = lower_source(SOURCE, core_schema=schema)
                llvm_path = directory / ('core-' + schema.rsplit('.', 1)[-1] + '.so')
                with patch('hepta.parser.parse', side_effect=AssertionError('native consumer must use Core')):
                    receipt = build_program_native(core.canonical_bytes, llvm_path, clang=CLANG)
                self.assertTrue(receipt['ok'], receipt)
                library = ctypes.CDLL(str(llvm_path))
                record = {'schema': schema, 'program_sha256': core.sha256,
                          'llvm_receipt': receipt, 'source_rust_receipt': rust_receipt,
                          'source_rust': generated, 'observations': []}
                type(self).records.append(record)
                for entry, arguments, expected in cases():
                    types = {'shared_case': [ctypes.c_size_t, ctypes.c_uint8, ctypes.c_uint8],
                             'mutable_case': [ctypes.c_size_t, ctypes.c_uint8, ctypes.c_size_t],
                             'branch_case': [ctypes.c_size_t, ctypes.c_uint8, ctypes.c_uint8],
                             'failure_case': [ctypes.c_size_t]}[entry]
                    actual = []
                    for backend in (library, rust_library):
                        function = getattr(backend, entry)
                        function.argtypes, function.restype = types, ctypes.c_uint64
                        actual.append(function(*arguments))
                    record['observations'].append({'entry': entry, 'arguments': arguments,
                                                   'expected': expected, 'llvm': actual[0], 'rust': actual[1]})
                    self.assertEqual(actual, [expected, expected])
            retained = os.environ.get('HIA_LOCAL_VIEW_NATIVE_DIR')
            if retained:
                shutil.copytree(directory, Path(retained) / 'differential')

    def test_actual_allocator_failure_preserves_local_view_cleanup(self):
        from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
        from tests.test_hia_source_partial import RESTORE_OBSERVER
        core = lower_source(SOURCE, core_schema=SCHEMA_V8)
        observer = RESTORE_OBSERVER.replace('extern size_t restore_try(void);', 'extern uint64_t failure_case(size_t);')
        observer = observer.replace('size_t value=restore_try();', 'size_t value=(size_t)failure_case(7);')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source, object_path, executable = directory / 'observer.c', directory / 'core.o', directory / 'run'
            source.write_text(observer)
            receipt = compile_program_llvm(emit_program_llvm(core), program=core,
                                           output=object_path, clang=CLANG, kind='object')
            self.assertTrue(receipt['ok'], receipt)
            command = [CLANG, '-std=c11', '-O2', str(source), str(object_path),
                       '-Wl,--wrap=malloc', '-Wl,--wrap=calloc', '-Wl,--wrap=free', '-o', str(executable)]
            built = subprocess.run(command, capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stderr)
            record = {'program_sha256': core.sha256, 'object_receipt': receipt, 'observer': observer,
                      'link': {'argv': command, 'returncode': built.returncode, 'stdout': built.stdout, 'stderr': built.stderr},
                      'observations': []}
            type(self).allocator = record
            for failure, expected, allocations, peak in ((0, 50, 2, 10), (2, 41, 1, 3)):
                run = subprocess.run([str(executable), str(failure)], capture_output=True, text=True, timeout=20)
                record['observations'].append({'failure': failure, 'returncode': run.returncode,
                                              'stdout': run.stdout, 'stderr': run.stderr})
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(json.loads(run.stdout), {'value': expected, 'attempts': 2,
                    'allocations': allocations, 'frees': allocations, 'live_bytes': 0, 'peak_bytes': peak})
            record['binary_sha256'] = hashlib.sha256(executable.read_bytes()).hexdigest()
            retained = os.environ.get('HIA_LOCAL_VIEW_NATIVE_DIR')
            if retained:
                shutil.copytree(directory, Path(retained) / 'allocator')


if __name__ == '__main__':
    unittest.main()
