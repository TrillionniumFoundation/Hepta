"""Finite unit enums lower to existing Core; native claims require real tools."""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.checker import check
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_llvm import emit_program_llvm
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap, execute_program
from hepta.hia_program_source import HIAProgramSourceRejected, lower_source, source_report
from hepta.hia_routes import admit_route
from hepta.hia_rust_crosscheck import HIARustCrosscheckRejected, crosscheck_rust_execution
from hepta.hia_schema import SCHEMA, SCHEMA_V8
from hepta.parser import parse
from hepta.resource_ir import verify_resource_ir
from hepta.resource_lowering import lower_resource_ir

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'examples/hia_program/source_unit_enums.hepta').read_text()
CLANG = os.environ.get('CLANG') or shutil.which('clang')
NM = shutil.which('llvm-nm') or shutil.which('nm')
ENTRIES = frozenset({'cycle_case', 'record_case', 'once_case', 'only_case', 'packet_case'})
INTERNAL = frozenset({'error_score', 'phase_score', 'next_phase', 'make_phase', 'pick', 'make_packet'})


def cases():
    """Independent finite arithmetic expectations, not another enum evaluator."""
    rows = []
    for rounds, total, final in ((0, 0, 4), (1, 17, 17), (2, 46, 29),
                                 (3, 50, 4), (5, 96, 29)):
        rows.extend([('cycle_case', [rounds], total),
                     ('record_case', [rounds], final + 4 + rounds)])
    rows.extend(('once_case', [choice], answer)
                for choice, answer in ((0, 1004), (1, 1017), (2, 1029), (255, 1029)))
    rows.append(('only_case', [], 99))
    for size, byte in ((0, 19), (1, 0), (5, 19), (8, 255), (9, 37)):
        for cancel in (0, 1):
            expected = 101 if size == 0 else 202 if size > 8 else 900 if cancel else size + byte + 57
            rows.append(('packet_case', [size, byte, cancel], expected))
    return rows


def invalid_tag_probe(core):
    """Explicit primitive adversary; never expose the nominal source helper."""
    document = core.as_dict()
    document['functions'].append({
        'name': 'invalid_probe', 'params': [{'name': 'tag', 'type': 'u32'}],
        'returns': ['u64'], 'effects': ['trap'], 'entry': 'entry',
        'blocks': [{'id': 'entry', 'params': [{'name': 'tag', 'type': 'u32'}],
                    'ops': [{'op': 'call', 'args': ['tag'],
                             'out': [{'name': 'answer', 'type': 'u64'}],
                             'attrs': {'function': 'error_score'}}],
                    'term': {'op': 'ret', 'values': ['answer']}}]})
    document['exports'].append('invalid_probe')
    return verify_program(document)


class HIASourceUnitEnumTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cores = {schema: lower_source(SOURCE, core_schema=schema) for schema in (SCHEMA, SCHEMA_V8)}

    def clean(self, report, expected):
        self.assertEqual(report['status'], 'returned')
        self.assertEqual(report['values'], [expected])
        ledger = report['resources']
        for field in ('live_owners', 'live_local_loans', 'live_bytes'):
            self.assertEqual(ledger[field], 0, field)
        self.assertEqual(ledger['allocations'], ledger['frees'])
        self.assertEqual(ledger['owners_created'], ledger['owners_dropped'])
        self.assertEqual(ledger['loans_started'], ledger['loans_ended'])

    def test_existing_source_checker_resource_ir_and_same_core_all_accept(self):
        ast = parse(SOURCE)
        checked = check(ast)
        self.assertTrue(checked.ok, [d.to_dict() for d in checked.diagnostics])
        self.assertTrue(verify_resource_ir(lower_resource_ir(ast, checked))['ok'])
        for schema, core in self.cores.items():
            report = source_report(SOURCE, core_schema=schema)
            self.assertEqual(report['unit_enums']['declarations']['BuildError'],
                             ['Empty', 'AboveLimit', 'AllocationFailed'])
            self.assertFalse(report['unit_enums']['payloads_or_generic_enums'])
            self.assertFalse(report['unit_enums']['public_enum_abi'])
            with patch('hepta.parser.parse', side_effect=AssertionError('Core cannot parse source')):
                restored = verify_program(core.canonical_bytes)
                for entry, arguments, expected in cases():
                    with self.subTest(schema=schema, entry=entry, arguments=arguments):
                        self.clean(execute_program(restored, entry, arguments), expected)

    def test_source_route_and_public_execution_reject_erased_enum_helpers(self):
        for schema in (SCHEMA, SCHEMA_V8):
            core = admit_route('hepta-source', SOURCE, core_schema=schema)
            self.assertEqual(core.scalar_entrypoints, ENTRIES)
            self.assertEqual(verify_program(core.canonical_bytes).scalar_entrypoints, ENTRIES)
            self.assertEqual(set(emit_program_llvm(core).exports), ENTRIES)
            names = {fn['name'] for fn in core.as_dict()['functions']}
            specialized = {row['instance'] for row in source_report(SOURCE, core_schema=schema)['specializations']
                           if row['kind'] == 'fn'}
            self.assertTrue(INTERNAL | specialized <= names)
            self.assertTrue((INTERNAL | specialized).isdisjoint(core.scalar_entrypoints))
            for helper, arguments in (('error_score', [0]), ('phase_score', [0]),
                                      ('next_phase', [0]), ('make_phase', [0]), ('pick', [0, 0])):
                with self.subTest(schema=schema, helper=helper), self.assertRaises(HIAProgramRejected):
                    execute_program(core, helper, arguments)

    def test_invalid_core_tag_traps_instead_of_selecting_last_variant(self):
        for core in self.cores.values():
            probe = invalid_tag_probe(core)
            for value, expected in ((0, 101), (1, 202), (2, 303)):
                self.clean(execute_program(probe, 'invalid_probe', [value]), expected)
            for value in (3, (1 << 32) - 1):
                with self.assertRaises(HIAProgramTrap) as caught:
                    execute_program(probe, 'invalid_probe', [value])
                self.assertEqual(caught.exception.report['error']['code'], 'user')

    def test_result_error_enum_and_real_owner_cleanup_at_failure(self):
        for core in self.cores.values():
            normal = execute_program(core, 'packet_case', [5, 19, 0])
            self.clean(normal, 81)
            self.assertEqual(normal['resources']['allocations'], 2)
            self.assertEqual(normal['resources']['peak_bytes'], 8)
            failed = execute_program(core, 'packet_case', [5, 19, 0], allocation_fail_at=2)
            self.clean(failed, 303)
            self.assertEqual(failed['resources']['allocations'], 1)
            self.assertEqual(failed['resources']['allocation_attempts'], 2)
            self.assertEqual(failed['resources']['peak_bytes'], 3)
            self.assertEqual(failed['resources']['owners_created'], 3)

    def test_step_stops_keep_real_partial_ledger_without_implicit_cleanup(self):
        core = self.cores[SCHEMA_V8]
        completed = execute_program(core, 'packet_case', [5, 19, 0])
        saw_live = False
        for limit in range(1, completed['steps']):
            with self.assertRaises(HIAProgramBudgetExceeded) as caught:
                execute_program(core, 'packet_case', [5, 19, 0], max_steps=limit)
            ledger = caught.exception.report['resources']
            self.assertEqual(ledger['owners_created'] - ledger['owners_dropped'], ledger['live_owners'])
            saw_live |= ledger['live_owners'] > 0
        self.assertTrue(saw_live)

    def test_unit_enum_match_preserves_scoped_shared_view_aliases(self):
        source = '''enum Choice{Left,Right}
struct View<'a>{data:read 'a [u8]}
fn inspect(b:read [u8],right:bool)->u64 effects{panic}{
 let outer=View{data:read b};let mut choice=Choice::Left;
 if right{choice=Choice::Right;}
 match choice{
  Choice::Left=>{let inner=outer;return len(inner.data) as u64;},
  Choice::Right=>{return len(outer.data) as u64+1;},
 }
}
fn probe(right:bool)->u64 effects{alloc,block,panic}{
 let b=buffer(3);let result=inspect(read b,right);drop(move b);return result;
}'''
        for schema in (SCHEMA, SCHEMA_V8):
            core = lower_source(source, core_schema=schema)
            for right in (False, True):
                self.clean(execute_program(core, 'probe', [right]), 3 + int(right))

    def test_32_variant_boundary_and_unused_unsupported_declarations(self):
        names = [f'V{i}' for i in range(32)]
        source = 'enum Many{' + ','.join(names) + '} fn probe()->u64 effects{}{match Many::V31{'
        source += ','.join(f'Many::{name}=>{{return {i};}}' for i, name in enumerate(names)) + ',}}'
        for schema in (SCHEMA, SCHEMA_V8):
            self.clean(execute_program(lower_source(source, core_schema=schema), 'probe', []), 31)
        for declaration in ('enum E{None,Payload(u8)}', 'enum E{None,Payload(Buffer<u8>)}',
                            'enum E<T>{None,Payload(T)}',
                            'enum E{' + ','.join(f'V{i}' for i in range(33)) + '}'):
            with self.subTest(declaration=declaration), self.assertRaisesRegex(HIAProgramSourceRejected, 'unit variants'):
                lower_source(declaration + 'fn probe()->u64 effects{}{return 7;}')

    def test_type_match_abi_and_complex_storage_refusals_remain_closed(self):
        prefix = 'enum E{A,B} '
        rejected = {
            'missing_arm': prefix + 'fn f(v:E)->u64 effects{}{match v{E::A=>{return 1;},}}',
            'duplicate_arm': prefix + 'fn f(v:E)->u64 effects{}{match v{E::A=>{return 1;},E::A=>{return 2;},E::B=>{return 3;},}}',
            'wrong_pattern': prefix + 'enum F{A,B} fn f(v:E)->u64 effects{}{match v{F::A=>{return 1;},E::B=>{return 2;},}}',
            'wrong_nominal': prefix + 'enum F{A,B} fn f()->E effects{}{return F::A;}',
            'cast_from_integer': prefix + 'fn f(x:u32)->E effects{}{return x as E;}',
            'cast_to_integer': prefix + 'fn f(x:E)->u32 effects{}{return x as u32;}',
            'public_parameter': prefix + 'export "C" fn f(x:E)->u64 effects{}{return 0;}',
            'public_return': prefix + 'export "C" fn f()->E effects{}{return E::A;}',
            'public_nested': prefix + 'struct R{x:E} export "C" fn f(x:R)->u64 effects{}{return 0;}',
            'recursive_payload': 'enum E{End,Next(E)} fn f()->u64 effects{}{return 0;}',
            'overlapping_mutable': prefix + '''fn edit(a:mut E,b:read E)->Unit effects{write}{a=E::A;}
                fn f()->Unit effects{write}{let mut e=E::B;edit(mut e,read e);}''',
            'enum_view_label': prefix + "struct V<'a>{data:read 'a [u8],tag:E} fn f()->Unit effects{}{}",
            'stored_returned_call': prefix + '''fn view(b:read [u8])->read [u8] from b effects{}{return read b;}
                fn f()->Unit effects{alloc,block,panic}{let b=buffer(1);let held=view(read b);drop(move b);assert(held[0]==0);}''',
        }
        for label, source in rejected.items():
            for schema in (SCHEMA, SCHEMA_V8):
                with self.subTest(label=label, schema=schema), self.assertRaises(HIAProgramSourceRejected):
                    lower_source(source, core_schema=schema)


@unittest.skipUnless(shutil.which('cargo'), 'Actual Rust unit-enum parity requires Cargo; NOT qualified')
class HIASourceUnitEnumRust(unittest.TestCase):
    observations = []

    @classmethod
    def setUpClass(cls):
        from tests.test_hia_rust_owned_cfg import RustByteOwnerCfgParity
        RustByteOwnerCfgParity.setUpClass.__func__(cls)
        cls.executable = Path(cls.executable)
        cls.digest = hashlib.sha256(cls.executable.read_bytes()).hexdigest()

    def compare(self, core, entry, arguments, expected=None, **policy):
        report = crosscheck_rust_execution(core, entry, arguments, self.executable,
                                           executable_sha256=self.digest, **policy)
        type(self).observations.append(report)
        self.assertEqual(report['status'], 'execution_corroborated_not_authority')
        if expected is not None:
            self.assertEqual(report['rust_report']['values'], [expected])
        return report

    def test_actual_rust_same_core_values_stops_failures_and_invalid_tags(self):
        for schema in (SCHEMA, SCHEMA_V8):
            core = lower_source(SOURCE, core_schema=schema)
            for entry, arguments, expected in cases():
                self.compare(core, entry, arguments, expected)
            self.compare(core, 'packet_case', [5, 19, 0], 303, allocation_fail_at=2)
            self.compare(core, 'packet_case', [5, 19, 0], max_heap_bytes=3)
            probe = invalid_tag_probe(core)
            for tag in (0, 1, 2, 3, (1 << 32) - 1):
                report = self.compare(probe, 'invalid_probe', [tag])
                self.assertEqual(report['rust_report']['status'], 'returned' if tag < 3 else 'trapped')
            for helper in ('error_score', 'phase_score', 'make_phase'):
                with self.assertRaisesRegex(HIARustCrosscheckRejected, 'public scalar'):
                    self.compare(core, helper, [0])
        core = lower_source(SOURCE, core_schema=SCHEMA_V8)
        completed = execute_program(core, 'packet_case', [5, 19, 0])
        for limit in range(1, completed['steps'] + 1):
            self.compare(core, 'packet_case', [5, 19, 0], max_steps=limit)


@unittest.skipUnless(CLANG and NM and shutil.which('rustc'),
                     'Actual Rust/LLVM unit-enum native tools required; NOT qualified')
class HIASourceUnitEnumNative(unittest.TestCase):
    records = []

    def test_actual_source_rust_core_llvm_values_and_public_symbol_boundary(self):
        from hepta.backend import compile_rust, emit_rust
        from hepta.hia_program_llvm import build_program_native
        ast = parse(SOURCE)
        generated = emit_rust(ast, check(ast), crate_type='cdylib')
        type(self).records = []
        with tempfile.TemporaryDirectory(prefix='hia-unit-enum-native-') as temporary:
            root = Path(temporary)
            reference_path = root / 'source.so'
            reference = compile_rust(generated, crate_type='cdylib', output=reference_path, linker=CLANG)
            self.assertTrue(reference['ok'], reference)
            rust = ctypes.CDLL(str(reference_path))
            for schema in (SCHEMA, SCHEMA_V8):
                core = lower_source(SOURCE, core_schema=schema)
                path = root / ('core-' + schema.rsplit('.', 1)[-1] + '.so')
                receipt = build_program_native(core, path, clang=CLANG)
                self.assertTrue(receipt['ok'], receipt)
                self.assertEqual(set(receipt['exports']), ENTRIES)
                llvm = ctypes.CDLL(str(path))
                symbols = subprocess.run([NM, '-D', '--defined-only', str(path)],
                                         capture_output=True, text=True, timeout=10)
                self.assertEqual(symbols.returncode, 0, symbols.stderr)
                self.assertEqual({line.split()[-1] for line in symbols.stdout.splitlines()}, ENTRIES)
                record = {'schema': schema, 'core_sha256': core.sha256, 'llvm_receipt': receipt,
                          'source_rust_receipt': reference, 'source_rust': generated,
                          'symbols': {'argv': symbols.args, 'stdout': symbols.stdout, 'stderr': symbols.stderr,
                                      'returncode': symbols.returncode}, 'observations': []}
                type(self).records.append(record)
                for entry, arguments, expected in cases():
                    types = {'cycle_case': [ctypes.c_size_t], 'record_case': [ctypes.c_size_t],
                             'once_case': [ctypes.c_uint8], 'only_case': [],
                             'packet_case': [ctypes.c_size_t, ctypes.c_uint8, ctypes.c_uint8]}[entry]
                    values = []
                    for library in (rust, llvm):
                        function = getattr(library, entry)
                        function.argtypes, function.restype = types, ctypes.c_uint64
                        values.append(function(*arguments))
                    record['observations'].append({'entry': entry, 'arguments': arguments,
                                                   'expected': expected, 'source_rust': values[0], 'core_llvm': values[1]})
                    self.assertEqual(values, [expected, expected])
                for name in INTERNAL:
                    with self.assertRaises(AttributeError):
                        getattr(llvm, name)
                caller = root / 'private.c'
                caller.write_text('#include <stdint.h>\nuint64_t error_score(uint32_t);\n'
                                  'uint32_t make_phase(uint8_t);\n'
                                  'int main(void){return error_score(make_phase(0))!=101;}\n')
                link = subprocess.run([CLANG, str(caller), str(path), '-o', str(root / 'private')],
                                      capture_output=True, text=True, timeout=30)
                record['private_link'] = {'argv': link.args, 'returncode': link.returncode,
                                          'stdout': link.stdout, 'stderr': link.stderr}
                self.assertNotEqual(link.returncode, 0)
                self.assertIn('error_score', link.stderr)
                self.assertIn('make_phase', link.stderr)
            retained = os.environ.get('HIA_UNIT_ENUM_NATIVE_DIR')
            if retained:
                shutil.copytree(root, Path(retained) / 'differential')

    def test_actual_allocator_failure_returns_enum_error_and_cleans_owners(self):
        from hepta.hia_program_llvm import compile_program_llvm
        from tests.test_hia_source_partial import RESTORE_OBSERVER
        core = lower_source(SOURCE, core_schema=SCHEMA_V8)
        observer = RESTORE_OBSERVER.replace('extern size_t restore_try(void);',
                                             'extern uint64_t packet_case(size_t,uint8_t,uint8_t);')
        observer = observer.replace('size_t value=restore_try();', 'size_t value=packet_case(5,19,0);')
        with tempfile.TemporaryDirectory(prefix='hia-unit-enum-allocator-') as temporary:
            root = Path(temporary)
            source, object_path, executable = root / 'observer.c', root / 'core.o', root / 'run'
            source.write_text(observer)
            receipt = compile_program_llvm(emit_program_llvm(core), program=core, output=object_path,
                                           clang=CLANG, kind='object')
            self.assertTrue(receipt['ok'], receipt)
            linked = subprocess.run([CLANG, '-std=c11', '-O2', str(source), str(object_path),
                                     '-Wl,--wrap=malloc', '-Wl,--wrap=calloc', '-Wl,--wrap=free',
                                     '-o', str(executable)], capture_output=True, text=True, timeout=60)
            self.assertEqual(linked.returncode, 0, linked.stderr)
            record = {'core_sha256': core.sha256, 'object_receipt': receipt, 'observer': observer,
                      'link': {'argv': linked.args, 'returncode': linked.returncode,
                               'stdout': linked.stdout, 'stderr': linked.stderr}, 'observations': []}
            type(self).allocator = record
            for failure, expected, allocated, peak in ((0, 81, 2, 8), (2, 303, 1, 3)):
                run = subprocess.run([str(executable), str(failure)], capture_output=True, text=True, timeout=10)
                record['observations'].append({'failure': failure, 'returncode': run.returncode,
                                              'stdout': run.stdout, 'stderr': run.stderr})
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(json.loads(run.stdout), {'value': expected, 'attempts': 2,
                    'allocations': allocated, 'frees': allocated, 'live_bytes': 0, 'peak_bytes': peak})
            record['binary_sha256'] = hashlib.sha256(executable.read_bytes()).hexdigest()
            retained = os.environ.get('HIA_UNIT_ENUM_NATIVE_DIR')
            if retained:
                shutil.copytree(root, Path(retained) / 'allocator')

    def test_actual_native_invalid_primitive_tag_traps(self):
        from hepta.hia_program_llvm import build_program_native
        core = invalid_tag_probe(lower_source(SOURCE, core_schema=SCHEMA_V8))
        worker = ('import ctypes,resource,sys;resource.setrlimit(resource.RLIMIT_CORE,(0,0));'
                  'f=ctypes.CDLL(sys.argv[1]).invalid_probe;f.argtypes=[ctypes.c_uint32];'
                  'f.restype=ctypes.c_uint64;print(f(int(sys.argv[2])))')
        with tempfile.TemporaryDirectory(prefix='hia-unit-enum-invalid-') as temporary:
            path = Path(temporary) / 'invalid.so'
            receipt = build_program_native(core, path, clang=CLANG)
            self.assertTrue(receipt['ok'], receipt)
            type(self).invalid = {'core': core.as_dict(), 'receipt': receipt, 'observations': []}
            for tag, status in ((0, 0), (3, -signal.SIGABRT), ((1 << 32) - 1, -signal.SIGABRT)):
                run = subprocess.run([sys.executable, '-c', worker, str(path), str(tag)],
                                     capture_output=True, text=True, timeout=10)
                type(self).invalid['observations'].append({'tag': tag, 'returncode': run.returncode,
                                                           'stdout': run.stdout, 'stderr': run.stderr})
                self.assertEqual(run.returncode, status, run.stderr)
                self.assertEqual(run.stdout, '101\n' if tag == 0 else '')
                self.assertEqual(run.stderr, '')


if __name__ == '__main__':
    unittest.main()
