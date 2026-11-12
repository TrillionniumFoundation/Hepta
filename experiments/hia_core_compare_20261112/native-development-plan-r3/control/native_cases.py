"""Finite actual-image controls, never a Core interpreter or compiler.

This module runs only in the isolated native child specified by REQUEST.json.
The original 172 source/VM numeric pairs are retained, then a separate >8 MiB
lowest-limb distinction forces complete native traversal of both integers.
"""
from __future__ import annotations

import ast
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import json
import math
import operator
import os
from pathlib import Path
import random
import resource
import struct
import subprocess
import sys
import time
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import patch

CONTROL = Path(__file__).resolve().parent
sys.path.insert(0, str(CONTROL))
from common import create, pin, read_file, require, save, wire
from trace import NativeTrace

OPERATORS = (operator.eq, operator.ne, operator.lt, operator.le, operator.gt, operator.ge)
bridge = selection = outer = None
REQUEST = EVIDENCE = None


def bits_float(word):
    return struct.unpack('<d', struct.pack('<Q', word))[0]


def describe(value):
    if type(value) is float:
        return {'kind': 'float', 'bits': struct.pack('<d', value).hex()}
    if type(value) is bool:
        return {'kind': 'bool', 'value': value}
    raw = int.to_bytes(abs(value), (int.bit_length(value) + 7) // 8, 'little')
    return {'kind': 'int', 'bits': int.bit_length(value), 'sign': int(value < 0),
            'magnitude_sha256': sha256(raw).hexdigest()}


def raw_operand(value):
    descriptor = bridge.summary(value)
    if type(value) is int:
        raw = int.to_bytes(abs(value), descriptor[1] * 4, 'little')
    elif type(value) is float:
        raw = struct.pack('<d', value)
    else:
        raw = bytes((1 if value else 0,))
    name = '%d-%s.bin' % (descriptor[0], sha256(raw).hexdigest())
    path = EVIDENCE / 'operands' / name
    if path.exists():
        found, actual = read_file(path, len(raw))
        require(found == raw, 'same operand identity contains different bytes')
    else:
        actual = create(path, raw)
    return {'description': describe(value), 'descriptor': list(descriptor),
            'path': 'operands/' + name, 'size': len(raw), 'sha256': actual['sha256']}


class FiniteNumericComparisonNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference_raw, _ = read_file(Path(REQUEST['vm_reference']), REQUEST['vm_reference_size'])
        cls.reference = json.loads(cls.reference_raw)
        require(cls.reference['schema'] == 'hepta.hia.core-compare-source-vm-cases.v1'
                and cls.reference['case_count'] == 172 and len(cls.reference['cases']) == 172
                and cls.reference['native_executed'] is False, 'fixed VM reference differs')
        cls.image_owner = selection.installed_compare(REQUEST['manifest'], REQUEST['compiler_sha256'])
        require(cls.image_owner.image.image_sha256 == REQUEST['image_sha256'], 'actual admitted image differs')
        require(isinstance(cls.image_owner.image._entry, ctypes._CFuncPtr), 'actual C image entry is required')
        cls.trace = NativeTrace(EVIDENCE / 'trace', cls.image_owner.image)
        cls.rows = []
        cls.reference_index = 0
        (EVIDENCE / 'operands').mkdir(mode=0o700)
        (EVIDENCE / 'negative-admission').mkdir(mode=0o700)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.trace.close()
        finally:
            save(EVIDENCE / 'NUMERIC-CASES.json', {
                'schema': 'hepta.hia.numeric-native-finite-cases.v1',
                'actual_image_sha256': REQUEST['image_sha256'],
                'compiler_sha256': REQUEST['compiler_sha256'],
                'VM_reference_sha256': sha256(cls.reference_raw).hexdigest(),
                'original_VM_pair_count': 172, 'matched_VM_pair_count': cls.reference_index,
                'actual_pair_count': len(cls.rows), 'cases': cls.rows,
                'original116_executed': False, 'cold_executed': False,
                'native_Core39_executed': False, 'default_activated': False})

    def comparison(self, left, right, operation=1):
        cls = type(self)
        expected_row = self.reference['cases'][cls.reference_index]
        expected_value = OPERATORS[operation - 1](left, right)
        relation = 1 if operator.eq(left, right) else (0 if operator.lt(left, right) else
                   (2 if operator.gt(left, right) else 3))
        self.assertEqual((describe(left), describe(right), operation),
                         (expected_row['left'], expected_row['right'], expected_row['operation']))
        metadata = {'VM_pair_index': cls.reference_index, 'operation': operation,
                    'left': raw_operand(left), 'right': raw_operand(right),
                    'expected_relation': relation, 'expected_predicate': expected_value}
        self.trace.begin_case('VM-pair-%03d' % cls.reference_index, metadata,
                              expected_row['actual_entry_calls'])
        session = bridge.NumericCompareSession(self.trace, operation, left, right)
        value = session.run()
        self.assertIs(value, expected_value)
        self.assertIs(type(value), bool)
        self.assertEqual(session.relation, relation)
        self.assertEqual([list(row) for row in session.actual_steps], expected_row['actual_VM_returns'])
        self.assertEqual([list(row) for row in session.actual_windows], expected_row['actual_windows'])
        record = self.trace.end_case({'actual_relation': session.relation, 'actual_predicate': value})
        cls.rows.append({'case_id': record['case_id'], 'VM_pair_index': cls.reference_index,
                         'operation': operation, 'relation': relation, 'predicate': value,
                         'actual_entries': len(session.actual_steps),
                         'actual_windows': len(session.actual_windows),
                         'native_buffers_equal_original_VM': True,
                         'path_kind': 'summary_only' if not session.actual_windows else 'requested_windows'})
        cls.reference_index += 1
        return session

    # Three complete vector-building method bodies are inserted verbatim from
    # the frozen source-control class; their AST provenance is frozen separately.
    def test_arbitrary_integer_windows_have_no_eight_mib_value_gate(self):
        # Both top/equal windows and low-word distinctions cross a window edge.
        for bit in (31, 32, 63, 64, 1023, 1024, 1025, 2048):
            value = (1 << bit) + 3
            for left, right in ((value, value), (-value, -value + 1), (value, value + 1)):
                self.comparison(left, right, 3)
        # Real exact integers beyond the old JSON byte boundary; only one high
        # window per operand is needed for this deliberately differing pair.
        bit = (9 << 20) * 8
        large = 1 << bit
        larger = large + (1 << (bit - 1))
        session = self.comparison(large, larger, 3)
        self.assertEqual(len(session.actual_windows), 2)
        self.assertTrue(all(row[2] > (8 << 20) // 4 for row in session.actual_windows))
        self.assertEqual((len(session.input), len(session.output), len(session.state)), (256, 128, 512))
        self.assertGreater(len(session.magnitudes[0]), 8 << 20)
        session = self.comparison(-large, -float('inf'), 5)
        self.assertEqual(session.actual_windows, [])
        self.assertEqual(session.magnitudes, [None, None])
        session = self.comparison(large, float.fromhex('0x1.fffffffffffffp+1023'), 5)
        self.assertEqual(session.actual_windows, [])
        self.assertEqual(session.magnitudes, [None, None])


    def test_integer_bool_and_ieee_special_values_match_builtin_oracle(self):
        values = (False, True, 0, 1, -1, 2, -2, 0.0, -0.0, 0.5, -0.5,
                  float('inf'), -float('inf'), bits_float(0x7ff8000000000001),
                  bits_float(0xfff0000000000001), bits_float(1), -bits_float(1))
        pairs = [(value, value) for value in values]
        pairs += [(left, right) for left, right in zip(values, reversed(values))]
        pairs += [(False, -0.0), (True, 1), (True, 1.0), (-1, -1.0), (-float('inf'), 0),
                  (float('inf'), -float('inf')), (bits_float(0x7ff0000000000001), True)]
        for index, (left, right) in enumerate(pairs):
            self.comparison(left, right, 1 + index % 6)


    def test_mixed_dyadic_boundaries_and_seeded_binary64_match_oracle(self):
        pairs = []
        for bit in (31, 32, 52, 53, 54, 63, 64, 1023):
            middle = 1 << bit
            fp = float(middle)  # Oracle vector construction, never the bridge.
            for delta in (-1, 0, 1):
                pairs.append((middle + delta, fp))
                pairs.append((-fp, -middle - delta))
        pairs += [((1 << 1024) - 1, float.fromhex('0x1.fffffffffffffp+1023')),
                  (1 << 1024, float('inf')), (0, bits_float(1)), (0, -bits_float(1)),
                  (1, math.nextafter(1.0, 0.0)), (1, math.nextafter(1.0, 2.0)),
                  (-1, math.nextafter(-1.0, 0.0)), (-1, math.nextafter(-1.0, -2.0))]
        randomizer = random.Random(0x434d5031)
        for _ in range(24):
            value = bits_float(randomizer.getrandbits(64))
            integer = randomizer.getrandbits(randomizer.randrange(0, 1100))
            if randomizer.getrandbits(1): integer = -integer
            pairs.append((value, integer))
        for index, (left, right) in enumerate(pairs):
            self.comparison(left, right, 1 + index % 6)


    def test_bindings_and_foreign_fallback_order(self):
        records = []
        replacement = lambda a, b: ('replacement', a, b)
        for operation, target in enumerate(OPERATORS, 1):
            expected = target(1, 2)
            order, old_calls = [], []
            registry = dict(outer._COMPARE)
            def get(handle):
                order.append(handle)
                registry[operation] = replacement
                return handle
            companion = bridge.NativeNumericCompare(self.trace)
            fake = SimpleNamespace(owner=SimpleNamespace(numeric_compare=companion), value=get)
            self.trace.begin_case('actual-outer-exact-%d' % operation)
            previous = sys.getprofile()
            def profile(frame, event, value):
                if event == 'c_call' and value is target:
                    old_calls.append(operation)
            try:
                sys.setprofile(profile)
                with patch.object(outer, '_COMPARE', registry):
                    actual = outer.LoweringSession._primitive(fake, 13, (operation, 1, 2), ())
            finally:
                sys.setprofile(previous)
            self.assertEqual(actual, (0, (expected,)))
            self.assertEqual(order, [1, 2])
            self.assertEqual(old_calls, [])
            row = self.trace.end_case({'retained_exact_target_calls': old_calls, 'get_order': order})
            self.assertGreater(row['entry_count'], 0)
            records.append(row)
        def forbidden(*args):
            raise AssertionError('foreign or rebound operator entered HIA comparison')
        class ForeignInt(int):
            def __lt__(self, other): return ('foreign-lt', int(self), other)
            def __ne__(self, other): return ('foreign-ne', int(self), other)
        class ForeignFloat(float):
            def __eq__(self, other): return ('foreign-eq', float(self), other)
        for left, right, operation in ((ForeignInt(3), 4, 3), (ForeignInt(3), 3, 2),
                                        (ForeignFloat(3), 3, 1), (3, [3], 7), (3, [3], 8)):
            fake = SimpleNamespace(owner=SimpleNamespace(numeric_compare=SimpleNamespace(compare=forbidden)),
                                   value={1: left, 2: right}.__getitem__)
            expected = outer._COMPARE[operation](left, right)
            before = self.trace.entry_count
            actual = outer.LoweringSession._primitive(fake, 13, (operation, 1, 2), ())
            self.assertEqual(actual, (0, (expected,)))
            self.assertEqual(self.trace.entry_count, before)
        with patch.dict(outer._COMPARE, {1: replacement}):
            fake = SimpleNamespace(owner=SimpleNamespace(numeric_compare=SimpleNamespace(compare=forbidden)),
                                   value={1: 3, 2: 3}.__getitem__)
            self.assertEqual(outer.LoweringSession._primitive(fake, 13, (1, 1, 2), ()),
                             (0, (('replacement', 3, 3),)))
        source = ast.parse(Path(REQUEST['retained_primitive']).read_bytes())
        original_class = next(n for n in source.body if isinstance(n, ast.ClassDef) and n.name == 'LoweringSession')
        method = next(n for n in original_class.body if getattr(n, 'name', None) == '_primitive')
        namespace = {'_COMPARE': None}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])),
                     '<retained-observation-oracle>', 'exec'), namespace)
        original = namespace['_primitive']
        for fault in ('none', 'lookup', 'left', 'right', 'target'):
            class Problem(BaseException): pass
            problem = Problem(fault)
            def run(current):
                observations = []
                def target(left, right):
                    observations.append(['target', left, right])
                    if fault == 'target': raise problem
                    return ['result', left, right]
                class Registry(dict):
                    def __getitem__(self, operation):
                        observations.append(['lookup', operation])
                        if fault == 'lookup': raise problem
                        return target
                registry = Registry()
                def get(handle):
                    observations.append(['get', handle])
                    if (handle == 1 and fault == 'left') or (handle == 2 and fault == 'right'):
                        raise problem
                    registry[1] = replacement
                    return handle + 10
                fake = SimpleNamespace(owner=SimpleNamespace(numeric_compare=SimpleNamespace(compare=forbidden)),
                                       value=get)
                namespace['_COMPARE'] = registry
                try:
                    with patch.object(outer, '_COMPARE', registry):
                        result = (outer.LoweringSession._primitive if current else original)(fake, 13, (1, 1, 2), ())
                    outcome = ['value', result]
                except BaseException as error:
                    outcome = ['error', type(error).__name__, error.args, error is problem]
                return observations, outcome
            expected, actual = run(False), run(True)
            self.assertEqual(actual, expected)
            records.append({'fault': fault, 'expected': expected, 'actual': actual})
        save(EVIDENCE / 'BINDING-ORDER.json', records)

    def test_explicit_admission_missing_and_drift_refusals(self):
        manifest_raw, _ = read_file(Path(REQUEST['manifest']), 4096)
        manifest = json.loads(manifest_raw)
        owner = selection.installed_compare(REQUEST['manifest'], REQUEST['compiler_sha256'])
        self.assertEqual(owner.image.image_sha256, REQUEST['image_sha256'])
        self.assertEqual(owner._admitted_compare.compiler_sha256, REQUEST['compiler_sha256'])
        self.assertIn(REQUEST['compiler_sha256'].encode(), selection.implementation_identity(owner))
        refusals = []
        with patch.dict(os.environ, {selection.SELECTOR: ''}):
            self.assertIsNone(selection.selected_compare(REQUEST['compiler_sha256']))
        with patch.dict(os.environ, {selection.SELECTOR: str(EVIDENCE / 'missing-manifest.json')}):
            with self.assertRaises(FileNotFoundError): selection.selected_compare(REQUEST['compiler_sha256'])
            refusals.append('selected-missing-manifest')
        for field in ('source_sha256', 'abi_sha256', 'bridge_sha256', 'selection_sha256', 'compiler_sha256'):
            changed = dict(manifest); changed[field] = 'f' * 64
            path = EVIDENCE / 'negative-admission' / (field + '.json')
            save(path, changed)
            with self.assertRaises(ValueError): selection.installed_compare(path, REQUEST['compiler_sha256'])
            refusals.append(field)
        for label, raw in (('missing', None), ('changed', b'changed image'), ('oversize', bytes(1048577))):
            folder = EVIDENCE / 'negative-admission' / label
            folder.mkdir(mode=0o700)
            path = folder / 'manifest.json'
            save(path, manifest)
            if raw is not None:
                create(folder / 'core-compare.image.bin', raw)
            with self.assertRaises(FileNotFoundError if raw is None else ValueError):
                selection.installed_compare(path, REQUEST['compiler_sha256'])
            refusals.append('image-' + label)
        original_inputs = selection.current_inputs()
        for name in original_inputs:
            changed = dict(original_inputs); changed[name] += b' '
            with patch.object(selection, 'current_inputs', return_value=changed):
                with self.assertRaises(ValueError): selection.implementation_identity(owner)
            refusals.append('warm-source:' + name)
        save(EVIDENCE / 'ADMISSION.json', {'actual_manifest_sha256': sha256(manifest_raw).hexdigest(),
             'actual_image_sha256': owner.image.image_sha256,
             'actual_compiler_sha256': owner._admitted_compare.compiler_sha256,
             'source_and_bridge_identity': sha256(selection.implementation_identity(owner)).hexdigest(),
             'refusals': refusals, 'default_selected': False, 'installed_wheel_executed': False})

    def test_four_relations_and_six_predicates_are_HIA_decisions(self):
        for operation in range(1, 7):
            for left, right in ((1, 2.0), (True, 1.0), (2.0, 1), (bits_float(0x7ff8000000000001), 1)):
                self.comparison(left, right, operation)

    def test_one_use_and_bad_native_ack_are_terminal(self):
        for fault in ('observe-reuse', 'step-reuse', 'transport-error', 'post-entry-error', 'finish-reuse'):
            self.trace.begin_case('actual-lifecycle-' + fault)
            session = bridge.NumericCompareSession(self.trace, 1, 1 << 80, 1 << 80)
            first_count = self.trace.entry_count
            if fault == 'post-entry-error':
                class FailingLedger:
                    def append(self, value): raise MemoryError('after actual native entry')
                session.actual_steps = FailingLedger()
                with self.assertRaises(MemoryError): session.step(session.next_packet)
                self.assertEqual(self.trace.entry_count, first_count + 1)
            elif fault == 'finish-reuse':
                self.assertTrue(session.run())
                with self.assertRaises(RuntimeError): session.finish()
            else:
                packet = session.next_packet
                self.assertEqual(session.step(packet), 1)
                if fault == 'step-reuse':
                    with self.assertRaises(RuntimeError): session.step(packet)
                elif fault == 'observe-reuse':
                    session.observe()
                    with self.assertRaises(RuntimeError): session.observe()
                else:
                    def failing(*args): raise KeyboardInterrupt('representation failure')
                    session._limbs = failing
                    with self.assertRaises(KeyboardInterrupt): session.observe()
            actual_count = self.trace.entry_count
            for call in (lambda: session.step(None), session.observe, session.finish):
                with self.assertRaises(RuntimeError): call()
            self.assertEqual(self.trace.entry_count, actual_count)
            self.assertTrue(session.finished)
            self.assertFalse(session.pending or session.finish_pending)
            self.trace.end_case({'fault': fault, 'replayed_native_entries': 0})
        self.trace.begin_case('actual-malformed-ACK-and-terminal-workspace')
        session = bridge.NumericCompareSession(self.trace, 1, 1 << 80, (1 << 80) + 1)
        status, output, state = self.trace.raw_entry(session.next_packet)
        self.assertEqual(status, 1)
        header = bridge.FRAME.unpack(output)
        side, start, count = header[3:6]
        raw = session._limbs(side, start, count)
        correct = bridge.FRAME.pack(bridge.MAGIC, 1, header[1], side, start, count, *([0] * 10)) + raw + bytes(128-len(raw))
        for offset in (0, 8, 16, 24, 32, 40, 48, 255):
            changed = bytearray(correct); changed[offset] ^= 1
            status, _, failed = self.trace.raw_entry(bytes(changed), state)
            self.assertEqual(status, bridge.REFUSAL, offset)
            self.assertEqual(struct.unpack_from('<Q', failed, 8)[0], 99)
            status, _, _ = self.trace.raw_entry(correct, failed)
            self.assertEqual(status, bridge.REFUSAL)
        malformed = bytearray(session.next_packet)
        struct.pack_into('<Q', malformed, 24, 7)
        status, _, _ = self.trace.raw_entry(bytes(malformed))
        self.assertEqual(status, bridge.REFUSAL)
        self.trace.end_case({'bad_ACK_offsets': [0, 8, 16, 24, 32, 40, 48, 255],
                             'closed_workspace_phase': 99})

    def test_z_complete_large_low_limb_traversal(self):
        self.assertEqual(type(self).reference_index, 172)
        words = (8 << 20) // 4 + 1
        bit = (words - 1) * 32
        left = (1 << bit) | 0x12345678
        right = left + 1
        metadata = {'full_large_low_limb': True, 'words': words, 'operation': 3,
                    'left': raw_operand(left), 'right': raw_operand(right),
                    'expected_relation': 0, 'expected_predicate': True,
                    'expected_windows_each_side': (words + 31) // 32,
                    'summary_shortcut_allowed': False}
        self.assertGreater(metadata['left']['size'], 8 << 20)
        self.trace.begin_case('large-complete-lowest-limb-difference', metadata)
        session = bridge.NumericCompareSession(self.trace, 3, left, right)
        self.assertTrue(session.run())
        self.assertEqual(session.relation, 0)
        count = 2 * ((words + 31) // 32)
        self.assertEqual(len(session.actual_windows), count)
        self.assertEqual(len(session.actual_steps), count + 1)
        for position, row in enumerate(session.actual_windows):
            remaining = words - (position // 2) * 32
            expected_count = min(remaining, 32)
            self.assertEqual(row, (position + 1, position % 2, remaining - expected_count, expected_count))
        self.assertEqual([len(raw) for raw in session.magnitudes], [words * 4, words * 4])
        self.assertEqual((len(session.input), len(session.output), len(session.state)), (256, 128, 512))
        record = self.trace.end_case({'actual_relation': 0, 'actual_predicate': True,
                                     'windows_each_side': count // 2, 'full_operand_traversal': True})
        type(self).rows.append({'case_id': record['case_id'], 'VM_pair_index': None,
             'operation': 3, 'relation': 0, 'predicate': True, 'actual_entries': count + 1,
             'actual_windows': count, 'path_kind': 'complete_large_low_limb_traversal',
             'words': words, 'padded_operand_bytes': words * 4,
             'native_buffers_equal_original_VM': None})


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def main():
    global REQUEST, EVIDENCE, bridge, selection, outer
    request_path = Path(sys.argv[1])
    raw_request, _ = read_file(request_path, 262144)
    REQUEST = json.loads(raw_request)
    require(REQUEST['schema'] == 'hepta.hia.numeric-native-finite-child.v1', 'child request differs')
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode, 'isolated native child required')
    require(list(sys.version_info[:3]) == REQUEST['python_version'], 'native child Python version differs')
    EVIDENCE = Path(REQUEST['evidence'])
    EVIDENCE.mkdir(mode=0o700)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    require(libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0,
            'native child core dumps were not disabled')
    # This is a new finite control child. The unchanged outer owner contains
    # compilation and all cases in one 180/3 budget; it is the wall deadline.
    resource.setrlimit(resource.RLIMIT_CPU, (180, 180))
    resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
    resource.setrlimit(resource.RLIMIT_STACK, (8 << 20, 8 << 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 << 20, 16 << 20))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    started = time.monotonic()
    report = {'schema': 'hepta.hia.numeric-native-finite-results.v1', 'status': 'HOLD',
              'expected_ids': REQUEST['expected_ids'], 'loaded_ids': [], 'executed_ids': [],
              'source_preserved': False, 'native_image_sha256': REQUEST['image_sha256'],
              'compiler_sha256': REQUEST['compiler_sha256'], 'runtime': sys.version,
              'request_sha256': sha256(raw_request).hexdigest(),
              'native_buffer_sizes': [256, 128, 512], 'native_window_limbs': 32,
              'original18_executed': False, 'original116_executed': False,
              'native_Core39_executed': False, 'installed_wheel_executed': False,
              'cold_executed': False, 'default_activated': False,
              'forbidden_imports': [], 'subprocess_attempts': []}
    paths = [Path(row['path']) for row in REQUEST['input_pins']]
    before = [pin(path) for path in paths]
    save(EVIDENCE / 'inputs-before.json', before)
    try:
        require(before == REQUEST['input_pins'], 'actual native child inputs differ')
        sys.path.insert(0, REQUEST['stage'])
        from hepta import hia_core_compare_native as actual_bridge
        from hepta import hia_core_compare_selection as actual_selection
        from hepta import hia_core_lowering_native as actual_outer
        bridge, selection, outer = actual_bridge, actual_selection, actual_outer
        executed = []
        class Result(unittest.TextTestResult):
            def startTest(self, test):
                executed.append(test.id())
                super().startTest(test)
        def forbidden(*args, **kwargs):
            report['subprocess_attempts'].append('subprocess.Popen')
            raise AssertionError('native finite child may not start a compiler or subprocess')
        with patch.object(subprocess, 'Popen', forbidden):
            loader = unittest.TestLoader()
            suite = loader.loadTestsFromTestCase(FiniteNumericComparisonNativeTests)
            report['loaded_ids'] = [test.id() for test in flatten(suite)]
            require(report['loaded_ids'] == REQUEST['expected_ids'] and not loader.errors,
                    'finite native methods differ from the frozen denominator')
            with (EVIDENCE / 'unittest.log').open('x') as stream:
                result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
            report.update(executed_ids=executed, tests_run=result.testsRun, loader_errors=list(loader.errors))
            for name in ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses'):
                report[name] = [(item[0].id(), item[1]) if isinstance(item, tuple) else item.id()
                                for item in getattr(result, name)]
            report['forbidden_imports'] = sorted(name for name in sys.modules if
                name.startswith(('hepta.hia_program', 'hepta.hia_agent_assembly', 'tools.generate_hia_',
                                 'tools.qualify_hia_selfhost', 'hepta.hia_core_lowering_authoring')))
            require(result.wasSuccessful() and result.testsRun == len(REQUEST['expected_ids'])
                    and executed == report['loaded_ids'] == REQUEST['expected_ids']
                    and not any(report[name] for name in ('errors', 'failures', 'skipped',
                        'expectedFailures', 'unexpectedSuccesses', 'loader_errors',
                        'forbidden_imports', 'subprocess_attempts')), 'finite native controls did not all pass')
            require(FiniteNumericComparisonNativeTests.reference_index == 172
                    and len(FiniteNumericComparisonNativeTests.rows) == 173,
                    'numeric case denominator differs')
            report['status'] = 'FINITE_NATIVE_CASES_PASS'
    except BaseException:
        report['status'] = 'HOLD'
        report['error'] = traceback.format_exc()
    finally:
        try:
            after = [pin(path) for path in paths]
            save(EVIDENCE / 'inputs-after.json', after)
            report['source_preserved'] = after == before
            if after != before:
                report['status'] = 'HOLD'
        except BaseException:
            report['status'] = 'HOLD'
            report['preservation_error'] = traceback.format_exc()
        report['seconds'] = time.monotonic() - started
        save(EVIDENCE / 'report.json', report)
    print(json.dumps({'status': report['status'], 'loaded': len(report['loaded_ids']),
                      'executed': len(report['executed_ids']), 'seconds': report['seconds']}))
    return 0 if report['status'] == 'FINITE_NATIVE_CASES_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
