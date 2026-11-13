"""Independent source/Core-VM controls; this suite never loads native code.

The builtin operators are the retained semantic oracle. VM execution observes
the generated HIA relation, predicate and window requests, not a Python copy
of that algorithm. These tests are not the unchanged complete Core116 gate.
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
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests.hia_core_pc_expected import current_core39_fixture

from hepta import hia_core_compare_native as bridge
from hepta import hia_core_compare_selection as selection
from hepta import hia_core_lowering_native as outer
from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import _Machine, _Owner, _View
from tools import generate_hia_core_compare as author

ROOT = Path(__file__).resolve().parents[1]
BASE = Path(os.environ.get('HEPTA_COMPARE_BASE_ROOT', str(ROOT)))
_EXPLICIT_EVIDENCE = os.environ.get('HEPTA_COMPARE_CONTROL_EVIDENCE')
EVIDENCE = Path(_EXPLICIT_EVIDENCE) if _EXPLICIT_EVIDENCE is not None else None
OPERATORS = (operator.eq, operator.ne, operator.lt, operator.le, operator.gt, operator.ge)
EXPECTED_NAMES = (
    'test_arbitrary_integer_windows_have_no_eight_mib_value_gate',
    'test_complete_Core39_outer_protocol_and_original116_are_unchanged',
    'test_exact_target_type_guards_preserve_foreign_and_contains',
    'test_explicit_admission_binds_abi_source_image_and_compiler',
    'test_four_relations_and_six_predicates_are_HIA_decisions',
    'test_generated_Core_roundtrip_and_original_compiler_caps',
    'test_get_binding_order_and_exceptions_match_retained_dispatch',
    'test_integer_bool_and_ieee_special_values_match_builtin_oracle',
    'test_mixed_dyadic_boundaries_and_seeded_binary64_match_oracle',
    'test_native_protocol_rejects_bad_ack_and_seals_workspace',
    'test_one_use_and_post_entry_or_transport_failures_are_terminal',
)


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


class VMImage:
    """An independent Core interpreter adapter, explicitly not a native image."""
    image_sha256 = 'SOURCE_CORE_VM_NOT_A_NATIVE_IMAGE'

    def __init__(self, program):
        self.program = program
        self.calls = []

    def raw_entry(self, packet, state=None):
        actual_state = bytes(512) if state is None else bytes(state)
        owners = [_Owner(-1, bytearray(packet)), _Owner(-2, bytearray(128)),
                  _Owner(-3, bytearray(actual_state))]
        machine = _Machine(self.program, 1_000_000, 1 << 20, None, 128)
        result = machine.invoke(self.program.as_dict()['functions'][0], [
            _View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
        self.calls.append({'status': result, 'input_sha256': sha256(packet).hexdigest(),
                           'output_sha256': sha256(owners[1].data).hexdigest()})
        return result, bytes(owners[1].data), bytes(owners[2].data)

    def _entry(self, source, size, output, output_size, workspace, workspace_size):
        if (size, output_size, workspace_size) != (256, 128, 512):
            raise AssertionError('companion transport changed its constant extent')
        result, raw_output, raw_state = self.raw_entry(
            ctypes.string_at(source, size), ctypes.string_at(workspace, workspace_size))
        ctypes.memmove(output, raw_output, output_size)
        ctypes.memmove(workspace, raw_state, workspace_size)
        return result


class ExactNumericComparisonSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global EVIDENCE
        if _EXPLICIT_EVIDENCE is None:
            # A fresh, retained fixture makes ordinary unittest discovery
            # portable without deleting diagnostics from a failing run.
            EVIDENCE = Path(tempfile.mkdtemp(prefix='hia-core-compare-source-')) / 'evidence'
        cls.evidence_directory = EVIDENCE
        EVIDENCE.mkdir(mode=0o700)
        (EVIDENCE / 'authoring-source.py.txt').write_text(author.source())
        cls.document = author.document()
        (EVIDENCE / 'document.json').write_text(json.dumps(cls.document, sort_keys=True) + '\n')
        cls.assembly = render_assembly(cls.document)
        (EVIDENCE / 'core_compare.hiaasm').write_text(cls.assembly)
        cls.program = verify_program(cls.document)
        cls.rows = []
        cls._names = {node.name: 'f' + str(index)
                      for index, node in enumerate(ast.parse(author.source()).body)}

    @classmethod
    def tearDownClass(cls):
        (EVIDENCE / 'actual-VM-cases.json').write_text(json.dumps({
            'schema': 'hepta.hia.core-compare-source-vm-cases.v1',
            'native_executed': False, 'compiler_executed': False,
            'case_count': len(cls.rows), 'cases': cls.rows}, indent=2, sort_keys=True) + '\n')

    def comparison(self, left, right, operation=1):
        vm = VMImage(self.program)
        session = bridge.NumericCompareSession(vm, operation, left, right)
        value = session.run()
        expected = OPERATORS[operation - 1](left, right)
        relation = 1 if operator.eq(left, right) else (0 if operator.lt(left, right) else
                   (2 if operator.gt(left, right) else 3))
        self.assertIs(type(value), bool)
        self.assertIs(value, expected)
        self.assertEqual(session.relation, relation)
        self.assertTrue(all(1 <= row[3] <= 32 for row in session.actual_windows))
        self.rows.append({'left': describe(left), 'right': describe(right), 'operation': operation,
            'expected_relation': relation, 'actual_relation': session.relation,
            'expected_predicate': expected, 'actual_predicate': value,
            'actual_VM_returns': session.actual_steps, 'actual_windows': session.actual_windows,
            'actual_entry_calls': vm.calls})
        return session

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

    def test_complete_Core39_outer_protocol_and_original116_are_unchanged(self):
        fixture = current_core39_fixture(ROOT, 'comparison')
        self.assertEqual(len(fixture['files']), 40)
        for row in fixture['files']:
            raw = (BASE / row['path']).read_bytes()
            self.assertEqual((len(raw), sha256(raw).hexdigest()), (row['size'], row['sha256']))
        old = ast.parse((ROOT / 'tests/fixtures/hia_core_lowering_before_compare.py.txt').read_bytes())
        new = ast.parse((ROOT / 'hepta/hia_core_lowering_native.py').read_bytes())
        old_class = next(node for node in old.body if isinstance(node, ast.ClassDef) and node.name == 'LoweringSession')
        new_class = next(node for node in new.body if isinstance(node, ast.ClassDef) and node.name == 'LoweringSession')
        old_primitive = next(node for node in old_class.body if getattr(node, 'name', '') == '_primitive')
        new_primitive = next(node for node in new_class.body if getattr(node, 'name', '') == '_primitive')
        branch = next(node for node in new_primitive.body if isinstance(node, ast.If)
                      and ast.dump(node.test) == ast.dump(ast.parse('opcode == 13', mode='eval').body))
        self.assertEqual(len(branch.body), 3)
        self.assertIsInstance(branch.body[1], ast.If)
        del branch.body[1]
        for code in (11, 12):
            integer_branch = next(node for node in new_primitive.body if isinstance(node, ast.If)
                and ast.dump(node.test) == ast.dump(ast.parse('opcode == ' + str(code), mode='eval').body))
            self.assertEqual(len(integer_branch.body), 3)
            self.assertIsInstance(integer_branch.body[1], ast.If)
            del integer_branch.body[1]
        self.assertEqual(ast.dump(old_class), ast.dump(new_class))
        self.assertEqual(outer.FRAME.size, 128)
        # Original full caller source is read as bytes, not replaced or loaded.
        old_ids = ast.parse((BASE / 'tools/qualify_hia_core_lowering_callers.py').read_bytes())
        counts = []
        for name in ('COMPONENT_IDS', 'ORIGINAL_IDS', 'CORE_IDS'):
            value = next(node.value for node in old_ids.body if isinstance(node, ast.Assign)
                         and any(isinstance(target, ast.Name) and target.id == name for target in node.targets))
            counts.append(len(ast.literal_eval(value)))
        self.assertEqual(counts, [15, 51, 50])

    def test_exact_target_type_guards_preserve_foreign_and_contains(self):
        trace = []
        class ForeignInt(int):
            def __lt__(self, other):
                trace.append(('lt', int(self), other)); return 'foreign-lt'
            def __ne__(self, other):
                trace.append(('ne', int(self), other)); return 'foreign-ne'
        class ForeignFloat(float):
            def __eq__(self, other):
                trace.append(('eq', float(self), other)); return 'foreign-eq'
        values = [(ForeignInt(3), 4, 3), (ForeignInt(3), 3, 2), (ForeignFloat(3), 3, 1)]
        def forbidden(*args):
            raise AssertionError('foreign path entered the numeric companion')
        for left, right, operation in values:
            fake = SimpleNamespace(owner=SimpleNamespace(numeric_compare=SimpleNamespace(compare=forbidden)),
                                   value={1: left, 2: right}.__getitem__)
            self.assertFalse(bridge.eligible(operation, outer._COMPARE[operation], left, right))
            expected = outer._COMPARE[operation](left, right)
            self.assertEqual(outer.LoweringSession._primitive(fake, 13, (operation, 1, 2), ()), (0, (expected,)))
        replacement = lambda a, b: ('replacement', a, b)
        with patch.dict(outer._COMPARE, {1: replacement}):
            fake = SimpleNamespace(owner=SimpleNamespace(numeric_compare=SimpleNamespace(compare=forbidden)),
                                   value={1: 3, 2: 3}.__getitem__)
            self.assertEqual(outer.LoweringSession._primitive(fake, 13, (1, 1, 2), ()),
                             (0, (('replacement', 3, 3),)))
        for operation in (7, 8):
            fake = SimpleNamespace(owner=SimpleNamespace(numeric_compare=SimpleNamespace(compare=forbidden)),
                                   value={1: 3, 2: [3]}.__getitem__)
            self.assertEqual(outer.LoweringSession._primitive(fake, 13, (operation, 1, 2), ()),
                             (0, (operation == 7,)))
        self.assertTrue(trace)
        for operation, target in enumerate(OPERATORS, 1):
            self.assertTrue(bridge.eligible(operation, target, True, 1.0))
            expected = target(1, 2)
            vm = VMImage(self.program)
            companion = bridge.NativeNumericCompare(vm)
            order, old_calls = [], []
            registry = dict(outer._COMPARE)
            def get(handle):
                order.append(handle)
                registry[operation] = replacement
                return handle
            fake = SimpleNamespace(owner=SimpleNamespace(numeric_compare=companion), value=get)
            def profile(frame, event, value):
                if event == 'c_call' and value is target:
                    old_calls.append(operation)
            previous = sys.getprofile()
            try:
                sys.setprofile(profile)
                with patch.object(outer, '_COMPARE', registry):
                    actual = outer.LoweringSession._primitive(fake, 13, (operation, 1, 2), ())
            finally:
                sys.setprofile(previous)
            self.assertEqual(actual, (0, (expected,)))
            self.assertEqual(order, [1, 2])
            self.assertEqual(old_calls, [])
            self.assertGreater(len(vm.calls), 0)

    def test_explicit_admission_binds_abi_source_image_and_compiler(self):
        raw = (ROOT / selection.ABI_SOURCE).read_bytes()
        selection.checked_abi(raw)
        for field in ('input_bytes', 'output_bytes', 'workspace_bytes', 'window_limbs', 'limb_bits'):
            changed = json.loads(raw); changed[field] = True
            with self.assertRaises(ValueError): selection.checked_abi(json.dumps(changed).encode())
        for group in ('relations', 'predicates'):
            changed = json.loads(raw); changed[group][next(iter(changed[group]))] = True
            with self.assertRaises(ValueError): selection.checked_abi(json.dumps(changed).encode())
        inputs = {selection.HIA_SOURCE: self.assembly.encode(), selection.ABI_SOURCE: raw,
                  selection.BRIDGE_SOURCE: (ROOT / selection.BRIDGE_SOURCE).read_bytes(),
                  selection.SELECTION_SOURCE: (ROOT / selection.SELECTION_SOURCE).read_bytes()}
        hashes = {name: sha256(data).hexdigest() for name, data in inputs.items()}
        manifest = {'schema': selection.SCHEMA, 'image_path': 'core-compare.image.bin',
            'image_sha256': 'a' * 64, 'compiler_sha256': 'b' * 64,
            'source_sha256': hashes[selection.HIA_SOURCE], 'abi_sha256': hashes[selection.ABI_SOURCE],
            'bridge_sha256': hashes[selection.BRIDGE_SOURCE],
            'selection_sha256': hashes[selection.SELECTION_SOURCE]}
        data = json.dumps(manifest).encode()
        self.assertEqual(selection._manifest(data, hashes, 'b' * 64), manifest)
        for key in ('source_sha256', 'abi_sha256', 'bridge_sha256', 'selection_sha256', 'compiler_sha256'):
            changed = dict(manifest); changed[key] = 'c' * 64
            with self.assertRaises(ValueError): selection._manifest(json.dumps(changed).encode(), hashes, 'b' * 64)
        with patch.dict(os.environ, {selection.SELECTOR: ''}):
            self.assertIsNone(selection.selected_compare('b' * 64))
        with patch.dict(os.environ, {selection.SELECTOR: str(EVIDENCE / 'absent-manifest.json')}):
            with self.assertRaises(FileNotFoundError): selection.selected_compare('b' * 64)
        admitted = selection._Admitted(manifest['source_sha256'], manifest['abi_sha256'],
            manifest['bridge_sha256'], manifest['selection_sha256'], 'a' * 64, 'b' * 64, sha256(data).hexdigest())
        owner = SimpleNamespace(_admitted_compare=admitted, image=SimpleNamespace(
            image_sha256='a' * 64, admitted_source_sha256=manifest['source_sha256']))
        with patch.object(selection, 'current_inputs', return_value=inputs):
            self.assertIn(b'native.v1', selection.implementation_identity(owner))
        for name in inputs:
            changed = dict(inputs); changed[name] += b' '
            with patch.object(selection, 'current_inputs', return_value=changed):
                with self.assertRaises(ValueError): selection.implementation_identity(owner)
        owner.image.admitted_source_sha256 = 'd' * 64
        with patch.object(selection, 'current_inputs', return_value=inputs):
            with self.assertRaises(ValueError): selection.implementation_identity(owner)

    def test_four_relations_and_six_predicates_are_HIA_decisions(self):
        function = next(row for row in self.program.as_dict()['functions']
                        if row['name'] == self._names['predicate'])
        expected = ((False, True, True, True, False, False),
                    (True, False, False, True, False, True),
                    (False, True, False, False, True, True),
                    (False, True, False, False, False, False))
        for relation in range(4):
            for operation in range(1, 7):
                machine = _Machine(self.program, 100_000, 1 << 20, None, 128)
                actual = machine.invoke(function, [operation, relation])[0]
                self.assertEqual(actual, int(expected[relation][operation - 1]))
        for operation in range(1, 7):
            for left, right in ((1, 2.0), (True, 1.0), (2.0, 1), (bits_float(0x7ff8000000000001), 1)):
                self.comparison(left, right, operation)

    def test_generated_Core_roundtrip_and_original_compiler_caps(self):
        from tools.hia_selfhost_limits import MAX_FUNCTIONS, MAX_BLOCKS, MAX_INSTRUCTIONS
        roundtrip = assemble_program(self.assembly)
        self.assertEqual(roundtrip.as_dict(), self.program.as_dict())
        functions = self.document['functions']
        self.assertLessEqual(len(self.assembly.encode()), 1 << 20)
        self.assertLessEqual(len(functions), MAX_FUNCTIONS)
        blocks = [block for fn in functions for block in fn['blocks']]
        self.assertLessEqual(len(blocks), MAX_BLOCKS)
        self.assertLessEqual(sum(len(block['ops']) for block in blocks), MAX_INSTRUCTIONS)
        for fn in functions:
            self.assertLessEqual(len(fn['blocks']), 256)
            self.assertLessEqual(len(fn['params']), 16)
            self.assertLessEqual(len(fn['returns']), 3)
            for block in fn['blocks']:
                self.assertLessEqual(len(block.get('params', [])), 16)
                for instruction in block['ops']:
                    self.assertLessEqual(len(instruction.get('args', [])), 16)
                    self.assertLessEqual(len(instruction.get('out', [])), 3)
        def argument_extents(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == 'args' and isinstance(item, list):
                        yield len(item)
                    yield from argument_extents(item)
            elif isinstance(value, list):
                for item in value: yield from argument_extents(item)
        self.assertLessEqual(max(argument_extents(self.document)), 16)
        # All SSA identifiers are checked, including edge and call operands.
        def walk(value):
            if isinstance(value, dict):
                for item in value.values(): yield from walk(item)
            elif isinstance(value, list):
                for item in value: yield from walk(item)
            elif isinstance(value, str) and value.startswith('v') and value[1:].isdigit():
                yield int(value[1:])
        self.assertLessEqual(max(walk(self.document)), 2047)
        report = {'functions': len(functions), 'blocks': len(blocks),
                  'max_blocks': max(len(fn['blocks']) for fn in functions),
                  'instructions': sum(len(block['ops']) for block in blocks),
                  'max_ssa': max(walk(self.document)), 'source_bytes': len(self.assembly.encode()),
                  'native_compile_performed': False}
        (EVIDENCE / 'public-Core-and-caps.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')

    def test_get_binding_order_and_exceptions_match_retained_dispatch(self):
        source = ast.parse((ROOT / 'tests/fixtures/hia_core_lowering_before_compare.py.txt').read_bytes())
        cls = next(node for node in source.body if isinstance(node, ast.ClassDef) and node.name == 'LoweringSession')
        method = next(node for node in cls.body if getattr(node, 'name', '') == '_primitive')
        namespace = {'_COMPARE': None}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])), '<retained-primitive>', 'exec'), namespace)
        original = namespace['_primitive']
        records = []
        for fail in ('none', 'lookup', 'left', 'right', 'target'):
            class Problem(BaseException): pass
            problem = Problem('original ' + fail)
            def run(current):
                trace = []
                def target(left, right):
                    trace.append(('target', left, right))
                    if fail == 'target': raise problem
                    return ('foreign-result', left, right)
                class Registry(dict):
                    def __getitem__(self, operation):
                        trace.append(('lookup', operation))
                        if fail == 'lookup': raise problem
                        return target
                registry = Registry()
                def get(handle):
                    trace.append(('get', handle))
                    if (handle == 1 and fail == 'left') or (handle == 2 and fail == 'right'):
                        raise problem
                    registry[1] = lambda *args: (_ for _ in ()).throw(AssertionError('rebound target called'))
                    return handle + 10
                def forbidden(*args): raise AssertionError('changed target used HIA')
                fake = SimpleNamespace(value=get, owner=SimpleNamespace(numeric_compare=SimpleNamespace(compare=forbidden)))
                namespace['_COMPARE'] = registry
                try:
                    with patch.object(outer, '_COMPARE', registry):
                        value = (outer.LoweringSession._primitive if current else original)(fake, 13, (1, 1, 2), ())
                    outcome = ('value', value)
                except BaseException as error:
                    outcome = ('error', type(error).__name__, error.args, error is problem)
                return trace, outcome
            expected, actual = run(False), run(True)
            self.assertEqual(actual, expected)
            records.append({'case': fail, 'expected': expected, 'actual': actual})
        (EVIDENCE / 'binding-and-exception-order.json').write_text(json.dumps(records, indent=2) + '\n')

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

    def test_native_protocol_rejects_bad_ack_and_seals_workspace(self):
        vm = VMImage(self.program)
        session = bridge.NumericCompareSession(vm, 1, 1 << 80, (1 << 80) + 1)
        status, output, state = vm.raw_entry(session.next_packet)
        self.assertEqual(status, 1)
        header = bridge.FRAME.unpack(output)
        side, start, count = header[3:6]
        raw = session._limbs(side, start, count)
        correct = bridge.FRAME.pack(bridge.MAGIC, 1, header[1], side, start, count, *([0] * 10)) + raw + bytes(128-len(raw))
        for offset in (0, 8, 16, 24, 32, 40, 48, 255):
            changed = bytearray(correct); changed[offset] ^= 1
            status, _, failed_state = vm.raw_entry(bytes(changed), state)
            self.assertEqual(status, bridge.REFUSAL, offset)
            self.assertEqual(struct.unpack_from('<Q', failed_state, 8)[0], 99)
            status, _, _ = vm.raw_entry(correct, failed_state)
            self.assertEqual(status, bridge.REFUSAL)
        malformed = bytearray(session.next_packet)
        struct.pack_into('<Q', malformed, 24, 7)
        status, _, _ = vm.raw_entry(bytes(malformed))
        self.assertEqual(status, bridge.REFUSAL)

    def test_one_use_and_post_entry_or_transport_failures_are_terminal(self):
        for fault in ('observe-reuse', 'step-reuse', 'transport-error', 'post-entry-error', 'finish-reuse'):
            vm = VMImage(self.program)
            session = bridge.NumericCompareSession(vm, 1, 1 << 80, 1 << 80)
            if fault == 'post-entry-error':
                class FailingLedger:
                    def append(self, value): raise MemoryError('after real VM entry')
                session.actual_steps = FailingLedger()
                with self.assertRaises(MemoryError): session.step(session.next_packet)
                self.assertEqual(len(vm.calls), 1)
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
            count = len(vm.calls)
            for call in (lambda: session.step(None), session.observe, session.finish):
                with self.assertRaises(RuntimeError): call()
            self.assertEqual(len(vm.calls), count)
            self.assertTrue(session.finished)
            self.assertFalse(session.pending or session.finish_pending)


if __name__ == '__main__':
    unittest.main()
