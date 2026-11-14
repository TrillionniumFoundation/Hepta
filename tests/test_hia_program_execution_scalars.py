"""Independent arithmetic and machine controls for the HIA VM scalar slice.

The standalone wrapper is a test fixture, not an installed runtime or a cold
qualification.  Its seven input words are (op, output_type, first_input_type,
a, b, c, mode); its three output words are (raw_result, first_error, error_type).
Workspace words 0/8 seed the error/type after the wrapper explicitly clears
96/104, solely to observe first-error and success-preservation behavior.
"""
from __future__ import annotations

import ast
import ctypes
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_opcodes import OPCODES
from hepta.hia_program import verify_core
from hepta.hia_program_runtime import HIAProgramTrap, _Machine, _Owner, _View
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.hia_program_execution_scalars import BODY, ScalarBuilder


ROOT = Path(__file__).resolve().parents[1]
DEVELOPMENT_COMPILER = 'HEPTA_HIA_PROGRAM_EXECUTION_SCALARS_DEVELOPMENT_COMPILER'
COLD_REPORT = 'HEPTA_HIA_PROGRAM_EXECUTION_COLD_REPORT'
OBSERVATIONS = 'HEPTA_HIA_PROGRAM_EXECUTION_SCALARS_OBSERVATIONS'
MASK64 = (1 << 64) - 1
TYPES = ('', 'i8', 'i16', 'i32', 'i64', 'u8', 'u16', 'u32', 'u64', 'isize', 'usize', 'bool', 'unit')
WIDTHS = (0, 8, 16, 32, 64, 8, 16, 32, 64, 64, 64)
NAMES = ('', 'const', 'int.add.checked', 'int.add.wrap', 'int.sub.checked', 'int.sub.wrap',
         'int.mul.checked', 'int.mul.wrap', 'int.div.checked', 'int.rem.checked',
         'int.shl.checked', 'int.shr.checked', 'bit.and', 'bit.or', 'bit.xor', 'bit.not',
         'int.neg.checked', 'compare.eq', 'compare.ne', 'compare.lt', 'compare.le',
         'compare.gt', 'compare.ge', 'bool.not', 'bool.and', 'bool.or', 'int.cast', 'select')

WRAPPER = r'''
def scalar_probe(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 56 or length(o) != 24 or length(w) < 112:
        return 0
    error = get(w, 0)
    error_type = get(w, 8)
    put(w, 96, 0)
    put(w, 104, 0)
    put(w, 96, error)
    put(w, 104, error_type)
    value = vm_scalar(w, scalar_read(s, 0), scalar_read(s, 8), scalar_read(s, 16), scalar_read(s, 24), scalar_read(s, 32), scalar_read(s, 40), scalar_read(s, 48))
    put(o, 0, value)
    put(o, 8, get(w, 96))
    put(o, 16, get(w, 104))
    return 24

def scalar_read(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
'''


def document():
    nodes = ast.parse(WRAPPER + BODY).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = ScalarBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
        'module': 'program_execution_scalar_probe', 'functions': functions})


def signed(t):
    return TYPES[t].startswith('i')


def limits(t):
    bits = WIDTHS[t]
    return (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed(t) else (0, (1 << bits) - 1)


def raw(t, value):
    if t == 12:
        assert value is None
        return 0
    if t == 11:
        assert type(value) is bool
        return int(value)
    return value % (1 << WIDTHS[t])


def semantic(t, value):
    if t == 12:
        return None
    if t == 11:
        return bool(value)
    if signed(t) and value >= (1 << (WIDTHS[t] - 1)):
        return value - (1 << WIDTHS[t])
    return value


@dataclass(frozen=True)
class Case:
    op: int
    t: int
    at: int
    a: int
    b: int = 0
    c: int = 0
    mode: int = 0

    def wire(self):
        return struct.pack('<7Q', self.op, self.t, self.at, self.a, self.b, self.c, self.mode)

    def arguments(self):
        if self.op == 27:
            return [bool(self.a), semantic(self.t, self.b), semantic(self.t, self.c)]
        values = [semantic(self.at, self.a)]
        if self.op not in (15, 16, 23, 26):
            values.append(semantic(self.at, self.b))
        return values


def math_result(case):
    """Unbounded integer mathematics, independent of the HIA word algorithms."""
    op, t = case.op, case.t
    args = case.arguments()
    a = args[0]
    b = args[1] if len(args) > 1 else None
    checked = False
    if 2 <= op <= 7:
        if op <= 3:
            value = a + b
        elif op <= 5:
            value = a - b
        else:
            value = a * b
        checked = op in (2, 4, 6)
    elif op in (8, 9):
        if b == 0:
            return 0, 2, t
        if signed(t) and a == limits(t)[0] and b == -1:
            return 0, 3, t
        quotient = abs(a) // abs(b)
        if (a < 0) != (b < 0):
            quotient = -quotient
        value = quotient if op == 8 else a - b * quotient
    elif op in (10, 11):
        if not 0 <= b < WIDTHS[t]:
            return 0, 4, t
        value = a << b if op == 10 else a >> b
    elif op == 12:
        value = a & b
    elif op == 13:
        value = a | b
    elif op == 14:
        value = a ^ b
    elif op == 15:
        value = ~a
    elif op == 16:
        value, checked = -a, True
    elif 17 <= op <= 22:
        value = (a == b, a != b, a < b, a <= b, a > b, a >= b)[op - 17]
    elif op == 23:
        value = not a
    elif op == 24:
        value = a and b
    elif op == 25:
        value = a or b
    elif op == 26:
        value, checked = a, case.mode == 1
    elif op == 27:
        value = b if a else args[2]
    else:
        raise AssertionError('mathematical oracle only admits declared scalar cases')
    if checked and not limits(t)[0] <= value <= limits(t)[1]:
        return 0, 1, t
    return raw(t, value), 0, 0


def reference_result(case):
    """Observe the original scalar operation body, with its exact trap message."""
    args = case.arguments()
    env = {'a' + str(index): value for index, value in enumerate(args)}
    instruction = {'op': NAMES[case.op], 'args': list(env), 'out': [{'name': 'result', 'type': TYPES[case.t]}],
                   'attrs': {'mode': 'checked' if case.mode == 1 else 'wrap'} if case.op == 26 else {}}
    # Scalar branches use no machine resource state. Calling the real method
    # directly keeps this oracle independent from the new VM dispatch.
    machine = object.__new__(_Machine)
    try:
        machine.operation(instruction, env, 0)
    except HIAProgramTrap as error:
        return None, (error.code, str(error))
    return raw(case.t, env['result']), None


def trap_for(error, t):
    code, message = {
        1: ('overflow', 'result is outside ' + TYPES[t]),
        2: ('division_by_zero', 'integer divisor is zero'),
        3: ('overflow', 'signed minimum divided by minus one'),
        4: ('overflow', 'shift count is outside the word width'),
    }[error]
    return code, 'E_HIA_TRAP_' + code.upper() + ': ' + message


def boundaries(t):
    lo, hi = limits(t)
    middle = 1 << (WIDTHS[t] // 2)
    candidates = (lo, lo + 1, -middle - 1, -middle, -2, -1, 0, 1, 2,
                  middle - 1, middle, middle + 1, hi - 1, hi)
    return sorted({value for value in candidates if lo <= value <= hi})


def integer_cases():
    for t in range(1, 11):
        values = boundaries(t)
        for op in range(2, 17):
            for a in values:
                if op in (15, 16):
                    yield Case(op, t, t, raw(t, a))
                    continue
                right = values
                if op in (10, 11):
                    lo, hi = limits(t)
                    right = sorted(set(values) | {v for v in (-1, 0, 1, WIDTHS[t] - 1, WIDTHS[t], WIDTHS[t] + 1)
                                                  if lo <= v <= hi})
                for b in right:
                    yield Case(op, t, t, raw(t, a), raw(t, b))


def compare_cases():
    for t in range(1, 12):
        values = boundaries(t) if t != 11 else (False, True)
        for op in range(17, 19 if t == 11 else 23):
            for a in values:
                for b in values:
                    yield Case(op, 11, t, raw(t, a), raw(t, b))


def cast_cases():
    for at in range(1, 11):
        for t in range(1, 11):
            source_lo, source_hi = limits(at)
            target_lo, target_hi = limits(t)
            values = sorted(set(boundaries(at)) | {v for v in (target_lo - 1, target_lo, target_hi, target_hi + 1)
                                                    if source_lo <= v <= source_hi})
            for mode in (1, 2):
                for value in values:
                    yield Case(26, t, at, raw(at, value), mode=mode)


def boolean_select_cases():
    for a in (False, True):
        yield Case(23, 11, 11, raw(11, a))
        for b in (False, True):
            for op in (24, 25):
                yield Case(op, 11, 11, raw(11, a), raw(11, b))
    for t in range(1, 13):
        values = boundaries(t) if t <= 10 else (False, True) if t == 11 else (None,)
        for left in values:
            for right in values:
                for condition in (0, 1):
                    yield Case(27, t, 11, condition, raw(t, left), raw(t, right))


class ProgramExecutionScalarsSourceTests(unittest.TestCase):
    def test_complete_opcode_and_type_abi_and_original_limits(self):
        from tools.hia_selfhost_limits import MAX_FUNCTIONS, MAX_BLOCKS, MAX_INSTRUCTIONS
        self.assertEqual(tuple(OPCODES)[:27], NAMES[1:])
        names = [node.name for node in ast.parse(BODY).body]
        self.assertEqual(names.count('vm_scalar'), 1)
        self.assertTrue(all(name == 'vm_scalar' or name.startswith('vm_s_') for name in names))
        value = document()
        self.assertLessEqual(len(value['functions']), MAX_FUNCTIONS)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in value['functions']), MAX_BLOCKS)
        self.assertLessEqual(sum(len(block['ops']) for fn in value['functions'] for block in fn['blocks']), MAX_INSTRUCTIONS)
        self.assertLessEqual(max(len(block['params']) for fn in value['functions'] for block in fn['blocks']), 16)
        self.assertLessEqual(max(len(fn['blocks']) for fn in value['functions']), 256)
        verify_core(value)

    def test_math_oracle_matches_original_operations_and_exact_traps(self):
        count = 0
        for corpus in (integer_cases, compare_cases, cast_cases, boolean_select_cases):
            for case in corpus():
                value, error, typ = math_result(case)
                expected = (None, trap_for(error, typ)) if error else (value, None)
                self.assertEqual(reference_result(case), expected, case)
                count += 1
        self.assertGreater(count, 10000)

    def test_unsigned_division_is_never_marked_total_or_speculated(self):
        node = ast.parse('def division(a:u64,b:u64)->u64:\n return a//b\n').body[0]
        self.assertNotIn('division', total_scalar_functions([node]))
        builder = ScalarBuilder(node, {'division': 'f0'}, {'division': (['u64', 'u64'], 'u64')})
        self.assertFalse(builder.total_scalar_expression(node.body[0].value))
        builder.statements(node.body)
        self.assertEqual(builder.blocks[0]['ops'][-1]['op'], 'int.div.checked')
        node = ast.parse('def division(a:i64,b:i64)->i64:\n return a//b\n').body[0]
        builder = ScalarBuilder(node, {'division': 'f0'}, {'division': (['i64', 'i64'], 'i64')})
        with self.assertRaisesRegex(ValueError, 'requires u64'):
            builder.statements(node.body)

    def test_development_cannot_replace_requested_cold_before_output(self):
        with patch.dict(os.environ, {DEVELOPMENT_COMPILER: '/unread-development', COLD_REPORT: '/unread-cold'}), patch(
                'tempfile.TemporaryDirectory', side_effect=AssertionError('fixture output preceded admission')):
            with self.assertRaisesRegex(AssertionError, 'development.*cold'):
                ProgramExecutionScalarsNativeTests.setUpClass()


class ProgramExecutionScalarsNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        development, cold = os.environ.get(DEVELOPMENT_COMPILER), os.environ.get(COLD_REPORT)
        if development and cold:
            raise AssertionError('development scalar fixture cannot override requested cold qualification')
        cls.source_inputs = {name: (ROOT / name).read_bytes() for name in (
            'tools/hia_program_execution_scalars.py', 'tests/test_hia_program_execution_scalars.py',
            'tools/generate_hia_selfhost.py', 'hepta/hia_program_runtime.py')}
        cls.cold_bytes = cls.cold_sources = None
        compiler = None
        if cold:
            from tools.build_hia_json_preflight import admit_cold_build
            cls.cold_bytes = Path(cold).read_bytes()
            report = json.loads(cls.cold_bytes)
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            cls.compiler_bytes = compiler.read_bytes()
            cls.cold_sources = admit_cold_build(cls.compiler_bytes, cls.cold_bytes)
            for name, data in cls.source_inputs.items():
                if cls.cold_sources.get(name) != sha256(data).hexdigest():
                    raise AssertionError('scalar fixture source is outside the admitted cold contract')
            cls.scope = 'MATCHING_SOURCE_COLD_COMPILER_COMPONENT_TEST'
        elif development:
            compiler = Path(development)
            cls.compiler_bytes = compiler.read_bytes()
            cls.scope = 'DEVELOPMENT_ONLY'
        else:
            cls.scope = 'BOOTSTRAP_DEVELOPMENT_ONLY'
        target = os.environ.get(OBSERVATIONS)
        if target:
            cls.folder = Path(target) / cls.__name__
            cls.folder.mkdir(mode=0o700, parents=True)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-vm-scalars-')
            cls.addClassCleanup(cls.temporary.cleanup)
            cls.folder = Path(cls.temporary.name)
        if compiler is None:
            seed, _ = build_seed(cls.folder)
            source = (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            if first.read_bytes() != compiler.read_bytes():
                raise AssertionError('development compiler generations differ')
            cls.compiler_bytes = compiler.read_bytes()
        cls.compiler = compiler
        cls.document = document()
        cls.checked = verify_core(cls.document)
        cls.source = render_assembly(cls.document).encode()
        (cls.folder / 'scalar-probe.hiaasm').write_bytes(cls.source)
        image, receipt = compile_stage(cls.folder, 'scalar-probe', compiler, cls.source)
        image_bytes = image.read_bytes()
        if compiler.read_bytes() != cls.compiler_bytes:
            raise AssertionError('compiler changed during scalar compilation')
        cls.native = NativeHiaJsonImage(image_bytes, sha256(image_bytes).hexdigest())
        cls.addClassCleanup(cls.native._mapping.close)
        cls.native_entries = cls.vm_entries = cls.math_cases = 0
        cls.manifest = {'scope': cls.scope, 'source_sha256': sha256(cls.source).hexdigest(),
            'image_sha256': sha256(image_bytes).hexdigest(), 'image_path': image.name,
            'compiler_sha256': sha256(cls.compiler_bytes).hexdigest(),
            'source_files': {name: sha256(data).hexdigest() for name, data in cls.source_inputs.items()},
            'compile_receipt': receipt}
        (cls.folder / 'manifest.json').write_text(json.dumps(cls.manifest, indent=2, sort_keys=True) + '\n')

    @classmethod
    def tearDownClass(cls):
        unchanged = all((ROOT / name).read_bytes() == data for name, data in cls.source_inputs.items())
        compiler_unchanged = cls.compiler.read_bytes() == cls.compiler_bytes
        cold_unchanged = True
        if cls.cold_bytes is not None:
            from tools.build_hia_json_preflight import current_sources
            cold_unchanged = (Path(os.environ[COLD_REPORT]).read_bytes() == cls.cold_bytes
                              and current_sources() == cls.cold_sources)
        observed = {'scope': cls.scope, 'native_entries': cls.native_entries, 'vm_entries': cls.vm_entries,
            'mathematical_cases': cls.math_cases, 'source_unchanged': unchanged,
            'compiler_unchanged': compiler_unchanged, 'cold_inputs_unchanged': cold_unchanged}
        (cls.folder / 'observations.json').write_text(json.dumps(observed, indent=2, sort_keys=True) + '\n')
        if not (unchanged and compiler_unchanged and cold_unchanged):
            raise AssertionError('scalar fixture inputs changed')

    def actual(self, case, *, preset=(0, 0), fill=165):
        guard = b'\x7b' * 16
        input_data = case.wire()
        source = ctypes.create_string_buffer(guard + input_data + guard, 88)
        output = ctypes.create_string_buffer(guard + b'\xa5' * 24 + guard, 56)
        initial = bytearray([fill] * 128)
        struct.pack_into('<2Q', initial, 0, *preset)
        workspace = ctypes.create_string_buffer(guard + initial + guard, 160)
        returned = self.native._entry(ctypes.byref(source, 16), 56, ctypes.byref(output, 16), 24,
                                      ctypes.byref(workspace, 16), 128)
        type(self).native_entries += 1
        self.assertEqual(returned, 24, case)
        self.assertEqual(source.raw, guard + input_data + guard, case)
        self.assertEqual(output.raw[:16] + output.raw[40:], guard + guard, case)
        self.assertEqual(workspace.raw[:16] + workspace.raw[144:], guard + guard, case)
        result = struct.unpack('<3Q', output.raw[16:40])
        expected_workspace = bytearray(initial)
        struct.pack_into('<2Q', expected_workspace, 96, result[1], result[2])
        self.assertEqual(workspace.raw[16:144], expected_workspace, case)
        return result, bytes(initial), workspace.raw[16:144]

    def check_corpus(self, cases):
        count = 0
        for case in cases:
            expected = math_result(case)
            actual, _before, _after = self.actual(case)
            self.assertEqual(actual, expected, case)
            value, error, typ = expected
            self.assertEqual(reference_result(case), (None, trap_for(error, typ)) if error else (value, None), case)
            count += 1
        type(self).math_cases += count
        return count

    def test_all_integer_operations_and_ten_type_boundaries(self):
        self.assertGreater(self.check_corpus(integer_cases()), 10000)

    def test_signed_unsigned_boolean_comparisons(self):
        self.assertGreater(self.check_corpus(compare_cases()), 1000)

    def test_every_integer_cast_pair_checked_and_wrap(self):
        cases = tuple(cast_cases())
        self.assertEqual({(case.at, case.t, case.mode) for case in cases},
                         {(a, b, mode) for a in range(1, 11) for b in range(1, 11) for mode in (1, 2)})
        self.check_corpus(cases)

    def test_boolean_operators_and_scalar_unit_select(self):
        self.check_corpus(boolean_select_cases())

    def test_private_invalid_opcode_type_and_noncanonical_words_refuse(self):
        cases = [Case(0, 1, 1, 0), Case(1, 1, 1, 0), Case(28, 1, 1, 0), Case(MASK64, 1, 1, 0),
                 Case(2, 0, 0, 0), Case(2, 13, 13, 0), Case(2, 1, 2, 0), Case(2, 1, 1, 256),
                 Case(8, 2, 2, 0, 65536), Case(16, 11, 11, 0), Case(17, 1, 1, 0),
                 Case(17, 11, 12, 0), Case(19, 11, 11, 0), Case(17, 11, 11, 2),
                 Case(23, 11, 11, 2), Case(24, 11, 11, 1, 2), Case(25, 11, 1, 0),
                 Case(26, 1, 11, 0, mode=1), Case(26, 11, 1, 0, mode=2),
                 Case(26, 1, 1, 0, mode=0), Case(26, 1, 1, 256, mode=2),
                 Case(27, 1, 1, 0), Case(27, 1, 11, 2), Case(27, 1, 11, 0, 256),
                 Case(27, 11, 11, 1, 1, 2), Case(27, 12, 11, 0, 1), Case(27, 0, 11, 0)]
        for case in cases:
            self.assertEqual(self.actual(case)[0], (0, 255, case.t), case)

    def test_existing_first_error_and_success_type_word_are_preserved(self):
        cases = [Case(2, 1, 1, 127, 1), Case(8, 8, 8, 7, 0), Case(8, 1, 1, 128, 255),
                 Case(10, 8, 8, 1, 64), Case(999, 99, 98, MASK64), Case(3, 8, 8, 9, 10)]
        for first in ((1, 5), (2, 12), (255, MASK64)):
            for case in cases:
                self.assertEqual(self.actual(case, preset=first)[0], (0, *first), (first, case))
        self.assertEqual(self.actual(Case(3, 8, 8, 9, 10), preset=(0, MASK64))[0], (19, 0, MASK64))

    def test_independent_vm_complete_output_workspace_and_canaries(self):
        cases = []
        for t in range(1, 11):
            lo, hi = limits(t)
            cases.extend((Case(2, t, t, raw(t, hi), 1), Case(7, t, t, raw(t, hi), raw(t, hi)),
                Case(8, t, t, raw(t, lo), raw(t, -1 if signed(t) else 0)),
                Case(9, t, t, raw(t, -7 if signed(t) else 7), raw(t, 3)),
                Case(11, t, t, raw(t, lo), 1), Case(26, 8, t, raw(t, lo), mode=2),
                Case(19, 11, t, raw(t, lo), raw(t, hi))))
        cases += [Case(23, 11, 11, 1), Case(27, 12, 11, 1), Case(27, 11, 11, 0, 1, 0), Case(1, 1, 1, 0)]
        for index, case in enumerate(cases):
            preset = (2, 12) if index == len(cases) - 1 else (0, 0)
            actual, before, after = self.actual(case, preset=preset, fill=(0, 165, 255)[index % 3])
            roots = [_Owner(-1, bytearray(case.wire())), _Owner(-2, bytearray([165] * 24)),
                     _Owner(-3, bytearray(before))]
            views = [_View(root, index != 0) for index, root in enumerate(roots)]
            machine = _Machine(self.checked, 100000, 0, None, 64)
            result = machine.invoke(machine.functions['f0'], views)
            type(self).vm_entries += 1
            self.assertEqual(result, [24], case)
            self.assertEqual(bytes(roots[0].data), case.wire(), case)
            self.assertEqual(bytes(roots[1].data), struct.pack('<3Q', *actual), case)
            self.assertEqual(bytes(roots[2].data), after, case)
            self.assertTrue(all(root.active and view.active for root, view in zip(roots, views)), case)
            self.assertEqual((machine.owners, machine.chains, machine.loans_started, machine.loans_ended), ({}, {}, 0, 0))


if __name__ == '__main__':
    unittest.main()
