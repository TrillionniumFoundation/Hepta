"""Differential controls for the independent Safe Core x86 decoder."""
from __future__ import annotations

import itertools
import os
import random
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from hepta.hia_safe_core_x64 import (
    Executor, SafeCoreMachineRejected, _reference_decode, _reference_memory_admitted,
    _reference_validate_calls,
)
from hepta.hia_safe_core_x64_decode_native import SELECTOR, SOURCE, installed_safe_core_x64_decode


class SafeCoreX64DecodeSourceTests(unittest.TestCase):
    def test_native_decoder_source_matches_independent_rules(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_safe_core_x64_decode import document
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))


class SafeCoreX64DecodeNativeTests(unittest.TestCase):
    def setUp(self):
        selected = os.environ.get(SELECTOR)
        if not selected:
            self.skipTest('requires a bound HIA Safe Core x86 decoder')
        self.native = installed_safe_core_x64_decode(selected)

    def test_native_core_profile_keeps_operation_order_and_type_boundaries(self):
        from hepta.hia_opcodes import OPCODES, TYPES
        from hepta.hia_safe_core import (
            SafeCoreRejected, _profile, _profile_configuration, _reference_profile_rows,
            _unsigned_profile_version,
        )
        from hepta.hia_program import verify_program
        from tests.test_hia_program import arithmetic

        for version in range(1, 7):
            _, _, widths = _profile_configuration(version)
            cases = [([(name, False)], []) for name in OPCODES]
            cases += [([], [name]) for name in TYPES]
            cases += [([('int.cast', True), ('call', False)], []),
                      ([('const', False), ('call', False), ('int.cast', True)], ['unit'])]
            for operations, types in cases:
                with self.subTest(version=version, operations=operations, types=types):
                    try:
                        _reference_profile_rows(operations, types, widths, version)
                    except SafeCoreRejected:
                        allowed = False
                    else:
                        allowed = True
                    decided, refusal = self.native.core_profile(version, operations, types)
                    self.assertEqual((decided, refusal is None), (version, allowed))
        self.assertEqual(self.native.core_profile(1, [('int.cast', True), ('call', False)], ['unit']),
                         (1, (2, 0)))
        self.assertEqual(self.native.core_profile(1, [('const', False), ('call', False)], ['unit']),
                         (1, (1, 1)))
        self.assertEqual(self.native.core_profile(6, [], ['u64'] * 260 + ['unit']), (6, (3, 0)))

        with patch('hepta.hia_safe_core._reference_profile_rows', side_effect=AssertionError('host profile entered')):
            for operation, typ, version in (('int.add.wrap', 'u64', 2), ('int.shl.checked', 'u64', 3),
                                            ('int.mul.checked', 'u64', 4), ('int.div.checked', 'u64', 5),
                                            ('int.add.wrap', 'i64', 6)):
                core = verify_program(arithmetic(operation, typ))
                self.assertEqual(_unsigned_profile_version(core), version)
                self.assertEqual(_profile(core, profile_version=version)[0]['returns'], [typ])

    def test_word_projection_uses_the_bound_elf_and_checks_stack_and_sysv(self):
        from pathlib import Path
        import tempfile
        from hepta.hia_program import verify_program
        from hepta.hia_program_native import compile_program_machine, emit_program_machine
        from hepta.hia_safe_core_elf import bind_final_artifact
        from tests.test_hia_program import arithmetic

        for name, operation in (('int.add.wrap', 9), ('int.sub.wrap', 10), ('int.mul.wrap', 32)):
            with self.subTest(operation=name), tempfile.TemporaryDirectory() as directory:
                core = verify_program(arithmetic(name, 'u64'))
                emitted = emit_program_machine(core)
                final = Path(directory) / 'scalar.so'
                compile_program_machine(emitted, program=core, output=final, linker='ld')
                function, = core.as_dict()['functions']
                binding = bind_final_artifact(emitted.object_bytes, final.read_bytes(), function['name'])
                nodes, value, abort, counts = self.native.project_scalar_values(binding, 2)
                self.assertEqual(abort, 3)
                self.assertEqual(nodes, ((1, 64, 0, 0, 0), (1, 64, 0, 0, 0),
                                         (operation, 64, 0, 1, 0), (2, 1, 0, 0, 0)))
                self.assertEqual(value, 2)
                self.assertGreater(counts['maximum_observed_stack_bytes'], 0)
                self.assertEqual(counts['machine_terminal_paths'], 1)

        def project(code, calls=None):
            return self.native.project_scalar_values({'text': bytes.fromhex(code), 'entry': 0,
                                                      'calls': calls or {}}, 1)

        # A returning leaf with a valid stack. The value is the first ABI word.
        self.assertEqual(project('4889f8c3')[1], 0)
        for name, raw, calls in (
                ('callee-saved register clobbered', '4889fb4889f8c3', {}),
                ('unknown input register used as RAX', '4889d8c3', {}),
                ('write to caller return word', '4889bc24000000004889f8c3', {}),
                ('out-of-window load', '488b8424f8ffffffc3', {}),
                ('misaligned local call', 'e8000000004889f8c3', {0: 5}),
                ('repeated instruction', 'e9fbffffff', {}),
                ('abort path is outside this projection', 'e8000000000f0b', {0: 'abort'})):
            with self.subTest(case=name):
                self.assertIsNone(project(raw, calls))

    def test_unsigned_profiles_preserve_exact_decoding_and_state_effects(self):
        import z3

        ctx = z3.Context()
        reference, native = Executor.__new__(Executor), Executor.__new__(Executor)
        reference.__dict__.update(z=z3, ctx=ctx, steps=1, native_model=None)
        native.__dict__.update(vars(reference), native_model=self.native)
        inputs = {index: z3.BitVec(f'extended_r{index}', 64, ctx=ctx) for index in range(16)}
        flags = {name: z3.Bool(name, ctx=ctx) for name in ('zf', 'cf')}
        true = z3.BoolVal(True, ctx=ctx)

        def equivalent(left, right):
            if not z3.eq(z3.simplify(left), z3.simplify(right)):
                solver = z3.Solver(ctx=ctx)
                solver.set(timeout=5000)
                solver.add(left != right)
                self.assertEqual(solver.check(), z3.unsat)

        for operation, opcode, group, profile in (
                ('shl_cl', 0xd3, 4, 'allow_variable_shifts'),
                ('shr_cl', 0xd3, 5, 'allow_variable_shifts'),
                ('mul', 0xf7, 4, 'allow_unsigned_multiply'),
                ('div', 0xf7, 6, 'allow_unsigned_divide')):
            for register in range(16):
                with self.subTest(operation=operation, register=register):
                    code = bytes((0x48 | (register >> 3), opcode, 0xc0 | (group << 3) | (register & 7)))
                    with self.assertRaises(SafeCoreMachineRejected):
                        self.native.decode(code)
                    self.assertEqual(self.native.decode(code, **{profile: True}),
                                     _reference_decode(code, **{profile: True}))
                    before = SimpleNamespace(registers=inputs.copy(), flags=flags.copy(), path=true)
                    after = SimpleNamespace(registers=inputs.copy(), flags=flags.copy(), path=true)
                    reference.extended_registers(before, operation, (register,))
                    native.extended_registers(after, operation, (register,))
                    for index in inputs:
                        equivalent(before.registers[index], after.registers[index])
                    for name in flags:
                        equivalent(before.flags[name], after.flags[name])
                    equivalent(before.path, after.path)

    def test_new_core_unsigned_formulas_match_the_independent_theory(self):
        import z3
        from hepta.hia_safe_core import _Theory, WIDTHS_V2

        theory = _Theory(z3, 5000, widths=WIDTHS_V2)
        theory.core_model = self.native
        for typ in ('u8', 'u16', 'u32', 'u64', 'usize'):
            operands = tuple(theory.normalized(z3.BitVec(f'operand{index}', 64, ctx=theory.ctx), typ)
                             for index in range(2))
            for op in ('mul', 'div', 'rem', 'neg', 'shl', 'shr'):
                with self.subTest(type=typ, operation=op):
                    name = f'int.{op}.checked'
                    arguments = operands[:1] if op == 'neg' else operands
                    actual = theory.scalar_operation(name, {}, arguments, typ)
                    expected = theory._reference_scalar_operation(name, {}, arguments, typ)
                    self.assertTrue(all(z3.eq(z3.simplify(a), z3.simplify(b))
                                        for a, b in zip(actual, expected, strict=True)))

    def test_parameter_words_match_independent_type_normalization(self):
        import z3
        from hepta.hia_safe_core import _Theory, WIDTHS_V6

        theory = _Theory(z3, 5000, widths=WIDTHS_V6)
        theory.core_model = self.native
        theory.arguments({'params': [{'name': kind, 'type': kind} for kind in WIDTHS_V6]})
        for kind, word in zip(WIDTHS_V6, theory.words, strict=True):
            self.assertTrue(z3.eq(theory.inputs[kind], theory.normalized(word, kind)), kind)
        self.assertEqual(self.native.argument_registers(), (7, 6, 2, 1, 8, 9))

    def test_artifact_predicates_preserve_the_exact_retained_smt_expressions(self):
        from hepta.hia_safe_core import _Theory, _reference_artifact_assumptions, _reference_artifact_errors
        import z3

        theory = _Theory(z3, 5000)
        ctx = theory.ctx
        stack, pointer, length, left, right = [
            z3.BitVec(name, 64, ctx=ctx) for name in ('stack', 'pointer', 'length', 'left', 'right')]
        theory.loan = pointer, length, 'mutbuf'
        core_live, core_abort, machine_live, machine_abort = [
            z3.Bool(name, ctx=ctx) for name in ('core_live', 'core_abort', 'machine_live', 'machine_abort')]
        core_bytes, machine_bytes = [
            z3.Array(name, z3.BitVecSort(64, ctx), z3.BitVecSort(8, ctx))
            for name in ('core_bytes', 'machine_bytes')]

        def native(operation, *args):
            return self.native.artifact_predicate(z3, ctx, operation, *args)

        def smt(expressions):
            solver = z3.Solver(ctx=ctx)
            solver.add(*expressions)
            return solver.sexpr()

        for extent in (0, 32, 4096):
            actual = [native(rule, stack) for rule in
                      ('caller_stack_floor', 'caller_stack_ceiling', 'caller_stack_alignment')]
            actual.append(native('caller_loan_disjoint', stack, pointer, length, theory.bv(extent)))
            self.assertEqual(smt(actual), smt(_reference_artifact_assumptions(theory, stack, extent)))
        expected = _reference_artifact_errors(
            z3, (core_live, core_abort, left, core_bytes), (machine_live, machine_abort, right, machine_bytes))
        actual = (native('terminal_coverage_error', core_live, machine_live),
                  native('observable_refinement_error', core_abort, machine_abort, left, right,
                         native('caller_memory_difference', core_bytes, machine_bytes)))
        self.assertEqual(smt(actual), smt(expected))

    def test_selected_signed_builds_prove_without_foreign_search(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        import z3
        from hepta.hia_cnf_native import selected_cnf
        from hepta.hia_safe_core import build_safe_core
        from tests.test_hia_safe_core_signed import core_operation

        solver = selected_cnf()
        if solver is None:
            self.skipTest('requires the installed HIA Boolean solver')
        cases = (
            ('int.add.wrap', 'i8', {}), ('int.sub.wrap', 'i32', {}),
            ('int.neg.checked', 'i8', {}), ('int.shr.checked', 'i8', {}),
            ('int.add.checked', 'i8', {}),
            ('int.cast', 'i16', {'destination': 'u8', 'mode': 'checked'}),
            ('int.div.checked', 'i8', {}), ('int.rem.checked', 'i8', {}),
            ('int.div.checked', 'i16', {}),
            ('int.div.checked', 'i32', {}), ('int.rem.checked', 'i32', {}),
            ('int.div.checked', 'i64', {}), ('int.rem.checked', 'i64', {}),
        )
        with TemporaryDirectory(prefix='hia-native-signed-proof-') as root:
            for index, (operation, kind, attrs) in enumerate(cases):
                with (self.subTest(operation=operation, type=kind),
                      patch('hepta.hia_cnf_native.bitblast_goal', side_effect=AssertionError('host bitblaster')),
                      patch.object(z3.Solver, 'check', side_effect=AssertionError('host solver'))):
                    output = Path(root) / f'{index}.so'
                    report = build_safe_core(core_operation(operation, kind, **attrs), output, profile_version=6)
                    self.assertTrue(report['ok'])
                    self.assertTrue(output.is_file())
                    for row in report['validation']['obligations']:
                        self.assertEqual(row['native_cnf']['method'], 'native_hia_circuit_cnf')
                        self.assertEqual(row['native_cnf']['image_sha256'], solver.image_sha256)

    def test_wide_arithmetic_abstraction_never_confirms_a_spurious_sat(self):
        import time
        import z3
        from hepta.hia_cnf_native import SAT, abstract_wide_division, bitvector_circuit, selected_cnf
        from hepta.hia_safe_core import _native_obligation

        native = selected_cnf()
        if native is None:
            self.skipTest('requires the installed HIA Boolean solver')
        left, right = z3.BitVecs('abstract_left abstract_right', 32)
        expression = z3.And(left == 1, right == 1, left / right == 0)
        foreign = z3.Solver()
        foreign.add(expression)
        self.assertEqual(foreign.check(), z3.unsat)
        relaxed = abstract_wide_division(z3, z3.simplify(expression))
        circuit = bitvector_circuit(z3, relaxed)
        spurious = native.solve_circuit(circuit.nodes, circuit.returns, steps=200000, watched=True)
        self.assertEqual(spurious[0], SAT)
        with (patch.object(native, 'solve_circuit', side_effect=(None, spurious)),
              patch('hepta.hia_cnf_native.bitblast_goal', return_value=None)):
            self.assertIsNone(_native_obligation(z3, native, expression, time.monotonic() + 5))

    def test_signed_admission_and_machine_effects_use_native_recipes(self):
        import z3

        ctx = z3.Context()
        ref = Executor.__new__(Executor)
        ref.__dict__.update(z=z3, ctx=ctx, steps=7, native_model=None, signed_profile=True)
        native = Executor.__new__(Executor)
        native.__dict__.update(vars(ref), native_model=self.native)
        words = [z3.BitVec(f'signed_r{index}', 64, ctx=ctx) for index in range(3)]
        flags = {name: z3.Bool(name, ctx=ctx) for name in ('zf', 'cf', 'sf', 'of')}
        live = z3.BoolVal(True, ctx=ctx)

        def state(values=words):
            return SimpleNamespace(registers=dict(enumerate(values)), flags=flags.copy(), path=live)

        def same(a, b):
            if not z3.eq(z3.simplify(a), z3.simplify(b)):
                solver = z3.Solver(ctx=ctx)
                solver.set(timeout=5000)
                solver.add(a != b)
                self.assertEqual(solver.check(), z3.unsat)

        def compare(method, operation, args, values=words):
            with self.subTest(operation=operation, args=args):
                before, after = state(values), state(values)
                getattr(ref, method)(before, operation, *args)
                getattr(native, method)(after, operation, *args)
                for index in before.registers:
                    same(before.registers[index], after.registers[index])
                for name in flags:
                    same(before.flags[name], after.flags[name])
                same(before.path, after.path)

        profiles = {'allow_signed': True, 'allow_variable_shifts': True}
        new_encodings = ('4899', '48f7d8', '48c1f83f', '48d3f8', '48f7ea', '48f7fa', '0f8c0000000090', '400f9cc0')
        for encoding in new_encodings:
            code = bytes.fromhex(encoding)
            with self.assertRaises(SafeCoreMachineRejected):
                self.native.decode(code, allow_variable_shifts=True)
            self.assertEqual(self.native.decode(code, **profiles), _reference_decode(code, **profiles))

        for condition in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 14, 15):
            same(ref.condition(state(), condition), native.condition(state(), condition))
            compare('register_formula', 'setcc', ((condition, 0),))
        for op in ('add', 'sub', 'cmp', 'and', 'or', 'xor', 'test'):
            compare('alu', op, (0, words[1]))
        compare('register_formula', 'neg', ((0,),))
        compare('register_formula', 'imul', ((0, 1),))
        for op in ('shl', 'shr', 'sar'):
            for count in (0, 1, 2, 63):
                compare('register_formula', op, ((0, count),))
            compare('extended_registers', op + '_cl', ((1,),))
        for register in (0, 2):
            compare('extended_registers', 'imul_full', ((register,),))
            compare('extended_registers', 'idiv', ((register,),))
            compare('extended_registers', 'idiv', ((register,),), [*words[:2], ref.cqo(words[0])])
        same(ref.cqo(words[0]), native.cqo(words[0]))

    def test_all_byte_pairs_and_complete_instruction_controls(self):
        def outcome(decode, raw):
            try:
                return None, decode(raw)
            except SafeCoreMachineRejected as exc:
                return str(exc), None

        corpus = bytes.fromhex(
            '4157 415f 48b8ffffffffffffffff b834120000 c9 c3 90 '
            'e8f0ffffff e900000000 90 0f8400000000 90 400f95c0 4d0f45c1 480fafc3 '
            '480fb68424f0ffffff 0f0b 40888424f0ffffff 4889d1 48898c24f0ffffff '
            '488b8c24f0ffffff 488d8c24f0ffffff 4801c1 4829c1 4821c1 4809c1 4831c1 4839c1 4885c1 '
            '4881c0f0ffffff 4883e8ff 48c1e03f 48c1e800 48f7d0'
        )
        rng = random.Random(2996)
        samples = itertools.chain(
            (b'', b'\x90' * 8192, b'\x90' * 8193, b'\x90' * 65537, corpus),
            (bytes((opcode,)) for opcode in range(256)),
            map(bytes, itertools.product(range(256), repeat=2)),
            (corpus[:i] + bytes((value,)) + corpus[i + 1:]
             for i in range(len(corpus)) for value in (0, 0x40, 0x48, 0x90, 0xff)),
            (rng.randbytes(rng.randrange(1, 96)) for _ in range(4096)),
        )
        for index, raw in enumerate(samples):
            self.assertEqual(outcome(self.native.decode, raw), outcome(_reference_decode, raw),
                             (index, raw[:32].hex(), len(raw)))

    def test_symbolic_register_and_condition_formulas_match_independent_reference(self):
        import z3

        ctx = z3.Context()
        left, right = (z3.BitVec(name, 64, ctx=ctx) for name in ('left', 'right'))
        zf, cf = (z3.Bool(name, ctx=ctx) for name in ('zero', 'carry'))
        host = SimpleNamespace(z=z3, ctx=ctx, steps=42, native_model=None)
        reference, native = Executor.__new__(Executor), Executor.__new__(Executor)
        reference.__dict__.update(vars(host))
        native.__dict__.update(vars(host), native_model=self.native)

        def state():
            return SimpleNamespace(registers={0: left, 1: right}, flags={'zf': zf, 'cf': cf})

        def compare(before, after, case):
            self.assertTrue(z3.eq(before.registers[0], after.registers[0]), case)
            self.assertTrue(z3.eq(before.registers[1], after.registers[1]), case)
            for flag in ('zf', 'cf'):
                self.assertTrue(z3.eq(before.flags[flag], after.flags[flag]), (case, flag))

        for operation in ('add', 'sub', 'and', 'or', 'xor', 'cmp', 'test'):
            for operand in (right, left, z3.BitVecVal(0, 64, ctx=ctx), z3.BitVecVal(-1, 64, ctx=ctx)):
                before, after = state(), state()
                reference.alu(before, operation, 0, operand)
                native.alu(after, operation, 0, operand)
                compare(before, after, operation)

        cases = [('not', (0,)), ('cmovne', (0, 1)), ('cmovne', (0, 0)),
                 ('imul', (0, 1)), ('imul', (0, 0))]
        cases += [(operation, (0, count)) for operation in ('shl', 'shr') for count in range(64)]
        cases += [('setcc', (condition, 0)) for condition in range(2, 8)]
        for operation, args in cases:
            before, after = state(), state()
            reference.register_formula(before, operation, args)
            native.register_formula(after, operation, args)
            compare(before, after, (operation, args))
        for condition in range(2, 8):
            self.assertTrue(z3.eq(reference.condition(state(), condition),
                                  native.condition(state(), condition)), condition)

    def test_machine_address_and_stack_formulas_match_reference(self):
        import z3

        ctx = z3.Context()
        base, pointer, length = (z3.BitVec(name, 64, ctx=ctx) for name in ('base', 'pointer', 'length'))
        executor = Executor.__new__(Executor)
        executor.__dict__.update(z=z3, ctx=ctx, native_model=self.native)
        for offset in (None, -(1 << 63), -16385, -16384, -1, 0, 8, 9, (1 << 63) - 1):
            self.assertEqual(self.native.stack_admitted(offset), executor._reference_stack_admitted(offset))
        for word in (base, base + 8, executor.value(-1)):
            for op in ('load', 'load8', 'store', 'store8', 'lea'):
                for disp in (-(1 << 31), -1, 0, (1 << 31) - 1):
                    self.assertTrue(z3.eq(executor.address(op, word, disp),
                                          executor._reference_address(word, disp)), (op, disp))
            for op in ('push', 'pop', 'leave', 'call', 'ret'):
                actual = executor.stack_adjustment(op, word)
                expected = executor._reference_stack_adjustment(op, word)
                self.assertTrue(z3.eq(actual[0], expected[0]), op)
                if expected[1] is None:
                    self.assertIsNone(actual[1], op)
                else:
                    self.assertTrue(z3.eq(actual[1], expected[1]), op)
            self.assertTrue(z3.eq(executor.borrow_range(word, pointer, length),
                                  executor._reference_borrow_range(word, pointer, length)))

    def test_native_return_recovers_sites_and_preserves_exact_caller_registers(self):
        import z3

        ctx = z3.Context()
        initial = [z3.BitVec(f'caller_r{register}', 64, ctx=ctx) for register in range(16)]
        executor = Executor.__new__(Executor)
        executor.__dict__.update(z=z3, ctx=ctx, native_model=self.native,
                                 codebase=z3.BitVec('codebase', 64, ctx=ctx),
                                 sp=initial[4], initial=initial)
        for offset in (0, 1, 128, 65535):
            address = executor.return_site(offset)
            expected = executor._reference_return_site(offset, recover=False)
            self.assertTrue(z3.eq(address, expected))
            self.assertEqual(executor.return_site(address, recover=True).as_long(), offset)
        restored = initial.copy()
        restored[4] = initial[4] + 8
        for register in range(16):
            changed = restored.copy()
            changed[register] += 1
            actual = executor.caller_restored(changed)
            self.assertTrue(z3.eq(actual, executor._reference_caller_restored(changed)), register)
            self.assertEqual(z3.is_true(z3.simplify(actual)), register not in (3, 4, 5, 12, 13, 14, 15))

    def test_core_scalar_rules_preserve_normalized_values_and_traps(self):
        import z3

        from hepta.hia_safe_core import WIDTHS_V2, _Theory

        theory = _Theory(z3, 15000, widths=WIDTHS_V2)
        a, b, c = (z3.BitVec(name, 64, ctx=theory.ctx) for name in ('core_a', 'core_b', 'core_c'))

        def compare(name, attributes, args, kind):
            expected = theory._reference_scalar_operation(name, attributes, args, kind)
            actual = theory.scalar_operation(name, attributes, args, kind)
            for before, after in zip(expected, actual, strict=True):
                if before is None or after is None:
                    self.assertIs(before, after, (name, kind))
                else:
                    self.assertTrue(z3.eq(before, after), (name, kind))

        for kind in ('u8', 'u16', 'u32', 'u64', 'usize'):
            left, right = theory.normalized(a, kind), theory.normalized(b, kind)
            for op in ('int.add.wrap', 'int.sub.wrap', 'int.mul.wrap', 'int.add.checked',
                       'int.sub.checked', 'bit.and', 'bit.or', 'bit.xor'):
                compare(op, {}, [left, right], kind)
            compare('bit.not', {}, [left], kind)
            for mode in ('wrap', 'checked'):
                compare('int.cast', {'mode': mode}, [a], kind)
            compare('const', {'value': (1 << theory.widths[kind]) - 1}, [], kind)
            for relation in ('eq', 'ne', 'lt', 'le', 'gt', 'ge'):
                compare('compare.' + relation, {}, [left, right], 'bool')
            compare('select', {}, [theory.normalized(c, 'bool'), left, right], kind)
        boolean = [theory.normalized(value, 'bool') for value in (a, b)]
        for op in ('bool.and', 'bool.or'):
            compare(op, {}, boolean, 'bool')
        compare('bool.not', {}, boolean[:1], 'bool')

    def test_native_core_topology_matches_reference_for_all_graph_sizes(self):
        from hepta.hia_safe_core import SafeCoreRejected, _reference_core_graph

        rng = random.Random(3009)
        for count in range(1, 17):
            for trial in range(32):
                adjacency, blocks = [], {}
                for index in range(count):
                    start = 0 if trial % 2 else index + 1
                    targets = rng.sample(range(start, count), min(max(0, count - start), rng.randrange(3)))
                    adjacency.append(sum(1 << target for target in targets))
                    if targets == []:
                        term = dict(op='ret')
                    elif len(targets) == 1:
                        term = dict(op='jump', target=targets[0])
                    else:
                        term = {'op': 'branch', 'then': {'target': targets[0]},
                                'else': {'target': targets[1]}}
                    blocks[index] = {'term': term}
                try:
                    _reference_core_graph(blocks)
                    expected = True
                except SafeCoreRejected:
                    expected = False
                self.assertEqual(self.native.acyclic_core_graph(adjacency), expected, adjacency)

    def test_native_graph_plan_preserves_branch_multiplicity_and_entry_budget(self):
        graph = ((), (0, 2), (0,), (1, 1), (0, 0))
        adjacency = (0, 5, 1, 2, 1)
        original_order = self.native.core_graph_order(adjacency)
        for entry, paths in enumerate((1, 2, 1, 4, 2)):
            with self.subTest(entry=entry):
                self.assertEqual(self.native.core_graph_plan(graph, entry, paths),
                                 (original_order, paths))
                if paths > 1:
                    self.assertIsNone(self.native.core_graph_plan(graph, entry, paths - 1))
        cascade = tuple((index + 1, index + 1) for index in range(15)) + ((),)
        self.assertIsNone(self.native.core_graph_plan(cascade, 0, 1024))
        self.assertEqual(self.native.core_graph_plan(cascade, 5, 1024), (tuple(range(16)), 1024))
        self.assertEqual(self.native.core_graph_plan(cascade, 15, 1), (tuple(range(16)), 1))
        self.assertIsNone(self.native.core_graph_plan(((1,), (0,)), 0, 1024))
        self.assertIsNone(self.native.core_graph_plan(((2,), ()), 2, 1024))

    def test_actual_borrowed_abi_uses_native_guards_and_byte_addresses(self):
        from pathlib import Path
        import tempfile

        from hepta.hia_cnf_native import selected_cnf
        from hepta.hia_safe_core import _FiniteCallerMemory, _Theory, build_safe_core
        from tests.test_hia_safe_core import guarded_update

        blocked = {name: Mock(side_effect=AssertionError('host borrow rule entered: ' + name))
                   for name in ('_reference_borrow_guards', '_reference_buffer_address')}
        blocked_machine = {
            name: Mock(side_effect=AssertionError('host machine memory rule entered: ' + name))
            for name in ('_reference_borrow_range', '_reference_address', '_reference_stack_admitted',
                         '_reference_stack_adjustment', '_reference_return_site', '_reference_caller_restored')
        }
        lowered = []
        reduce_memory = _FiniteCallerMemory.reduce

        def observe_memory(memory, expression):
            result = reduce_memory(memory, expression)
            if result is not None:
                lowered.append((len(memory.rows), len(memory.initial_bytes)))
            return result

        with (tempfile.TemporaryDirectory(prefix='hia-safe-core-borrow-') as root,
              patch('hepta.hia_safe_core._reference_core_graph',
                    side_effect=AssertionError('host Core topology entered')),
              patch('hepta.hia_safe_core._reference_artifact_assumptions',
                    side_effect=AssertionError('host caller contract entered')),
              patch('hepta.hia_safe_core._reference_artifact_errors',
                    side_effect=AssertionError('host artifact obligations entered')),
              patch.multiple(Executor, **blocked_machine),
              patch.multiple(_Theory, **blocked),
              patch.object(_FiniteCallerMemory, 'reduce', observe_memory)):
            report = build_safe_core(guarded_update(), Path(root) / 'candidate.so',
                                     foreign_extent=32)
        self.assertTrue(report['validation']['ok'], report)
        if selected_cnf() is not None:
            self.assertEqual(len(lowered), 1)
            self.assertGreater(lowered[0][0], 1)
            self.assertGreater(lowered[0][1], 0)

    def test_finite_memory_inventory_tracks_only_reachable_writes(self):
        rng = random.Random(3015)
        for count in range(1, 64):
            rows, writes = [(0, 0, 0)], [set()]
            for index in range(1, count):
                parent = rng.randrange(index)
                if rng.randrange(2):
                    rows.append((1, parent, 0))
                    writes.append(writes[parent] | {index})
                else:
                    alternate = rng.randrange(index)
                    rows.append((2, parent, alternate))
                    writes.append(writes[parent] | writes[alternate])
            for _ in range(4):
                first, second = (rng.randrange(count) for _ in range(2))
                self.assertEqual(self.native.possible_memory_writes(rows, first, second),
                                 tuple(sorted(writes[first] | writes[second])))
        self.assertEqual(self.native.possible_memory_writes(
            [(0, 0, 0), *[(1, index - 1, 0) for index in range(1, 63)]], 0, 62), tuple(range(1, 63)))
        for rows in ([(1, 0, 0)], [(0, 0, 0), (1, 1, 0)], [(0, 0, 0), (2, 0, 1)],
                     [(0, 0, 0), (0, 0, 0)], [(0, 0, 0), (1, 0, 1)]):
            with self.assertRaisesRegex(RuntimeError, 'memory graph'):
                self.native.possible_memory_writes(rows, 0, len(rows) - 1)

    def test_native_learning_discharges_all_guarded_update_obligations(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory

        import z3

        from hepta.hia_cnf_native import selected_cnf
        from hepta.hia_safe_core import ARTIFACT_OBLIGATIONS, build_safe_core
        from tests.test_hia_safe_core import guarded_update

        cnf = selected_cnf()
        if cnf is None:
            self.skipTest('requires the installed HIA Boolean solver')
        with TemporaryDirectory(prefix='hia-safe-core-guarded-cnf-') as root:
            for extent in (64, 4096):
                with self.subTest(extent=extent):
                    destination = Path(root) / f'guarded-{extent}.so'
                    with (patch.object(z3.Solver, 'check', side_effect=AssertionError('host solver entered')),
                          patch('hepta.hia_cnf_native.bitblast_goal',
                                side_effect=AssertionError('host bitblaster entered'))):
                        report = build_safe_core(guarded_update(), destination, foreign_extent=extent)
                    self.assertTrue(report['ok'], report)
                    self.assertTrue(destination.is_file())
                    obligations = report['validation']['obligations']
                    self.assertEqual(tuple((item['name'], item['result']) for item in obligations),
                                     ARTIFACT_OBLIGATIONS)
                    for item in obligations:
                        evidence = item['native_cnf']
                        self.assertEqual(evidence['method'], 'native_hia_circuit_cnf')
                        self.assertEqual(evidence['search'], 'native_hia_conflict_learning')
                        self.assertEqual(evidence['restarts'], 'bounded_geometric')
                        self.assertEqual(evidence['image_sha256'], cnf.image_sha256)
                    self.assertEqual(obligations[-1]['native_cnf']['caller_memory'],
                                     'native_hia_finite_byte_array')

    def test_finite_memory_obligation_projects_aliases_and_counterexamples(self):
        import time
        import z3

        from hepta.hia_cnf_native import selected_cnf
        from hepta.hia_safe_core import _FiniteCallerMemory, _native_obligation

        cnf = selected_cnf()
        if cnf is None:
            self.skipTest('requires the installed HIA Boolean solver')
        ctx = z3.Context()
        initial = z3.Array('caller_memory', z3.BitVecSort(64, ctx), z3.BitVecSort(8, ctx))
        at, other = (z3.BitVec(name, 64, ctx=ctx) for name in ('at', 'other'))
        condition = z3.Bool('pick_left', ctx=ctx)
        update = z3.Store(initial, at, 117)
        joined = z3.If(condition, update, z3.Store(initial, other, 53))
        cases = (
            (z3.And(at == other, z3.Select(initial, at) != z3.Select(initial, other)), 'unsat'),
            (z3.And(condition, at == other, update != joined), 'unsat'),
            (z3.And(z3.Not(condition), at == other, update == joined), 'unsat'),
            (z3.And(z3.Not(condition), at == other, joined != initial, z3.Select(initial, at) == 17), 'sat'),
        )
        for expression, expected in cases:
            deadline = time.monotonic() + 8
            finite = _FiniteCallerMemory(z3, self.native, initial, deadline)
            reference = z3.Solver(ctx=ctx)
            reference.add(expression)
            self.assertEqual(str(reference.check()), expected)
            with (patch.object(z3.Solver, 'check', side_effect=AssertionError('host SMT search entered')),
                  patch('hepta.hia_cnf_native.bitblast_goal',
                        side_effect=AssertionError('host Boolean lowering entered'))):
                solved = _native_obligation(z3, cnf, expression, deadline, memory=finite)
            self.assertIsNotNone(solved, expression)
            verdict, model, receipt = solved
            self.assertEqual(verdict, expected, expression)
            self.assertEqual(receipt.get('caller_memory'), 'native_hia_finite_byte_array')
            if model is not None:
                self.assertTrue(z3.is_true(model.eval(expression, model_completion=True)))
                self.assertEqual(model.eval(z3.Select(initial, model.eval(at))).as_long(), 17)
        alien = z3.Array('different_memory', initial.domain(), initial.range())
        finite = _FiniteCallerMemory(z3, self.native, initial, time.monotonic() + 8)
        self.assertIsNone(finite.reduce(initial != alien))

    def test_actual_consumer_proves_from_installed_machine_rules_without_host_formulas(self):
        from hashlib import sha256
        from pathlib import Path
        import tempfile

        from hepta.hia_program import verify_program
        from hepta.hia_program_native import compile_program_machine, emit_program_machine
        from hepta.hia_safe_core import _Theory, validate_safe_core_artifact
        from tests.test_hia_program import arithmetic

        core = verify_program(arithmetic('int.mul.wrap', 'u32'))
        image = emit_program_machine(core)
        with tempfile.TemporaryDirectory(prefix='hia-safe-core-x64-') as root:
            final = Path(root) / 'candidate.so'
            compile_program_machine(image, program=core, output=final, linker='ld')
            blocked = {name: Mock(side_effect=AssertionError('host machine rule entered: ' + name))
                       for name in ('_reference_alu', '_reference_condition',
                                    '_reference_register_formula', '_reference_schedule')}
            with (patch('hepta.hia_safe_core_x64._reference_decode',
                        side_effect=AssertionError('host decoder entered the Safe Core checker')),
                  patch('hepta.hia_safe_core_x64._reference_validate_calls',
                        side_effect=AssertionError('host call binding entered the Safe Core checker')),
                  patch('hepta.hia_safe_core_x64._reference_memory_admitted',
                        side_effect=AssertionError('host access policy entered the Safe Core checker')),
                  patch.object(_Theory, '_reference_scalar_operation',
                               side_effect=AssertionError('host Core scalar semantics entered')),
                  patch.object(_Theory, 'normalized',
                               side_effect=AssertionError('host Core parameter normalization entered')),
                  patch.multiple(Executor, **blocked)):
                proof = validate_safe_core_artifact(core, image.object_bytes, final.read_bytes())
        self.assertTrue(proof['ok'], proof)
        self.assertEqual(proof['source_identity']['native_x64_decoder_image_sha256'], self.native.image_sha256)
        self.assertEqual(proof['source_identity']['native_x64_decoder_source_sha256'],
                         sha256(SOURCE.read_bytes()).hexdigest())
        self.assertFalse(proof['checker']['producer_reemission_used'])

    def test_call_inventory_matches_exact_decoded_instruction_boundaries(self):
        def retained(data, calls):
            code = _reference_decode(data)
            _reference_validate_calls(code, calls)
            return code

        def observe(check, data, calls):
            try:
                return check(data, calls)
            except SafeCoreMachineRejected as exc:
                return str(exc)

        text = bytes.fromhex('e801000000 90 c3')
        pair = bytes.fromhex('e805000000 e801000000 90 c3')
        cases = [(text, calls) for calls in ({0: 6}, {0: 'abort'}, {}, {1: 6}, {0: 5},
                                            {0: 2}, {0: -1}, {-1: 6}, {0: 6, 1: 6})]
        cases += [(pair, calls) for calls in ({5: 11, 0: 10}, {0: 2}, {0: 2, 5: 11},
                                             {0: 'abort', 5: 11}, {0: 'abort', 6: 11})]
        cases.append((text[:-3], {0: 6}))
        for data, calls in cases:
            self.assertEqual(observe(self.native.decode, data, calls),
                             observe(retained, data, calls), calls)

    def test_memory_admission_matches_reference_at_signed_boundaries(self):
        offsets = (-(1 << 63), -16385, -16384, -8, -7, -1, 0, 1, 7, 8, 9, (1 << 63) - 1)
        cases = itertools.chain(
            itertools.product(offsets, (-16384, -8, 0, 8), (1, 8), (False, True), (None,)),
            itertools.product((None,), (None,), (1, 8), (False, True), (None, 'readbuf', 'mutbuf')),
        )
        for args in cases:
            self.assertEqual(self.native.memory_admitted(*args), _reference_memory_admitted(*args), args)

    def test_scheduler_paths_are_depth_first_with_independent_ancestor_snapshots(self):
        policy = self.native.scheduler()
        self.assertEqual(policy.start(1), (1, 1, 0))
        self.assertEqual(policy.observed(True, 0), (2, 1, 1))
        self.assertEqual(policy.advance(False, 2), (1, 1, 1))
        self.assertEqual(policy.observed(True, 1), (2, 1, 2))
        self.assertEqual(policy.advance(False, 3), (1, 1, 2))
        self.assertEqual(policy.observed(True, 2), (2, 1, 3))
        self.assertEqual(policy.advance(True), (1, 3, 3))
        self.assertEqual(policy.observed(True, 2), (2, 3, 4))
        self.assertEqual(policy.advance(True), (1, 2, 4))
        self.assertEqual(policy.observed(True, 1), (2, 2, 5))
        self.assertEqual(policy.advance(False), (1, 2, 5))
        with self.assertRaisesRegex(SafeCoreMachineRejected, 'cycle or recursion'):
            policy.observed(True, 0)

        policy = self.native.scheduler()
        self.assertEqual(policy.start(4), (1, 4, 0))
        self.assertEqual(policy.observed(False), (0, 0, 0))
        policy = self.native.scheduler()
        policy.start(5)
        with self.assertRaisesRegex(SafeCoreMachineRejected, 'unknown instruction entry'):
            policy.observed(True)

    def test_scheduler_checks_both_exact_budget_boundaries(self):
        policy = self.native.scheduler()
        policy.start(1)
        for ordinal in range(4096):
            self.assertEqual(policy.observed(True, ordinal), (2, 1, ordinal + 1))
            policy.advance(False, ordinal + 2)
        for handle in range(4097, 2, -1):
            self.assertEqual(policy.observed(False), (1, handle, 4096))
        with self.assertRaisesRegex(SafeCoreMachineRejected, 'machine path budget exceeded'):
            policy.observed(False)

        policy = self.native.scheduler()
        policy.start(1)
        for ordinal in range(16):
            policy.observed(True, ordinal)
            policy.advance(False, ordinal + 2)
        steps = 16
        with self.assertRaisesRegex(SafeCoreMachineRejected, 'machine execution budget exceeded'):
            for handle in (1, *range(17, 1, -1)):
                for ordinal in range(16, 4112):
                    self.assertEqual(policy.observed(True, ordinal), (2, handle, steps + 1))
                    steps += 1
                    policy.advance(False)
                policy.observed(False)
        self.assertEqual(steps, 65536)

    def test_actual_native_solver_proves_scalar_artifact_without_host_search(self):
        from pathlib import Path
        import tempfile
        import time

        import z3
        from hepta.hia_cnf_native import selected_cnf
        from hepta.hia_program import verify_program
        from hepta.hia_program_native import compile_program_machine, emit_program_machine
        from hepta.hia_safe_core import _native_obligation, validate_safe_core_artifact
        from tests.test_hia_program import arithmetic

        cnf = selected_cnf()
        if cnf is None:
            self.skipTest('requires the installed HIA Boolean solver')
        with tempfile.TemporaryDirectory(prefix='hia-safe-core-native-sat-') as root:
            core = verify_program(arithmetic('int.mul.wrap', 'u32'))
            image = emit_program_machine(core)
            final = Path(root) / 'candidate.so'
            compile_program_machine(image, program=core, output=final, linker='ld')
            retained = Path(root) / 'queries'
            with (patch.object(z3.Solver, 'check', side_effect=AssertionError('host SMT search entered')),
                  patch('hepta.hia_cnf_native.bitblast_goal',
                        side_effect=AssertionError('host Boolean lowering entered'))):
                report = validate_safe_core_artifact(core, image.object_bytes, final.read_bytes(),
                                                     query_directory=retained)
                ctx = z3.Context()
                word = z3.BitVec('native_witness_word', 64, ctx=ctx)
                verdict, witness, receipt = _native_obligation(z3, cnf, word == 0xD00D, time.monotonic() + 4)
        self.assertTrue(report['ok'], report)
        self.assertEqual([row['result'] for row in report['obligations']], ['sat', *(['unsat'] * 4)])
        self.assertEqual(report['source_identity']['native_cnf_image_sha256'], cnf.image_sha256)
        for row in report['obligations']:
            proof = row['native_cnf']
            self.assertEqual(proof['method'], 'native_hia_circuit_cnf')
            self.assertEqual(proof['image_sha256'], cnf.image_sha256)
            self.assertEqual(len(proof['formula_sha256']), 64)
        self.assertEqual(verdict, 'sat')
        self.assertEqual(witness.eval(word).as_long(), 0xD00D)
        self.assertEqual(receipt['image_sha256'], cnf.image_sha256)


if __name__ == '__main__':
    unittest.main()
