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

    def test_actual_consumer_proves_from_installed_machine_rules_without_host_formulas(self):
        from hashlib import sha256
        from pathlib import Path
        import tempfile

        from hepta.hia_program import verify_program
        from hepta.hia_program_native import compile_program_machine, emit_program_machine
        from hepta.hia_safe_core import validate_safe_core_artifact
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


if __name__ == '__main__':
    unittest.main()
