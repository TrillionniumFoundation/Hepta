"""Independent checks for the selected reference VM scalar semantics."""

from hashlib import sha256
from itertools import product
import json
import os
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import WIDTHS, integer_range
from hepta.hia_program_runtime import HIAProgramTrap, _Machine, execute_program
from hepta.hia_scalar_reference_native import (
    OPCODES, SCHEMA, SELECTOR, SOURCE, NativeScalarReference,
)


class ScalarReferenceSourceTests(unittest.TestCase):
    def test_checked_in_hia_source_reproduces(self):
        from tools.generate_hia_scalar_reference import document

        source = SOURCE.read_text()
        self.assertEqual(source, render_assembly(document()))
        assemble_program(source)


class ScalarReferenceNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_selfhost import build_seed, compile_stage

        cls.tmp = tempfile.TemporaryDirectory(prefix='hia-scalar-reference-')
        cls.addClassCleanup(cls.tmp.cleanup)
        root = Path(cls.tmp.name)
        seed, _ = build_seed(root)
        selfhost = SOURCE.with_name('selfhost.hepta').read_bytes()
        first, _ = compile_stage(root, 'B1', seed, selfhost, image_format='seed-shared')
        compiler, _ = compile_stage(root, 'B2', first, selfhost)
        assert first.read_bytes() == compiler.read_bytes()
        image, receipt = compile_stage(root, 'reference', compiler, SOURCE.read_bytes())
        assert receipt['forbidden_compiler_modules_loaded'] == []
        image_bytes = image.read_bytes()
        digest = sha256(image_bytes).hexdigest()
        cls.native = NativeScalarReference(image_bytes, digest)
        cls.manifest = root/'manifest.json'
        cls.manifest.write_text(json.dumps({'schema': SCHEMA,
            'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(), 'image_path': image.name,
            'image_sha256': digest, 'compiler_sha256': sha256(compiler.read_bytes()).hexdigest()}))

    def test_finite_domains_are_complete_and_lexicographic(self):
        by_type = {'bool': (False, True), 'i8': range(-128, 128), 'u8': range(256)}
        for types in ((), ('bool',) * 12, ('bool', 'i8', 'bool'), ('u8',) + ('bool',) * 4):
            expected = list(product(*(by_type[kind] for kind in types)))
            actual = [self.native.finite_arguments(types, i, len(expected))
                      for i in range(len(expected))]
            self.assertEqual(actual, expected)
            with self.assertRaisesRegex(RuntimeError, 'finite-domain argument'):
                self.native.finite_arguments(types, len(expected), len(expected))

    def test_agent_finite_proof_matches_transcript_and_first_counterexample(self):
        from hepta.hia_agent_service import HIAAgentService
        from hepta.hia_program import verify_program
        from tools.hia_agent_native_qualification import add_program

        service = object.__new__(HIAAgentService)
        original = verify_program(add_program(typ='i8'))
        equivalent = verify_program(add_program(typ='i8', optimized=True))
        changed = add_program(typ='i8')
        changed['functions'][0]['blocks'][0]['term']['values'] = ['x']
        changed = verify_program(changed)
        targets = equivalent, changed
        expected = [service._behavior_equivalence(original, target, 10000) for target in targets]
        self.assertEqual(expected[0][0], 'proved')
        self.assertEqual(expected[0][2]['checked'], 256)
        self.assertEqual(expected[1][0], 'refuted')
        self.assertEqual(expected[1][2]['counterexample']['arguments'], [-128])
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch('hepta.hia_agent_service.itertools.product', side_effect=AssertionError('host enumeration')),
              patch.object(_Machine, 'invoke', side_effect=AssertionError('host CFG interpreter'))):
            self.assertEqual([service._behavior_equivalence(original, target, 10000)
                              for target in targets], expected)

        self.assertTrue(self.native.same_observation(b'\0\xff', b'\0\xff'))
        self.assertFalse(self.native.same_observation(b'\0\xff', b'\0\xfe'))
        self.assertFalse(self.native.same_observation(b'\0', b'\0\0'))

    def test_every_scalar_operator_and_signed_unsigned_boundaries_match_reference(self):
        rng = random.Random(0x484941)
        vm = object.__new__(_Machine)
        vm.scalar_reference = None

        def observed(operation):
            try:
                return ('value', operation())
            except HIAProgramTrap as error:
                return ('trap', error.code, str(error))

        def test(opcode, typ, inputs):
            env = dict(zip(('a', 'b', 'c'), inputs))
            is_cast = opcode.startswith('cast.')
            ins = {'op': 'int.cast' if is_cast else opcode, 'args': list(env),
                   'out': [{'name': 'out', 'type': typ}],
                   'attrs': {'mode': opcode[5:]} if is_cast else {}}

            def reference():
                vm.operation(ins, env, 0)
                return env['out']

            self.assertEqual(observed(lambda: self.native.operation(opcode, typ, inputs)),
                             observed(reference), (opcode, typ, inputs))

        for typ, width in WIDTHS.items():
            low, high = integer_range(typ)
            points = sorted({value for value in (low, low + 1, -2, -1, 0, 1, 2, high - 1, high)
                             if low <= value <= high})
            pairs = [(left, right) for left in points for right in points]
            pairs += [(rng.randint(low, high), rng.randint(low, high)) for _ in range(32)]
            for opcode in OPCODES:
                if opcode.startswith('bool.'):
                    continue
                if opcode.startswith('cast.'):
                    for source_type in WIDTHS:
                        minimum, maximum = integer_range(source_type)
                        for value in (minimum, minimum + 1, 0, maximum - 1, maximum,
                                      rng.randint(minimum, maximum)):
                            test(opcode, typ, (value,))
                elif opcode in ('int.neg.checked', 'bit.not'):
                    for value in points:
                        test(opcode, typ, (value,))
                elif opcode in ('int.shl.checked', 'int.shr.checked'):
                    for value in points:
                        for shift in (0, 1, width-1, width, width+1, (1<<64)-1):
                            test(opcode, typ, (value, shift))
                elif opcode == 'select':
                    for condition in (True, False):
                        test(opcode, typ, (condition, low, high))
                else:
                    for left, right in pairs:
                        test(opcode, 'bool' if opcode.startswith('compare.') else typ, (left, right))
        for left in (False, True):
            test('bool.not', 'bool', (left,))
            for right in (False, True):
                for opcode in ('bool.and', 'bool.or', 'compare.eq', 'compare.ne'):
                    test(opcode, 'bool', (left, right))

    def test_normal_reference_entry_returns_exact_report_and_first_trap(self):
        from tests.test_hia_program import b, f, i, m, ret

        args = [('a', 'i64'), ('b', 'i64')]
        doc = m(f('calculate', args, ['i64'], ['trap'], [b('entry', args, [
            i('int.mul.checked', ['a', 'b'], [('product', 'i64')]),
            i('int.div.checked', ['product', 'b'], [('result', 'i64')])], ret('result'))]))

        def observe(values):
            try:
                return execute_program(doc, 'calculate', values)
            except HIAProgramTrap as error:
                return error.report

        inputs = ((-113, 28), (4, 0), (-(1<<63), -1))
        expected = [observe(values) for values in inputs]
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch('hepta.hia_program_runtime._checked', side_effect=AssertionError('host ALU')),
              patch('hepta.hia_program_runtime._wrap', side_effect=AssertionError('host ALU'))):
            self.assertEqual([observe(values) for values in inputs], expected)

    def test_disposable_reference_child_uses_exact_inherited_sealed_bytes(self):
        import subprocess
        from hepta.hia_agent_runner import run_reference_batch
        from hepta.hia_program import verify_program
        from tests.test_hia_program_tools import scalar_program

        program = verify_program(scalar_program())
        cases = [{'function': 'increment', 'arguments': [5]}]
        budget = {'timeout_ms': 3000, 'memory_bytes': 128 << 20}
        unselected = run_reference_batch(program, cases, **budget)
        popen = subprocess.Popen

        def child(*args, **kwargs):
            self.assertEqual(len(kwargs.get('pass_fds', ())), 1)
            kwargs['env'] = {**os.environ, SELECTOR: '/missing/reference-manifest.json'}
            return popen(*args, **kwargs)

        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch('hepta.hia_agent_runner.subprocess.Popen', side_effect=child)):
            selected = run_reference_batch(program, cases, **budget)
        self.assertEqual(unselected['status'], 'returned', unselected)
        self.assertEqual(selected['status'], 'returned', selected)
        self.assertEqual(selected['report']['reference_evaluator_sha256'], self.native.image_sha256)
        self.assertEqual(selected['report']['observations'], unselected['report']['observations'])

    def test_native_scalar_control_preserves_parallel_edges_returns_and_budgets(self):
        from hepta.hia_program_runtime import HIAProgramBudgetExceeded
        from tests.test_hia_program import b, f, i, m, ret
        from tests.test_hia_program_native import scalar_document

        arithmetic = scalar_document()
        argument = [('x', 'i32')]
        recursive = m(f('again', argument, ['i32'], [], [b('entry', argument, [
            i('call', ['x'], [('y', 'i32')], function='again')], ret('y'))]))
        returns = ['i32', 'bool']
        results = m(f('pair', argument, returns, [], [b('entry', argument, [
            i('compare.eq', ['x', 'x'], [('same', 'bool')])], ret('x', 'same'))]),
            f('pairs', argument, returns, [], [b('entry', argument, [
                i('call', ['x'], [('value', 'i32'), ('same', 'bool')], function='pair')],
                ret('value', 'same'))]))
        cases = [(arithmetic, 'edge_swap', [13, 27, count], {}) for count in range(15)]
        cases += [(arithmetic, 'edge_swap', [13, 27, 14], {'max_steps': ticks})
                  for ticks in (1, 2, 8, 30, 132)]
        cases += [(arithmetic, 'explicit_trap', [], {}), (results, 'pairs', [-7], {})]
        cases += [(recursive, 'again', [5], {'max_call_depth': depth})
                  for depth in (1, 5, 127, 256)]

        def observe(cases):
            terminal = []
            for program, entry, arguments, limits in cases:
                try:
                    terminal.append(execute_program(program, entry, arguments, **limits))
                except (HIAProgramBudgetExceeded, HIAProgramTrap) as error:
                    terminal.append(error.report)
            return terminal

        expected = observe(cases)
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch.object(_Machine, 'invoke', side_effect=AssertionError('host CFG interpreter'))):
            self.assertEqual(observe(cases), expected)

    def test_byte_ranges_and_traps_use_existing_owned_buffers_without_host_writes(self):
        from tests.test_hia_program_native_review import _bounds_program, _empty_memory_program

        target = bytearray(range(9))
        source = bytearray(range(30, 39))
        self.native.byte_operation('copy_range', target, offset=1, source=source, source_offset=2, count=3)
        self.native.byte_operation('fill', target, offset=5, count=2, value=3)
        self.native.byte_operation('move', target, offset=2, source_offset=0, count=5)
        self.native.byte_operation('move', target, offset=0, source_offset=2, count=4)
        self.native.byte_operation('swap', target, offset=1, source_offset=3)
        self.native.byte_operation('store', target, offset=7, value=255)
        self.assertEqual(self.native.byte_operation('load', target, offset=7), 255)
        self.assertEqual(target, bytearray((0, 34, 33, 32, 33, 34, 4, 255, 8)))
        self.assertEqual(source, bytearray(range(30, 39)))
        snapshot = target[:]
        invalid = (('load', {'offset':len(target)}), ('store', {'offset':len(target)}),
                   ('fill', {'offset':len(target), 'count':1}),
                   ('copy_range', {'source':source, 'source_offset':len(source), 'count':1}),
                   ('move', {'offset':1, 'source_offset':0, 'count':1<<63}),
                   ('swap', {'offset':1, 'source_offset':len(target)}))
        for kind, arguments in invalid:
            with self.subTest(kind=kind), self.assertRaises(HIAProgramTrap):
                self.native.byte_operation(kind, target, **arguments)
            self.assertEqual(target, snapshot)
        self.native.byte_operation('move', target, offset=len(target), source_offset=len(target), count=0)
        self.native.byte_operation('copy_range', bytearray(), source=bytearray(), count=0)

        empty = _empty_memory_program()
        bounds = _bounds_program()
        cases = [(empty, 'empty_memory', ()),
                 *((bounds, name, ((1 << 64) - 1, 1))
                   for name in ('bad_copy', 'bad_fill', 'bad_move', 'bad_swap'))]
        def observe():
            terminal = []
            for doc, name, arguments in cases:
                try:
                    terminal.append(execute_program(doc, name, arguments))
                except HIAProgramTrap as error:
                    terminal.append(error.report)
            return terminal

        expected = observe()
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch('hepta.hia_program_runtime.fill_bytes', side_effect=AssertionError('host fill')),
              patch('hepta.hia_program_runtime.move_bytes', side_effect=AssertionError('host move'))):
            self.assertEqual(observe(), expected)

    def test_allocator_preflight_keeps_empty_attempts_fault_injection_and_heap_status(self):
        from hepta.hia_program_runtime import HIAProgramBudgetExceeded
        from tests.test_hia_program import resource_program

        self.assertEqual(self.native.allocation(0, 0, 0, 0, 1), ('empty', 0))
        self.assertEqual(self.native.allocation(1 << 63, 8, 0, 0, 1), ('object-model', 0))
        self.assertEqual(self.native.allocation(5, 8, 4, 2, 3), ('heap-budget', 2))
        self.assertEqual(self.native.allocation(4, 8, 4, 2, 3), ('injected', 3))
        self.assertEqual(self.native.allocation(4, 8, 4, 2, 1 << 200), ('allocate', 3))

        cases = ((8, 8, 1), (8, 7, 1), (8, 8, None), (8, 8, 1 << 200), (1 << 63, 8, None))
        def compare():
            answers = []
            for size, limit, fault in cases:
                try:
                    answers.append(execute_program(resource_program(), 'owned', [size, 45],
                                                   max_heap_bytes=limit, allocation_fail_at=fault))
                except (HIAProgramTrap, HIAProgramBudgetExceeded) as error:
                    answers.append(error.report)
            return answers

        expected = compare()
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch.object(_Machine, '_reference_allocation_decision',
                           side_effect=AssertionError('host allocation preflight'))):
            self.assertEqual(compare(), expected)
