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

    def test_resource_cfg_resumes_exactly_at_calls_edges_and_partial_destruction(self):
        from hepta.hia_program_runtime import HIAProgramBudgetExceeded
        from hepta.hia_schema import SCHEMA_V7
        from tests.test_hia_program import b, c, f, i, joined_loan_program, m, ret

        child = f('dispose', [('nodes', 'chain')], [], ['alloc', 'write', 'trap'], [
            b('entry', [('nodes', 'chain')], [i('owner.drop', ['nodes'])], ret())])
        entry = f('build', [], ['bool'], ['alloc', 'write', 'trap'], [b('entry', [], [
            c('size', 'usize', 2), i('chain.empty', [], [('empty', 'chain')]),
            i('buffer.new', ['size'], [('payload', 'buffer')]),
            i('chain.try_push', ['empty', 'payload'],
              [('built', 'chain'), ('remaining', 'buffer'), ('pushed', 'bool')]),
            i('owner.drop', ['remaining']),
            i('call', ['built'], function='dispose'),
        ], ret('pushed'))])
        chain = m(entry, child)
        chain['schema'] = SCHEMA_V7
        cases = [(joined_loan_program(), 'join', [condition], {})
                 for condition in (False, True)]
        cases += [(chain, 'build', [], {'max_steps': steps, 'allocation_fail_at': failure})
                  for steps in range(1, 15) for failure in (None, 2)]
        cases += [(chain, 'build', [], {'max_call_depth': 1})]

        def observe():
            reports = []
            for program, entry, arguments, options in cases:
                try:
                    reports.append(execute_program(program, entry, arguments, **options))
                except (HIAProgramTrap, HIAProgramBudgetExceeded) as error:
                    reports.append(error.report)
            return reports

        expected = observe()
        self.assertTrue(any(row['status'] == 'returned' for row in expected))
        self.assertTrue(any(row['status'] == 'budget_exceeded' for row in expected))
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch.object(_Machine, 'invoke', side_effect=AssertionError('host CFG interpreter')),
              patch.object(_Machine, 'operation', side_effect=AssertionError('host resource interpreter')),
              patch.object(_Machine, '_reference_allocation_decision',
                           side_effect=AssertionError('host allocation preflight'))):
            self.assertEqual(observe(), expected)

    def test_native_nested_return_loans_keep_original_parent_and_exact_deadline(self):
        from hepta.hia_program_runtime import HIAProgramBudgetExceeded
        from tests.test_hia_returned_chain_loans import chain_program

        def observe():
            result = []
            for permission in ('read', 'mut'):
                for kind in ('child', 'forward'):
                    source = chain_program(permission, kind)
                    entry, = source['exports']
                    for ticks in range(11, 37):
                        try:
                            report = execute_program(source, entry, [37], max_steps=ticks)
                        except HIAProgramBudgetExceeded as error:
                            report = error.report
                        result.append(report)
            return result

        expected = observe()
        self.assertEqual({row['status'] for row in expected}, {'returned', 'budget_exceeded'})
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch.object(_Machine, 'invoke', side_effect=AssertionError('host CFG interpreter')),
              patch.object(_Machine, 'return_view', side_effect=AssertionError('host return-loan owner')),
              patch.object(_Machine, 'operation', side_effect=AssertionError('host resource interpreter'))):
            self.assertEqual(observe(), expected)

    def test_native_loan_arena_refuses_expired_generation_and_permission_escalation(self):
        table = bytearray(24 * 3)
        status, parent, root = self.native.loan_operation(table, 2, 2, mutable=True)
        self.assertEqual((status, root), (0, 2))
        status, first, root = self.native.loan_operation(table, 2, parent)
        self.assertEqual((status, root), (0, 2))
        frozen = table[:]
        self.assertEqual(self.native.loan_operation(table, 2, parent)[0], 3)
        self.assertEqual(self.native.loan_operation(table, 1, first, mutable=True)[0], 2)
        self.assertEqual(self.native.loan_operation(table, 4, parent, first)[0], 4)
        self.assertEqual(table, frozen)
        self.assertEqual(self.native.loan_operation(table, 3, first)[0], 0)
        status, second, root = self.native.loan_operation(table, 2, parent)
        self.assertEqual((status, root), (0, 2))
        self.assertEqual(first & ((1<<25)-1), second & ((1<<25)-1))
        self.assertNotEqual(first, second)
        frozen = table[:]
        self.assertEqual(self.native.loan_operation(table, 1, first)[0], 1)
        self.assertEqual(table, frozen)
        self.assertEqual(self.native.loan_operation(table, 4, second, parent), (0, second, 2))

    def test_native_chain_arena_rotates_consumed_handles_and_preserves_refusal(self):
        table = bytearray(40 * 3)
        status, empty, _, _, present, live = self.native.chain_operation(table, 1, 0)
        self.assertEqual((status, present, live), (0, False, 1))
        status, pushed, _, _, present, live = self.native.chain_operation(table, 3, empty, 21, 31, True)
        self.assertEqual((status, present, live), (0, True, 1))
        self.assertNotEqual(empty, pushed)
        frozen = table[:]
        self.assertEqual(self.native.chain_operation(table, 2, empty)[0], 1)
        self.assertEqual(self.native.chain_operation(table, 3, pushed, 22, 32, True)[0], 3)
        self.assertEqual(table, frozen)
        status, rest, payload, storage, present, live = self.native.chain_operation(table, 4, pushed)
        self.assertEqual((status, payload, storage, present, live), (0, 21, 31, True, 1))
        self.assertEqual(self.native.chain_operation(table, 5, rest), (0, 0, 0, 0, False, 0))

    def test_native_chain_reclaims_a_wide_list_under_the_exact_step_limit(self):
        from hepta.hia_program_runtime import HIAProgramBudgetExceeded
        from hepta.hia_schema import SCHEMA_V7
        from tests.test_hia_program import b, c, f, i, m, ret

        operations = [c('size', 'usize', 1), i('chain.empty', out=[('chain0', 'chain')])]
        for ordinal in range(36):
            payload, fallback, ok = (f'{name}{ordinal}' for name in ('payload', 'fallback', 'ok'))
            operations.extend([
                i('buffer.new', ['size'], [(payload, 'buffer')]),
                i('chain.try_push', [f'chain{ordinal}', payload],
                  [(f'chain{ordinal+1}', 'chain'), (fallback, 'buffer'), (ok, 'bool')]),
                i('owner.drop', [fallback]),
            ])
        operations += [i('owner.drop', ['chain36'])]
        program = m(f('many', [], [], ['alloc', 'trap'], [b('entry', [], operations, ret())]))
        program['schema'] = SCHEMA_V7

        def observe():
            states = []
            for steps in (112, 128, 256):
                try:
                    states.append(execute_program(program, 'many', [], max_steps=steps))
                except HIAProgramBudgetExceeded as error:
                    states.append(error.report)
            return states

        expected = observe()
        self.assertEqual([row['resources']['chain_nodes_dropped'] for row in expected], [0, 16, 36])
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch.object(_Machine, 'invoke', side_effect=AssertionError('host CFG interpreter')),
              patch.object(_Machine, 'operation', side_effect=AssertionError('host resource interpreter'))):
            self.assertEqual(observe(), expected)

    def test_live_read_loans_grow_the_table_and_balance_without_host_borrows(self):
        from tests.test_hia_program import b, c, f, i, m, ret

        code = [c('size', 'usize', 1), i('buffer.new', ['size'], [('owner', 'buffer')])]
        names = [f'loan{n}' for n in range(40)]
        code += [i('borrow.read', ['owner'], [(name, 'readbuf')]) for name in names]
        code += [i('loan.end', [name]) for name in reversed(names)]
        code += [i('owner.drop', ['owner'])]
        doc = m(f('many', [], [], ['alloc', 'trap'], [b('entry', [], code, ret())]))
        expected = execute_program(doc, 'many', [])
        self.assertEqual(expected['resources']['loans_ended'], 40)
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch.object(_Machine, 'invoke', side_effect=AssertionError('host CFG interpreter'))):
            self.assertEqual(execute_program(doc, 'many', []), expected)

    def test_external_snapshots_use_native_cfg_on_return_and_abort(self):
        from hepta.hia_agent_buffers import reference_observation
        from tests.test_hia_agent_buffer_lifecycle import trap_program, workload
        from tests.test_hia_native_byte_abi import byte_program
        from tests.test_hia_program import b, c, f, ret

        copy_case, = workload()['cases']
        trap_case = {'function': 'write_then_trap', 'arguments': [{'bytes_hex': 'ff00'}]}
        params = [('snapshot', 'readbuf')]
        unused = trap_program()
        unused['functions'] = [f('unused', params, ['u32'], [], [
            b('entry', params, [c('answer', 'u32', 1)], ret('answer'))])]
        unused_case = {'function': 'unused', 'arguments': [{'bytes_hex': '00ff'}]}

        def observe():
            return [reference_observation(doc, case, ((case['function'], 8),), steps=ticks, heap=0)
                    for doc, case in ((byte_program(), copy_case), (trap_program(), trap_case),
                                      (unused, unused_case))
                    for ticks in (1, 5, 1000)]

        expected = observe()
        self.assertEqual({row['status'] for row in expected}, {'returned', 'trapped', 'budget_exceeded'})
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch.object(_Machine, 'invoke', side_effect=AssertionError('host CFG interpreter'))):
            self.assertEqual(observe(), expected)

    def test_wide_verified_function_needs_only_one_materialized_root_frame(self):
        from hepta.hia_program import verify_program
        from tests.test_hia_program import b, c, f, m, ret

        operations = [c(f'value{i}', 'u16', i) for i in range(5000)]
        doc = m(f('wide', [], ['u16'], [], [b('entry', [], operations, ret('value4999'))]))
        checked = verify_program(doc)
        expected = execute_program(checked, 'wide', [])
        native_entry = self.native._entry
        workspaces = []

        def enter(source, source_size, output, output_size, workspace, workspace_size):
            workspaces.append(workspace_size)
            return native_entry(source, source_size, output, output_size, workspace, workspace_size)

        with patch.object(self.native, '_entry', side_effect=enter):
            self.assertEqual(self.native.program(checked.canonical_bytes, 'wide', [], 1_000_000, 256),
                             (expected['steps'], [4999], None))
        self.assertEqual(workspaces, [64 + 8*(5000 + 1 + 1)])
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch.object(_Machine, 'invoke', side_effect=AssertionError('host CFG interpreter'))):
            self.assertEqual(execute_program(checked, 'wide', []), expected)
